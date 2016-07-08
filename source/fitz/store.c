#include "mupdf/fitz.h"

typedef struct fz_item_s fz_item;

struct fz_item_s
{
	void *key;
	fz_storable *val;
	size_t size;
	fz_item *next;
	fz_item *prev;
	fz_store *store;
	fz_store_type *type;
};

struct fz_store_s
{
	int refs;

	/* Every item in the store is kept in a doubly linked list, ordered
	 * by usage (so LRU entries are at the end). */
	fz_item *head;
	fz_item *tail;

	/* We have a hash table that allows to quickly find a subset of the
	 * entries (those whose keys are indirect objects). */
	fz_hash_table *hash;

	/* We keep track of the size of the store, and keep it below max. */
	size_t max;
	size_t size;
};

void
fz_new_store_context(fz_context *ctx, size_t max)
{
	fz_store *store;
	store = fz_malloc_struct(ctx, fz_store);
	fz_try(ctx)
	{
		store->hash = fz_new_hash_table(ctx, 4096, sizeof(fz_store_hash), FZ_LOCK_ALLOC);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, store);
		fz_rethrow(ctx);
	}
	store->refs = 1;
	store->head = NULL;
	store->tail = NULL;
	store->size = 0;
	store->max = max;
	ctx->store = store;
}

void *
fz_keep_storable(fz_context *ctx, const fz_storable *sc)
{
	/* Explicitly drop const to allow us to use const
	 * sanely throughout the code. */
	fz_storable *s = (fz_storable *)sc;

	if (s && s->refs > 0)
		(void)Memento_takeRef(s);
	return fz_keep_imp(ctx, s, &s->refs);
}

void
fz_drop_storable(fz_context *ctx, const fz_storable *sc)
{
	/* Explicitly drop const to allow us to use const
	 * sanely throughout the code. */
	fz_storable *s = (fz_storable *)sc;

	/*
		If we are dropping the last reference to an object, then
		it cannot possibly be in the store (as the store always
		keeps a ref to everything in it, and doesn't drop via
		this method. So we can simply drop the storable object
		itself without any operations on the fz_store.
	 */
	if (s && s->refs > 0)
		(void)Memento_dropRef(s);
	if (fz_drop_imp(ctx, s, &s->refs))
		s->drop(ctx, s);
}

static void
evict(fz_context *ctx, fz_item *item)
{
	fz_store *store = ctx->store;
	int drop;

	store->size -= item->size;
	/* Unlink from the linked list */
	if (item->next)
		item->next->prev = item->prev;
	else
		store->tail = item->prev;
	if (item->prev)
		item->prev->next = item->next;
	else
		store->head = item->next;

	/* Drop a reference to the value (freeing if required) */
	drop = (item->val->refs > 0 && --item->val->refs == 0);

	/* Remove from the hash table */
	if (item->type->make_hash_key)
	{
		fz_store_hash hash = { NULL };
		hash.drop = item->val->drop;
		if (item->type->make_hash_key(ctx, &hash, item->key))
			fz_hash_remove(ctx, store->hash, &hash);
	}
	fz_unlock(ctx, FZ_LOCK_ALLOC);
	if (drop)
		item->val->drop(ctx, item->val);

	/* Always drops the key and drop the item */
	item->type->drop_key(ctx, item->key);
	fz_free(ctx, item);
	fz_lock(ctx, FZ_LOCK_ALLOC);
}

static size_t
ensure_space(fz_context *ctx, size_t tofree)
{
	fz_item *item, *prev;
	size_t count;
	fz_store *store = ctx->store;

	fz_assert_lock_held(ctx, FZ_LOCK_ALLOC);

	/* First check that we *can* free tofree; if not, we'd rather not
	 * cache this. */
	count = 0;
	for (item = store->tail; item; item = item->prev)
	{
		if (item->val->refs == 1)
		{
			count += item->size;
			if (count >= tofree)
				break;
		}
	}

	/* If we ran out of items to search, then we can never free enough */
	if (item == NULL)
	{
		return 0;
	}

	/* Actually free the items */
	count = 0;
	for (item = store->tail; item; item = prev)
	{
		prev = item->prev;
		if (item->val->refs == 1)
		{
			/* Free this item. Evict has to drop the lock to
			 * manage that, which could cause prev to be removed
			 * in the meantime. To avoid that we bump its reference
			 * count here. This may cause another simultaneous
			 * evict process to fail to make enough space as prev is
			 * pinned - but that will only happen if we're near to
			 * the limit anyway, and it will only cause something to
			 * not be cached. */
			count += item->size;
			if (prev)
				prev->val->refs++;
			evict(ctx, item); /* Drops then retakes lock */
			/* So the store has 1 reference to prev, as do we, so
			 * no other evict process can have thrown prev away in
			 * the meantime. So we are safe to just decrement its
			 * reference count here. */
			if (prev)
				--prev->val->refs;

			if (count >= tofree)
				return count;
		}
	}

	return count;
}

static void
touch(fz_store *store, fz_item *item)
{
	if (item->next != item)
	{
		/* Already in the list - unlink it */
		if (item->next)
			item->next->prev = item->prev;
		else
			store->tail = item->prev;
		if (item->prev)
			item->prev->next = item->next;
		else
			store->head = item->next;
	}
	/* Now relink it at the start of the LRU chain */
	item->next = store->head;
	if (item->next)
		item->next->prev = item;
	else
		store->tail = item;
	store->head = item;
	item->prev = NULL;
}

void *
fz_store_item(fz_context *ctx, void *key, void *val_, size_t itemsize, fz_store_type *type)
{
	fz_item *item = NULL;
	size_t size;
	fz_storable *val = (fz_storable *)val_;
	fz_store *store = ctx->store;
	fz_store_hash hash = { NULL };
	int use_hash = 0;
	unsigned pos;

	if (!store)
		return NULL;

	fz_var(item);

	/* If we fail for any reason, we swallow the exception and continue.
	 * All that the above program will see is that we failed to store
	 * the item. */
	fz_try(ctx)
	{
		item = fz_malloc_struct(ctx, fz_item);
	}
	fz_catch(ctx)
	{
		return NULL;
	}

	if (type->make_hash_key)
	{
		hash.drop = val->drop;
		use_hash = type->make_hash_key(ctx, &hash, key);
	}

	type->keep_key(ctx, key);
	fz_lock(ctx, FZ_LOCK_ALLOC);

	/* Fill out the item. To start with, we always set item->next == item
	 * and item->prev == item. This is so that we can spot items that have
	 * been put into the hash table without having made it into the linked
	 * list yet. */
	item->key = key;
	item->val = val;
	item->size = itemsize;
	item->next = item;
	item->prev = item;
	item->type = type;

	/* If we can index it fast, put it into the hash table. This serves
	 * to check whether we have one there already. */
	if (use_hash)
	{
		fz_item *existing;

		fz_try(ctx)
		{
			/* May drop and retake the lock */
			existing = fz_hash_insert_with_pos(ctx, store->hash, &hash, item, &pos);
		}
		fz_catch(ctx)
		{
			/* Any error here means that item never made it into the
			 * hash - so no one else can have a reference. */
			fz_unlock(ctx, FZ_LOCK_ALLOC);
			fz_free(ctx, item);
			type->drop_key(ctx, key);
			return NULL;
		}
		if (existing)
		{
			/* There was one there already! Take a new reference
			 * to the existing one, and drop our current one. */
			touch(store, existing);
			if (existing->val->refs > 0)
				existing->val->refs++;
			fz_unlock(ctx, FZ_LOCK_ALLOC);
			fz_free(ctx, item);
			type->drop_key(ctx, key);
			return existing->val;
		}
	}
	/* Now bump the ref */
	if (val->refs > 0)
		val->refs++;
	/* If we haven't got an infinite store, check for space within it */
	if (store->max != FZ_STORE_UNLIMITED)
	{
		size = store->size + itemsize;
		while (size > store->max)
		{
			/* ensure_space may drop, then retake the lock */
			size_t saved = ensure_space(ctx, size - store->max);
			size -= saved;
			if (saved == 0)
			{
				/* Failed to free any space. */
				/* We used to 'unstore' it here, but that's wrong.
				 * If we've already spent the memory to malloc it
				 * then not putting it in the store just means that
				 * a resource used multiple times will just be malloced
				 * again. Better to put it in the store, have the
				 * store account for it, and for it to potentially be reused.
				 * When the caller drops the reference to it, it can then
				 * be dropped from the store on the next attempt to store
				 * anything else. */
				break;
			}
		}
	}
	store->size += itemsize;

	/* Regardless of whether it's indexed, it goes into the linked list */
	touch(store, item);
	fz_unlock(ctx, FZ_LOCK_ALLOC);

	return NULL;
}

void *
fz_find_item(fz_context *ctx, fz_store_drop_fn *drop, void *key, fz_store_type *type)
{
	fz_item *item;
	fz_store *store = ctx->store;
	fz_store_hash hash = { NULL };
	int use_hash = 0;

	if (!store)
		return NULL;

	if (!key)
		return NULL;

	if (type->make_hash_key)
	{
		hash.drop = drop;
		use_hash = type->make_hash_key(ctx, &hash, key);
	}

	fz_lock(ctx, FZ_LOCK_ALLOC);
	if (use_hash)
	{
		/* We can find objects keyed on indirected objects quickly */
		item = fz_hash_find(ctx, store->hash, &hash);
	}
	else
	{
		/* Others we have to hunt for slowly */
		for (item = store->head; item; item = item->next)
		{
			if (item->val->drop == drop && !type->cmp_key(ctx, item->key, key))
				break;
		}
	}
	if (item)
	{
		/* LRU the block. This also serves to ensure that any item
		 * picked up from the hash before it has made it into the
		 * linked list does not get whipped out again due to the
		 * store being full. */
		touch(store, item);
		/* And bump the refcount before returning */
		if (item->val->refs > 0)
			item->val->refs++;
		fz_unlock(ctx, FZ_LOCK_ALLOC);
		return (void *)item->val;
	}
	fz_unlock(ctx, FZ_LOCK_ALLOC);

	return NULL;
}

void
fz_remove_item(fz_context *ctx, fz_store_drop_fn *drop, void *key, fz_store_type *type)
{
	fz_item *item;
	fz_store *store = ctx->store;
	int dodrop;
	fz_store_hash hash = { NULL };
	int use_hash = 0;

	if (type->make_hash_key)
	{
		hash.drop = drop;
		use_hash = type->make_hash_key(ctx, &hash, key);
	}

	fz_lock(ctx, FZ_LOCK_ALLOC);
	if (use_hash)
	{
		/* We can find objects keyed on indirect objects quickly */
		item = fz_hash_find(ctx, store->hash, &hash);
		if (item)
			fz_hash_remove(ctx, store->hash, &hash);
	}
	else
	{
		/* Others we have to hunt for slowly */
		for (item = store->head; item; item = item->next)
			if (item->val->drop == drop && !type->cmp_key(ctx, item->key, key))
				break;
	}
	if (item)
	{
		/* Momentarily things can be in the hash table without being
		 * in the list. Don't attempt to unlink these. We indicate
		 * such items by setting item->next == item. */
		if (item->next != item)
		{
			if (item->next)
				item->next->prev = item->prev;
			else
				store->tail = item->prev;
			if (item->prev)
				item->prev->next = item->next;
			else
				store->head = item->next;
		}
		dodrop = (item->val->refs > 0 && --item->val->refs == 0);
		fz_unlock(ctx, FZ_LOCK_ALLOC);
		if (dodrop)
			item->val->drop(ctx, item->val);
		type->drop_key(ctx, item->key);
		fz_free(ctx, item);
	}
	else
		fz_unlock(ctx, FZ_LOCK_ALLOC);
}

void
fz_empty_store(fz_context *ctx)
{
	fz_store *store = ctx->store;

	if (store == NULL)
		return;

	fz_lock(ctx, FZ_LOCK_ALLOC);
	/* Run through all the items in the store */
	while (store->head)
	{
		evict(ctx, store->head); /* Drops then retakes lock */
	}
	fz_unlock(ctx, FZ_LOCK_ALLOC);
}

fz_store *
fz_keep_store_context(fz_context *ctx)
{
	if (ctx == NULL || ctx->store == NULL)
		return NULL;
	return fz_keep_imp(ctx, ctx->store, &ctx->store->refs);
}

void
fz_drop_store_context(fz_context *ctx)
{
	if (ctx == NULL || ctx->store == NULL)
		return;
	if (fz_drop_imp(ctx, ctx->store, &ctx->store->refs))
	{
		fz_empty_store(ctx);
		fz_drop_hash(ctx, ctx->store->hash);
		fz_free(ctx, ctx->store);
		ctx->store = NULL;
	}
}

static void
print_item(fz_context *ctx, fz_output *out, void *item_)
{
	fz_item *item = (fz_item *)item_;
	fz_printf(ctx, out, " val=%p item=%p\n", item->val, item);
}

void
fz_print_store_locked(fz_context *ctx, fz_output *out)
{
	fz_item *item, *next;
	fz_store *store = ctx->store;

	fz_printf(ctx, out, "-- resource store contents --\n");

	for (item = store->head; item; item = next)
	{
		next = item->next;
		if (next)
			next->val->refs++;
		fz_printf(ctx, out, "store[*][refs=%d][size=%d] ", item->val->refs, item->size);
		fz_unlock(ctx, FZ_LOCK_ALLOC);
		item->type->print(ctx, out, item->key);
		fz_printf(ctx, out, " = %p\n", item->val);
		fz_lock(ctx, FZ_LOCK_ALLOC);
		if (next)
			next->val->refs--;
	}
	fz_printf(ctx, out, "-- resource store hash contents --\n");
	fz_print_hash_details(ctx, out, store->hash, print_item);
	fz_printf(ctx, out, "-- end --\n");
}

void
fz_print_store(fz_context *ctx, fz_output *out)
{
	fz_lock(ctx, FZ_LOCK_ALLOC);
	fz_print_store_locked(ctx, out);
	fz_unlock(ctx, FZ_LOCK_ALLOC);
}

/* This is now an n^2 algorithm - not ideal, but it'll only be bad if we are
 * actually managing to scavenge lots of blocks back. */
static int
scavenge(fz_context *ctx, size_t tofree)
{
	fz_store *store = ctx->store;
	size_t count = 0;
	fz_item *item, *prev;

	/* Free the items */
	for (item = store->tail; item; item = prev)
	{
		prev = item->prev;
		if (item->val->refs == 1)
		{
			/* Free this item */
			count += item->size;
			evict(ctx, item); /* Drops then retakes lock */

			if (count >= tofree)
				break;

			/* Have to restart search again, as prev may no longer
			 * be valid due to release of lock in evict. */
			prev = store->tail;
		}
	}
	/* Success is managing to evict any blocks */
	return count != 0;
}

int fz_store_scavenge(fz_context *ctx, size_t size, int *phase)
{
	fz_store *store;
	size_t max;

	if (ctx == NULL)
		return 0;
	store = ctx->store;
	if (store == NULL)
		return 0;

#ifdef DEBUG_SCAVENGING
	printf("Scavenging: store=" FMT_zu " size=" FMT_zu " phase=%d\n", store->size, size, *phase);
	fz_print_store_locked(ctx, stderr);
	Memento_stats();
#endif
	do
	{
		size_t tofree;

		/* Calculate 'max' as the maximum size of the store for this phase */
		if (*phase >= 16)
			max = 0;
		else if (store->max != FZ_STORE_UNLIMITED)
			max = store->max / 16 * (16 - *phase);
		else
			max = store->size / (16 - *phase) * (15 - *phase);
		(*phase)++;

		/* Slightly baroque calculations to avoid overflow */
		if (size > SIZE_MAX - store->size)
			tofree = SIZE_MAX - max;
		else if (size + store->size > max)
			continue;
		else
			tofree = size + store->size - max;

		if (scavenge(ctx, tofree))
		{
#ifdef DEBUG_SCAVENGING
			printf("scavenged: store=" FMT_zu "\n", store->size);
			fz_print_store(ctx, stderr);
			Memento_stats();
#endif
			return 1;
		}
	}
	while (max > 0);

#ifdef DEBUG_SCAVENGING
	printf("scavenging failed\n");
	fz_print_store(ctx, stderr);
	Memento_listBlocks();
#endif
	return 0;
}

int
fz_shrink_store(fz_context *ctx, unsigned int percent)
{
	int success;
	fz_store *store;
	size_t new_size;

	if (ctx == NULL)
		return 0;

	if (percent >= 100)
		return 1;

	store = ctx->store;
	if (store == NULL)
		return 0;

#ifdef DEBUG_SCAVENGING
	fprintf(stderr, "fz_shrink_store: " FMT_zu "\n", store->size/(1024*1024));
#endif
	fz_lock(ctx, FZ_LOCK_ALLOC);

	new_size = (size_t)(((uint64_t)store->size * percent) / 100);
	if (store->size > new_size)
		scavenge(ctx, store->size - new_size);

	success = (store->size <= new_size) ? 1 : 0;
	fz_unlock(ctx, FZ_LOCK_ALLOC);
#ifdef DEBUG_SCAVENGING
	fprintf(stderr, "fz_shrink_store after: " FMT_zu "\n", store->size/(1024*1024));
#endif

	return success;
}
