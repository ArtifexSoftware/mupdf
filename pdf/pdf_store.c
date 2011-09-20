#include "fitz.h"
#include "mupdf.h"

typedef struct pdf_item_s pdf_item;

struct pdf_item_s
{
	pdf_store_drop_fn *drop_func;
	fz_obj *key;
	void *val;
	int age;
	pdf_item *next;
};

struct refkey
{
	pdf_store_drop_fn *drop_func;
	int num;
	int gen;
};

struct pdf_store_s
{
	fz_hash_table *hash;	/* hash for num/gen keys */
	pdf_item *root;		/* linked list for everything else */
};

pdf_store *
pdf_new_store(fz_context *ctx)
{
	pdf_store *store;
	store = fz_malloc(ctx, sizeof(pdf_store));
	store->hash = fz_new_hash_table(ctx, 4096, sizeof(struct refkey));
	store->root = NULL;
	return store;
}

void
pdf_store_item(fz_context *ctx, pdf_store *store, pdf_store_keep_fn *keep_func, pdf_store_drop_fn *drop_func, fz_obj *key, void *val)
{
	pdf_item *item;

	if (!store)
		return;

	item = fz_malloc(ctx, sizeof(pdf_item));
	item->drop_func = drop_func;
	item->key = fz_keep_obj(key);
	item->val = keep_func(val);
	item->age = 0;
	item->next = NULL;

	if (fz_is_indirect(key))
	{
		struct refkey refkey;
		refkey.drop_func = drop_func;
		refkey.num = fz_to_num(key);
		refkey.gen = fz_to_gen(key);
		fz_hash_insert(ctx, store->hash, &refkey, item);
	}
	else
	{
		item->next = store->root;
		store->root = item;
	}
}

void *
pdf_find_item(fz_context *ctx, pdf_store *store, pdf_store_drop_fn *drop_func, fz_obj *key)
{
	struct refkey refkey;
	pdf_item *item;

	if (!store)
		return NULL;

	if (key == NULL)
		return NULL;

	if (fz_is_indirect(key))
	{
		refkey.drop_func = drop_func;
		refkey.num = fz_to_num(key);
		refkey.gen = fz_to_gen(key);
		item = fz_hash_find(store->hash, &refkey);
		if (item)
		{
			item->age = 0;
			return item->val;
		}
	}
	else
	{
		for (item = store->root; item; item = item->next)
		{
			if (item->drop_func == drop_func && !fz_objcmp(item->key, key))
			{
				item->age = 0;
				return item->val;
			}
		}
	}

	return NULL;
}

void
pdf_remove_item(fz_context *ctx, pdf_store *store, pdf_store_drop_fn *drop_func, fz_obj *key)
{
	struct refkey refkey;
	pdf_item *item, *prev, *next;

	if (fz_is_indirect(key))
	{
		refkey.drop_func = drop_func;
		refkey.num = fz_to_num(key);
		refkey.gen = fz_to_gen(key);
		item = fz_hash_find(store->hash, &refkey);
		if (item)
		{
			fz_hash_remove(store->hash, &refkey);
			item->drop_func(ctx, item->val);
			fz_drop_obj(item->key);
			fz_free(ctx, item);
		}
	}
	else
	{
		prev = NULL;
		for (item = store->root; item; item = next)
		{
			next = item->next;
			if (item->drop_func == drop_func && !fz_objcmp(item->key, key))
			{
				if (!prev)
					store->root = next;
				else
					prev->next = next;
				item->drop_func(ctx, item->val);
				fz_drop_obj(item->key);
				fz_free(ctx, item);
			}
			else
				prev = item;
		}
	}
}

void
pdf_age_store(fz_context *ctx, pdf_store *store, int maxage)
{
	struct refkey *refkey;
	pdf_item *item, *prev, *next;
	int i, n;

	n = fz_hash_len(store->hash);
	for (i = 0; i < n; i++)
	{
		refkey = fz_hash_get_key(store->hash, i);
		item = fz_hash_get_val(store->hash, i);
		if (item && ++item->age > maxage)
		{
			fz_hash_remove(store->hash, refkey);
			item->drop_func(ctx, item->val);
			fz_drop_obj(item->key);
			fz_free(ctx, item);
			i--; /* items with same hash may move into place */
		}
	}

	prev = NULL;
	for (item = store->root; item; item = next)
	{
		next = item->next;
		if (++item->age > maxage)
		{
			if (!prev)
				store->root = next;
			else
				prev->next = next;
			item->drop_func(ctx, item->val);
			fz_drop_obj(item->key);
			fz_free(ctx, item);
		}
		else
			prev = item;
	}
}

void
pdf_free_store(fz_context *ctx, pdf_store *store)
{
	pdf_age_store(ctx, store, 0);
	fz_free_hash(ctx, store->hash);
	fz_free(ctx, store);
}

void
pdf_debug_store(fz_context *ctx, pdf_store *store)
{
	pdf_item *item;
	pdf_item *next;
	struct refkey *refkey;
	int i, n;

	printf("-- resource store contents --\n");

	n = fz_hash_len(store->hash);
	for (i = 0; i < n; i++)
	{
		refkey = fz_hash_get_key(store->hash, i);
		item = fz_hash_get_val(store->hash, i);
		if (item)
			printf("store[%d] (%d %d R) = %p\n", i, refkey->num, refkey->gen, item->val);
	}

	for (item = store->root; item; item = next)
	{
		next = item->next;
		printf("store[*] ");
		fz_debug_obj(item->key);
		printf(" = %p\n", item->val);
	}
}
