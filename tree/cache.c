#include <fitz.h>

static int
hash(fz_cachekey *k)
{
	int h;
	int i;

	h = (int)k->tree ^ (int)k->node ^ k->tag;

	/* http://www.cs.yorku.ca/~oz/hash.html -- sdbm */
	for (i = 0; i < k->len; i++)
		h = k->key[i] + (h << 6) + (h << 16) - h;

	return h;
}

static int
equal(fz_cachekey *a, fz_cachekey *b)
{
	if (a->tree != b->tree) return 0;
	if (a->node != b->node) return 0;
	if (a->tag != b->tag) return 0;
	if (a->len != b->len) return 0;
	return memcmp(a->key, b->key, a->len) == 0;
}

fz_cache *
fz_newcache(int maxentries, int maxdatasize)
{
	fz_cache *cache;
	int i;

	cache = fz_malloc(sizeof(fz_cache));
	if (!cache) return nil;

	cache->maxsize = maxdatasize;
	cache->cursize = 0;
	cache->len = maxentries;
	cache->table = fz_malloc(sizeof(fz_cachebucket) * maxentries);
	if (!cache->table) {
		fz_free(cache);
		return nil;
	}

	for (i = 0; i < cache->len; i++) {
		cache->table[i].val = nil;
	}

	return cache;
}

void *
fz_findincache(fz_cache *cache, fz_cachekey *key)
{
	int h;
	int i;

	h = hash(key); 

	i = h % cache->len;
	if (equal(key, &cache->table[i].key))
		return cache->table[i].val;
	return nil;
}

int
fz_insertincache(fz_cache *cache, fz_cachekey *key, void *data, int size)
{
	int h;
	int i;

	h = hash(key);
	i = h % cache->len;

	if (cache->table[i].val)
		fz_free(cache->table[i].val);
	cache->table[i].key = *key;

	return FZ_OKAY;
}

int
fz_evictfromcache(fz_cache *cache, fz_cachekey *key)
{
	/* TODO */
	return FZ_OKAY;
}

void
fz_freecache(fz_cache *cache)
{
	/* FIXME evict everything from cache first? */
	if (cache->table)
		fz_free(cache->table);
	fz_free(cache);
}

