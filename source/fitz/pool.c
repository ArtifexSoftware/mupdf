#include "mupdf/fitz.h"

fz_pool *fz_new_pool(fz_context *ctx)
{
	fz_pool *pool = fz_malloc_struct(ctx, fz_pool);
	fz_pool_node *node = fz_malloc_struct(ctx, fz_pool_node);
	pool->head = pool->tail = node;
	pool->pos = node->mem;
	pool->end = node->mem + sizeof node->mem;
	return pool;
}

void *fz_pool_alloc(fz_context *ctx, fz_pool *pool, size_t size)
{
	char *ptr;

	/* round size to pointer alignment (we don't expect to use doubles) */
	size = ((size + sizeof(void*) - 1) / sizeof(void*)) * sizeof(void*);

	if (pool->pos + size > pool->end)
	{
		fz_pool_node *node = fz_malloc_struct(ctx, fz_pool_node);
		pool->tail = pool->tail->next = node;
		pool->pos = node->mem;
		pool->end = node->mem + sizeof node->mem;
		if (pool->pos + size > pool->end)
			fz_throw(ctx, FZ_ERROR_GENERIC, "out of memory: allocation too large to fit in pool");
	}
	ptr = pool->pos;
	pool->pos += size;
	return ptr;
}

void fz_drop_pool(fz_context *ctx, fz_pool *pool)
{
	fz_pool_node *node = pool->head;
	while (node)
	{
		fz_pool_node *next = node->next;
		fz_free(ctx, node);
		node = next;
	}
	fz_free(ctx, pool);
}
