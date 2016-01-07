#ifndef MUPDF_FITZ_POOL_H
#define MUPDF_FITZ_POOL_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"

typedef struct fz_pool_s fz_pool;
typedef struct fz_pool_node_s fz_pool_node;

struct fz_pool_s
{
	fz_pool_node *head, *tail;
	char *pos, *end;
};

struct fz_pool_node_s
{
	fz_pool_node *next;
	char mem[64 << 10]; /* 64k blocks */
};

fz_pool *fz_new_pool(fz_context *ctx);
void *fz_pool_alloc(fz_context *ctx, fz_pool *pool, size_t size);
void fz_drop_pool(fz_context *ctx, fz_pool *pool);

#endif
