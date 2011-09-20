#include "fitz.h"

void *
fz_malloc(fz_context *ctx, size_t size)
{
	void *p;
	fz_alloc_context *alloc;

	assert(ctx != NULL);
	alloc = ctx->alloc;
	assert(alloc != NULL);
	p = alloc->malloc(alloc->opaque, size);
	if (!p)
	{
		fz_throw(ctx, "malloc failed (%d bytes)", size);
	}
	return p;
}

void *fz_calloc(fz_context *ctx, size_t count, size_t size)
{
	void *p;
	fz_alloc_context *alloc;

	assert(ctx != NULL);
	alloc = ctx->alloc;
	assert(alloc != NULL);
	p = alloc->calloc(alloc->opaque, count, size);
	if (!p)
	{
		fz_throw(ctx, "calloc failed (%d x %d bytes)", count, size);
	}
	return p;
}

void *
fz_realloc(fz_context *ctx, void *p, size_t size)
{
	fz_alloc_context *alloc;

	assert(ctx != NULL);
	alloc = ctx->alloc;
	assert(alloc != NULL);
	p = alloc->realloc(alloc->opaque, p, size);
	if (!p)
	{
		fz_throw(ctx, "realloc failed (%d bytes)", size);
	}
	return p;
}

void
fz_free(fz_context *ctx, void *p)
{
	fz_alloc_context *alloc;

	assert(ctx != NULL);
	alloc = ctx->alloc;
	assert(alloc != NULL);
	alloc->free(alloc->opaque, p);
}

void *
fz_malloc_nothrow(fz_context *ctx, size_t size)
{
	fz_alloc_context *alloc;

	assert(ctx != NULL);
	alloc = ctx->alloc;
	assert(alloc != NULL);
	return alloc->malloc(alloc->opaque, size);
}

void *fz_calloc_nothrow(fz_context *ctx, size_t count, size_t size)
{
	fz_alloc_context *alloc;

	assert(ctx != NULL);
	alloc = ctx->alloc;
	assert(alloc != NULL);
	return alloc->calloc(alloc->opaque, count, size);
}

void *
fz_realloc_nothrow(fz_context *ctx, void *p, size_t size)
{
	fz_alloc_context *alloc;

	assert(ctx != NULL);
	alloc = ctx->alloc;
	assert(alloc != NULL);
	return alloc->realloc(alloc->opaque, p, size);
}

void *
fz_malloc_default(void *opaque, size_t size)
{
	return malloc(size);
}

void *
fz_calloc_default(void *opaque, size_t count, size_t size)
{
	return calloc(count, size);
}

void *
fz_realloc_default(void *opaque, void *p, size_t size)
{
	return realloc(p, size);
}

void
fz_free_default(void *opaque, void *p)
{
	free(p);
}

fz_alloc_context fz_alloc_default =
{
	(void *)-1,
	fz_malloc_default,
	fz_realloc_default,
	fz_free_default,
	fz_calloc_default
};

char *
fz_strdup(fz_context *ctx, char *s)
{
	int len = strlen(s) + 1;
	char *ns = fz_malloc(ctx, len);
	memcpy(ns, s, len);
	return ns;
}
