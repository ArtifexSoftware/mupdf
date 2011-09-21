#include "fitz.h"

void *
fz_malloc(fz_context *ctx, unsigned int size)
{
	void *p = malloc(size);
	if (!p)
	{
		fprintf(stderr, "fatal error: out of memory\n");
		abort();
	}
	return p;
}

void *
fz_malloc_array(fz_context *ctx, unsigned int count, unsigned int size)
{
	void *p;

	if (count == 0 || size == 0)
		return 0;

	if (count > UINT_MAX / size)
	{
		fprintf(stderr, "fatal error: out of memory (integer overflow)\n");
		abort();
	}

	p = malloc(count * size);
	if (!p)
	{
		fprintf(stderr, "fatal error: out of memory\n");
		abort();
	}
	return p;
}

void *
fz_resize_array(fz_context *ctx, void *p, unsigned int count, unsigned int size)
{
	void *np;

	if (count == 0 || size == 0)
	{
		fz_free(ctx, p);
		return 0;
	}

	if (count > UINT_MAX / size)
	{
		fprintf(stderr, "fatal error: out of memory (integer overflow)\n");
		abort();
	}

	np = realloc(p, count * size);
	if (np == NULL)
	{
		fprintf(stderr, "fatal error: out of memory\n");
		abort();
	}
	return np;
}

void
fz_free(fz_context *ctx, void *p)
{
	free(p);
}

char *
fz_strdup(fz_context *ctx, char *s)
{
	int len = strlen(s) + 1;
	char *ns = fz_malloc(ctx, len);
	memcpy(ns, s, len);
	return ns;
}
