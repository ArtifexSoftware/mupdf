/*
 * Some additional glue functions for using Harfbuzz with
 * custom allocators.
 */

#include "mupdf/fitz.h"

#include "hb.h"

/* Potentially we can write different versions
 * of get_context and set_context for different
 * threading systems.
 *
 * This simple version relies on harfbuzz never
 * trying to make 2 allocations at once on
 * different threads. The only way that can happen
 * is when one of those other threads is someone
 * outside MuPDF calling harfbuzz while MuPDF
 * is running.
 *
 * If this is actually a problem, then we can
 * reimplement set_context/get_context using
 * Thread Local Storage.
 */

static fz_context *hb_secret = NULL;

static void set_context(fz_context *ctx)
{
	hb_secret = ctx;
}

static fz_context *get_context()
{
	return hb_secret;
}

void hb_lock(fz_context *ctx)
{
	fz_lock(ctx, FZ_LOCK_FREETYPE);

	set_context(ctx);
}

void hb_unlock(fz_context *ctx)
{
	set_context(NULL);

	fz_unlock(ctx, FZ_LOCK_FREETYPE);
}

void *hb_malloc(size_t size)
{
	fz_context *ctx = get_context();

	/* Should never happen, but possibly someone else
	 * is calling our version of the library. */
	if (ctx == NULL)
		return malloc(size);

	return fz_malloc_no_throw(ctx, (unsigned int)size);
}

void *hb_calloc(size_t n, size_t size)
{
	fz_context *ctx = get_context();

	/* Should never happen, but possibly someone else
	 * is calling our version of the library. */
	if (ctx == NULL)
		return calloc(n, size);

	return fz_calloc_no_throw(ctx, (unsigned int)n, (unsigned int)size);
}

void *hb_realloc(void *ptr, size_t size)
{
	fz_context *ctx = get_context();

	/* Should never happen, but possibly someone else
	 * is calling our version of the library. */
	if (ctx == NULL)
		return realloc(ptr, size);

	return fz_resize_array_no_throw(ctx, ptr, (unsigned int)1, (unsigned int)size);
}

void hb_free(void *ptr)
{
	fz_context *ctx = get_context();

	/* Should never happen, but possibly someone else
	 * is calling our version of the library. */
	if (ctx == NULL)
		free(ptr);
	else
		fz_free(ctx, ptr);
}
