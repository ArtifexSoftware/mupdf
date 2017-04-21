/*
 * Some additional glue functions for using Harfbuzz with
 * custom allocators.
 */

#include "mupdf/fitz.h"

#include "hb.h"

#include <assert.h>

/* Harfbuzz has some major design flaws.
 *
 * It is utterly thread unsafe. It uses statics to hold
 * structures in, meaning that if it is ever called from
 * more than one thread at a time, access to such
 * structures can race. We work around this by imposing
 * a lock on our calls to harfbuzz (we reuse the freetype
 * lock).
 *
 * This does not protect us against the possibility of
 * other people calling harfbuzz; for instance, if we
 * link MuPDF into an app that either calls harfbuzz
 * itself, or uses another library that calls harfbuzz,
 * there is no guarantee that that library will take
 * the same lock while calling harfbuzz. This leaves
 * us open to the possibility of crashes. The only
 * way around this would be to use completely separate
 * harfbuzz instances.
 *
 * In order to ensure that allocations throughout mupdf
 * are done consistently, we get harfbuzz to call our
 * own hb_malloc/realloc/calloc/free functions that
 * call down to fz_malloc/realloc/calloc/free. These
 * require context variables, so we get our hb_lock
 * and unlock to set these. Any attempt to call through
 * without setting these will be detected.
 *
 * It is therefore vital that any fz_lock/fz_unlock
 * handlers are shared between all the fz_contexts in
 * use at a time.
 *
 * Finally, harfbuzz stores various malloced structures
 * in statics. These can either be left to leak on
 * closedown, or (if HAVE_ATEXIT is defined), they will
 * be freed using various 'atexit' callbacks. Unfortunately
 * this won't reset the fz_context value, so the allocators
 * can't free them correctly.
 *
 * Consequently, we leave them to leak, and warn Memento
 * about this.
 */

/* Potentially we can write different versions
 * of get_context and set_context for different
 * threading systems.
 *
 * This simple version relies on harfbuzz never
 * trying to make 2 allocations at once on
 * different threads. The only way that can happen
 * is when one of those other threads is someone
 * outside MuPDF calling harfbuzz while MuPDF
 * is running. This will cause us such huge
 * problems that for now, we'll just forbid it.
 */

static fz_context *hb_secret = NULL;

static void set_hb_context(fz_context *ctx)
{
	hb_secret = ctx;
}

static fz_context *get_hb_context()
{
	return hb_secret;
}

void hb_lock(fz_context *ctx)
{
	fz_lock(ctx, FZ_LOCK_FREETYPE);

	set_hb_context(ctx);
}

void hb_unlock(fz_context *ctx)
{
	set_hb_context(NULL);

	fz_unlock(ctx, FZ_LOCK_FREETYPE);
}

void *hb_malloc(size_t size)
{
	fz_context *ctx = get_hb_context();

	assert(ctx != NULL);

	return fz_malloc_no_throw(ctx, size);
}

void *hb_calloc(size_t n, size_t size)
{
	fz_context *ctx = get_hb_context();

	assert(ctx != NULL);

	return fz_calloc_no_throw(ctx, n, size);
}

void *hb_realloc(void *ptr, size_t size)
{
	fz_context *ctx = get_hb_context();

	assert(ctx != NULL);

	return fz_resize_array_no_throw(ctx, ptr, 1, size);
}

void hb_free(void *ptr)
{
	fz_context *ctx = get_hb_context();

	assert(ctx != NULL);

	fz_free(ctx, ptr);
}
