#ifndef MUPDF_FITZ_IMP_H
#define MUPDF_FITZ_IMP_H

#include "mupdf/fitz.h"

#include <stdio.h>

struct fz_buffer_s
{
	int refs;
	unsigned char *data;
	size_t cap, len;
	int unused_bits;
	int shared;
};

void fz_new_colorspace_context(fz_context *ctx);
void fz_new_cmm_context(fz_context *ctx);
void fz_drop_cmm_context(fz_context *ctx);
fz_colorspace_context *fz_keep_colorspace_context(fz_context *ctx);
void fz_drop_colorspace_context(fz_context *ctx);

struct fz_device_container_stack_s
{
	fz_rect scissor;
	int flags;
	int user;
};

enum
{
	fz_device_container_stack_is_clip_path = 1,
	fz_device_container_stack_is_clip_stroke_path = 2,
	fz_device_container_stack_is_clip_text = 4,
	fz_device_container_stack_is_clip_stroke_text = 8,
	fz_device_container_stack_is_clip_image_mask = 16,
	fz_device_container_stack_in_mask = 32,
	fz_device_container_stack_is_mask = 64,
	fz_device_container_stack_is_group = 128,
};

/*
	fz_new_font_context: Initialise the font context.

	For internal use only.
*/
void fz_new_font_context(fz_context *ctx);

/*
	fz_keep_font_context: Increment the ref count for
	the current font context.

	For internal use only.
*/
fz_font_context *fz_keep_font_context(fz_context *ctx);

/*
	fz_drop_font_context: Drop the ref count for the
	current font context.

	For internal use only.
*/
void fz_drop_font_context(fz_context *ctx);

/* Tuning context implementation details */
struct fz_tuning_context_s
{
	int refs;
	fz_tune_image_decode_fn *image_decode;
	void *image_decode_arg;
	fz_tune_image_scale_fn *image_scale;
	void *image_scale_arg;
};

void fz_default_image_decode(void *arg, int w, int h, int l2factor, fz_irect *subarea);
int fz_default_image_scale(void *arg, int dst_w, int dst_h, int src_w, int src_h);

fz_context *fz_clone_context_internal(fz_context *ctx);

void fz_new_aa_context(fz_context *ctx);
void fz_drop_aa_context(fz_context *ctx);
void fz_copy_aa_context(fz_context *dst, fz_context *src);

void fz_new_glyph_cache_context(fz_context *ctx);
fz_glyph_cache *fz_keep_glyph_cache(fz_context *ctx);
void fz_drop_glyph_cache_context(fz_context *ctx);

void fz_new_document_handler_context(fz_context *ctx);
void fz_drop_document_handler_context(fz_context *ctx);
fz_document_handler_context *fz_keep_document_handler_context(fz_context *ctx);

void fz_new_output_context(fz_context *ctx);
void fz_drop_output_context(fz_context *ctx);
fz_output_context *fz_keep_output_context(fz_context *ctx);

fz_stream *fz_open_file_ptr_no_close(fz_context *ctx, FILE *file);

#if defined(MEMENTO) || !defined(NDEBUG)
#define FITZ_DEBUG_LOCKING
#endif

#ifdef FITZ_DEBUG_LOCKING

void fz_assert_lock_held(fz_context *ctx, int lock);
void fz_assert_lock_not_held(fz_context *ctx, int lock);
void fz_lock_debug_lock(fz_context *ctx, int lock);
void fz_lock_debug_unlock(fz_context *ctx, int lock);

#else

#define fz_assert_lock_held(A,B) do { } while (0)
#define fz_assert_lock_not_held(A,B) do { } while (0)
#define fz_lock_debug_lock(A,B) do { } while (0)
#define fz_lock_debug_unlock(A,B) do { } while (0)

#endif /* !FITZ_DEBUG_LOCKING */

static inline void
fz_lock(fz_context *ctx, int lock)
{
	fz_lock_debug_lock(ctx, lock);
	ctx->locks.lock(ctx->locks.user, lock);
}

static inline void
fz_unlock(fz_context *ctx, int lock)
{
	fz_lock_debug_unlock(ctx, lock);
	ctx->locks.unlock(ctx->locks.user, lock);
}

static inline void *
fz_keep_imp(fz_context *ctx, void *p, int *refs)
{
	if (p)
	{
		(void)Memento_checkIntPointerOrNull(refs);
		fz_lock(ctx, FZ_LOCK_ALLOC);
		if (*refs > 0)
		{
			(void)Memento_takeRef(p);
			++*refs;
		}
		fz_unlock(ctx, FZ_LOCK_ALLOC);
	}
	return p;
}

static inline void *
fz_keep_imp8(fz_context *ctx, void *p, int8_t *refs)
{
	if (p)
	{
		(void)Memento_checkBytePointerOrNull(refs);
		fz_lock(ctx, FZ_LOCK_ALLOC);
		if (*refs > 0)
		{
			(void)Memento_takeRef(p);
			++*refs;
		}
		fz_unlock(ctx, FZ_LOCK_ALLOC);
	}
	return p;
}

static inline void *
fz_keep_imp16(fz_context *ctx, void *p, int16_t *refs)
{
	if (p)
	{
		(void)Memento_checkShortPointerOrNull(refs);
		fz_lock(ctx, FZ_LOCK_ALLOC);
		if (*refs > 0)
		{
			(void)Memento_takeRef(p);
			++*refs;
		}
		fz_unlock(ctx, FZ_LOCK_ALLOC);
	}
	return p;
}

static inline int
fz_drop_imp(fz_context *ctx, void *p, int *refs)
{
	if (p)
	{
		int drop;
		(void)Memento_checkIntPointerOrNull(refs);
		fz_lock(ctx, FZ_LOCK_ALLOC);
		if (*refs > 0)
		{
			(void)Memento_dropIntRef(p);
			drop = --*refs == 0;
		}
		else
			drop = 0;
		fz_unlock(ctx, FZ_LOCK_ALLOC);
		return drop;
	}
	return 0;
}

static inline int
fz_drop_imp8(fz_context *ctx, void *p, int8_t *refs)
{
	if (p)
	{
		int drop;
		(void)Memento_checkBytePointerOrNull(refs);
		fz_lock(ctx, FZ_LOCK_ALLOC);
		if (*refs > 0)
		{
			(void)Memento_dropByteRef(p);
			drop = --*refs == 0;
		}
		else
			drop = 0;
		fz_unlock(ctx, FZ_LOCK_ALLOC);
		return drop;
	}
	return 0;
}

static inline int
fz_drop_imp16(fz_context *ctx, void *p, int16_t *refs)
{
	if (p)
	{
		int drop;
		(void)Memento_checkShortPointerOrNull(refs);
		fz_lock(ctx, FZ_LOCK_ALLOC);
		if (*refs > 0)
		{
			(void)Memento_dropShortRef(p);
			drop = --*refs == 0;
		}
		else
			drop = 0;
		fz_unlock(ctx, FZ_LOCK_ALLOC);
		return drop;
	}
	return 0;
}

#endif
