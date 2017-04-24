#ifndef MUPDF_FITZ_IMP_H
#define MUPDF_FITZ_IMP_H

#include "mupdf/fitz.h"

struct fz_buffer_s
{
	int refs;
	unsigned char *data;
	size_t cap, len;
	int unused_bits;
	int shared;
};

void fz_new_colorspace_context(fz_context *ctx);
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

#endif
