#ifndef MUPDF_FITZ_COLORSPACE_IMP_H
#define MUPDF_FITZ_COLORSPACE_IMP_H

#include "mupdf/fitz/colorspace.h"
#include "mupdf/fitz/pixmap.h"
#include "mupdf/fitz/color-management.h"
#include "mupdf/fitz/context.h"

struct fz_colorspace_s
{
	fz_storable storable;
	size_t size;
	char name[16];
	int n;
	int is_subtractive;
	fz_colorspace_convert_fn *to_ccs;
	fz_colorspace_convert_fn *from_ccs;
	fz_colorspace_clamp_fn *clamp;
	fz_colorspace_base_fn *get_base;
	fz_colorspace_destruct_fn *free_data;
	void *data;
};

struct fz_iccprofile_s
{
	int num_devcomp;
	fz_buffer *buffer;
	unsigned char md5[16];
	void *cmm_handle;
};

struct fz_icclink_s
{
	fz_storable storable;
	int num_in;
	int num_out;
	int depth;
	int alpha;
	int is_identity;
	void *cmm_handle;
};

struct fz_default_colorspaces_s
{
	int refs;
	fz_colorspace *gray;
	fz_colorspace *rgb;
	fz_colorspace *cmyk;
	fz_colorspace *oi;
};

struct fz_colorspace_context_s
{
	int ctx_refs;
	fz_colorspace *gray, *rgb, *bgr, *cmyk, *lab;
	fz_color_params *params;
};

static inline int
fz_cmm_avoid_white_fix_flag(fz_context *ctx)
{
	return ctx && ctx->cmm ? ctx->cmm->avoid_white_fix_flag : 0;
}

static inline void
fz_cmm_transform_pixmap(fz_context *ctx, fz_icclink *link, fz_pixmap *dst, fz_pixmap *src)
{
	ctx->cmm->transform_pixmap(ctx->cmm_instance, link, dst, src);
}

static inline void
fz_cmm_transform_color(fz_context *ctx, fz_icclink *link, unsigned short *dst, const unsigned short *src)
{
	ctx->cmm->transform_color(ctx->cmm_instance, link, dst, src);
}

static inline void
fz_cmm_new_link(fz_context *ctx, fz_icclink *link, const fz_color_params *rend, int cmm_flags, int num_bytes, int alpha, const fz_iccprofile *src, const fz_iccprofile *prf, const fz_iccprofile *des)
{
	ctx->cmm->new_link(ctx->cmm_instance, link, rend, cmm_flags, num_bytes, alpha, src, prf, des);
}

static inline void
fz_cmm_drop_link(fz_context *ctx, fz_icclink *link)
{
	ctx->cmm->drop_link(ctx->cmm_instance, link);
}

static inline fz_cmm_instance *fz_cmm_new_instance(fz_context *ctx)
{
	if (!ctx || !ctx->cmm)
		return NULL;
	return ctx->cmm->new_instance(ctx);
}

static inline void fz_cmm_drop_instance(fz_context *ctx)
{
	if (ctx && ctx->cmm)
		ctx->cmm->drop_instance(ctx->cmm_instance);
}

static inline void fz_cmm_new_profile(fz_context *ctx, fz_iccprofile *profile)
{
	ctx->cmm->new_profile(ctx->cmm_instance, profile);
}

static inline void fz_cmm_drop_profile(fz_context *ctx, fz_iccprofile *profile)
{
	ctx->cmm->drop_profile(ctx->cmm_instance, profile);
}

#endif
