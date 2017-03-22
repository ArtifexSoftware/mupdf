#ifndef MUPDF_FITZ_COLORLCMS_H
#define MUPDF_FITZ_COLORLCMS_H

#include "colorspace.h"
enum
{
	FZ_INTENT_PERCEPTUAL = 0,
	FZ_INTENT_COLORIMETRIC = 1,
	FZ_INTENT_SATURATION = 2,
	FZ_INTENT_ABSOLUTE = 3
};

int fz_cmm_avoid_white_fix_flag();
void fz_cmm_transform_pixmap(fz_context *ctx, fz_icclink *link, fz_pixmap *dst, fz_pixmap *src);
void fz_cmm_transform_color(fz_icclink *link, int num_bytes, const void *dst, void *src);
void fz_cmm_new_link(fz_context *ctx, fz_icclink *link, fz_rendering_param *rend, int cmm_flags, fz_iccprofile *dst, fz_iccprofile *src);
void fz_cmm_free_link(fz_icclink *link);
void * fz_cmm_new_ctx(fz_context *ctx);
void fz_cmm_free_ctx(void *cmm_ctx);
void fz_cmm_new_profile(fz_context *ctx, fz_iccprofile *profile);
void fz_cmm_free_profile(fz_iccprofile *profile);

#endif
