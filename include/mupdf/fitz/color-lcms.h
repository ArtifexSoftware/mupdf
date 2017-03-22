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

/*
	fz_colorspace_is_lab: Return true, iff a given colorspace is
	lab.
*/
int fz_cmm_avoid_white_fix_flag();
void fz_cmm_transform_color_buffer(fz_context *ctx, fz_icclink *link, fz_color_bufferdesc *in_desc, fz_color_bufferdesc *out_desc, void *input, void *output);
void fz_cmm_transform_color(fz_icclink *link, const void *inputcolor, void *outputcolor, int num_bytes);
void fz_cmm_new_link(fz_context *ctx, fz_icclink *link, fz_iccprofile *src, fz_iccprofile *des, fz_rendering_param *rend, int cmm_flags);
void fz_cmm_free_link(fz_icclink *link);
void * fz_cmm_new_ctx(fz_context *ctx);
void fz_cmm_free_ctx(void *cmm_ctx);
void fz_cmm_new_profile(fz_context *ctx, fz_iccprofile *profile);
void fz_cmm_free_profile(fz_iccprofile *profile);

#endif
