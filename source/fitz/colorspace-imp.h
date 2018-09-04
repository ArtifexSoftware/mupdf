#ifndef MUPDF_FITZ_COLORSPACE_IMP_H
#define MUPDF_FITZ_COLORSPACE_IMP_H

#include "mupdf/fitz/context.h"
#include "mupdf/fitz/colorspace.h"
#include "mupdf/fitz/color-management.h"
#include "mupdf/fitz/pixmap.h"

void fz_cmm_transform_pixmap(fz_context *ctx, fz_icclink *link, fz_pixmap *dst, fz_pixmap *src);
void fz_cmm_transform_color(fz_context *ctx, fz_icclink *link, unsigned short *dst, const unsigned short *src);
void fz_cmm_init_link(fz_context *ctx, fz_icclink *link, const fz_iccprofile *dst, int dst_extras, const fz_iccprofile *src, int src_extras, const fz_iccprofile *prf, const fz_color_params *rend, int cmm_flags, int num_bytes, int copy_spots);
void fz_cmm_fin_link(fz_context *ctx, fz_icclink *link);
fz_cmm_instance *fz_cmm_new_instance(fz_context *ctx);
void fz_cmm_drop_instance(fz_context *ctx);
void fz_cmm_init_profile(fz_context *ctx, fz_iccprofile *profile);
void fz_cmm_fin_profile(fz_context *ctx, fz_iccprofile *profile);

enum
{
	FZ_CS_HAS_CMYK = (FZ_COLORSPACE_LAST_PUBLIC_FLAG<<1),
	FZ_CS_HAS_SPOTS = (FZ_COLORSPACE_LAST_PUBLIC_FLAG<<2),
	FZ_CS_HAS_CMYK_AND_SPOTS = FZ_CS_HAS_CMYK|FZ_CS_HAS_SPOTS
};

struct fz_colorspace_s
{
	fz_key_storable key_storable;
	size_t size;
	char name[24];
	enum fz_colorspace_type type;
	int flags;
	int n;
	fz_colorspace_convert_fn *to_ccs;
	fz_colorspace_convert_fn *from_ccs;
	fz_colorspace_clamp_fn *clamp;
	fz_colorspace_base_fn *get_base;
	fz_colorspace_destruct_fn *free_data;
	void *data;
	char *colorant[FZ_MAX_COLORS];
};

struct fz_iccprofile_s
{
	char *desc;
	int num_devcomp;
	int bgr;
	fz_buffer *buffer;
	unsigned char md5[16];
	void *cmm_handle;
};

struct fz_icclink_s
{
	fz_storable storable;
	int depth;
	int src_extras;
	int dst_extras;
	int copy_spots;
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
	const fz_cmm_engine *cmm;
	fz_colorspace *gray, *rgb, *bgr, *cmyk, *lab;
};

#endif
