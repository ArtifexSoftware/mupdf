#ifndef MUPDF_FITZ_COLORSPACE_H
#define MUPDF_FITZ_COLORSPACE_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/store.h"

enum { FZ_MAX_COLORS = 32 };

enum
{
	/* Same order as needed by lcms */
	FZ_RI_PERCEPTUAL,
	FZ_RI_RELATIVECOLORIMETRIC,
	FZ_RI_SATURATION,
	FZ_RI_ABSOLUTECOLORIMETRIC,
};

typedef struct fz_color_params_s fz_color_params;

struct fz_color_params_s
{
	int ri;
	int bp;
	int op;
	int opm;
};


int fz_lookup_rendering_intent(const char *name);
char *fz_rendering_intent_name(int ri);

/*
	A fz_colorspace object represents an abstract colorspace. While
	this should be treated as a black box by callers of the library at
	this stage, know that it encapsulates knowledge of how to convert
	colors to and from the colorspace, any lookup tables generated, the
	number of components in the colorspace etc.
*/
typedef struct fz_colorspace_s fz_colorspace;

/*
	A fz_iccprofile object encapusulates details about the icc profile. It
	also includes the profile handle provided by the cmm and as such is used
	in the creation of links between color spaces.
*/
typedef struct fz_iccprofile_s fz_iccprofile;

/*
	A fz_icclink object encapusulates details about the link between profiles.
*/
typedef struct fz_icclink_s fz_icclink;

/*
	fz_colorspace_is_subtractive: Return true if a colorspace is subtractive.

	True for CMYK, Separation and DeviceN colorspaces.
*/
int fz_colorspace_is_subtractive(fz_context *ctx, fz_colorspace *pix);

/*
	fz_device_gray: Get colorspace representing device specific gray.
*/
fz_colorspace *fz_device_gray(fz_context *ctx);

/*
	fz_device_rgb: Get colorspace representing device specific rgb.
*/
fz_colorspace *fz_device_rgb(fz_context *ctx);

/*
	fz_device_bgr: Get colorspace representing device specific bgr.
*/
fz_colorspace *fz_device_bgr(fz_context *ctx);

/*
	fz_device_cmyk: Get colorspace representing device specific CMYK.
*/
fz_colorspace *fz_device_cmyk(fz_context *ctx);

/*
	fz_device_lab: Get colorspace representing device specific LAB.
*/
fz_colorspace *fz_device_lab(fz_context *ctx);

/*
fz_cs_params: Get default color params for general color conversion.
*/
fz_color_params *fz_cs_params(fz_context *ctx);

typedef void (fz_colorspace_convert_fn)(fz_context *ctx, fz_colorspace *cs, const float *src, float *dst);

typedef void (fz_colorspace_destruct_fn)(fz_context *ctx, fz_colorspace *cs);

typedef fz_colorspace* (fz_colorspace_base_cs_fn)(fz_colorspace *cs);

typedef void (fz_colorspace_clamp_fn)(const fz_colorspace *cs, const float *src, float *dst);

fz_colorspace *fz_new_colorspace(fz_context *ctx, char *name, int storable, int n, int is_subtractive, fz_colorspace_convert_fn *to_rgb, fz_colorspace_convert_fn *from_rgb, fz_colorspace_base_cs_fn *base, fz_colorspace_clamp_fn *clamp, fz_colorspace_destruct_fn *destruct, void *data, size_t size);
fz_colorspace *fz_new_indexed_colorspace(fz_context *ctx, fz_colorspace *base, int high, unsigned char *lookup);
fz_colorspace *fz_keep_colorspace(fz_context *ctx, fz_colorspace *colorspace);
void fz_drop_colorspace(fz_context *ctx, fz_colorspace *colorspace);
void fz_drop_colorspace_imp(fz_context *ctx, fz_storable *colorspace);

int fz_colorspace_base_is(const fz_colorspace *cs, const char *name);
int fz_colorspace_is(const fz_colorspace *cs, const char *name);
int fz_colorspace_n(fz_context *ctx, const fz_colorspace *cs);
const char *fz_colorspace_name(fz_context *ctx, const fz_colorspace *cs);
void fz_clamp_color(fz_context *ctx, const fz_colorspace *cs, const float *in, float *out);
void fz_convert_color(fz_context *ctx, fz_color_params *params, fz_colorspace *dsts, float *dstv, fz_colorspace *srcs, const float *srcv);

typedef struct fz_color_converter_s fz_color_converter;

/* This structure is public because it allows us to avoid dynamic allocations.
 * Callers should only rely on the convert entry - the rest of the structure
 * is subject to change without notice.
 */
struct fz_color_converter_s
{
	void (*convert)(fz_context *, fz_color_converter *, float *, const float *);
	fz_colorspace *ds;
	fz_colorspace *ss;
	fz_color_params *params;
	void *opaque;
};

void fz_lookup_color_converter(fz_context *ctx, fz_color_converter *cc, fz_colorspace *ds, fz_colorspace *ss, fz_color_params *params);
void fz_init_cached_color_converter(fz_context *ctx, fz_color_converter *cc, fz_colorspace *ds, fz_colorspace *ss, fz_color_params *params);
void fz_fin_cached_color_converter(fz_context *ctx, fz_color_converter *cc);

/* Public to allow use in icc creation */
typedef struct fz_cal_color_s fz_cal_color;

struct fz_cal_color_s {
	float wp[3];
	float bp[3];
	float gamma[3];
	float matrix[9];
	int n;
	fz_iccprofile *profile;
};

/*
	icc methods
*/
void * fz_get_cmm_ctx(fz_context *ctx);
void fz_set_cmm_ctx(fz_context *ctx, void *cmm_ctx);
fz_colorspace * fz_new_icc_colorspace(fz_context *ctx, int storable, int num, fz_buffer *buf, const char *name);
fz_colorspace * fz_new_cal_colorspace(fz_context *ctx, float *wp, float *bp, float *gamma, float *matrix);
int fz_create_icc_from_cal(fz_context *ctx, unsigned char **buffer, fz_cal_color *cal);

void fz_color_param_init(fz_color_params *cs_param);

#endif
