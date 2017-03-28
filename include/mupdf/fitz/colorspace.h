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
	A fz_rendering_param object describes the settings to use when creating a link.
*/
typedef struct fz_rendering_param_s fz_rendering_param;

/*
	fz_colorspace_is_indexed: Return true, iff a given colorspace is
	indexed.
*/
int fz_colorspace_is_indexed(fz_context *ctx, fz_colorspace *cs);

/*
	fz_colorspace_is_lab: Return true, iff a given colorspace is
	lab.
*/
int fz_colorspace_is_lab(fz_context *ctx, fz_colorspace *cs);

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
	fz_set_device_gray: Set colorspace representing device specific gray.
*/
void fz_set_device_gray(fz_context *ctx, fz_colorspace *cs);

/*
	fz_set_device_rgb: Set colorspace representing device specific rgb.
*/
void fz_set_device_rgb(fz_context *ctx, fz_colorspace *cs);

/*
	fz_set_device_bgr: Set colorspace representing device specific bgr.
*/
void fz_set_device_bgr(fz_context *ctx, fz_colorspace *cs);

/*
	fz_set_device_cmyk: Set colorspace representing device specific CMYK.
*/
void fz_set_device_cmyk(fz_context *ctx, fz_colorspace *cs);

typedef void (fz_colorspace_convert_fn)(fz_context *ctx, fz_colorspace *cs, const float *src, float *dst);

typedef void (fz_colorspace_destruct_fn)(fz_context *ctx, fz_colorspace *cs);

fz_colorspace *fz_new_colorspace(fz_context *ctx, char *name, int storable, int n, int is_subtractive, fz_colorspace_convert_fn *to_rgb, fz_colorspace_convert_fn *from_rgb, fz_colorspace_destruct_fn *destruct, void *data, size_t size);
fz_colorspace *fz_new_indexed_colorspace(fz_context *ctx, fz_colorspace *base, int high, unsigned char *lookup);
fz_colorspace *fz_keep_colorspace(fz_context *ctx, fz_colorspace *colorspace);
void fz_drop_colorspace(fz_context *ctx, fz_colorspace *colorspace);
void fz_drop_colorspace_imp(fz_context *ctx, fz_storable *colorspace);

int fz_colorspace_is(fz_context *ctx, const fz_colorspace *cs, fz_colorspace_convert_fn *to_rgb);
int fz_colorspace_n(fz_context *ctx, const fz_colorspace *cs);
const char *fz_colorspace_name(fz_context *ctx, const fz_colorspace *cs);

void fz_convert_color(fz_context *ctx, fz_colorspace *dsts, float *dstv, fz_colorspace *srcs, const float *srcv);

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
	void *opaque;
};

void fz_lookup_color_converter(fz_context *ctx, fz_color_converter *cc, fz_colorspace *ds, fz_colorspace *ss);

void fz_init_cached_color_converter(fz_context *ctx, fz_color_converter *cc, fz_colorspace *ds, fz_colorspace *ss);
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

#endif
