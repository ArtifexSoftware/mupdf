#ifndef MUPDF_FITZ_COLORSPACE_H
#define MUPDF_FITZ_COLORSPACE_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/store.h"

enum { FZ_MAX_COLORS = 32 };

/*
	A fz_colorspace object represents an abstract colorspace. While
	this should be treated as a black box by callers of the library at
	this stage, know that it encapsulates knowledge of how to convert
	colors to and from the colorspace, any lookup tables generated, the
	number of components in the colorspace etc.
*/
typedef struct fz_colorspace_s fz_colorspace;

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

fz_colorspace *fz_new_colorspace(fz_context *ctx, char *name, int n, int is_subtractive, fz_colorspace_convert_fn *to_rgb, fz_colorspace_convert_fn *from_rgb, fz_colorspace_destruct_fn *destruct, void *data, size_t size);
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

#endif
