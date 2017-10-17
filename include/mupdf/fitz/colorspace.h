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
	FZ_RI_RELATIVE_COLORIMETRIC,
	FZ_RI_SATURATION,
	FZ_RI_ABSOLUTE_COLORIMETRIC,
};

typedef struct fz_color_params_s fz_color_params;

struct fz_color_params_s
{
	uint8_t ri;
	uint8_t bp;
	uint8_t op;
	uint8_t opm;
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
	A fz_iccprofile object encapsulates details about the icc profile. It
	also includes the profile handle provided by the cmm and as such is used
	in the creation of links between color spaces.
*/
typedef struct fz_iccprofile_s fz_iccprofile;

/*
	A fz_icclink object encapsulates details about the link between profiles.
*/
typedef struct fz_icclink_s fz_icclink;

/*
	Used to communicate any document internal page specific default color spaces.
*/
typedef struct fz_default_colorspaces_s fz_default_colorspaces;

/*
	fz_colorspace_is_subtractive: Return true if a colorspace is subtractive.

	True for CMYK, Separation and DeviceN colorspaces.
*/
int fz_colorspace_is_subtractive(fz_context *ctx, const fz_colorspace *cs);

/*
	fz_colorspace_is_device_n: Return true if a colorspace is separation or devicen.

	True for Separation and DeviceN colorspaces.
*/
int fz_colorspace_is_device_n(fz_context *ctx, const fz_colorspace *cs);

/*
	fz_colorspace_device_n_has_only_cmyk: Return true if devicen color space
	has only colorants from the cmyk set.
*/
int fz_colorspace_device_n_has_only_cmyk(fz_context *ctx, const fz_colorspace *cs);

/*
	fz_colorspace_device_n_has_cmyk: Return true if devicen color space has cyan
	magenta yellow or black as one of its colorants.
*/
int fz_colorspace_device_n_has_cmyk(fz_context *ctx, const fz_colorspace *cs);

/*
	fz_colorspace_is_device_gray: Return true if the color space is
	device gray.
*/
int fz_colorspace_is_device_gray(fz_context *ctx, const fz_colorspace *cs);

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
	fz_default_color_params: Get default color params for general color conversion.
*/
const fz_color_params *fz_default_color_params(fz_context *ctx);

typedef void (fz_colorspace_convert_fn)(fz_context *ctx, const fz_colorspace *cs, const float *src, float *dst);

typedef void (fz_colorspace_destruct_fn)(fz_context *ctx, fz_colorspace *cs);

typedef fz_colorspace *(fz_colorspace_base_fn)(const fz_colorspace *cs);

typedef void (fz_colorspace_clamp_fn)(const fz_colorspace *cs, const float *src, float *dst);

enum
{
	FZ_CS_DEVICE_GRAY = 1,
	FZ_CS_DEVICE_N = 2,
	FZ_CS_SUBTRACTIVE = 4,

	FZ_CS_LAST_PUBLIC_FLAG = 4
};

fz_colorspace *fz_new_colorspace(fz_context *ctx, const char *name, int n, int flags, fz_colorspace_convert_fn *to_ccs, fz_colorspace_convert_fn *from_ccs, fz_colorspace_base_fn *base, fz_colorspace_clamp_fn *clamp, fz_colorspace_destruct_fn *destruct, void *data, size_t size);
void fz_colorspace_name_colorant(fz_context *ctx, fz_colorspace *cs, int n, const char *name);
const char *fz_colorspace_colorant(fz_context *ctx, const fz_colorspace *cs, int n);
fz_colorspace *fz_new_indexed_colorspace(fz_context *ctx, fz_colorspace *base, int high, unsigned char *lookup);
fz_colorspace *fz_keep_colorspace(fz_context *ctx, fz_colorspace *colorspace);
fz_colorspace *fz_keep_colorspace_store_key(fz_context *ctx, fz_colorspace *colorspace);
void fz_drop_colorspace_store_key(fz_context *ctx, fz_colorspace *colorspace);

void fz_drop_colorspace(fz_context *ctx, fz_colorspace *colorspace);
void fz_drop_colorspace_imp(fz_context *ctx, fz_storable *colorspace);

fz_colorspace *fz_colorspace_base(fz_context *ctx, const fz_colorspace *cs);
int fz_colorspace_is_icc(fz_context *ctx, const fz_colorspace *cs);
int fz_colorspace_is_lab(fz_context *ctx, const fz_colorspace *cs);
int fz_colorspace_is_lab_icc(fz_context *ctx, const fz_colorspace *cs);
int fz_colorspace_is_cal(fz_context *ctx, const fz_colorspace *cs);
int fz_colorspace_is_indexed(fz_context *ctx, const fz_colorspace *cs);
void fz_set_icc_bgr(fz_context *ctx, fz_colorspace *cs);
int fz_colorspace_n(fz_context *ctx, const fz_colorspace *cs);
int fz_colorspace_devicen_n(fz_context *ctx, const fz_colorspace *cs);
const char *fz_colorspace_name(fz_context *ctx, const fz_colorspace *cs);
void fz_clamp_color(fz_context *ctx, const fz_colorspace *cs, const float *in, float *out);
void fz_convert_color(fz_context *ctx, const fz_color_params *params, const fz_colorspace *intcs, const fz_colorspace *dscs, float *dstv, const fz_colorspace *srcs, const float *srcv);

typedef struct fz_color_converter_s fz_color_converter;

/* This structure is public because it allows us to avoid dynamic allocations.
 * Callers should only rely on the convert entry - the rest of the structure
 * is subject to change without notice.
 */
struct fz_color_converter_s
{
	void (*convert)(fz_context *, fz_color_converter *, float *, const float *);
	const fz_colorspace *ds;
	const fz_colorspace *ss;
	const fz_colorspace *is;
	void *opaque;
	void *link;
	int n;
};

void fz_find_color_converter(fz_context *ctx, fz_color_converter *cc, const fz_colorspace *is, const fz_colorspace *ds, const fz_colorspace *ss, const fz_color_params *params);
void fz_drop_color_converter(fz_context *ctx, fz_color_converter *cc);
void fz_init_cached_color_converter(fz_context *ctx, fz_color_converter *cc, fz_colorspace *is, fz_colorspace *ds, fz_colorspace *ss, const fz_color_params *params);
void fz_fin_cached_color_converter(fz_context *ctx, fz_color_converter *cc);

/* Public to allow use in icc creation */
typedef struct fz_cal_colorspace_s fz_cal_colorspace;

struct fz_cal_colorspace_s {
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
fz_colorspace *fz_new_icc_colorspace(fz_context *ctx, const char *name, int num, fz_buffer *buf);
fz_colorspace *fz_new_icc_colorspace_from_file(fz_context *ctx, const char *name, const char *path);
fz_colorspace *fz_new_icc_colorspace_from_stream(fz_context *ctx, const char *name, fz_stream *in);
fz_colorspace *fz_new_cal_colorspace(fz_context *ctx, const char *name, float *wp, float *bp, float *gamma, float *matrix);
fz_buffer *fz_new_icc_data_from_cal_colorspace(fz_context *ctx, fz_cal_colorspace *cal);
fz_buffer *fz_icc_data_from_icc_colorspace(fz_context *ctx, const fz_colorspace *cs);

/* Default cs */
fz_default_colorspaces *fz_new_default_colorspaces(fz_context *ctx);
fz_default_colorspaces* fz_keep_default_colorspaces(fz_context *ctx, fz_default_colorspaces *default_cs);
void fz_drop_default_colorspaces(fz_context *ctx, fz_default_colorspaces *default_cs);
fz_default_colorspaces *fz_clone_default_colorspaces(fz_context *ctx, fz_default_colorspaces *base);

/* Do we want to make fz_default_colorspaces public and get rid of these? */
void fz_set_default_gray(fz_context *ctx, fz_default_colorspaces *default_cs, fz_colorspace *cs);
void fz_set_default_rgb(fz_context *ctx, fz_default_colorspaces *default_cs, fz_colorspace *cs);
void fz_set_default_cmyk(fz_context *ctx, fz_default_colorspaces *default_cs, fz_colorspace *cs);
void fz_set_default_output_intent(fz_context *ctx, fz_default_colorspaces *default_cs, fz_colorspace *cs);

fz_colorspace *fz_default_gray(fz_context *ctx, const fz_default_colorspaces *default_cs);
fz_colorspace *fz_default_rgb(fz_context *ctx, const fz_default_colorspaces *default_cs);
fz_colorspace *fz_default_cmyk(fz_context *ctx, const fz_default_colorspaces *default_cs);
fz_colorspace *fz_default_output_intent(fz_context *ctx, const fz_default_colorspaces *default_cs);

#endif
