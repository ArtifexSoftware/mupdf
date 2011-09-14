#include "fitz.h"
#include "mupdf.h"

/* ICCBased */

static fz_error
load_icc_based(fz_colorspace **csp, pdf_xref *xref, fz_obj *dict)
{
	int n;

	n = fz_to_int(xref->ctx, fz_dict_gets(xref->ctx, dict, "N"));

	switch (n)
	{
	case 1: *csp = fz_device_gray; return fz_okay;
	case 3: *csp = fz_device_rgb; return fz_okay;
	case 4: *csp = fz_device_cmyk; return fz_okay;
	}

	return fz_error_make("syntaxerror: ICCBased must have 1, 3 or 4 components");
}

/* Lab */

static inline float fung(float x)
{
	if (x >= 6.0f / 29.0f)
		return x * x * x;
	return (108.0f / 841.0f) * (x - (4.0f / 29.0f));
}

static void
lab_to_rgb(fz_colorspace *cs, float *lab, float *rgb)
{
	/* input is in range (0..100, -128..127, -128..127) not (0..1, 0..1, 0..1) */
	float lstar, astar, bstar, l, m, n, x, y, z, r, g, b;
	lstar = lab[0];
	astar = lab[1];
	bstar = lab[2];
	m = (lstar + 16) / 116;
	l = m + astar / 500;
	n = m - bstar / 200;
	x = fung(l);
	y = fung(m);
	z = fung(n);
	r = (3.240449f * x + -1.537136f * y + -0.498531f * z) * 0.830026f;
	g = (-0.969265f * x + 1.876011f * y + 0.041556f * z) * 1.05452f;
	b = (0.055643f * x + -0.204026f * y + 1.057229f * z) * 1.1003f;
	rgb[0] = sqrtf(CLAMP(r, 0, 1));
	rgb[1] = sqrtf(CLAMP(g, 0, 1));
	rgb[2] = sqrtf(CLAMP(b, 0, 1));
}

static void
rgb_to_lab(fz_colorspace *cs, float *rgb, float *lab)
{
	fz_warn("cannot convert into L*a*b colorspace");
	lab[0] = rgb[0];
	lab[1] = rgb[1];
	lab[2] = rgb[2];
}

static fz_colorspace k_device_lab = { -1, "Lab", 3, lab_to_rgb, rgb_to_lab };
static fz_colorspace *fz_device_lab = &k_device_lab;

/* Separation and DeviceN */

struct separation
{
	fz_colorspace *base;
	pdf_function *tint;
};

static void
separation_to_rgb(fz_colorspace *cs, float *color, float *rgb)
{
	struct separation *sep = cs->data;
	float alt[FZ_MAX_COLORS];
	pdf_eval_function(sep->tint, color, cs->n, alt, sep->base->n);
	sep->base->to_rgb(sep->base, alt, rgb);
}

static void
free_separation(fz_context *ctx, fz_colorspace *cs)
{
	struct separation *sep = cs->data;
	fz_drop_colorspace(ctx, sep->base);
	pdf_drop_function(ctx, sep->tint);
	fz_free(ctx, sep);
}

static fz_error
load_separation(fz_colorspace **csp, pdf_xref *xref, fz_obj *array)
{
	fz_error error;
	fz_colorspace *cs;
	struct separation *sep;
	fz_context *ctx = xref->ctx;
	fz_obj *nameobj = fz_array_get(ctx, array, 1);
	fz_obj *baseobj = fz_array_get(ctx, array, 2);
	fz_obj *tintobj = fz_array_get(ctx, array, 3);
	fz_colorspace *base;
	pdf_function *tint;
	int n;

	if (fz_is_array(ctx, nameobj))
		n = fz_array_len(ctx, nameobj);
	else
		n = 1;

	if (n > FZ_MAX_COLORS)
		return fz_error_make("too many components in colorspace");

	error = pdf_load_colorspace(&base, xref, baseobj);
	if (error)
		return fz_error_note(error, "cannot load base colorspace (%d %d R)", fz_to_num(baseobj), fz_to_gen(baseobj));

	error = pdf_load_function(&tint, xref, tintobj);
	if (error)
	{
		fz_drop_colorspace(ctx, base);
		return fz_error_note(error, "cannot load tint function (%d %d R)", fz_to_num(tintobj), fz_to_gen(tintobj));
	}

	sep = fz_malloc(ctx, sizeof(struct separation));
	sep->base = base;
	sep->tint = tint;

	cs = fz_new_colorspace(ctx, n == 1 ? "Separation" : "DeviceN", n);
	cs->to_rgb = separation_to_rgb;
	cs->free_data = free_separation;
	cs->data = sep;

	*csp = cs;
	return fz_okay;
}

/* Indexed */

struct indexed
{
	fz_colorspace *base;
	int high;
	unsigned char *lookup;
};

static void
indexed_to_rgb(fz_colorspace *cs, float *color, float *rgb)
{
	struct indexed *idx = cs->data;
	float alt[FZ_MAX_COLORS];
	int i, k;
	i = color[0] * 255;
	i = CLAMP(i, 0, idx->high);
	for (k = 0; k < idx->base->n; k++)
		alt[k] = idx->lookup[i * idx->base->n + k] / 255.0f;
	idx->base->to_rgb(idx->base, alt, rgb);
}

static void
free_indexed(fz_context *ctx, fz_colorspace *cs)
{
	struct indexed *idx = cs->data;
	if (idx->base)
		fz_drop_colorspace(ctx, idx->base);
	fz_free(ctx, idx->lookup);
	fz_free(ctx, idx);
}

fz_pixmap *
pdf_expand_indexed_pixmap(fz_context *ctx, fz_pixmap *src)
{
	struct indexed *idx;
	fz_pixmap *dst;
	unsigned char *s, *d;
	int y, x, k, n, high;
	unsigned char *lookup;

	assert(src->colorspace->to_rgb == indexed_to_rgb);
	assert(src->n == 2);

	idx = src->colorspace->data;
	high = idx->high;
	lookup = idx->lookup;
	n = idx->base->n;

	dst = fz_new_pixmap_with_rect(ctx, idx->base, fz_bound_pixmap(src));
	s = src->samples;
	d = dst->samples;

	for (y = 0; y < src->h; y++)
	{
		for (x = 0; x < src->w; x++)
		{
			int v = *s++;
			int a = *s++;
			v = MIN(v, high);
			for (k = 0; k < n; k++)
				*d++ = fz_mul255(lookup[v * n + k], a);
			*d++ = a;
		}
	}

	if (src->mask)
		dst->mask = fz_keep_pixmap(src->mask);
	dst->interpolate = src->interpolate;

	return dst;
}

static fz_error
load_indexed(fz_colorspace **csp, pdf_xref *xref, fz_obj *array)
{
	fz_error error;
	fz_colorspace *cs;
	struct indexed *idx;
	fz_context *ctx = xref->ctx;
	fz_obj *baseobj = fz_array_get(ctx, array, 1);
	fz_obj *highobj = fz_array_get(ctx, array, 2);
	fz_obj *lookup = fz_array_get(ctx, array, 3);
	fz_colorspace *base;
	int i, n;

	error = pdf_load_colorspace(&base, xref, baseobj);
	if (error)
		return fz_error_note(error, "cannot load base colorspace (%d %d R)", fz_to_num(baseobj), fz_to_gen(baseobj));

	idx = fz_malloc(ctx, sizeof(struct indexed));
	idx->base = base;
	idx->high = fz_to_int(ctx, highobj);
	idx->high = CLAMP(idx->high, 0, 255);
	n = base->n * (idx->high + 1);
	idx->lookup = fz_calloc(ctx, 1, n);

	cs = fz_new_colorspace(ctx, "Indexed", 1);
	cs->to_rgb = indexed_to_rgb;
	cs->free_data = free_indexed;
	cs->data = idx;

	if (fz_is_string(ctx, lookup) && fz_to_str_len(ctx, lookup) == n)
	{
		unsigned char *buf = (unsigned char *) fz_to_str_buf(ctx, lookup);
		for (i = 0; i < n; i++)
			idx->lookup[i] = buf[i];
	}
	else if (fz_is_indirect(lookup))
	{
		fz_stream *file;

		error = pdf_open_stream(&file, xref, fz_to_num(lookup), fz_to_gen(lookup));
		if (error)
		{
			fz_drop_colorspace(ctx, cs);
			return fz_error_note(error, "cannot open colorspace lookup table (%d 0 R)", fz_to_num(lookup));
		}

		i = fz_read(file, idx->lookup, n);
		if (i < 0)
		{
			fz_drop_colorspace(ctx, cs);
			return fz_error_make("cannot read colorspace lookup table (%d 0 R)", fz_to_num(lookup));
		}

		fz_close(file);
	}
	else
	{
		fz_drop_colorspace(ctx, cs);
		return fz_error_make("cannot parse colorspace lookup table");
	}

	*csp = cs;
	return fz_okay;
}

/* Parse and create colorspace from PDF object */

static fz_error
pdf_load_colorspace_imp(fz_colorspace **csp, pdf_xref *xref, fz_obj *obj)
{
	fz_context *ctx = xref->ctx;

	if (fz_is_name(ctx, obj))
	{
		if (!strcmp(fz_to_name(ctx, obj), "Pattern"))
			*csp = fz_device_gray;
		else if (!strcmp(fz_to_name(ctx, obj), "G"))
			*csp = fz_device_gray;
		else if (!strcmp(fz_to_name(ctx, obj), "RGB"))
			*csp = fz_device_rgb;
		else if (!strcmp(fz_to_name(ctx, obj), "CMYK"))
			*csp = fz_device_cmyk;
		else if (!strcmp(fz_to_name(ctx, obj), "DeviceGray"))
			*csp = fz_device_gray;
		else if (!strcmp(fz_to_name(ctx, obj), "DeviceRGB"))
			*csp = fz_device_rgb;
		else if (!strcmp(fz_to_name(ctx, obj), "DeviceCMYK"))
			*csp = fz_device_cmyk;
		else
			return fz_error_make("unknown colorspace: %s", fz_to_name(ctx, obj));
		return fz_okay;
	}

	else if (fz_is_array(ctx, obj))
	{
		fz_obj *name = fz_array_get(ctx, obj, 0);

		if (fz_is_name(ctx, name))
		{
			/* load base colorspace instead */
			if (!strcmp(fz_to_name(ctx, name), "Pattern"))
			{
				fz_error error;

				obj = fz_array_get(ctx, obj, 1);
				if (!obj)
				{
					*csp = fz_device_gray;
					return fz_okay;
				}

				error = pdf_load_colorspace(csp, xref, obj);
				if (error)
					return fz_error_note(error, "cannot load pattern (%d %d R)", fz_to_num(obj), fz_to_gen(obj));
			}

			else if (!strcmp(fz_to_name(ctx, name), "G"))
				*csp = fz_device_gray;
			else if (!strcmp(fz_to_name(ctx, name), "RGB"))
				*csp = fz_device_rgb;
			else if (!strcmp(fz_to_name(ctx, name), "CMYK"))
				*csp = fz_device_cmyk;
			else if (!strcmp(fz_to_name(ctx, name), "DeviceGray"))
				*csp = fz_device_gray;
			else if (!strcmp(fz_to_name(ctx, name), "DeviceRGB"))
				*csp = fz_device_rgb;
			else if (!strcmp(fz_to_name(ctx, name), "DeviceCMYK"))
				*csp = fz_device_cmyk;
			else if (!strcmp(fz_to_name(ctx, name), "CalGray"))
				*csp = fz_device_gray;
			else if (!strcmp(fz_to_name(ctx, name), "CalRGB"))
				*csp = fz_device_rgb;
			else if (!strcmp(fz_to_name(ctx, name), "CalCMYK"))
				*csp = fz_device_cmyk;
			else if (!strcmp(fz_to_name(ctx, name), "Lab"))
				*csp = fz_device_lab;

			else if (!strcmp(fz_to_name(ctx, name), "ICCBased"))
				return load_icc_based(csp, xref, fz_array_get(ctx, obj, 1));

			else if (!strcmp(fz_to_name(ctx, name), "Indexed"))
				return load_indexed(csp, xref, obj);
			else if (!strcmp(fz_to_name(ctx, name), "I"))
				return load_indexed(csp, xref, obj);

			else if (!strcmp(fz_to_name(ctx, name), "Separation"))
				return load_separation(csp, xref, obj);

			else if (!strcmp(fz_to_name(ctx, name), "DeviceN"))
				return load_separation(csp, xref, obj);

			else
				return fz_error_make("syntaxerror: unknown colorspace %s", fz_to_name(ctx, name));

			return fz_okay;
		}
	}

	return fz_error_make("syntaxerror: could not parse color space (%d %d R)", fz_to_num(obj), fz_to_gen(obj));
}

fz_error
pdf_load_colorspace(fz_colorspace **csp, pdf_xref *xref, fz_obj *obj)
{
	fz_error error;
	fz_context *ctx = xref->ctx;

	if ((*csp = pdf_find_item(ctx, xref->store, (pdf_store_drop_fn *)fz_drop_colorspace, obj)))
	{
		fz_keep_colorspace(*csp);
		return fz_okay;
	}

	error = pdf_load_colorspace_imp(csp, xref, obj);
	if (error)
		return fz_error_note(error, "cannot load colorspace (%d %d R)", fz_to_num(obj), fz_to_gen(obj));

	pdf_store_item(ctx, xref->store, (pdf_store_keep_fn *)fz_keep_colorspace, (pdf_store_drop_fn *)fz_drop_colorspace, obj, *csp);

	return fz_okay;
}
