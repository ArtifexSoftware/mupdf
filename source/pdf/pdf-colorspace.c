#include "mupdf/pdf.h"

/* ICCBased */

static fz_colorspace *
load_icc_based(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	int n;
	pdf_obj *obj;

	n = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_N));
	obj = pdf_dict_get(ctx, dict, PDF_NAME_Alternate);

	if (obj)
	{
		fz_colorspace *cs_alt = NULL;

		fz_try(ctx)
		{
			cs_alt = pdf_load_colorspace(ctx, doc, obj);
			if (cs_alt->n != n)
			{
				fz_drop_colorspace(ctx, cs_alt);
				fz_throw(ctx, FZ_ERROR_GENERIC, "ICCBased /Alternate colorspace must have %d components", n);
			}
		}
		fz_catch(ctx)
		{
			cs_alt = NULL;
		}

		if (cs_alt)
			return cs_alt;
	}

	switch (n)
	{
	case 1: return fz_device_gray(ctx);
	case 3: return fz_device_rgb(ctx);
	case 4: return fz_device_cmyk(ctx);
	}

	fz_throw(ctx, FZ_ERROR_GENERIC, "syntaxerror: ICCBased must have 1, 3 or 4 components");
}

/* Lab */

static inline float fung(float x)
{
	if (x >= 6.0f / 29.0f)
		return x * x * x;
	return (108.0f / 841.0f) * (x - (4.0f / 29.0f));
}

static void
lab_to_rgb(fz_context *ctx, fz_colorspace *cs, const float *lab, float *rgb)
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
	rgb[0] = sqrtf(fz_clamp(r, 0, 1));
	rgb[1] = sqrtf(fz_clamp(g, 0, 1));
	rgb[2] = sqrtf(fz_clamp(b, 0, 1));
}

static void
rgb_to_lab(fz_context *ctx, fz_colorspace *cs, const float *rgb, float *lab)
{
	fz_warn(ctx, "cannot convert into L*a*b colorspace");
	lab[0] = rgb[0];
	lab[1] = rgb[1];
	lab[2] = rgb[2];
}

static fz_colorspace k_device_lab = { {-1, fz_drop_colorspace_imp}, 0, "Lab", 3, lab_to_rgb, rgb_to_lab };
static fz_colorspace *fz_device_lab = &k_device_lab;

/* Separation and DeviceN */

struct separation
{
	fz_colorspace *base;
	fz_function *tint;
};

static void
separation_to_rgb(fz_context *ctx, fz_colorspace *cs, const float *color, float *rgb)
{
	struct separation *sep = cs->data;
	float alt[FZ_MAX_COLORS];
	fz_eval_function(ctx, sep->tint, color, cs->n, alt, sep->base->n);
	sep->base->to_rgb(ctx, sep->base, alt, rgb);
}

static void
free_separation(fz_context *ctx, fz_colorspace *cs)
{
	struct separation *sep = cs->data;
	fz_drop_colorspace(ctx, sep->base);
	fz_drop_function(ctx, sep->tint);
	fz_free(ctx, sep);
}

static fz_colorspace *
load_separation(fz_context *ctx, pdf_document *doc, pdf_obj *array)
{
	fz_colorspace *cs;
	struct separation *sep = NULL;
	pdf_obj *nameobj = pdf_array_get(ctx, array, 1);
	pdf_obj *baseobj = pdf_array_get(ctx, array, 2);
	pdf_obj *tintobj = pdf_array_get(ctx, array, 3);
	fz_colorspace *base;
	fz_function *tint = NULL;
	int n;

	fz_var(tint);
	fz_var(sep);

	if (pdf_is_array(ctx, nameobj))
		n = pdf_array_len(ctx, nameobj);
	else
		n = 1;

	if (n > FZ_MAX_COLORS)
		fz_throw(ctx, FZ_ERROR_GENERIC, "too many components in colorspace");

	base = pdf_load_colorspace(ctx, doc, baseobj);

	fz_try(ctx)
	{
		tint = pdf_load_function(ctx, doc, tintobj, n, base->n);
		/* RJW: fz_drop_colorspace(ctx, base);
		 * "cannot load tint function (%d %d R)", pdf_to_num(ctx, tintobj), pdf_to_gen(ctx, tintobj) */

		sep = fz_malloc_struct(ctx, struct separation);
		sep->base = base;
		sep->tint = tint;

		cs = fz_new_colorspace(ctx, n == 1 ? "Separation" : "DeviceN", n);
		cs->to_rgb = separation_to_rgb;
		cs->free_data = free_separation;
		cs->data = sep;
		cs->size += sizeof(struct separation) + (base ? base->size : 0) + fz_function_size(ctx, tint);
	}
	fz_catch(ctx)
	{
		fz_drop_colorspace(ctx, base);
		fz_drop_function(ctx, tint);
		fz_free(ctx, sep);
		fz_rethrow(ctx);
	}

	return cs;
}

int
pdf_is_tint_colorspace(fz_context *ctx, fz_colorspace *cs)
{
	return cs && cs->to_rgb == separation_to_rgb;
}

/* Indexed */

static fz_colorspace *
load_indexed(fz_context *ctx, pdf_document *doc, pdf_obj *array)
{
	pdf_obj *baseobj = pdf_array_get(ctx, array, 1);
	pdf_obj *highobj = pdf_array_get(ctx, array, 2);
	pdf_obj *lookupobj = pdf_array_get(ctx, array, 3);
	fz_colorspace *base = NULL;
	fz_colorspace *cs;
	int i, n, high;
	unsigned char *lookup = NULL;

	fz_var(base);
	fz_var(lookup);

	fz_try(ctx)
	{
		base = pdf_load_colorspace(ctx, doc, baseobj);

		high = pdf_to_int(ctx, highobj);
		high = fz_clampi(high, 0, 255);
		n = base->n * (high + 1);
		lookup = fz_malloc_array(ctx, 1, n);

		if (pdf_is_string(ctx, lookupobj) && pdf_to_str_len(ctx, lookupobj) >= n)
		{
			unsigned char *buf = (unsigned char *) pdf_to_str_buf(ctx, lookupobj);
			for (i = 0; i < n; i++)
				lookup[i] = buf[i];
		}
		else if (pdf_is_indirect(ctx, lookupobj))
		{
			fz_stream *file = NULL;

			fz_var(file);

			fz_try(ctx)
			{
				file = pdf_open_stream(ctx, doc, pdf_to_num(ctx, lookupobj), pdf_to_gen(ctx, lookupobj));
				i = fz_read(ctx, file, lookup, n);
				if (i < n)
					memset(lookup+i, 0, n-i);
			}
			fz_always(ctx)
			{
				fz_drop_stream(ctx, file);
			}
			fz_catch(ctx)
			{
				fz_rethrow_message(ctx, "cannot open colorspace lookup table (%d 0 R)", pdf_to_num(ctx, lookupobj));
			}
		}
		else
		{
			fz_rethrow_message(ctx, "cannot parse colorspace lookup table");
		}

		cs = fz_new_indexed_colorspace(ctx, base, high, lookup);
	}
	fz_catch(ctx)
	{
		fz_drop_colorspace(ctx, base);
		fz_free(ctx, lookup);
		fz_rethrow(ctx);
	}

	return cs;
}

/* Parse and create colorspace from PDF object */

static fz_colorspace *
pdf_load_colorspace_imp(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{

	if (pdf_obj_marked(ctx, obj))
		fz_throw(ctx, FZ_ERROR_GENERIC, "Recursion in colorspace definition");

	if (pdf_is_name(ctx, obj))
	{
		if (pdf_name_eq(ctx, obj, PDF_NAME_Pattern))
			return fz_device_gray(ctx);
		else if (pdf_name_eq(ctx, obj, PDF_NAME_G))
			return fz_device_gray(ctx);
		else if (pdf_name_eq(ctx, obj, PDF_NAME_RGB))
			return fz_device_rgb(ctx);
		else if (pdf_name_eq(ctx, obj, PDF_NAME_CMYK))
			return fz_device_cmyk(ctx);
		else if (pdf_name_eq(ctx, obj, PDF_NAME_DeviceGray))
			return fz_device_gray(ctx);
		else if (pdf_name_eq(ctx, obj, PDF_NAME_DeviceRGB))
			return fz_device_rgb(ctx);
		else if (pdf_name_eq(ctx, obj, PDF_NAME_DeviceCMYK))
			return fz_device_cmyk(ctx);
		else
			fz_throw(ctx, FZ_ERROR_GENERIC, "unknown colorspace: %s", pdf_to_name(ctx, obj));
	}

	else if (pdf_is_array(ctx, obj))
	{
		pdf_obj *name = pdf_array_get(ctx, obj, 0);

		if (pdf_is_name(ctx, name))
		{
			/* load base colorspace instead */
			if (pdf_name_eq(ctx, name, PDF_NAME_G))
				return fz_device_gray(ctx);
			else if (pdf_name_eq(ctx, name, PDF_NAME_RGB))
				return fz_device_rgb(ctx);
			else if (pdf_name_eq(ctx, name, PDF_NAME_CMYK))
				return fz_device_cmyk(ctx);
			else if (pdf_name_eq(ctx, name, PDF_NAME_DeviceGray))
				return fz_device_gray(ctx);
			else if (pdf_name_eq(ctx, name, PDF_NAME_DeviceRGB))
				return fz_device_rgb(ctx);
			else if (pdf_name_eq(ctx, name, PDF_NAME_DeviceCMYK))
				return fz_device_cmyk(ctx);
			else if (pdf_name_eq(ctx, name, PDF_NAME_CalGray))
				return fz_device_gray(ctx);
			else if (pdf_name_eq(ctx, name, PDF_NAME_CalRGB))
				return fz_device_rgb(ctx);
			else if (pdf_name_eq(ctx, name, PDF_NAME_CalCMYK))
				return fz_device_cmyk(ctx);
			else if (pdf_name_eq(ctx, name, PDF_NAME_Lab))
				return fz_device_lab;
			else
			{
				fz_colorspace *cs;
				fz_try(ctx)
				{
					pdf_mark_obj(ctx, obj);
					if (pdf_name_eq(ctx, name, PDF_NAME_ICCBased))
						cs = load_icc_based(ctx, doc, pdf_array_get(ctx, obj, 1));

					else if (pdf_name_eq(ctx, name, PDF_NAME_Indexed))
						cs = load_indexed(ctx, doc, obj);
					else if (pdf_name_eq(ctx, name, PDF_NAME_I))
						cs = load_indexed(ctx, doc, obj);

					else if (pdf_name_eq(ctx, name, PDF_NAME_Separation))
						cs = load_separation(ctx, doc, obj);

					else if (pdf_name_eq(ctx, name, PDF_NAME_DeviceN))
						cs = load_separation(ctx, doc, obj);
					else if (pdf_name_eq(ctx, name, PDF_NAME_Pattern))
					{
						pdf_obj *pobj;

						pobj = pdf_array_get(ctx, obj, 1);
						if (!pobj)
						{
							cs = fz_device_gray(ctx);
							break;
						}

						cs = pdf_load_colorspace(ctx, doc, pobj);
					}
					else
						fz_throw(ctx, FZ_ERROR_GENERIC, "syntaxerror: unknown colorspace %s", pdf_to_name(ctx, name));
				}
				fz_always(ctx)
				{
					pdf_unmark_obj(ctx, obj);
				}
				fz_catch(ctx)
				{
					fz_rethrow(ctx);
				}
				return cs;
			}
		}
	}

	fz_throw(ctx, FZ_ERROR_GENERIC, "syntaxerror: could not parse color space (%d %d R)", pdf_to_num(ctx, obj), pdf_to_gen(ctx, obj));
}

fz_colorspace *
pdf_load_colorspace(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	fz_colorspace *cs;

	if ((cs = pdf_find_item(ctx, fz_drop_colorspace_imp, obj)) != NULL)
	{
		return cs;
	}

	cs = pdf_load_colorspace_imp(ctx, doc, obj);

	pdf_store_item(ctx, obj, cs, cs->size);

	return cs;
}
