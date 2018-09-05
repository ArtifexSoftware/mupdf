#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include "../fitz/colorspace-imp.h"

#include <string.h>

/* ICCBased */
static fz_colorspace *
load_icc_based(fz_context *ctx, pdf_obj *dict, int alt)
{
	int n;
	pdf_obj *obj;
	fz_buffer *buffer = NULL;
	fz_colorspace *cs = NULL;
	fz_colorspace *cs_alt = NULL;
	fz_colorspace_clamp_fn *alt_lab_clamping = NULL;

	fz_var(cs);
	fz_var(cs_alt);
	fz_var(buffer);

	/*
		alt => "If ICC unreadable/unsupported, then return the
		alternate instead".

		Regardless of whether alt is set or not, we DO read the
		alternate space, because we need to know whether it's a
		LAB space or not to affect our clamping. We just might
		not return it.
	*/
	fz_try(ctx)
	{
		obj = pdf_dict_get(ctx, dict, PDF_NAME(Alternate));
		if (obj)
		{
			cs_alt = pdf_load_colorspace(ctx, obj);
			if (fz_colorspace_is_lab_icc(ctx, cs_alt))
				alt_lab_clamping = cs_alt->clamp;
		}
	}
	fz_catch(ctx)
	{
		fz_drop_colorspace(ctx, cs_alt);
		cs_alt = NULL;
	}

	/* If we're not going to be allowed to return it, drop it! */
	if (!alt)
	{
		fz_drop_colorspace(ctx, cs_alt);
		cs_alt = NULL;
	}

	n = pdf_dict_get_int(ctx, dict, PDF_NAME(N));

	fz_try(ctx)
	{
		if (fz_get_cmm_engine(ctx))
		{
			enum fz_colorspace_type type;
			if (n == 1) type = FZ_COLORSPACE_GRAY;
			else if (n == 3) type = FZ_COLORSPACE_RGB;
			else if (n == 4) type = FZ_COLORSPACE_CMYK;
			else type = FZ_COLORSPACE_NONE;
			buffer = pdf_load_stream(ctx, dict);
			cs = fz_new_icc_colorspace(ctx, type, buffer);
		}
	}
	fz_always(ctx)
		fz_drop_buffer(ctx, buffer);
	fz_catch(ctx)
	{
		if (!alt) {
			fz_drop_colorspace(ctx, cs_alt);
			fz_rethrow(ctx);
		}
	}

	if (cs)
	{
		if (n != 1 && n != 3 && n != 4)
		{
			fz_drop_colorspace(ctx, cs_alt);
			fz_drop_colorspace(ctx, cs);
			fz_throw(ctx, FZ_ERROR_GENERIC, "ICC Based must have 1, 3 or 4 components");
		}

		/* Override the clamping if the alternate was LAB */
		if (alt_lab_clamping)
			cs->clamp = alt_lab_clamping;
		fz_drop_colorspace(ctx, cs_alt);
		return cs;
	}

	/* Failed to load the ICC profile - either because it was broken,
	 * or because we aren't in an ICC workflow. If we aren't allowed
	 * to return the alternate, then that's all she wrote. */
	if (!alt)
	{
		fz_drop_colorspace(ctx, cs_alt);
		fz_throw(ctx, FZ_ERROR_GENERIC, "Unable to read ICC workflow");
	}

	/* If we have an alternate we are allowed to use, return that. */
	if (cs_alt)
	{
		if (n != 1 && n != 3 && n != 4)
		{
			fz_drop_colorspace(ctx, cs_alt);
			fz_throw(ctx, FZ_ERROR_GENERIC, "ICC Based must have 1, 3 or 4 components");
		}
		return cs_alt;
	}

	switch (n)
	{
	case 1:
		cs = fz_keep_colorspace(ctx, fz_device_gray(ctx));
		break;
	case 3:
		cs = fz_keep_colorspace(ctx, fz_device_rgb(ctx));
		break;
	case 4:
		cs = fz_keep_colorspace(ctx, fz_device_cmyk(ctx));
		break;
	default: fz_throw(ctx, FZ_ERROR_SYNTAX, "ICCBased must have 1, 3 or 4 components");
	}

	return cs;
}

struct devicen
{
	fz_colorspace *base;
	pdf_function *tint;
};

static void
devicen_to_alt(fz_context *ctx, const fz_colorspace *cs, const float *color, float *alt)
{
	struct devicen *devn = cs->data;
	pdf_eval_function(ctx, devn->tint, color, cs->n, alt, devn->base->n);
}

static void
devicen_to_rgb(fz_context *ctx, const fz_colorspace *cs, const float *color, float *rgb)
{
	struct devicen *devn = cs->data;
	float alt[FZ_MAX_COLORS];
	pdf_eval_function(ctx, devn->tint, color, cs->n, alt, devn->base->n);
	fz_convert_color(ctx, fz_default_color_params(ctx), NULL, fz_device_rgb(ctx), rgb, devn->base, alt);
}

static void
free_devicen(fz_context *ctx, fz_colorspace *cs)
{
	struct devicen *devn = cs->data;
	fz_drop_colorspace(ctx, devn->base);
	pdf_drop_function(ctx, devn->tint);
	fz_free(ctx, devn);
}

static fz_colorspace *
base_devicen(const fz_colorspace *cs)
{
	struct devicen *devn = cs->data;

	return devn->base;
}

static fz_colorspace *
load_devicen(fz_context *ctx, pdf_obj *array)
{
	fz_colorspace *cs = NULL;
	struct devicen *devn = NULL;
	pdf_obj *nameobj = pdf_array_get(ctx, array, 1);
	pdf_obj *baseobj = pdf_array_get(ctx, array, 2);
	pdf_obj *tintobj = pdf_array_get(ctx, array, 3);
	fz_colorspace *base;
	pdf_function *tint = NULL;
	char *colorspace_name;
	int i, n;

	fz_var(tint);
	fz_var(devn);

	if (pdf_is_array(ctx, nameobj))
	{
		n = pdf_array_len(ctx, nameobj);
		colorspace_name = "DeviceN";
	}
	else
	{
		n = 1;
		colorspace_name = "Separation";
	}

	if (n < 1)
		fz_throw(ctx, FZ_ERROR_SYNTAX, "insufficient components in colorspace");
	if (n > FZ_MAX_COLORS)
		fz_throw(ctx, FZ_ERROR_SYNTAX, "too many components in colorspace");

	base = pdf_load_colorspace(ctx, baseobj);

	fz_try(ctx)
	{
		tint = pdf_load_function(ctx, tintobj, n, base->n);
		/* RJW: fz_drop_colorspace(ctx, base);
		 * "cannot load tint function (%d 0 R)", pdf_to_num(ctx, tintobj) */

		devn = fz_malloc_struct(ctx, struct devicen);
		devn->base = fz_keep_colorspace(ctx, base);  /* We drop it during the devn free... */
		devn->tint = tint;

		cs = fz_new_colorspace(ctx, colorspace_name, FZ_COLORSPACE_SEPARATION, 0, n,
			fz_colorspace_is_icc(ctx, fz_device_rgb(ctx)) ? devicen_to_alt : devicen_to_rgb, NULL, base_devicen, NULL, free_devicen, devn,
			sizeof(struct devicen) + base->size + pdf_function_size(ctx, tint));

		devn = NULL;
		if (pdf_is_array(ctx, nameobj))
			for (i = 0; i < n; i++)
				fz_colorspace_name_colorant(ctx, cs, i, pdf_to_name(ctx, pdf_array_get(ctx, nameobj, i)));
		else
			fz_colorspace_name_colorant(ctx, cs, 0, pdf_to_name(ctx, nameobj));

	}
	fz_always(ctx)
		fz_drop_colorspace(ctx, base);
	fz_catch(ctx)
	{
		pdf_drop_function(ctx, tint);
		fz_free(ctx, devn);
		fz_rethrow(ctx);
	}

	return cs;
}

int
pdf_is_tint_colorspace(fz_context *ctx, fz_colorspace *cs)
{
	return cs && cs->free_data == free_devicen;
}

/* Indexed */

static fz_colorspace *
load_indexed(fz_context *ctx, pdf_obj *array)
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
		base = pdf_load_colorspace(ctx, baseobj);

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
				file = pdf_open_stream(ctx, lookupobj);
				i = (int)fz_read(ctx, file, lookup, n);
				if (i < n)
					memset(lookup+i, 0, n-i);
			}
			fz_always(ctx)
			{
				fz_drop_stream(ctx, file);
			}
			fz_catch(ctx)
			{
				fz_rethrow(ctx);
			}
		}
		else
		{
			fz_throw(ctx, FZ_ERROR_SYNTAX, "cannot parse colorspace lookup table");
		}

		cs = fz_new_indexed_colorspace(ctx, base, high, lookup);
	}
	fz_always(ctx)
		fz_drop_colorspace(ctx, base);
	fz_catch(ctx)
	{
		fz_free(ctx, lookup);
		fz_rethrow(ctx);
	}

	return cs;
}

static void
pdf_load_cal_common(fz_context *ctx, pdf_obj *dict, float *wp, float *bp, float *gamma)
{
	pdf_obj *obj;
	int i;

	obj = pdf_dict_get(ctx, dict, PDF_NAME(WhitePoint));
	if (pdf_array_len(ctx, obj) != 3)
		fz_throw(ctx, FZ_ERROR_SYNTAX, "WhitePoint must be a 3-element array");

	for (i = 0; i < 3; i++)
	{
		wp[i] = pdf_array_get_real(ctx, obj, i);
		if (wp[i] < 0)
			fz_throw(ctx, FZ_ERROR_SYNTAX, "WhitePoint numbers must be positive");
	}
	if (wp[1] != 1)
		fz_throw(ctx, FZ_ERROR_SYNTAX, "WhitePoint Yw must be 1.0");

	obj = pdf_dict_get(ctx, dict, PDF_NAME(BlackPoint));
	if (pdf_array_len(ctx, obj) == 3)
	{
		for (i = 0; i < 3; i++)
		{
			bp[i] = pdf_array_get_real(ctx, obj, i);
			if (bp[i] < 0)
				fz_throw(ctx, FZ_ERROR_SYNTAX, "BlackPoint numbers must be positive");
		}
	}

	obj = pdf_dict_get(ctx, dict, PDF_NAME(Gamma));
	if (pdf_is_number(ctx, obj))
	{
		gamma[0] = pdf_to_real(ctx, obj);
		gamma[1] = gamma[2];
		if (gamma[0] <= 0)
			fz_throw(ctx, FZ_ERROR_SYNTAX, "Gamma must be greater than zero");
	}
	else if (pdf_array_len(ctx, obj) == 3)
	{
		for (i = 0; i < 3; i++)
		{
			gamma[i] = pdf_array_get_real(ctx, obj, i);
			if (gamma[i] <= 0)
				fz_throw(ctx, FZ_ERROR_SYNTAX, "Gamma must be greater than zero");
		}
	}
}

static fz_colorspace *
pdf_load_cal_gray(fz_context *ctx, pdf_obj *dict)
{
	float wp[3];
	float bp[3] = { 0, 0, 0 };
	float gamma[3] = { 1, 1, 1 };

	if (dict == NULL)
		return fz_keep_colorspace(ctx, fz_device_gray(ctx));

	fz_try(ctx)
	{
		pdf_load_cal_common(ctx, dict, wp, bp, gamma);
		gamma[2] = gamma[1] = gamma[0];
	}
	fz_catch(ctx)
		return fz_keep_colorspace(ctx, fz_device_gray(ctx));
	return fz_new_cal_colorspace(ctx, "CalGray", wp, bp, gamma, NULL);
}

static fz_colorspace *
pdf_load_cal_rgb(fz_context *ctx, pdf_obj *dict)
{
	pdf_obj *obj;
	float matrix[9] = { 1, 0, 0, 0, 1, 0, 0, 0, 1 };
	float wp[3];
	float bp[3] = { 0, 0, 0 };
	float gamma[3] = { 1, 1, 1 };
	int i;

	if (dict == NULL)
		return fz_keep_colorspace(ctx, fz_device_rgb(ctx));

	fz_try(ctx)
	{
		pdf_load_cal_common(ctx, dict, wp, bp, gamma);

		obj = pdf_dict_get(ctx, dict, PDF_NAME(Matrix));
		if (pdf_array_len(ctx, obj) == 9)
		{
			for (i = 0; i < 9; i++)
				matrix[i] = pdf_array_get_real(ctx, obj, i);
		}
	}
	fz_catch(ctx)
		return fz_keep_colorspace(ctx, fz_device_rgb(ctx));
	return fz_new_cal_colorspace(ctx, "CalRGB", wp, bp, gamma, matrix);
}

/* Parse and create colorspace from PDF object */

static fz_colorspace *
pdf_load_colorspace_imp(fz_context *ctx, pdf_obj *obj)
{
	if (pdf_obj_marked(ctx, obj))
		fz_throw(ctx, FZ_ERROR_SYNTAX, "recursion in colorspace definition");

	if (pdf_is_name(ctx, obj))
	{
		if (pdf_name_eq(ctx, obj, PDF_NAME(Pattern)))
			return fz_keep_colorspace(ctx, fz_device_gray(ctx));
		else if (pdf_name_eq(ctx, obj, PDF_NAME(G)))
			return fz_keep_colorspace(ctx, fz_device_gray(ctx));
		else if (pdf_name_eq(ctx, obj, PDF_NAME(RGB)))
			return fz_keep_colorspace(ctx, fz_device_rgb(ctx));
		else if (pdf_name_eq(ctx, obj, PDF_NAME(CMYK)))
			return fz_keep_colorspace(ctx, fz_device_cmyk(ctx));
		else if (pdf_name_eq(ctx, obj, PDF_NAME(DeviceGray)))
			return fz_keep_colorspace(ctx, fz_device_gray(ctx));
		else if (pdf_name_eq(ctx, obj, PDF_NAME(DeviceRGB)))
			return fz_keep_colorspace(ctx, fz_device_rgb(ctx));
		else if (pdf_name_eq(ctx, obj, PDF_NAME(DeviceCMYK)))
			return fz_keep_colorspace(ctx, fz_device_cmyk(ctx));
		else
			fz_throw(ctx, FZ_ERROR_SYNTAX, "unknown colorspace: %s", pdf_to_name(ctx, obj));
	}

	else if (pdf_is_array(ctx, obj))
	{
		pdf_obj *name = pdf_array_get(ctx, obj, 0);

		if (pdf_is_name(ctx, name))
		{
			/* load base colorspace instead */
			if (pdf_name_eq(ctx, name, PDF_NAME(G)))
				return fz_keep_colorspace(ctx, fz_device_gray(ctx));
			else if (pdf_name_eq(ctx, name, PDF_NAME(RGB)))
				return fz_keep_colorspace(ctx, fz_device_rgb(ctx));
			else if (pdf_name_eq(ctx, name, PDF_NAME(CMYK)))
				return fz_keep_colorspace(ctx, fz_device_cmyk(ctx));
			else if (pdf_name_eq(ctx, name, PDF_NAME(DeviceGray)))
				return fz_keep_colorspace(ctx, fz_device_gray(ctx));
			else if (pdf_name_eq(ctx, name, PDF_NAME(DeviceRGB)))
				return fz_keep_colorspace(ctx, fz_device_rgb(ctx));
			else if (pdf_name_eq(ctx, name, PDF_NAME(DeviceCMYK)))
				return fz_keep_colorspace(ctx, fz_device_cmyk(ctx));
			else if (pdf_name_eq(ctx, name, PDF_NAME(CalGray)))
			{
				if (fz_get_cmm_engine(ctx))
					return pdf_load_cal_gray(ctx, pdf_array_get(ctx, obj, 1));
				else
					return fz_keep_colorspace(ctx, fz_device_gray(ctx));
			}
			else if (pdf_name_eq(ctx, name, PDF_NAME(CalRGB)))
			{
				if (fz_get_cmm_engine(ctx))
					return pdf_load_cal_rgb(ctx, pdf_array_get(ctx, obj, 1));
				else
					return fz_keep_colorspace(ctx, fz_device_rgb(ctx));
			}
			else if (pdf_name_eq(ctx, name, PDF_NAME(CalCMYK)))
				return fz_keep_colorspace(ctx, fz_device_cmyk(ctx));
			else if (pdf_name_eq(ctx, name, PDF_NAME(Lab)))
				return fz_keep_colorspace(ctx, fz_device_lab(ctx));
			else
			{
				fz_colorspace *cs;
				fz_try(ctx)
				{
					if (pdf_mark_obj(ctx, obj))
						fz_throw(ctx, FZ_ERROR_SYNTAX, "recursive colorspace");
					if (pdf_name_eq(ctx, name, PDF_NAME(ICCBased)))
						cs = load_icc_based(ctx, pdf_array_get(ctx, obj, 1), 1);

					else if (pdf_name_eq(ctx, name, PDF_NAME(Indexed)))
						cs = load_indexed(ctx, obj);
					else if (pdf_name_eq(ctx, name, PDF_NAME(I)))
						cs = load_indexed(ctx, obj);

					else if (pdf_name_eq(ctx, name, PDF_NAME(Separation)))
						cs = load_devicen(ctx, obj);

					else if (pdf_name_eq(ctx, name, PDF_NAME(DeviceN)))
						cs = load_devicen(ctx, obj);
					else if (pdf_name_eq(ctx, name, PDF_NAME(Pattern)))
					{
						pdf_obj *pobj;

						pobj = pdf_array_get(ctx, obj, 1);
						if (!pobj)
						{
							cs = fz_keep_colorspace(ctx, fz_device_gray(ctx));
							break;
						}

						cs = pdf_load_colorspace(ctx, pobj);
					}
					else
						fz_throw(ctx, FZ_ERROR_SYNTAX, "unknown colorspace %s", pdf_to_name(ctx, name));
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

	/* We have seen files where /DefaultRGB is specified as 1 0 R,
	 * and 1 0 obj << /Length 3144 /Alternate /DeviceRGB /N 3 >>
	 * stream ...iccprofile... endstream endobj.
	 * This *should* be [ /ICCBased 1 0 R ], but Acrobat seems to
	 * handle it, so do our best. */
	else if (pdf_is_dict(ctx, obj))
	{
		return load_icc_based(ctx, obj, 1);
	}

	fz_throw(ctx, FZ_ERROR_SYNTAX, "could not parse color space (%d 0 R)", pdf_to_num(ctx, obj));
}

fz_colorspace *
pdf_load_colorspace(fz_context *ctx, pdf_obj *obj)
{
	fz_colorspace *cs;

	if ((cs = pdf_find_item(ctx, fz_drop_colorspace_imp, obj)) != NULL)
	{
		return cs;
	}

	cs = pdf_load_colorspace_imp(ctx, obj);

	pdf_store_item(ctx, obj, cs, cs->size);

	return cs;
}

static fz_colorspace *
pdf_load_output_intent(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME(Root));
	pdf_obj *intents = pdf_dict_get(ctx, root, PDF_NAME(OutputIntents));
	pdf_obj *intent_dict;
	pdf_obj *dest_profile;
	fz_colorspace *cs = NULL;

	/* An array of intents */
	if (!intents)
		return NULL;

	/* For now, always just use the first intent. I have never even seen a file
	 * with multiple intents but it could happen */
	intent_dict = pdf_array_get(ctx, intents, 0);
	if (!intent_dict)
		return NULL;
	dest_profile = pdf_dict_get(ctx, intent_dict, PDF_NAME(DestOutputProfile));
	if (!dest_profile)
		return NULL;

	fz_var(cs);

	fz_try(ctx)
		cs = load_icc_based(ctx, dest_profile, 0);
	fz_catch(ctx)
	{
		/* Swallow the error */
		fz_warn(ctx, "Attempt to read Output Intent failed");
	}

	return cs;
}

fz_colorspace *
pdf_document_output_intent(fz_context *ctx, pdf_document *doc)
{
#ifndef NOICC
	if (!doc->oi)
		doc->oi = pdf_load_output_intent(ctx, doc);
#endif
	return doc->oi;
}
