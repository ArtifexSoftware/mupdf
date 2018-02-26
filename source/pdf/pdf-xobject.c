#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

pdf_obj *
pdf_xobject_resources(fz_context *ctx, pdf_obj *xobj)
{
	return pdf_dict_get(ctx, xobj, PDF_NAME_Resources);
}

fz_rect *
pdf_xobject_bbox(fz_context *ctx, pdf_obj *xobj, fz_rect *bbox)
{
	return pdf_to_rect(ctx, pdf_dict_get(ctx, xobj, PDF_NAME_BBox), bbox);
}

fz_matrix *
pdf_xobject_matrix(fz_context *ctx, pdf_obj *xobj, fz_matrix *matrix)
{
	return pdf_to_matrix(ctx, pdf_dict_get(ctx, xobj, PDF_NAME_Matrix), matrix);
}

int pdf_xobject_isolated(fz_context *ctx, pdf_obj *xobj)
{
	pdf_obj *group = pdf_dict_get(ctx, xobj, PDF_NAME_Group);
	if (group)
		return pdf_to_bool(ctx, pdf_dict_get(ctx, group, PDF_NAME_I));
	return 0;
}

int pdf_xobject_knockout(fz_context *ctx, pdf_obj *xobj)
{
	pdf_obj *group = pdf_dict_get(ctx, xobj, PDF_NAME_Group);
	if (group)
		return pdf_to_bool(ctx, pdf_dict_get(ctx, group, PDF_NAME_K));
	return 0;
}

int pdf_xobject_transparency(fz_context *ctx, pdf_obj *xobj)
{
	pdf_obj *group = pdf_dict_get(ctx, xobj, PDF_NAME_Group);
	if (group)
		if (pdf_name_eq(ctx, pdf_dict_get(ctx, group, PDF_NAME_S), PDF_NAME_Transparency))
			return 1;
	return 0;
}

fz_colorspace *
pdf_xobject_colorspace(fz_context *ctx, pdf_obj *xobj)
{
	pdf_obj *group = pdf_dict_get(ctx, xobj, PDF_NAME_Group);
	if (group)
	{
		pdf_obj *cs = pdf_dict_get(ctx, group, PDF_NAME_CS);
		if (cs)
		{
			fz_colorspace *colorspace = NULL;
			fz_try(ctx)
				colorspace = pdf_load_colorspace(ctx, cs);
			fz_catch(ctx)
				fz_warn(ctx, "cannot load xobject colorspace");
			return colorspace;
		}
	}
	return NULL;
}

pdf_obj *
pdf_new_xobject(fz_context *ctx, pdf_document *doc, const fz_rect *bbox, const fz_matrix *mat)
{
	pdf_obj *form = NULL;
	pdf_obj *dict = NULL;
	pdf_obj *res = NULL;
	pdf_obj *procset;

	fz_var(dict);
	fz_var(res);

	fz_try(ctx)
	{
		dict = pdf_new_dict(ctx, doc, 0);
		pdf_dict_put_rect(ctx, dict, PDF_NAME_BBox, bbox);
		pdf_dict_put_int(ctx, dict, PDF_NAME_FormType, 1);
		pdf_dict_put_int(ctx, dict, PDF_NAME_Length, 0);
		pdf_dict_put_matrix(ctx, dict, PDF_NAME_Matrix, mat);

		res = pdf_new_dict(ctx, doc, 0);
		pdf_dict_put(ctx, dict, PDF_NAME_Resources, res);

		procset = pdf_new_array(ctx, doc, 2);
		pdf_dict_put_drop(ctx, res, PDF_NAME_ProcSet, procset);
		pdf_array_push(ctx, procset, PDF_NAME_PDF);
		pdf_array_push(ctx, procset, PDF_NAME_Text);

		pdf_dict_put(ctx, dict, PDF_NAME_Subtype, PDF_NAME_Form);
		pdf_dict_put(ctx, dict, PDF_NAME_Type, PDF_NAME_XObject);

		form = pdf_add_object(ctx, doc, dict);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, dict);
		pdf_drop_obj(ctx, res);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return form;
}

void pdf_update_xobject_contents(fz_context *ctx, pdf_document *doc, pdf_obj *form, fz_buffer *buffer)
{
	pdf_update_stream(ctx, doc, form, buffer, 0);
}
