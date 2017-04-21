#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

pdf_xobject *
pdf_keep_xobject(fz_context *ctx, pdf_xobject *xobj)
{
	return fz_keep_storable(ctx, &xobj->storable);
}

void
pdf_drop_xobject(fz_context *ctx, pdf_xobject *xobj)
{
	fz_drop_storable(ctx, &xobj->storable);
}

static void
pdf_drop_xobject_imp(fz_context *ctx, fz_storable *xobj_)
{
	pdf_xobject *xobj = (pdf_xobject *)xobj_;
	pdf_drop_obj(ctx, xobj->obj);
	fz_free(ctx, xobj);
}

static size_t
pdf_xobject_size(pdf_xobject *xobj)
{
	if (xobj == NULL)
		return 0;
	return sizeof(*xobj);
}

pdf_obj *
pdf_xobject_resources(fz_context *ctx, pdf_xobject *xobj)
{
	return pdf_dict_get(ctx, xobj->obj, PDF_NAME_Resources);
}

fz_rect *
pdf_xobject_bbox(fz_context *ctx, pdf_xobject *xobj, fz_rect *bbox)
{
	return pdf_to_rect(ctx, pdf_dict_get(ctx, xobj->obj, PDF_NAME_BBox), bbox);
}

fz_matrix *
pdf_xobject_matrix(fz_context *ctx, pdf_xobject *xobj, fz_matrix *matrix)
{
	return pdf_to_matrix(ctx, pdf_dict_get(ctx, xobj->obj, PDF_NAME_Matrix), matrix);
}

int pdf_xobject_isolated(fz_context *ctx, pdf_xobject *xobj)
{
	pdf_obj *group = pdf_dict_get(ctx, xobj->obj, PDF_NAME_Group);
	if (group)
		return pdf_to_bool(ctx, pdf_dict_get(ctx, group, PDF_NAME_I));
	return 0;
}

int pdf_xobject_knockout(fz_context *ctx, pdf_xobject *xobj)
{
	pdf_obj *group = pdf_dict_get(ctx, xobj->obj, PDF_NAME_Group);
	if (group)
		return pdf_to_bool(ctx, pdf_dict_get(ctx, group, PDF_NAME_K));
	return 0;
}

int pdf_xobject_transparency(fz_context *ctx, pdf_xobject *xobj)
{
	pdf_obj *group = pdf_dict_get(ctx, xobj->obj, PDF_NAME_Group);
	if (group)
		if (pdf_name_eq(ctx, pdf_dict_get(ctx, group, PDF_NAME_S), PDF_NAME_Transparency))
			return 1;
	return 0;
}

fz_colorspace *
pdf_xobject_colorspace(fz_context *ctx, pdf_xobject *xobj)
{
	pdf_obj *group = pdf_dict_get(ctx, xobj->obj, PDF_NAME_Group);
	if (group)
	{
		pdf_obj *cs = pdf_dict_get(ctx, group, PDF_NAME_CS);
		if (cs)
		{
			fz_colorspace *colorspace = NULL;
			fz_try(ctx)
				colorspace = pdf_load_colorspace(ctx, pdf_get_bound_document(ctx, xobj->obj), cs);
			fz_catch(ctx)
				fz_warn(ctx, "cannot load xobject colorspace");
			return colorspace;
		}
	}
	return NULL;
}

pdf_xobject *
pdf_load_xobject(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	pdf_xobject *form;

	if ((form = pdf_find_item(ctx, pdf_drop_xobject_imp, dict)) != NULL)
		return form;

	form = fz_malloc_struct(ctx, pdf_xobject);
	FZ_INIT_STORABLE(form, 1, pdf_drop_xobject_imp);
	form->obj = NULL;
	form->iteration = 0;

	/* Store item immediately, to avoid possible recursion if objects refer back to this one */
	pdf_store_item(ctx, dict, form, pdf_xobject_size(form));

	form->obj = pdf_keep_obj(ctx, dict);

	return form;
}

pdf_obj *
pdf_new_xobject(fz_context *ctx, pdf_document *doc, const fz_rect *bbox, const fz_matrix *mat)
{
	int idict_num;
	pdf_obj *idict = NULL;
	pdf_obj *dict = NULL;
	pdf_xobject *form = NULL;
	pdf_obj *res = NULL;
	pdf_obj *procset;

	fz_var(idict);
	fz_var(dict);
	fz_var(form);
	fz_var(res);

	fz_try(ctx)
	{
		dict = pdf_new_dict(ctx, doc, 0);
		pdf_dict_put_drop(ctx, dict, PDF_NAME_BBox, pdf_new_rect(ctx, doc, bbox));
		pdf_dict_put_drop(ctx, dict, PDF_NAME_FormType, pdf_new_int(ctx, doc, 1));
		pdf_dict_put_drop(ctx, dict, PDF_NAME_Length, pdf_new_int(ctx, doc, 0));
		pdf_dict_put_drop(ctx, dict, PDF_NAME_Matrix, pdf_new_matrix(ctx, doc, mat));

		res = pdf_new_dict(ctx, doc, 0);
		pdf_dict_put(ctx, dict, PDF_NAME_Resources, res);

		procset = pdf_new_array(ctx, doc, 2);
		pdf_dict_put_drop(ctx, res, PDF_NAME_ProcSet, procset);
		pdf_array_push(ctx, procset, PDF_NAME_PDF);
		pdf_array_push(ctx, procset, PDF_NAME_Text);

		pdf_dict_put(ctx, dict, PDF_NAME_Subtype, PDF_NAME_Form);
		pdf_dict_put(ctx, dict, PDF_NAME_Type, PDF_NAME_XObject);

		form = fz_malloc_struct(ctx, pdf_xobject);
		FZ_INIT_STORABLE(form, 1, pdf_drop_xobject_imp);
		form->obj = NULL;
		form->iteration = 0;

		idict_num = pdf_create_object(ctx, doc);
		pdf_update_object(ctx, doc, idict_num, dict);
		idict = pdf_new_indirect(ctx, doc, idict_num, 0);

		pdf_store_item(ctx, idict, form, pdf_xobject_size(form));

		form->obj = pdf_keep_obj(ctx, idict);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, dict);
		pdf_drop_obj(ctx, res);
		pdf_drop_xobject(ctx, form);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, idict);
		fz_rethrow(ctx);
	}

	return idict;
}

void pdf_update_xobject_contents(fz_context *ctx, pdf_document *doc, pdf_xobject *form, fz_buffer *buffer)
{
	pdf_update_stream(ctx, doc, form->obj, buffer, 0);
	form->iteration ++;
}
