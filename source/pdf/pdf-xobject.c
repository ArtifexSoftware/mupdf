#include "mupdf/pdf.h"

pdf_xobject *
pdf_keep_xobject(fz_context *ctx, pdf_xobject *xobj)
{
	return (pdf_xobject *)fz_keep_storable(ctx, &xobj->storable);
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

	if (xobj->colorspace)
		fz_drop_colorspace(ctx, xobj->colorspace);
	pdf_drop_obj(ctx, xobj->resources);
	pdf_drop_obj(ctx, xobj->contents);
	pdf_drop_obj(ctx, xobj->me);
	fz_free(ctx, xobj);
}

static unsigned int
pdf_xobject_size(pdf_xobject *xobj)
{
	if (xobj == NULL)
		return 0;
	return sizeof(*xobj) + (xobj->colorspace ? xobj->colorspace->size : 0);
}

pdf_xobject *
pdf_load_xobject(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	pdf_xobject *form;
	pdf_obj *obj;

	if ((form = pdf_find_item(ctx, pdf_drop_xobject_imp, dict)) != NULL)
	{
		return form;
	}

	form = fz_malloc_struct(ctx, pdf_xobject);
	FZ_INIT_STORABLE(form, 1, pdf_drop_xobject_imp);
	form->document = doc;
	form->resources = NULL;
	form->contents = NULL;
	form->colorspace = NULL;
	form->me = NULL;
	form->iteration = 0;

	/* Store item immediately, to avoid possible recursion if objects refer back to this one */
	pdf_store_item(ctx, dict, form, pdf_xobject_size(form));

	fz_try(ctx)
	{
		obj = pdf_dict_get(ctx, dict, PDF_NAME_BBox);
		pdf_to_rect(ctx, obj, &form->bbox);

		obj = pdf_dict_get(ctx, dict, PDF_NAME_Matrix);
		if (obj)
			pdf_to_matrix(ctx, obj, &form->matrix);
		else
			form->matrix = fz_identity;

		form->isolated = 0;
		form->knockout = 0;
		form->transparency = 0;

		obj = pdf_dict_get(ctx, dict, PDF_NAME_Group);
		if (obj)
		{
			pdf_obj *attrs = obj;

			form->isolated = pdf_to_bool(ctx, pdf_dict_get(ctx, attrs, PDF_NAME_I));
			form->knockout = pdf_to_bool(ctx, pdf_dict_get(ctx, attrs, PDF_NAME_K));

			obj = pdf_dict_get(ctx, attrs, PDF_NAME_S);
			if (pdf_name_eq(ctx, obj, PDF_NAME_Transparency))
				form->transparency = 1;

			obj = pdf_dict_get(ctx, attrs, PDF_NAME_CS);
			if (obj)
			{
				fz_try(ctx)
				{
					form->colorspace = pdf_load_colorspace(ctx, doc, obj);
				}
				fz_catch(ctx)
				{
					fz_warn(ctx, "cannot load xobject colorspace");
				}
			}
		}

		form->resources = pdf_dict_get(ctx, dict, PDF_NAME_Resources);
		if (form->resources)
			pdf_keep_obj(ctx, form->resources);

		form->contents = pdf_keep_obj(ctx, dict);
	}
	fz_catch(ctx)
	{
		pdf_remove_item(ctx, pdf_drop_xobject_imp, dict);
		pdf_drop_xobject(ctx, form);
		fz_rethrow_message(ctx, "cannot load xobject content stream (%d %d R)", pdf_to_num(ctx, dict), pdf_to_gen(ctx, dict));
	}
	form->me = pdf_keep_obj(ctx, dict);

	return form;
}

pdf_obj *
pdf_new_xobject(fz_context *ctx, pdf_document *doc, const fz_rect *bbox, const fz_matrix *mat)
{
	int idict_num;
	pdf_obj *idict = NULL;
	pdf_obj *dict = NULL;
	pdf_xobject *form = NULL;
	pdf_obj *obj = NULL;
	pdf_obj *res = NULL;
	pdf_obj *procset = NULL;

	fz_var(idict);
	fz_var(dict);
	fz_var(form);
	fz_var(obj);
	fz_var(res);
	fz_var(procset);
	fz_try(ctx)
	{
		dict = pdf_new_dict(ctx, doc, 0);

		obj = pdf_new_rect(ctx, doc, bbox);
		pdf_dict_put(ctx, dict, PDF_NAME_BBox, obj);
		pdf_drop_obj(ctx, obj);
		obj = NULL;

		obj = pdf_new_int(ctx, doc, 1);
		pdf_dict_put(ctx, dict, PDF_NAME_FormType, obj);
		pdf_drop_obj(ctx, obj);
		obj = NULL;

		obj = pdf_new_int(ctx, doc, 0);
		pdf_dict_put(ctx, dict, PDF_NAME_Length, obj);
		pdf_drop_obj(ctx, obj);
		obj = NULL;

		obj = pdf_new_matrix(ctx, doc, mat);
		pdf_dict_put(ctx, dict, PDF_NAME_Matrix, obj);
		pdf_drop_obj(ctx, obj);
		obj = NULL;

		res = pdf_new_dict(ctx, doc, 0);
		procset = pdf_new_array(ctx, doc, 2);
		pdf_array_push(ctx, procset, PDF_NAME_PDF);
		pdf_array_push(ctx, procset, PDF_NAME_Text);
		pdf_dict_put(ctx, res, PDF_NAME_ProcSet, procset);
		pdf_drop_obj(ctx, procset);
		procset = NULL;
		pdf_dict_put(ctx, dict, PDF_NAME_Resources, res);

		pdf_dict_put(ctx, dict, PDF_NAME_Subtype, PDF_NAME_Form);

		pdf_dict_put(ctx, dict, PDF_NAME_Type, PDF_NAME_XObject);

		form = fz_malloc_struct(ctx, pdf_xobject);
		FZ_INIT_STORABLE(form, 1, pdf_drop_xobject_imp);
		form->document = doc;
		form->resources = NULL;
		form->contents = NULL;
		form->colorspace = NULL;
		form->me = NULL;
		form->iteration = 0;

		form->bbox = *bbox;

		form->matrix = *mat;

		form->isolated = 0;
		form->knockout = 0;
		form->transparency = 0;

		form->resources = res;
		res = NULL;

		idict_num = pdf_create_object(ctx, doc);
		pdf_update_object(ctx, doc, idict_num, dict);
		idict = pdf_new_indirect(ctx, doc, idict_num, 0);
		pdf_drop_obj(ctx, dict);
		dict = NULL;

		pdf_store_item(ctx, idict, form, pdf_xobject_size(form));

		form->contents = pdf_keep_obj(ctx, idict);
		form->me = pdf_keep_obj(ctx, idict);

		pdf_drop_xobject(ctx, form);
		form = NULL;
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, procset);
		pdf_drop_obj(ctx, res);
		pdf_drop_obj(ctx, obj);
		pdf_drop_obj(ctx, dict);
		pdf_drop_obj(ctx, idict);
		pdf_drop_xobject(ctx, form);
		fz_rethrow_message(ctx, "failed to create xobject)");
	}

	return idict;
}

void pdf_update_xobject_contents(fz_context *ctx, pdf_document *doc, pdf_xobject *form, fz_buffer *buffer)
{
	pdf_update_stream(ctx, doc, form->contents, buffer, 0);
	form->iteration ++;
}
