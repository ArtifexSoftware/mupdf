#include <fitz.h>
#include <mupdf.h>

fz_error *
pdf_loadxobject(pdf_xobject **formp, pdf_xref *xref, fz_obj *dict, fz_obj *ref)
{
	fz_error *error;
	pdf_xobject *form;
	fz_obj *obj;

	form = fz_malloc(sizeof(pdf_xobject));
	if (!form)
		return fz_outofmem;

	obj = fz_dictgets(dict, "BBox");
	form->bbox = pdf_torect(obj);

	obj = fz_dictgets(dict, "Matrix");
	if (obj)
		form->matrix = pdf_tomatrix(obj);
	else
		form->matrix = fz_identity();

	form->resources = nil;
	obj = fz_dictgets(dict, "Resources");
	if (obj)
	{
		error = pdf_resolve(&obj, xref);
		if (error)
		{
			fz_free(form);
			return error;
		}

		error = pdf_loadresources(&form->resources, xref, obj);
		if (error)
		{
			fz_dropobj(obj);
			fz_free(form);
			return error;
		}

		fz_dropobj(obj);
	}

	error = pdf_loadstream(&form->contents, xref, fz_tonum(ref), fz_togen(ref));
	if (error)
	{
		fz_dropobj(form->resources);
		fz_free(form);
		return error;
	}

	*formp = form;
	return nil;
}

