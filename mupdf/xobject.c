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

printf("loading xobject ");fz_debugobj(dict);printf("\n");

	obj = fz_dictgets(dict, "BBox");
	form->bbox.min.x = fz_toreal(fz_arrayget(obj, 0));
	form->bbox.min.y = fz_toreal(fz_arrayget(obj, 1));
	form->bbox.max.x = fz_toreal(fz_arrayget(obj, 2));
	form->bbox.max.y = fz_toreal(fz_arrayget(obj, 3));

	obj = fz_dictgets(dict, "Matrix");
	form->matrix.a = fz_toreal(fz_arrayget(obj, 0));
	form->matrix.b = fz_toreal(fz_arrayget(obj, 1));
	form->matrix.c = fz_toreal(fz_arrayget(obj, 2));
	form->matrix.d = fz_toreal(fz_arrayget(obj, 3));
	form->matrix.e = fz_toreal(fz_arrayget(obj, 4));
	form->matrix.f = fz_toreal(fz_arrayget(obj, 5));

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


