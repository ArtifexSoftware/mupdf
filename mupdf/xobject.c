#include <fitz.h>
#include <mupdf.h>

fz_error *
pdf_loadxobject(pdf_xobject **formp, pdf_xref *xref, fz_obj *dict, fz_obj *ref)
{
	fz_error *error;
	pdf_xobject *form;
	fz_obj *obj;

	if ((*formp = pdf_finditem(xref->store, PDF_KXOBJECT, ref)))
		return nil;

	form = fz_malloc(sizeof(pdf_xobject));
	if (!form)
		return fz_outofmem;

	pdf_logrsrc("load xobject %d %d (%p) {\n", fz_tonum(ref), fz_togen(ref), form);

	obj = fz_dictgets(dict, "BBox");
	form->bbox = pdf_torect(obj);

	pdf_logrsrc("bbox [%g %g %g %g]\n",
		form->bbox.min.x, form->bbox.min.y,
		form->bbox.max.x, form->bbox.max.y);

	obj = fz_dictgets(dict, "Matrix");
	if (obj)
		form->matrix = pdf_tomatrix(obj);
	else
		form->matrix = fz_identity();

	pdf_logrsrc("matrix [%g %g %g %g %g %g]\n",
		form->matrix.a, form->matrix.b,
		form->matrix.c, form->matrix.d,
		form->matrix.e, form->matrix.f);

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

	form->contents = nil;
	error = pdf_loadstream(&form->contents, xref, fz_tonum(ref), fz_togen(ref));
	if (error)
	{
		fz_dropobj(form->resources);
		fz_free(form);
		return error;
	}

	pdf_logrsrc("stream %d bytes\n", form->contents->wp - form->contents->rp);

	pdf_logrsrc("}\n");

	error = pdf_storeitem(xref->store, PDF_KXOBJECT, ref, form);
	if (error)
	{
		fz_dropbuffer(form->contents);
		fz_dropobj(form->resources);
		fz_free(form);
		return error;
	}

	*formp = form;
	return nil;
}

