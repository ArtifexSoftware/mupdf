#include <fitz.h>
#include <mupdf.h>

fz_error *
pdf_loadshadefunction(fz_shade *shade, pdf_xref *xref, fz_obj *shading, float t0, float t1)
{
	fz_error *error;
	float t;
	fz_obj *obj;
	pdf_function *func;
	
	obj = fz_dictgets(shading, "Function");
	error = pdf_loadfunction(&func, xref, obj);
	if (error) return error;

	for (int i=0; i<512; ++i) {
		t = t0 + (i / 511.) * (t1 - t0);
		error = pdf_evalfunction(func, &t, 1, shade->function[i], 0);
	}
	if (error) return error;

	return nil;
}

fz_error *
pdf_loadshadedict(fz_shade **shadep, pdf_xref *xref, fz_obj *shading, fz_obj *ref, fz_matrix mat)
{
	fz_error *error;
	fz_shade *shade;
	pdf_function *func;
	fz_obj *obj;

	fz_colorspace *cs = nil;

	fz_obj *sobj;
	int type;

	shade = fz_malloc(sizeof(fz_shade));

	shade->matrix = mat;

	pdf_logshade("load shade dict %d %d {\n", fz_tonum(ref), fz_togen(ref));

	sobj = fz_dictgets(shading, "ShadingType");
	type = fz_toint(sobj);

	sobj = fz_dictgets(shading, "ColorSpace");
	if (sobj)
	{
		error = pdf_resolve(&sobj, xref);
		if (error)
			return error;

		error = pdf_loadcolorspace(&cs, xref, sobj);
		if (error)
			return error;

		/*
		if (!strcmp(cs->name, "Indexed"))
		{
			indexed = (pdf_indexed*)cs;
			cs = indexed->base;
		}
		n = cs->n;
		a = 0;
		*/

		fz_dropobj(sobj);
	}
	shade->colorspace = cs;

	pdf_logshade("colorspace %s\n", shade->colorspace->name);

//	shade->background = fz_dictgets(shading, "Background");

	obj = fz_dictgets(shading, "BBox");
	if (fz_isarray(obj))
	{
		shade->bbox = pdf_torect(obj);
		pdf_logshade("bbox [%g %g %g %g]\n",
			shade->bbox.min.x, shade->bbox.min.y,
			shade->bbox.max.x, shade->bbox.max.y);
	}

	switch(type)
	{
	case 1:
//		error = pdf_loadtype1shade(shade, xref, shading, ref, mat);
		if (error) goto cleanup;
		break;
	case 2:
		error = pdf_loadtype2shade(shade, xref, shading, ref, mat);
		if (error) goto cleanup;
		break;
	case 3:
		error = pdf_loadtype3shade(shade, xref, shading, ref, mat);
		if (error) goto cleanup;
		break;
	case 4:
		break;
	default:
		break;
	};

	pdf_logshade("}\n");

	*shadep = shade;
	return nil;

cleanup:
	pdf_logshade("have an error: %s\n", error->msg);
	return error;
}

fz_error *
pdf_loadshade(fz_shade **shadep, pdf_xref *xref, fz_obj *obj, fz_obj *ref)
{
	fz_error *error = fz_throw("NYI");
	
	fz_obj *shading;
	fz_matrix mat;
	fz_obj *extgstate;

	if ((*shadep = pdf_finditem(xref->store, PDF_KSHADE, ref)))
		return nil;

	pdf_logshade("load shade %d %d {\n", fz_tonum(ref), fz_togen(ref));

	shading = fz_dictgets(obj, "Shading");

	if (fz_isindirect(shading)) {
		error = pdf_loadindirect(&shading, xref, shading);
		if (error) goto cleanup;
	}

	obj = fz_dictgets(obj, "Matrix");
	if (obj)
		mat = pdf_tomatrix(obj);
	else
		mat = fz_identity();

	if (fz_isdict(shading)) {
		pdf_loadshadedict(shadep, xref, shading, ref, mat);
	} 
	else if (pdf_isstream(xref, fz_tonum(shading), fz_togen(shading))) {
	}
	else {
	}

	pdf_logshade("}\n");

	if (*shadep)
	{
	error = pdf_storeitem(xref->store, PDF_KSHADE, ref, *shadep);
	if (error)
		goto cleanup;
	}

	return nil;

cleanup:
	return error;
}

void
pdf_setmeshvalue(float *mesh, int i, float x, float y, float t)
{
//	pdf_logshade("mesh %d: %g %g %g\n", i, x, y, t);
	mesh[i*3+0] = x;
	mesh[i*3+1] = y;
	mesh[i*3+2] = t;
}
