#include <fitz.h>
#include <mupdf.h>

fz_error *
pdf_loadshadedict(fz_shade **shadep, pdf_xref *xref, fz_obj *shading, fz_obj *ref, fz_matrix mat)
{
	fz_error *error;
	fz_shade *shade;
	pdf_function *func;

	fz_colorspace *cs = nil;

	fz_obj *sobj;
	int type;

	shade = fz_malloc(sizeof(fz_shade));

	shade->matrix = mat;

	sobj = fz_dictgets(shading, "ShadingType");
	type = fz_toint(sobj);

	shade->type = type;

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
	shade->cs = cs;

	shade->background = fz_dictgets(shading, "Background");

	//shade->bbox = fz_torect(fz_dictgets(shading, "BBox"));
	shade->antialias = fz_toint(fz_dictgets(shading, "AntiAlias"));

	switch(type) {
	case 1:
		shade->domain = fz_dictgets(shading, "Domain");
//		shade->matrix = fz_dictgets(shading, "Matrix"); /* NYI */
		sobj = fz_dictgets(shading, "Function");
		error = pdf_loadfunction(&shade->function, xref, sobj);
		if (error) goto cleanup;

		break;
	case 2:
	case 3:
		shade->coords = fz_dictgets(shading, "Coords");
		shade->domain = fz_dictgets(shading, "Domain");
		sobj = fz_dictgets(shading, "Function");
//		if (fz_isindirect(sobj)) {
//			error = pdf_loadindirect(&sobj, xref, sobj);
//		}
		error = pdf_loadfunction(&shade->function, xref, sobj);
		if (error) goto cleanup;

		shade->extend = fz_dictgets(shading, "Extend");
		break;
	case 4:
		break;
	default:
	};

	*shadep = shade;
	return nil;

cleanup:
	return error;
}

fz_error *
pdf_loadshade(fz_shade **shadep, pdf_xref *xref, fz_obj *obj, fz_obj *ref)
{
	fz_error *error = fz_throw("NYI");
	fz_shade *shade;
	
	fz_obj *shading;
	fz_matrix mat;
	fz_obj *extgstate;

	shade = fz_malloc(sizeof(fz_shade));
	if (!shade)
		return fz_outofmem;

printf("loading shade pattern\n");
	shading = fz_dictgets(obj, "Shading");

	if (fz_isindirect(shading)) {
		error = pdf_loadindirect(&shading, xref, shading);
		if (error) goto cleanup;
	}

	obj = fz_dictgets(obj, "Matrix");
	if (obj) {
		mat.a = fz_toreal(fz_arrayget(obj, 0));
		mat.b = fz_toreal(fz_arrayget(obj, 1));
		mat.c = fz_toreal(fz_arrayget(obj, 2));
		mat.d = fz_toreal(fz_arrayget(obj, 3));
		mat.e = fz_toreal(fz_arrayget(obj, 4));
		mat.f = fz_toreal(fz_arrayget(obj, 5));
	} 
	else {
		mat = fz_identity();
	}

	if (fz_isdict(shading)) {
		pdf_loadshadedict(&shade, xref, shading, ref, mat);
	} 
	else if (pdf_isstream(xref, fz_tonum(shading), fz_togen(shading))) {
			goto cleanup; /* NYI */
	}
	else 
		goto cleanup;

	*shadep = shade;
	return nil;

cleanup:
	return error;
}

