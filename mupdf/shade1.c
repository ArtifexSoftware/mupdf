#include <fitz.h>
#include <mupdf.h>

fz_error *
pdf_buildt1shademesh(fz_shade *shade, pdf_xref *xref, fz_obj *shading, 
					 fz_obj *ref, fz_matrix mat)
{
	fz_error *error;

	shade->meshlen = 2;
	shade->mesh = (float*) malloc(sizeof(float) * 9 * meshlen);

	pdf_setmeshvalue(mesh, 0, shade->
cleanup:
	return error;
}

fz_error *
pdf_loadtype1shade(fz_shade *shade, pdf_xref *xref, fz_obj *shading,
				   fz_obj *ref, fz_matrix mat)
{
	fz_error *error;
	fz_obj *obj;

	obj = fz_dictgets(shading, "Domain");
	if (obj) {
		t0 = fz_toreal(fz_arrayget(obj, 0));
		t1 = fz_toreal(fz_arrayget(obj, 1));
	} else {
		t0 = 0.;
		t1 = 1.;
	}

	pdf_loadshadefunction(shade, xref, shading);
	pdf_buildt1shademesh(shade, xref, shading, ref, mat);
}
