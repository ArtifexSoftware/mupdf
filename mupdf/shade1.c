#include <fitz.h>
#include <mupdf.h>

fz_error *
loadshadefunction(fz_shade *shade, pdf_xref *xref, fz_obj *dict,
					float x0, float x1, float y0, float y1)
{
	fz_error *error;
	float t[2];
	fz_obj *obj;
	pdf_function *func;
	int x, y;

	shade->usefunction = 1;

	obj = fz_dictgets(dict, "Function");
	error = pdf_loadfunction(&func, xref, obj);
	if (error)
		return error;

	for (y = 0; y < 16; ++y)
	{
		t[1] = y0 + (y / 15.0) * (y1 - y0);
		for (x = 0; x < 16; ++x)
		{
			t[0] = x0 + (x / 15.0) * (x1 - x0);
			error = pdf_evalfunction(func, t, 2, shade->function[y*16+x], shade->cs->n);
			if (error)
				return error;
		}
	}

	return nil;
}

fz_error *
pdf_loadtype1shade(fz_shade *shade, pdf_xref *xref, fz_obj *dict, fz_obj *ref)
{
	fz_error *error;
	fz_obj *obj;
	fz_matrix matrix;
	int xx, yy;
	float x, y;
	float xn, yn;
	float x0, y0, x1, y1;
	float t;
	int n;

	pdf_logshade("load type1 shade {\n");

	obj = fz_dictgets(dict, "Domain");
	x0 = fz_toreal(fz_arrayget(obj, 0));
	x1 = fz_toreal(fz_arrayget(obj, 1));
	y0 = fz_toreal(fz_arrayget(obj, 2));
	y1 = fz_toreal(fz_arrayget(obj, 3));

	pdf_logshade("domain %g %g %g %g\n", x0, x1, y0, y1);

	obj = fz_dictgets(dict, "Matrix");
	if (obj)
	{
		matrix = pdf_tomatrix(obj);
		pdf_logshade("matrix [%g %g %g %g %g %g]\n",
			matrix.a, matrix.b, matrix.c, matrix.d, matrix.e, matrix.f);
		shade->matrix = fz_concat(matrix, shade->matrix);
	}

	error = loadshadefunction(shade, xref, dict, x0, x1, y0, y1);
	if (error)
		return error;

	shade->meshlen = 512;
	shade->mesh = fz_malloc(sizeof(float) * 3*3 * shade->meshlen);
	if (!shade->mesh)
		return fz_outofmem;

	n = 0;
	for (yy = 0; yy < 16; ++yy)
	{
		y = y0 + (y1 - y0) * yy / 16.0;
		yn = y0 + (y1 - y0) * (yy + 1) / 16.0;
		for (xx = 0; xx < 16; ++xx)
		{
			x = x0 + (x1 - x0) * (xx / 16.0);
			xn = x0 + (x1 - x0) * (xx + 1) / 16.0;

			t = (yy * 16 + xx) / 255.;
			pdf_setmeshvalue(shade->mesh, n++, x, y, t);
			pdf_setmeshvalue(shade->mesh, n++, xn, y, t);
			pdf_setmeshvalue(shade->mesh, n++, xn, yn, t);
			pdf_setmeshvalue(shade->mesh, n++, x, y, t);
			pdf_setmeshvalue(shade->mesh, n++, xn, yn, t);
			pdf_setmeshvalue(shade->mesh, n++, x, yn, t);
		}
	}

	pdf_logshade("}\n");

	return nil;
}

