#include <fitz.h>
#include <mupdf.h>

#define NSEGS 32

fz_error *
pdf_loadtype1shade(fz_shade *shade, pdf_xref *xref, fz_obj *dict, fz_obj *ref)
{
	fz_error *error;
	fz_obj *obj;
	fz_matrix matrix;
	pdf_function *func;

	int xx, yy;
	float x, y;
	float xn, yn;
	float x0, y0, x1, y1;
	float t;
	int n;

	pdf_logshade("load type1 shade {\n");

	obj = fz_dictgets(dict, "Domain");
	if (obj) {
		x0 = fz_toreal(fz_arrayget(obj, 0));
		x1 = fz_toreal(fz_arrayget(obj, 1));
		y0 = fz_toreal(fz_arrayget(obj, 2));
		y1 = fz_toreal(fz_arrayget(obj, 3));
	} 
	else {
		x0 = 0;
		x1 = 1.0;
		y0 = 0;
		y1 = 1.0;
	}

	pdf_logshade("domain %g %g %g %g\n", x0, x1, y0, y1);

	obj = fz_dictgets(dict, "Matrix");
	if (obj)
	{
		matrix = pdf_tomatrix(obj);
		pdf_logshade("matrix [%g %g %g %g %g %g]\n",
			matrix.a, matrix.b, matrix.c, matrix.d, matrix.e, matrix.f);
	} 
	else
		matrix = fz_identity();

	obj = fz_dictgets(dict, "Function");
	error = pdf_loadfunction(&func, xref, obj);
	if (error)
		return error;
	
	shade->usefunction = 0;

	if (error)
		return error;

	shade->meshlen = NSEGS * NSEGS * 2;
	shade->mesh = fz_malloc(sizeof(float) * (2 + shade->cs->n) * 3 * shade->meshlen);
	if (!shade->mesh)
		return fz_outofmem;

	n = 0;
	for (yy = 0; yy < NSEGS; ++yy)
	{
		y = y0 + (y1 - y0) * yy / (float)NSEGS;
		yn = y0 + (y1 - y0) * (yy + 1) / (float)NSEGS;
		for (xx = 0; xx < NSEGS; ++xx)
		{
			x = x0 + (x1 - x0) * (xx / (float)NSEGS);
			xn = x0 + (x1 - x0) * (xx + 1) / (float)NSEGS;

#define ADD_VERTEX(xx, yy) \
			{\
				fz_point p;\
				float cp[2], cv[FZ_MAXCOLORS];\
				int c;\
				p.x = xx;\
				p.y = yy;\
				p = fz_transformpoint(matrix, p);\
				shade->mesh[n++] = p.x;\
				shade->mesh[n++] = p.y;\
				\
				cp[0] = xx;\
				cp[1] = yy;\
				error = pdf_evalfunction(func, cp, 2, cv, shade->cs->n);\
				\
				for (c = 0; c < shade->cs->n; ++c) {\
					shade->mesh[n++] = cv[c];\
				}\
			}\

			ADD_VERTEX(x, y);
			ADD_VERTEX(xn, y);
			ADD_VERTEX(xn, yn);
			
			ADD_VERTEX(x, y);
			ADD_VERTEX(xn, yn);
			ADD_VERTEX(x, yn);
		}
	}

	pdf_logshade("}\n");

	return nil;
}

