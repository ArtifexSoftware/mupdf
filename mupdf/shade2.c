#include <fitz.h>
#include <mupdf.h>

fz_error *
pdf_buildt2shademesh(fz_shade *shade, pdf_xref *xref, fz_obj *shading, 
					 fz_obj *ref, fz_matrix mat)
{
	fz_error *error;
	float x0, y0, x1, y1;
	float t0, t1;
	int e0, e1;
	fz_obj *obj;
	pdf_function *func;

	pdf_logshade("load type2 shade {\n");

	obj = fz_dictgets(shading, "Coords");
	x0 = fz_toreal(fz_arrayget(obj, 0));
	y0 = fz_toreal(fz_arrayget(obj, 1));
	x1 = fz_toreal(fz_arrayget(obj, 2));
	y1 = fz_toreal(fz_arrayget(obj, 3));

	pdf_logshade("coords %g %g %g %g\n", x0, y0, x1, y1);

	obj = fz_dictgets(shading, "Domain");
	if (obj) {
		t0 = fz_toreal(fz_arrayget(obj, 0));
		t1 = fz_toreal(fz_arrayget(obj, 1));
	} else {
		t0 = 0.;
		t1 = 1.;
	}

	obj = fz_dictgets(shading, "Extend");
	if (obj) {
		e0 = fz_tobool(fz_arrayget(obj, 0));
		e1 = fz_tobool(fz_arrayget(obj, 1));
	} else {
		e0 = 0;
		e1 = 0;
	}

	pdf_logshade("domain %g %g\n", t0, t1);
	pdf_logshade("extend %d %d\n", e0, e1);

	pdf_loadshadefunction(shade, xref, shading, t0, t1);

	shade->meshlen = 2 + e0 *2 + e1 * 2;
	shade->mesh = (float*) malloc(sizeof(float) * 3*3 * shade->meshlen);

	float theta;
	theta = atan2(y1 - y0, x1 - x0);
	theta += M_PI / 2.0;

	pdf_logshade("theta=%g\n", theta);

	fz_point p1, p2, p3, p4;
	fz_point ep1, ep2, ep3, ep4;
	float dist;
	dist = hypot(x1 - x0, y1 - y0);

#define BIGNUM 1000

	p1.x = x0 + BIGNUM * cos(theta);
	p1.y = y0 + BIGNUM * sin(theta);
	p2.x = x1 + BIGNUM * cos(theta);
	p2.y = y1 + BIGNUM * sin(theta);
	p3.x = x0 - BIGNUM * cos(theta);
	p3.y = y0 - BIGNUM * sin(theta);
	p4.x = x1 - BIGNUM * cos(theta);
	p4.y = y1 - BIGNUM * sin(theta);

	ep1.x = p1.x - (x1 - x0) / dist * BIGNUM;
	ep1.y = p1.y - (y1 - y0) / dist * BIGNUM;
	ep2.x = p2.x + (x1 - x0) / dist * BIGNUM;
	ep2.y = p2.y + (y1 - y0) / dist * BIGNUM;
	ep3.x = p3.x - (x1 - x0) / dist * BIGNUM;
	ep3.y = p3.y - (y1 - y0) / dist * BIGNUM;
	ep4.x = p4.x + (x1 - x0) / dist * BIGNUM;
	ep4.y = p4.y + (y1 - y0) / dist * BIGNUM;

	pdf_logshade("p1 %g %g\n", p1.x, p1.y);
	pdf_logshade("p2 %g %g\n", p2.x, p2.y);
	pdf_logshade("p3 %g %g\n", p3.x, p3.y);
	pdf_logshade("p4 %g %g\n", p4.x, p4.y);

	int n = 0;

	pdf_setmeshvalue(shade->mesh, n++, p1.x, p1.y, 0);
	pdf_setmeshvalue(shade->mesh, n++, p2.x, p2.y, 1);
	pdf_setmeshvalue(shade->mesh, n++, p4.x, p4.y, 1);
	pdf_setmeshvalue(shade->mesh, n++, p1.x, p1.y, 0);
	pdf_setmeshvalue(shade->mesh, n++, p4.x, p4.y, 1);
	pdf_setmeshvalue(shade->mesh, n++, p3.x, p3.y, 0);

	if (e0) {
		pdf_setmeshvalue(shade->mesh, n++, ep1.x, ep1.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p1.x, p1.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p3.x, p3.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, ep1.x, ep1.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p3.x, p3.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, ep3.x, ep3.y, 0);
	}

	if (e1) {
		pdf_setmeshvalue(shade->mesh, n++, p2.x, p2.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, ep2.x, ep2.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, ep4.x, ep4.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, p2.x, p2.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, ep4.x, ep4.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, p4.x, p4.y, 1);
	}

	pdf_logshade("}\n");

	return nil;

cleanup:
	return error;
}

fz_error *
pdf_loadtype2shade(fz_shade *shade, pdf_xref *xref, fz_obj *shading,
				   fz_obj *ref, fz_matrix mat)
{
	fz_error *error;
	fz_obj *obj;

	pdf_buildt2shademesh(shade, xref, shading, ref, mat);

	return nil;
}
