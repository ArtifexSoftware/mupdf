#include <fitz.h>
#include <mupdf.h>

#define BIGNUM 32000

#define MAX_RAD_SEGS 36

int
buildannulusmesh(float* mesh, int pos,
					float x0, float y0, float r0, float x1, float y1, float r1, 
					float c0, float c1, int nomesh)
{
	int n = pos * 3;
	float dist = hypot(x1 - x0, y1 - y0);
	float step;
	float theta;
	int i;

	if (dist != 0)
		theta = asin((r1 - r0) / dist) + M_PI/2.0 + atan2(y1 - y0, x1 - x0);
	else
		theta = 0;

	if (!(theta >= 0 && theta <= M_PI))
		theta = 0;

	step = M_PI * 2. / (float)MAX_RAD_SEGS;

	for (i = 0; i < MAX_RAD_SEGS; theta -= step, ++i)
	{
		fz_point pt1, pt2, pt3, pt4;

		pt1.x = cos (theta) * r1 + x1;
		pt1.y = sin (theta) * r1 + y1;
		pt2.x = cos (theta) * r0 + x0;
		pt2.y = sin (theta) * r0 + y0;
		pt3.x = cos (theta+step) * r1 + x1;
		pt3.y = sin (theta+step) * r1 + y1;
		pt4.x = cos (theta+step) * r0 + x0;
		pt4.y = sin (theta+step) * r0 + y0;

		if (r0 > 0) {
			if (!nomesh) {
				pdf_setmeshvalue(mesh, n++, pt1.x, pt1.y, c1);
				pdf_setmeshvalue(mesh, n++, pt2.x, pt2.y, c0);
				pdf_setmeshvalue(mesh, n++, pt4.x, pt4.y, c0);
			}
			pos++;
		}

		if (r1 > 0) {
			if (!nomesh) {
				pdf_setmeshvalue(mesh, n++, pt1.x, pt1.y, c1);
				pdf_setmeshvalue(mesh, n++, pt3.x, pt3.y, c1);
				pdf_setmeshvalue(mesh, n++, pt4.x, pt4.y, c0);
			}
			pos++;
		}
	}

	return pos;
}

fz_error *
pdf_loadtype3shade(fz_shade *shade, pdf_xref *xref, fz_obj *shading, fz_obj *ref)
{
	fz_obj *obj;
	float x0, y0, r0, x1, y1, r1;
	float t0, t1;
	int e0, e1;
	float ex0, ey0, er0;
	float ex1, ey1, er1;
	float rs;
	int i;

	pdf_logshade("load type3 shade {\n");

	obj = fz_dictgets(shading, "Coords");
	x0 = fz_toreal(fz_arrayget(obj, 0));
	y0 = fz_toreal(fz_arrayget(obj, 1));
	r0 = fz_toreal(fz_arrayget(obj, 2));
	x1 = fz_toreal(fz_arrayget(obj, 3));
	y1 = fz_toreal(fz_arrayget(obj, 4));
	r1 = fz_toreal(fz_arrayget(obj, 5));

	pdf_logshade("coords %g %g %g  %g %g %g\n", x0, y0, r0, x1, y1, r1);

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

	if (r0 < r1) 
		rs = r0 / (r0 - r1);
	else
		rs = -BIGNUM;

	ex0 = x0 + (x1 - x0) * rs;
	ey0 = y0 + (y1 - y0) * rs;
	er0 = r0 + (r1 - r0) * rs;

	if (r0 > r1) 
		rs = r1 / (r1 - r0);
	else
		rs = -BIGNUM;

	ex1 = x1 + (x0 - x1) * rs;
	ey1 = y1 + (y0 - y1) * rs;
	er1 = r1 + (r0 - r1) * rs;

	for (i=0; i<2; ++i)
	{
		int pos = 0;
		if (e0)
			pos = buildannulusmesh(shade->mesh, pos, ex0, ey0, er0, x0, y0, r0, 0, 0, 1-i);
		pos = buildannulusmesh(shade->mesh, pos, x0, y0, r0, x1, y1, r1, 0, 1., 1-i);
		if (e1)
			pos = buildannulusmesh(shade->mesh, pos, x1, y1, r1, ex1, ey1, er1, 1., 1., 1-i);

		if (i == 0)
		{
			shade->meshlen = pos;
			shade->mesh = fz_malloc(sizeof(float) * 9 * shade->meshlen);
			if (!shade->mesh)
				return fz_outofmem;
		}
	}

	pdf_logshade("}\n");

	return nil;
}

