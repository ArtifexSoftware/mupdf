#include <fitz.h>
#include <mupdf.h>

#define MAX_RAD_SEGS 36

int
buildannulusmesh(float* mesh, int pos,
					float x0, float y0, float r0, float x1, float y1, float r1, 
					float c0, float c1, int nomesh)
{
	int n = pos * 3;
	float dist = hypot(x1 - x0, y1 - y0);
	float theta;
	if (dist != 0)
		theta = asin((r1 - r0) / dist) + M_PI/2.0 + atan2(y1 - y0, x1 - x0);
	else
		theta = 0;
	if (!(theta >= 0 && theta <= M_PI)) {
		theta = 0;
	}

	float step = M_PI * 2. / (float)MAX_RAD_SEGS;
	fz_point pt1, pt2, pt3, pt4;

	for (int i=0; i < MAX_RAD_SEGS; theta -= step, ++i) {
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

#endif


fz_error *
fz_buildannulusmesh(float* mesh,
					int x0, int y0, int r0, int x1, int y1, int r1, 
					float c0, float c1, int nsegs)
{
	fz_error *error;
	fz_point pt1, pt2, pt3, pt4;
	float step;
	float theta;

	theta = 0.;
	step = 3.1415921 * 2. / (float)nsegs;
	
	for (int n=0; theta < step*nsegs; theta += step) {
		pt1.x = cos (theta) * r1 + x1;
		pt1.y = sin (theta) * r1 + y1;
		pt2.x = cos (theta) * r0 + x0;
		pt2.y = sin (theta) * r0 + y0;
		pt3.x = cos (theta+step) * r1 + x1;
		pt3.y = sin (theta+step) * r1 + y1;
		pt4.x = cos (theta+step) * r0 + x0;
		pt4.y = sin (theta+step) * r0 + y0;

		pdf_setmeshvalue(mesh, n, pt1.x, pt1.y, c1);
		++n;
		pdf_setmeshvalue(mesh, n, pt2.x, pt2.y, c0);
		++n;
		pdf_setmeshvalue(mesh, n, pt4.x, pt4.y, c0);
		++n;

		pdf_setmeshvalue(mesh, n, pt1.x, pt1.y, c1);
		++n;
		pdf_setmeshvalue(mesh, n, pt3.x, pt3.y, c1);
		++n;
		pdf_setmeshvalue(mesh, n, pt4.x, pt4.y, c0);
		++n;
	}

	return error;
}

fz_error *
pdf_loadtype3shade(fz_shade *shade, pdf_xref *xref, fz_obj *shading,
					fz_obj *ref, fz_matrix mat)
{
	fz_error *error;
	float x0, y0, r0, x1, y1, r1;
	float t0, t1;
	int e0, e1;
	int e0meshlen, e1meshlen;
	fz_obj *obj;
	pdf_function *func;
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
	pdf_logshade("extend %d %d\n", e0, e1);

	if (obj) {
		e0 = fz_tobool(fz_arrayget(obj, 0));
		e1 = fz_tobool(fz_arrayget(obj, 1));
	} else {
		e0 = 0;
		e1 = 0;
	}

	pdf_logshade("domain %g %g\n", t0, t1);

	pdf_loadshadefunction(shade, xref, shading, t0, t1);

	shade->meshlen = 36 * 10 * 2;
	shade->mesh = (float*) malloc(sizeof(float) * 9 * shade->meshlen);

	float tn, tn1;
	float tstep = (t1 - t0) / 10.;
	tn = t0;
	tn1 = t0 + tstep;

	for (int i = 0; i < 10; ++i) {
		float tx0, ty0, tr0;
		float tx1, ty1, tr1;
		float c0, c1;

		tx0 = x0 + (x1 - x0) * i / 10.;
		ty0 = y0 + (y1 - y0) * i / 10.;
		tr0 = r0 + (r1 - r0) * i / 10.;
		tx1 = x0 + (x1 - x0) * (i + 1) / 10.;
		ty1 = y0 + (y1 - y0) * (i + 1) / 10.;
		tr1 = r0 + (r1 - r0) * (i + 1) / 10.;
		c0 = i / 10.0;
		c1 = (i + 1) / 10.0;

		fz_buildannulusmesh(&(shade->mesh[i*36*2*9]), tx0, ty0, tr0, tx1, ty1, tr1, c0, c1, 36);
	}

	pdf_logshade("}\n");

	return nil;

cleanup:
	return error;
}
