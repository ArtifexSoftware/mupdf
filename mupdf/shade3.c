#include <fitz.h>
#include <mupdf.h>

#ifdef NONE__
double 
fz_shadet3rectradius(fz_rect rect, double x0, double y0)
{
    double d, dd;
	
    dd = hypot(rect.min.x - x0, rect.min.y - y0);
    d = hypot(rect.min.x - x0, rect.max.y - y0);
    dd = max(dd, d);
    d = hypot(rect.max.x - x0, rect.max.y - y0);
    dd = max(dd, d);
    d = hypot(rect.max.x - x0, rect.min.y - y0);
    dd = max(dd, d);

    return dd;
}

void
fz_outercircle(const fz_rect rect, 
			   double x0, double y0, double r0, 
			   double x1, double y1, double r1, 
			   double *x2, double *y2, double *r2)
{
    double dx = x1 - x0, dy = y1 - y0;
    double sp, sq, s;

	
    /* Compute a cone circle, which contacts the rect externally. */
    /* Don't bother with all 4 sides of the rect, 
	just do with the X or Y span only,
	so it's not an exact contact, sorry. */
    if (fabs(dx) > fabs(dy)) {
	/* Solving :
	x0 + (x1 - x0) * s - r0 - (r1 - r0) * s == bbox_x
	(x1 - x0) * s - (r1 - r0) * s == bbox_x - x0 + r0
	s = (bbox_x - x0 + r0) / (x1 - x0 - r1 + r0)
		*/
		assert(x1 - x0 + r1 - r0); /* We checked for obtuse cone. */
		sp = (rect.min.x - x0 + r0) / (x1 - x0 - r1 + r0);
		sq = (rect.max.x - x0 + r0) / (x1 - x0 - r1 + r0);
    } else {
		/* Same by Y. */
		sp = (rect.min.y - y0 + r0) / (y1 - y0 - r1 + r0);
		sq = (rect.max.y - y0 + r0) / (y1 - y0 - r1 + r0);
    }
    if (sp >= 1 && sq >= 1)
		s = min(sp, sq);
    else if(sp >= 1)
		s = sp;
    else if (sq >= 1)
		s = sq;
    else {
		/* The circle 1 is outside the rect, use it. */
        s = 1;
    }
    if (r0 + (r1 - r0) * s < 0) {
		/* Passed the cone apex, use the apex. */
		s = r0 / (r0 - r1);
		*r2 = 0;
    } else
		*r2 = r0 + (r1 - r0) * s;
    *x2 = x0 + (x1 - x0) * s;
    *y2 = y0 + (y1 - y0) * s;
}

int 
fz_iscovered(double ax, double ay, 
			 const fz_point *p0, const fz_point *p1, const fz_point *p)
{
    double dx0 = p0->x - ax, dy0 = p0->y - ay;
    double dx1 = p1->x - ax, dy1 = p1->y - ay;
    double dx = p->x - ax, dy = p->y - ay;
    double vp0 = dx0 * dy - dy0 * dx;
    double vp1 = dx * dy1 - dy * dx1;
	
    return vp0 >= 0 && vp1 >= 0;
}

fz_error *
fz_shadet3obtusecone(fz_rect rect, 
						 float x0, float y0, float r0,
						 float x1, float y1, float r1,
						 double t1, double r,
						 fz_matrix ctm, fz_pixmap *dstp, int destcol[512][4])
{
	fz_error *error;
    double dx = x1 - x0, dy = y1 - y0, dr = fabs(r1 - r0);
    double d = hypot(dx, dy);
    double ax, ay, as; /* Cone apex. */
    fz_point p0, p1; /* Tangent limits. */
    fz_point cp[4]; /* Corners.. */
    fz_point rp[4]; /* Covered corners.. */
    fz_point pb;
    int rp_count = 0, cp_start, i;
    int covered[4];

	
	
    as = r0 / (r0 - r1);
    ax = x0 + (x1 - x0) * as;
    ay = y0 + (y1 - y0) * as;
	
    if (fabs(d - dr) < 1e-7 * (d + dr)) {
		/* Nearly degenerate, replace with half-plane. */
		p0.x = ax - dy * r / d;
		p0.y = ay + dx * r / d;
		p1.x = ax + dy * r / d;
		p1.y = ay - dx * r / d;
    } else {
		/* Tangent limits by proportional triangles. */
		double da = hypot(ax - x0, ay - y0);
		double h = r * r0 / da, g;
		
		assert(h <= r);
		g = sqrt(r * r - h * h);
		p0.x = ax - dx * g / d - dy * h / d;
		p0.y = ay - dy * g / d + dx * h / d;
		p1.x = ax - dx * g / d + dy * h / d;
		p1.y = ay - dy * g / d - dx * h / d;
    }
    /* Now we have 2 limited tangents, and 4 corners of the rect. 
	Need to know what corners are covered. */
    cp[0].x = rect.min.x, cp[0].y = rect.min.y;
    cp[1].x = rect.max.x, cp[1].y = rect.min.y;
    cp[2].x = rect.max.x, cp[2].y = rect.max.y;
    cp[3].x = rect.min.x, cp[3].y = rect.max.y;
    covered[0] = fz_iscovered(ax, ay, &p0, &p1, &cp[0]);
    covered[1] = fz_iscovered(ax, ay, &p0, &p1, &cp[1]);
    covered[2] = fz_iscovered(ax, ay, &p0, &p1, &cp[2]);
    covered[3] = fz_iscovered(ax, ay, &p0, &p1, &cp[3]);

    if (!covered[0] && !covered[1] && !covered[2] && !covered[3]) {
		fz_point pt1, pt2, pt3;
		pt1.x = ax; pt1.y = ay;
		pt2 = p0;
		pt3 = p1;

		pt1 = fz_transformpoint(ctm, pt1);
		pt2 = fz_transformpoint(ctm, pt2);
		pt3 = fz_transformpoint(ctm, pt3);

		fz_triangle triangle;
		triangle.vertex[0].x = pt1.x;
		triangle.vertex[0].y = pt1.y;
		triangle.vertex[0].l = t1;
		triangle.vertex[1].x = pt2.x;
		triangle.vertex[1].y = pt2.y;
		triangle.vertex[1].l = t1;
		triangle.vertex[2].x = pt3.x;
		triangle.vertex[2].y = pt3.y;
		triangle.vertex[2].l = t1;

		error = fz_drawgouraudtriangle(triangle, dstp, destcol, 
					rect.min.x, rect.min.y, rect.max.x, rect.max.y);
		goto end;
    } 
    if (!covered[0] && covered[1])
		cp_start = 1;
    else if (!covered[1] && covered[2])
		cp_start = 2;
    else if (!covered[2] && covered[3])
		cp_start = 3;
    else if (!covered[3] && covered[0])
		cp_start = 0;
    else {
		/* Must not happen, handle somehow for safety. */
		cp_start = 0;
    }
    for (i = cp_start; i < cp_start + 4 && covered[i % 4]; i++) {
		rp[rp_count] = cp[i % 4];
		rp_count++;
    }
    /* Do paint. */
    pb = p0;
    for (i = 0; i < rp_count; i++) {
		fz_point pt1, pt2, pt3;
		pt1.x = ax; pt1.y = ay;
		pt2 = pb;
		pt3 = rp[i];

		pt1 = fz_transformpoint(ctm, pt1);
		pt2 = fz_transformpoint(ctm, pt2);
		pt3 = fz_transformpoint(ctm, pt3);

		fz_triangle triangle;
		triangle.vertex[0].x = pt1.x;
		triangle.vertex[0].y = pt1.y;
		triangle.vertex[0].l = t1;
		triangle.vertex[1].x = pt2.x;
		triangle.vertex[1].y = pt2.y;
		triangle.vertex[1].l = t1;
		triangle.vertex[2].x = pt3.x;
		triangle.vertex[2].y = pt3.y;
		triangle.vertex[2].l = t1;

		error = fz_drawgouraudtriangle(triangle, dstp, destcol, 
					rect.min.x, rect.min.y, rect.max.x, rect.max.y);
		if (error < 0)
			return error;
		pb = rp[i];
    }

	fz_point pt1, pt2, pt3;
	pt1.x = ax; pt1.y = ay;
	pt2 = pb;
	pt3 = p1;

	pt1 = fz_transformpoint(ctm, pt1);
	pt2 = fz_transformpoint(ctm, pt2);
	pt3 = fz_transformpoint(ctm, pt3);

	fz_triangle triangle;
	triangle.vertex[0].x = pt1.x;
	triangle.vertex[0].y = pt1.y;
	triangle.vertex[0].l = t1;
	triangle.vertex[1].x = pt2.x;
	triangle.vertex[1].y = pt2.y;
	triangle.vertex[1].l = t1;
	triangle.vertex[2].x = pt3.x;
	triangle.vertex[2].y = pt3.y;
	triangle.vertex[2].l = t1;

	error = fz_drawgouraudtriangle(triangle, dstp, destcol, 
				rect.min.x, rect.min.y, rect.max.x, rect.max.y);

end:
	return error;
}

fz_error *
fz_shadet3tensorconeapex(fz_rect rect, 
				   double x0, double y0, double r0, 
				   double x1, double y1, double r1, double t,
				   fz_matrix ctm, fz_pixmap *dstp, int destcol[512][4])
{
    double as = r0 / (r0 - r1);
    double ax = x0 + (x1 - x0) * as;
    double ay = y0 + (y1 - y0) * as;
	
    return fz_renderannulus(x1, y1, r1, ax, ay, 0, t, t, ctm, dstp, destcol);
}


fz_error *
fz_rendershadet3extentions(fz_rect rect, 
						 float x0, float y0, float r0,
						 float x1, float y1, float r1,
						 double t0, double t1, int Extend0, int Extend1,
						 fz_matrix ctm, fz_pixmap *dstp, int destcol[512][4])
{
    double dx = x1 - x0, dy = y1 - y0, dr = fabs(r1 - r0);
    double d = hypot(dx, dy), r;
    fz_error *error;
	
    if (dr >= d - 1e-7 * (d + dr)) {
		/* Nested circles, or degenerate. */
		if (r0 > r1) {
			if (Extend0) {
				r = fz_shadet3rectradius(rect, x0, y0);
				if (r > r0) {
					error = fz_renderannulus(x0, y0, r, x0, y0, r0, t0, t0, ctm, dstp, destcol);
					if (error)
						return error;
				}
			}
			if (Extend1 && r1 > 0)
				return fz_renderannulus(x1, y1, r1, x1, y1, 0, t1, t1, ctm, dstp, destcol);
		} else {
			if (Extend1) {
				r = fz_shadet3rectradius(rect, x1, y1);
				if (r > r1) {
					error = fz_renderannulus(x1, y1, r, x1, y1, r1, t1, t1, ctm, dstp, destcol);
					if (error < 0)
						return error;
				}
			}
			if (Extend0 && r0 > 0)
				return fz_renderannulus(x0, y0, r0, x0, y0, 0, t0, t0, ctm, dstp, destcol);
		}
    } else if (dr > d / 3) {
		/* Obtuse cone. */
		if (r0 > r1) {
			if (Extend0) {
				r = fz_shadet3rectradius(rect, x0, y0);
				error = fz_shadet3obtusecone(rect, x0, y0, r0, x1, y1, r1, t0, r, 
												ctm, dstp, destcol);
				if (error < 0)
					return error;
			}
			if (Extend1 && r1 != 0)
				return fz_shadet3tensorconeapex(rect, x0, y0, r0, x1, y1, r1, t1,
												ctm, dstp, destcol);
			return 0;
		} else {
			if (Extend1) {
				r = fz_shadet3rectradius(rect, x1, y1);
				error = fz_shadet3obtusecone(rect, x1, y1, r1, x0, y0, r0, t1, r, 
												ctm, dstp, destcol);
				if (error < 0)
					return error;
			}
			if (Extend0 && r0 != 0)
				return fz_shadet3tensorconeapex(rect, x1, y1, r1, x0, y0, r0, t0,
												ctm, dstp, destcol);
		}
    } else {
		/* Acute cone or cylinder. */
		double x2, y2, r2, x3, y3, r3;
		
		if (Extend0) {
			fz_outercircle(rect, x1, y1, r1, x0, y0, r0, &x3, &y3, &r3);
			if (x3 != x1 || y3 != y1) {
				error = fz_renderannulus(x0, y0, r0, x3, y3, r3, t0, t0,
										ctm, dstp, destcol);
				if (error < 0)
					return error;
			}
		}
		if (Extend1) {
			fz_outercircle(rect, x0, y0, r0, x1, y1, r1, &x2, &y2, &r2);
			if (x2 != x0 || y2 != y0) {
				error = fz_renderannulus(x1, y1, r1, x2, y2, r2, t1, t1, 
										ctm, dstp, destcol);
				if (error < 0)
					return error;
			}
		}
    }
    return 0;
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
	fz_obj *obj;
	pdf_function *func;

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
