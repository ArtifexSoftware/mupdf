#include <fitz.h>

fz_error *
fz_rendershade1(fz_shade *shade, fz_matrix ctm, fz_colorspace *dsts, fz_pixmap *dstp, int over)
{
	fz_error *error;
	int x, y;
	int dx, dy, dw, dh;
	float x0, y0, x1, y1;
	float xp;
	float yp;
	//	pdf_function *func;
	
	dx = dstp->x;
	dy = dstp->y;
	dw = dstp->w;
	dh = dstp->h;
	
	x0 = 0;
	y0 = 0;
	x1 = 0;
	y1 = 0;
	
	for (int y = 0; y < dh; ++y) {
		for (int x = 0; x < dw; ++x) {
			float outcol[16], outn;
			float destcol[16];
			xp = ((x1 - x0) * (x - x0) + (y1 - y0) * (y - y0))
				/ ((x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0));
			
			error = pdf_evalfunction(shade->function, &xp, 1, outcol, outn);
			shade->cs->convcolor(shade->cs, outcol, dsts, destcol);
			dstp->samples[(x+y*dw)*4+0] = 255;
			dstp->samples[(x+y*dw)*4+1] = destcol[0] * 255;
			dstp->samples[(x+y*dw)*4+2] = destcol[1] * 255;
			dstp->samples[(x+y*dw)*4+3] = destcol[2] * 255;
		}
	}
	
	return error;
}

fz_error *
fz_rendershade2(fz_shade *shade, fz_matrix ctm, fz_colorspace *dsts, fz_pixmap *dstp, int over)
{
	fz_error *error;
	int x, y;
	int dx, dy, dw, dh;
	float x0, y0, x1, y1;
	float t0, t1;
	int e0, e1;
	float xp;
	float yp;
	//	pdf_function *func;
	int destcol[512][4];
	
	ctm = fz_concat(shade->matrix, ctm);
	
	dx = dstp->x;
	dy = dstp->y;
	dw = dstp->w;
	dh = dstp->h;
	
	x0 = fz_toreal(fz_arrayget(shade->coords, 0));
	y0 = fz_toreal(fz_arrayget(shade->coords, 1));
	x1 = fz_toreal(fz_arrayget(shade->coords, 2));
	y1 = fz_toreal(fz_arrayget(shade->coords, 3));
	
	if (shade->domain) {
		t0 = fz_toreal(fz_arrayget(shade->domain, 0));
		t1 = fz_toreal(fz_arrayget(shade->domain, 1));
	} else {
		t0 = 0.;
		t1 = 1.;
	}
	
	if (shade->extend) {
		e0 = fz_toint(fz_arrayget(shade->extend, 0));
		e1 = fz_toint(fz_arrayget(shade->extend, 1));
	} else {
		e0 = 0;
		e1 = 0;
	}
	
	/* build color table */
	for (int i=0; i<512; ++i) {
		float destc[4];
		float outcol[4];
		float t = (i / 511.) / (t1 - t0) - t0;
		error = pdf_evalfunction(shade->function, &t, 1, outcol, 3);
		shade->cs->convcolor(shade->cs, outcol, dsts, destc);
		destcol[i][0] = destc[0]*255.;
		destcol[i][1] = destc[1]*255.;
		destcol[i][2] = destc[2]*255.;
	}
	
	for (int y = 0; y < dh; ++y) {
		for (int x = 0; x < dw; ++x) {
			int cidx;
			float t;
			float ix, iy;
			
			xp = x + dx;
			yp = y + dy;
			
			ix = (xp * ctm.d - yp * ctm.c + ctm.c * ctm.f - ctm.e*ctm.d) 
				/ (ctm.a * ctm.d - ctm.b * ctm.c); /* inverse */
			iy = (xp * ctm.b - yp * ctm.a + ctm.a * ctm.f - ctm.b*ctm.e) 
				/ (ctm.b * ctm.c - ctm.a * ctm.d); /* inverse */
			
			t = ((x1 - x0) * (ix - x0) + (y1 - y0) * (iy - y0))
				/ ((x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0));
			
			cidx = ((t + t0) * (t1 - t0)) * 511;
			
			dstp->samples[(x+y*dw)*4+0] = 255;
			dstp->samples[(x+y*dw)*4+1] = destcol[cidx][0];
			dstp->samples[(x+y*dw)*4+2] = destcol[cidx][1];
			dstp->samples[(x+y*dw)*4+3] = destcol[cidx][2];
		}
	}
	
	return error;
}

#define putpixel(x, y, c) \
	if (x >= 0 && x < dstp->w && y >= 0 && y < dstp->h) { \
	dstp->samples[((x)+(y)*(dstp->w))*4+0] = 255; \
	dstp->samples[((x)+(y)*(dstp->w))*4+1] = c[0]; \
	dstp->samples[((x)+(y)*(dstp->w))*4+2] = c[1]; \
	dstp->samples[((x)+(y)*(dstp->w))*4+3] = c[2]; \
	} \
	

typedef struct fz_vertex 
{
	float x, y;
	float l;
} fz_vertex;

typedef struct fz_triangle
{
	fz_vertex vertex[3];
} fz_triangle;

void fz_swapvertex(fz_vertex *a, fz_vertex *b)
{
	fz_vertex temp;
	temp = *a;
	*a = *b;
	*b = temp;
}

int fz_pointinrect(fz_point point, fz_rect rect)
{
	if (point.x < rect.min.x || point.x > rect.max.x) return 0;
	if (point.y < rect.min.y || point.y > rect.max.y) return 0;

	return 1;
}

void fz_drawgouraudtriangle(fz_triangle triangle, fz_pixmap *dstp, int destcol[512][4], 
							int bx0, int by0, int bx1, int by1)
{
	fz_vertex a, b, c;
	
	a = triangle.vertex[0];
	b = triangle.vertex[1];
	c = triangle.vertex[2];

	/* need more accurate clipping method */
	{
		fz_rect bb1;
		fz_rect bb2;
		
		bb1.min.x = min(min(a.x, b.x), c.x);
		bb1.min.y = min(min(a.y, b.y), c.y);
		bb1.max.x = max(max(a.x, b.x), c.x);
		bb1.max.y = max(max(a.y, b.y), c.y);

		bb2.min.x = bx0;
		bb2.min.y = by0;
		bb2.max.x = bx1;
		bb2.max.y = by1;

		if (fz_isemptyrect(fz_intersectrects(bb1, bb2))) 
			return;
	}

	if(a.y > b.y) fz_swapvertex(&a, &b);
	if(a.y > c.y) fz_swapvertex(&a, &c);
	if(b.y > c.y) fz_swapvertex(&b, &c);
	
	float diff_y = (b.y - a.y);
	float slopeab_x = (b.x - a.x) / diff_y;
	float slopeab_l = (b.l - a.l) / diff_y;
	float xab = a.x;
	float lab = a.l;
	diff_y = (c.y - a.y);
	float slopeac_x = (c.x - a.x) / diff_y;
	float slopeac_l = (c.l - a.l) / diff_y;
	float xac = a.x;
	float lac = a.l;
	int maxy = (int)(b.y);
	
	int incx;
	int y;
	for(y = (int)(a.y); y < maxy; y++)
	{
		int maxx = (int)(xac);
		if(xab < xac) incx = 1;
		else          incx = -1;
		float diff_x = (xac - xab) * incx;
		float slope_l = (lac - lab) / diff_x;
		float l = lab; 

		for(int x = (int)(xab); x != maxx+incx; x += incx)
		{
			if (l >= 0 && l <= 511)
				putpixel(x, y, destcol[(int)(l)]);
			l += slope_l;
		}
		
		xab += slopeab_x;
		lab += slopeab_l;
		xac += slopeac_x; 
		lac += slopeac_l; 
	}
	
	diff_y = (c.y - b.y);
	float slopebc_x = (c.x - b.x) / diff_y;
	float slopebc_l = (c.l - b.l) / diff_y;
	float xbc = b.x;
	float lbc = b.l;
	maxy = (int)(c.y);
	for(; y < maxy; y++)
	{
		int maxx = (int)(xac);
		if(xbc < xac) incx = 1;
		else          incx = -1;
		float diff_x = (xac - xbc) * incx;
		float slope_l = (lac - lbc) / diff_x;
		float l = lbc; 
		for(int x = (int)(xbc); x !=  maxx+incx; x += incx)
		{
			if (l >= 0 && l <= 511)
				putpixel(x, y, destcol[(int)(l)]);
			l += slope_l;
		}
		
		xac += slopeac_x; 
		lac += slopeac_l; 
		xbc += slopebc_x;   
		lbc += slopebc_l;
	}
}

fz_error *
fz_renderannulus(int x0, int y0, int r0, int x1, int y1, int r1, int t0, int t1,
					fz_matrix ctm, fz_pixmap *dstp, int destcol[512][4])
{
	fz_point pt1, pt2, pt3, pt4;
	fz_triangle triangle;
	float step;
	float theta;

	ctm = fz_concat(ctm, fz_translate(-dstp->x, -dstp->y));

	/*
	theta = atan((y1 - y0) / (x1 - x0));
	if ((x1 - x0) < 0) theta += M_PI;
	theta -= (M_PI / 2.);
	*/
	theta = 0;
	step = 3.1415921 * 2 / 36.;
	for (; theta < step*36; theta += step) {
		pt1.x = cos (theta) * r1 + x1;
		pt1.y = sin (theta) * r1 + y1;
		pt2.x = cos (theta) * r0 + x0;
		pt2.y = sin (theta) * r0 + y0;
		pt3.x = cos (theta+step) * r1 + x1;
		pt3.y = sin (theta+step) * r1 + y1;
		pt4.x = cos (theta+step) * r0 + x0;
		pt4.y = sin (theta+step) * r0 + y0;

		pt1 = fz_transformpoint(ctm, pt1);
		pt2 = fz_transformpoint(ctm, pt2);
		pt3 = fz_transformpoint(ctm, pt3);
		pt4 = fz_transformpoint(ctm, pt4);

		triangle.vertex[0].x = pt1.x;
		triangle.vertex[0].y = pt1.y;
		triangle.vertex[0].l = t1;
		triangle.vertex[1].x = pt2.x;
		triangle.vertex[1].y = pt2.y;
		triangle.vertex[1].l = t0;
		triangle.vertex[2].x = pt4.x;
		triangle.vertex[2].y = pt4.y;
		triangle.vertex[2].l = t0;

		fz_drawgouraudtriangle(triangle, dstp, destcol, 0, 0, dstp->w, dstp->h);

		triangle.vertex[0].x = pt1.x;
		triangle.vertex[0].y = pt1.y;
		triangle.vertex[0].l = t1;
		triangle.vertex[1].x = pt3.x;
		triangle.vertex[1].y = pt3.y;
		triangle.vertex[1].l = t1;
		triangle.vertex[2].x = pt4.x;
		triangle.vertex[2].y = pt4.y;
		triangle.vertex[2].l = t0;

		fz_drawgouraudtriangle(triangle, dstp, destcol, 0, 0, dstp->w, dstp->h);
	}
}

fz_error *
fz_rendershade3(fz_shade *shade, fz_matrix ctm, fz_colorspace *dsts, fz_pixmap *dstp, int over)
{
	fz_error *error;
	int x, y;
	int dx, dy, dw, dh;
	float x0, y0, r0, x1, y1, r1;
	float t0, t1;
	float xp;
	float yp;
	int e0, e1;
	float t;
	int destcol[512][4];
	int cidx0, cidx1;
	
	ctm = fz_concat(shade->matrix, ctm);
	
	dx = dstp->x;	dy = dstp->y;
	dw = dstp->w;	dh = dstp->h;
	
	x0 = fz_toreal(fz_arrayget(shade->coords, 0));
	y0 = fz_toreal(fz_arrayget(shade->coords, 1));
	r0 = fz_toreal(fz_arrayget(shade->coords, 2));
	x1 = fz_toreal(fz_arrayget(shade->coords, 3));
	y1 = fz_toreal(fz_arrayget(shade->coords, 4));
	r1 = fz_toreal(fz_arrayget(shade->coords, 5));
	
	if (shade->domain) {
		t0 = fz_toreal(fz_arrayget(shade->domain, 0));
		t1 = fz_toreal(fz_arrayget(shade->domain, 1));
	} else {
		t0 = 0.;
		t1 = 1.;
	}
	
	if (shade->extend) {
		e0 = fz_toint(fz_arrayget(shade->extend, 0));
		e1 = fz_toint(fz_arrayget(shade->extend, 1));
	} else {
		e0 = 0;
		e1 = 0;
	}
	
	/* build color table */
	for (int i=0; i<512; ++i) {
		float destc[4];
		float outcol[4];
		float t = (i / 511.) / (t1 - t0) - t0;
		error = pdf_evalfunction(shade->function, &t, 1, outcol, 3);
		shade->cs->convcolor(shade->cs, outcol, dsts, destc);
		destcol[i][0] = destc[0]*255.;
		destcol[i][1] = destc[1]*255.;
		destcol[i][2] = destc[2]*255.;
	}

	int steps = 10;
	float step = 0.1;
	steps = 10;
	step = 0.1;
	for (int i=0; i<steps ; ++i) {
		float nt0, nt1;
		float nx0, ny0, nr0;
		float nx1, ny1, nr1;

		nt0 = t0 + ((t1 - t0) * step * (i));
		nt1 = t0 + ((t1 - t0) * step * (i+1));

		nx0 = x0 + ((x1 - x0) * step * (i));
		nx1 = x0 + ((x1 - x0) * step * (i+1));

		ny0 = y0 + ((y1 - y0) * step * (i));
		ny1 = y0 + ((y1 - y0) * step * (i+1));

		nr0 = r0 + ((r1 - r0) * step * (i));
		nr1 = r0 + ((r1 - r0) * step * (i+1));

		cidx0 = ((nt0 + t0) * (t1 - t0)) * 511;
		cidx1 = ((nt1 + t0) * (t1 - t0)) * 511;

		if (cidx0 < 0 || cidx0 > 511) {
			int a;
			a++;
		}
		if (cidx1 < 0 || cidx1 > 511) {
			int a;
			a++;
		}
		
		fz_renderannulus(nx0, ny0, nr0, nx1, ny1, nr1, cidx0, cidx1, ctm, dstp, destcol);
	}
}

fz_error *
fz_rendershade(fz_shade *shade, fz_matrix ctm, fz_colorspace *dsts, fz_pixmap *dstp, int over)
{
	int x, y, w, h;
	
	switch (shade->type) {
	case 1:
		fz_rendershade1(shade, ctm, dsts, dstp, over);
		break;
	case 2:
		fz_rendershade2(shade, ctm, dsts, dstp, over);
		break;
	case 3:
		fz_rendershade3(shade, ctm, dsts, dstp, over);
		break;
	default:
	}
	
	//dstp->samples
	//	if (!over)
	//		fz_clearpixmap(dstp);
	return nil;
}
