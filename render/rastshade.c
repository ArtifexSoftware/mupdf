#include <fitz.h>

typedef struct fz_vertex 
{
       float x, y;
       float l;
} fz_vertex;

typedef struct fz_triangle
{
       fz_vertex vertex[3];
} fz_triangle;

#define putpixel(x, y, c) \
	if (x >= 0 && x < dstp->w && y >= 0 && y < dstp->h) { \
	dstp->samples[((x)+(y)*(dstp->w))*4+0] = 255; \
	dstp->samples[((x)+(y)*(dstp->w))*4+1] = c[0]; \
	dstp->samples[((x)+(y)*(dstp->w))*4+2] = c[1]; \
	dstp->samples[((x)+(y)*(dstp->w))*4+3] = c[2]; \
	} \

void fz_swapvertex(fz_vertex *a, fz_vertex *b)
{
	fz_vertex temp;
	temp = *a;
	*a = *b;
	*b = temp;
}

fz_error *
fz_drawgouraudtriangle(fz_triangle triangle, fz_pixmap *dstp, int destcol[512][4], 
							int bx0, int by0, int bx1, int by1)
{
	fz_error *error;
	fz_vertex a, b, c;
	
	a = triangle.vertex[0];
	b = triangle.vertex[1];
	c = triangle.vertex[2];

	/* need more accurate clipping method */
	{
		fz_rect bb1;
		fz_rect bb2;
		
		bb1.min.x = MIN(MIN(a.x, b.x), c.x);
		bb1.min.y = MIN(MIN(a.y, b.y), c.y);
		bb1.max.x = MAX(MAX(a.x, b.x), c.x);
		bb1.max.y = MAX(MAX(a.y, b.y), c.y);

		bb2.min.x = bx0;
		bb2.min.y = by0;
		bb2.max.x = bx1;
		bb2.max.y = by1;

		if (fz_isemptyrect(fz_intersectrects(bb1, bb2))) 
			return nil;
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
			if (l < 0) l = 0;
			if (l > 511) l = 511;
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
			if (l < 0) l = 0;
			if (l > 511) l = 511;
			putpixel(x, y, destcol[(int)(l)]);
			l += slope_l;
		}
		
		xac += slopeac_x; 
		lac += slopeac_l; 
		xbc += slopebc_x;   
		lbc += slopebc_l;
	}

	return nil;
}

fz_error *
fz_rendershade(fz_shade *shade, fz_matrix ctm, fz_colorspace *dsts, fz_pixmap *dstp)
{
	int x, y;
	fz_triangle triangle;
	fz_point point;
	int destcol[512][4];

	for (int i=0; i<512; ++i) {
		float col[4];
		shade->colorspace->convcolor(shade->colorspace, 
					shade->function[i], dsts, col);
		for (int j=0; j<3; ++j) {
			destcol[i][j] = col[j] * 255;
		}
	}

	if (!shade) return nil;

	ctm = fz_concat(shade->matrix, ctm);
	ctm = fz_concat(ctm, fz_translate(-dstp->x, -dstp->y));

	int ncomp = shade->meshcap;
	for (int i=0; i<shade->meshlen; ++i) {
		for (int j=0; j<3; ++j) {
			point.x = shade->mesh[(i*3+j)*3+0];
			point.y = shade->mesh[(i*3+j)*3+1];
			point = fz_transformpoint(ctm, point);
			triangle.vertex[j].x = point.x;
			triangle.vertex[j].y = point.y;
			triangle.vertex[j].l = shade->mesh[(i*3+j)*3+2];
		}
		fz_drawgouraudtriangle(triangle, dstp, destcol, 0, 0, dstp->w, dstp->h);
	}	

	return nil;
}
