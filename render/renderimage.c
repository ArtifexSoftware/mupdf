#include <fitz.h>

static int getcomp(fz_pixmap *pix, float u, float v, int k)
{
	float fu = floor(u);
	float fv = floor(v);
	float su = u - fu;
	float sv = v - fv;

	int x0 = fu;
	int x1 = x0 + 1;
	int y0 = fv;
	int y1 = y0 + 1;

	x0 = CLAMP(x0, 0, pix->w - 1);
	x1 = CLAMP(x1, 0, pix->w - 1);
	y0 = CLAMP(y0, 0, pix->h - 1);
	y1 = CLAMP(y1, 0, pix->h - 1);

	float a = pix->samples[ (y0 * pix->w + x0) * pix->n + k ];
	float b = pix->samples[ (y0 * pix->w + x1) * pix->n + k ];
	float c = pix->samples[ (y1 * pix->w + x0) * pix->n + k ];
	float d = pix->samples[ (y1 * pix->w + x1) * pix->n + k ];

	float ab = a * (1.0 - su) + b * su;
	float cd = c * (1.0 - su) + d * su;
	float abcd = ab * (1.0 - sv) + cd * sv;

	return (int)abcd;
}

static inline void
drawscan(fz_matrix *invmat, fz_pixmap *dst, fz_pixmap *src, int y, int x0, int x1)
{
	int x, k;

	float u = invmat->a * x0 + invmat->c * y + invmat->e;
	float v = invmat->b * x0 + invmat->d * y + invmat->f;

	for (x = x0; x < x1; x++)
	{
		for (k = 0; k < src->n; k++)
			dst->samples[ (y * dst->w + x) * dst->n + k ] = getcomp(src, u, v, k);
		u += invmat->a;
		v += invmat->c;
	}
}

static inline void
overscanrgb(fz_matrix *invmat, fz_pixmap *dst, fz_pixmap *src, int y, int x0, int x1)
{
	int x;

	float u = invmat->a * x0 + invmat->c * y + invmat->e;
	float v = invmat->b * x0 + invmat->d * y + invmat->f;

	for (x = x0; x < x1; x++)
	{
		int sa = getcomp(src, u, v, 0);
		int sr = getcomp(src, u, v, 1);
		int sg = getcomp(src, u, v, 2);
		int sb = getcomp(src, u, v, 3);

		int da = dst->samples[ (y * dst->w + x) * dst->n + 0 ];
		int dr = dst->samples[ (y * dst->w + x) * dst->n + 1 ];
		int dg = dst->samples[ (y * dst->w + x) * dst->n + 2 ];
		int db = dst->samples[ (y * dst->w + x) * dst->n + 3 ];

		int ssa = 255 - sa;

		da = sa + fz_mul255(da, ssa);
		dr = sr + fz_mul255(dr, ssa);
		dg = sg + fz_mul255(dg, ssa);
		db = sb + fz_mul255(db, ssa);

		dst->samples[ (y * dst->w + x) * dst->n + 0 ] = sa;
		dst->samples[ (y * dst->w + x) * dst->n + 1 ] = sr;
		dst->samples[ (y * dst->w + x) * dst->n + 2 ] = sg;
		dst->samples[ (y * dst->w + x) * dst->n + 3 ] = sb;

		u += invmat->a;
		v += invmat->c;
	}
}

static fz_error *
drawtile(fz_renderer *gc, fz_pixmap *out, fz_pixmap *tile, fz_matrix ctm, int over)
{
	static const fz_point rect[4] = { {0, 0}, {0, 1}, {1, 1}, {1, 0} };
	fz_error *error;
	fz_gel *gel = gc->gel;
	fz_ael *ael = gc->ael;
	fz_matrix imgmat;
	fz_matrix invmat;
	fz_point v[4];
	int i, e, y, x0, x1;

	imgmat.a = 1.0 / tile->w;
	imgmat.b = 0.0;
	imgmat.c = 0.0;
	imgmat.d = -1.0 / tile->h;
	imgmat.e = 0.0;
	imgmat.f = 1.0;
	invmat = fz_invertmatrix(fz_concat(imgmat, ctm));

	for (i = 0; i < 4; i++)
		v[i] = fz_transformpoint(ctm, rect[i]);
	fz_resetgel(gel, 1, 1);
	fz_insertgel(gel, v[0].x, v[0].y, v[1].x, v[1].y);
	fz_insertgel(gel, v[1].x, v[1].y, v[2].x, v[2].y);
	fz_insertgel(gel, v[2].x, v[2].y, v[3].x, v[3].y);
	fz_insertgel(gel, v[3].x, v[3].y, v[0].x, v[0].y);
	fz_sortgel(gel);

	e = 0;
	y = gel->edges[0].y;

	while (ael->len > 0 || e < gel->len)
	{
		error = fz_insertael(ael, gel, y, &e);
		if (error)
			return error;

		x0 = ael->edges[0]->x;
		x1 = ael->edges[ael->len - 1]->x;

		if (y >= out->y && y < out->y + out->h)
		{
			x0 = CLAMP(x0, out->x, out->x + out->w - 1);
			x1 = CLAMP(x1, out->x, out->x + out->w - 1);
			if (over && tile->n == 4)
				overscanrgb(&invmat, out, tile, y, x0, x1);
			else
				drawscan(&invmat, out, tile, y, x0, x1);
		}

		fz_advanceael(ael);

		if (ael->len > 0)
			y ++;
		else if (e < gel->len)
			y = gel->edges[e].y;
	}

	return nil;
}

fz_error *
fz_renderimage(fz_renderer *gc, fz_imagenode *node, fz_matrix ctm)
{
	fz_error *error;
	fz_pixmap *tile1;
	fz_pixmap *tile2;
	fz_pixmap *tile3;
	fz_image *image = node->image;
	fz_colorspace *cs = image->cs;
	int w = image->w;
	int h = image->h;
	int n = image->n;
	int a = image->a;

	float sx = sqrt(ctm.a * ctm.a + ctm.b * ctm.b);
	float sy = sqrt(ctm.c * ctm.c + ctm.d * ctm.d);

	int dx = 1;
	while ((w + dx - 1) / dx > sx) dx++;
	if (dx > 1) dx --;

	int dy = 1;
	while ((h + dy - 1) / dy > sy) dy++;
	if (dy > 1) dy --;

	if (dx > 1) dx --;
	if (dy > 1) dy --;

printf("renderimage s=%gx%g/%dx%d d=%d,%d\n", sx, sy, w, h, dx, dy);

	error = fz_newpixmap(&tile1, 0, 0, w, h, n + 1);

printf("  load tile\n");
	error = image->loadtile(image, tile1);
//fz_debugpixmap(tile1);getchar();

	if (dx != 1 || dy != 1)
	{
printf("  scale tile 1/%d x 1/%d\n", dx, dy);
		error = fz_scalepixmap(&tile2, tile1, dx, dy);
//fz_debugpixmap(tile2);getchar();
		fz_freepixmap(tile1);
	}
	else
		tile2 = tile1;

	/* render image mask */
	if (n == 0 && a == 1)
	{
printf("draw image mask\n");
		error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, 1);
		fz_clearpixmap(gc->tmp);
		error = drawtile(gc, gc->tmp, tile2, ctm, 0);
	}

	/* render rgb over */
	else if (n == 3 && a == 0 && gc->acc)
	{
printf("draw image rgb over\n");
		error = drawtile(gc, gc->acc, tile2, ctm, 1);
	}

	/* render generic image */
	else
	{
printf("draw generic image\n");
		error = fz_convertpixmap(&tile3, tile2, cs, gc->model);
		error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, gc->model->n + 1);
		fz_clearpixmap(gc->tmp);
		error = drawtile(gc, gc->tmp, tile3, ctm, 0);
		fz_freepixmap(tile3);
	}

	fz_freepixmap(tile2);
	return nil;
}

