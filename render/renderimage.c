#include <fitz.h>

fz_error *
fz_scalepixmap(fz_pixmap *src, fz_pixmap *dst, int xdenom, int ydenom);

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

	float a = pix->samples[ y0 * pix->stride + x0 * (pix->n + pix->a) + k ];
	float b = pix->samples[ y0 * pix->stride + x1 * (pix->n + pix->a) + k ];
	float c = pix->samples[ y1 * pix->stride + x0 * (pix->n + pix->a) + k ];
	float d = pix->samples[ y1 * pix->stride + x1 * (pix->n + pix->a) + k ];

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
		for (k = 0; k < src->n + src->a; k++)
			dst->samples[ y * dst->stride + x * (dst->n+dst->a) + k ] = getcomp(src, u, v, k);
		if (!src->a && dst->a)
			dst->samples[ y * dst->stride + x * (dst->n + dst->a) + dst->n ] = 0xFF;

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
		float a = 1.0;
		if (u < 0)
			a *= 1.0 - (u - floor(u));
		if (u > src->w - 1)
			a *= u - floor(u);
		if (v < 0)
			a *= 1.0 - (v - floor(v));
		if (v > src->h - 1)
			a *= v - floor(v);

		int sr = getcomp(src, u, v, 0);
		int sg = getcomp(src, u, v, 1);
		int sb = getcomp(src, u, v, 2);

		int dr = dst->samples[ y * dst->stride + x * (dst->n+dst->a) + 0 ];
		int dg = dst->samples[ y * dst->stride + x * (dst->n+dst->a) + 1 ];
		int db = dst->samples[ y * dst->stride + x * (dst->n+dst->a) + 2 ];

		int sa = a * 255;
		int ssa = 255 - sa;

		dr = fz_mul255(sr, sa) + fz_mul255(dr, ssa);
		dg = fz_mul255(sg, sa) + fz_mul255(dg, ssa);
		db = fz_mul255(sb, sa) + fz_mul255(db, ssa);

		dst->samples[ y * dst->stride + x * (dst->n+dst->a) + 0 ] = dr;
		dst->samples[ y * dst->stride + x * (dst->n+dst->a) + 1 ] = dg;
		dst->samples[ y * dst->stride + x * (dst->n+dst->a) + 2 ] = db;
		dst->samples[ y * dst->stride + x * (dst->n+dst->a) + 3 ] = sa;

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
			if (over && tile->cs && tile->cs->n == 3)
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
	int sw = w;
	int sh = h;

	float s = sqrt(ctm.a * ctm.a + ctm.b * ctm.b);

	int d = 1;
	while ((w + d - 1) / d > s)
		d++;
	if (d > 1)
		d --;

printf("renderimage s=%g d=%d\n", s, d);

	error = fz_newpixmap(&tile1, cs, 0, 0, w, h, n, a);

printf("  load tile\n");
	error = image->loadtile(image, tile1);

	if (d != 1)
	{
		sw = (w + d - 1) / d;
		sh = (h + d - 1) / d;

printf("  new pixmap\n");
		error = fz_newpixmap(&tile2, cs, 0, 0, sw, sh, n, a);
printf("  scale tile to %d %d\n", sw, sh);
		error = fz_scalepixmap(tile1, tile2, d, d);

printf("  free loaded tile\n");
		fz_freepixmap(tile1);
	}
	else
		tile2 = tile1;

printf("  swtich render mode\n");

	/* render image mask */
	if (n == 0 && a == 1)
	{
printf("draw image mask\n");
		error = fz_newpixmap(&gc->tmp, nil, gc->x, gc->y, gc->w, gc->h, 0, 1);
		fz_clearpixmap(gc->tmp);
		error = drawtile(gc, gc->tmp, tile2, ctm, 0);
fz_debugpixmap(gc->tmp);getchar();
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
		error = fz_newpixmap(&tile3, gc->model, 0, 0, sw, sh, gc->model->n, a);
		fz_convertpixmap(tile2, tile3);
		error = fz_newpixmap(&gc->tmp, gc->model, gc->x, gc->y, gc->w, gc->h, gc->model->n, 1);
		fz_clearpixmap(gc->tmp);
		error = drawtile(gc, gc->tmp, tile3, ctm, 0);
		fz_freepixmap(tile3);
	}

	fz_freepixmap(tile2);
	return nil;
}

