#include <fitz.h>

static inline void
drawscan(fz_matrix *invmat, fz_pixmap *dst, fz_pixmap *src, int y, int x0, int x1)
{
	int x, k;
	float u, v;
	float du, dv;
	fz_point p;
	int iu, iv;
	unsigned char c;

	p.x = x0;
	p.y = y;
	p = fz_transformpoint(*invmat, p);

	u = p.x;
	v = p.y;
	du = invmat->a;
	dv = invmat->c;

	for (x = x0; x < x1; x++)
	{
		iu = CLAMP((int)u, 0, src->w - 1);
		iv = CLAMP((int)v, 0, src->h - 1);

		for (k = 0; k < src->n + src->a; k++)
		{
			c = src->samples[ iv * src->stride + iu * (src->n+src->a) + k];
			dst->samples[ y * dst->stride + x * (dst->n+dst->a) + k ] = c;
		}

		u += du;
		v += dv;
	}
}

static fz_error *
drawtile(fz_renderer *gc, fz_pixmap *out, fz_pixmap *tile, fz_matrix ctm)
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
		drawscan(&invmat, out, tile, y, x0, x1);

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
	fz_pixmap *tile;
	fz_image *image = node->image;
	fz_colorspace *cs = image->cs;
	int w = image->w;
	int h = image->h;
	int n = image->n;

	error = fz_newpixmap(&tile, cs, 0, 0, w, h, n, 1);
	if (error)
		return error;

	error = fz_newpixmap(&gc->tmp, cs, gc->x, gc->y, gc->w, gc->h, n, 1);
	if (error)
		goto cleanup;

	fz_clearpixmap(gc->tmp);

	error = image->loadtile(image, tile);
	if (error)
		goto cleanup;

	error = drawtile(gc, gc->tmp, tile, ctm);
	if (error)
		goto cleanup;

printf("loadtile "); fz_debugpixmap(tile); getchar();
//printf("drawtile "); fz_debugpixmap(gc->tmp); getchar();

	fz_freepixmap(tile);
	return nil;

cleanup:
	fz_freepixmap(tile);
	return error;
}

