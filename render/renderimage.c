#include <fitz.h>

#define LERP(a,b,t) (a + (((b - a) * t) >> 16))

static inline int getcomp(fz_pixmap *pix, int u, int v, int k)
{
	if (u < 0 || u >= pix->w)
		return 0;
	if (v < 0 || v >= pix->h)
		return 0;
	return pix->samples[ (v * pix->w + u) * pix->n + k ];
}

static inline int sampleimage(fz_pixmap *pix, int u, int v, int k)
{
	int ui = u >> 16;
	int vi = v >> 16;
	int ud = u & 0xFFFF;
	int vd = v & 0xFFFF;

	int a = getcomp(pix, ui, vi, k);
	int b = getcomp(pix, ui + 1, vi, k);
	int c = getcomp(pix, ui, vi + 1, k);
	int d = getcomp(pix, ui + 1, vi + 1, k);

	int ab = LERP(a, b, ud);
	int cd = LERP(c, d, ud);
	return LERP(ab, cd, vd);
}

static inline void
sgeneral(fz_matrix *invmat, fz_pixmap *dst, fz_pixmap *src, int y, int x0, int x1)
{
	unsigned char *d;
	int k, n;

	int u = (invmat->a * (x0+0.5) + invmat->c * (y+0.5) + invmat->e) * 65536;
	int v = (invmat->b * (x0+0.5) + invmat->d * (y+0.5) + invmat->f) * 65536;
	int du = invmat->a * 65536;
	int dv = invmat->b * 65536;

	u -= 0.5 * 65536;
	v -= 0.5 * 65536;

	n = x1 - x0 + 1;
	d = dst->samples + ((y - dst->y) * dst->w + (x0 - dst->x)) * dst->n;

	while (n--)
	{
		for (k = 0; k < src->n; k++)
			*d++ = sampleimage(src, u, v, k);
		u += du;
		v += dv;
	}
}

static inline void
srgbover(fz_matrix *invmat, fz_pixmap *dst, fz_pixmap *src, int y, int x0, int x1)
{
	unsigned char *d;
	int x;

	int u = (invmat->a * (x0+0.5) + invmat->c * (y+0.5) + invmat->e) * 65536;
	int v = (invmat->b * (x0+0.5) + invmat->d * (y+0.5) + invmat->f) * 65536;
	int du = invmat->a * 65536;
	int dv = invmat->b * 65536;

	u -= 0.5 * 65536;
	v -= 0.5 * 65536;

	d = dst->samples + ((y - dst->y) * dst->w + (x0 - dst->x)) * dst->n;

	for (x = x0; x <= x1; x++)
	{
		int sa = sampleimage(src, u, v, 0);
		int sr = sampleimage(src, u, v, 1);
		int sg = sampleimage(src, u, v, 2);
		int sb = sampleimage(src, u, v, 3);
		int ssa = 255 - sa;
		d[0] = sa + fz_mul255(d[0], ssa);
		d[1] = sr + fz_mul255(d[1], ssa);
		d[2] = sg + fz_mul255(d[2], ssa);
		d[3] = sb + fz_mul255(d[3], ssa);
		d += 4;
		u += du;
		v += dv;
	}
}

static inline void
smaskover(fz_matrix *invmat, fz_pixmap *dst, fz_pixmap *src, int y, int x0, int x1)
{
	unsigned char *d;
	int x;

	int u = (invmat->a * (x0+0.5) + invmat->c * (y+0.5) + invmat->e) * 65536;
	int v = (invmat->b * (x0+0.5) + invmat->d * (y+0.5) + invmat->f) * 65536;
	int du = invmat->a * 65536;
	int dv = invmat->b * 65536;

	u -= 0.5 * 65536;
	v -= 0.5 * 65536;

	d = dst->samples + ((y - dst->y) * dst->w + (x0 - dst->x)) * dst->n;

	for (x = x0; x <= x1; x++)
	{
		int sa = sampleimage(src, u, v, 0);
		d[0] = sa + fz_mul255(d[0], 255 - sa);
		d += 1;
		u += du;
		v += dv;
	}
}

static inline void
smaskrgbover(fz_matrix *invmat, fz_pixmap *dst, fz_pixmap *src, int y, int x0, int x1, fz_renderer *gc)
{
	unsigned char r = gc->r;
	unsigned char g = gc->g;
	unsigned char b = gc->b;
	unsigned char *d;
	int x;

	int u = (invmat->a * (x0+0.5) + invmat->c * (y+0.5) + invmat->e) * 65536;
	int v = (invmat->b * (x0+0.5) + invmat->d * (y+0.5) + invmat->f) * 65536;
	int du = invmat->a * 65536;
	int dv = invmat->b * 65536;

	u -= 0.5 * 65536;
	v -= 0.5 * 65536;

	d = dst->samples + ((y - dst->y) * dst->w + (x0 - dst->x)) * dst->n;

	for (x = x0; x <= x1; x++)
	{
		int sa = sampleimage(src, u, v, 0);
		int ssa = 255 - sa;
		d[0] = sa + fz_mul255(d[0], ssa);
		d[1] = fz_mul255(r, sa) + fz_mul255(d[1], ssa);
		d[2] = fz_mul255(g, sa) + fz_mul255(d[2], ssa);
		d[3] = fz_mul255(b, sa) + fz_mul255(d[3], ssa);
		d += 4;
		u += du;
		v += dv;
	}
}

static fz_error *
drawtile(fz_renderer *gc, fz_pixmap *out, fz_pixmap *tile, fz_matrix ctm, int over)
{
	static const fz_point rect[4] = { {0, 0}, {0, 1}, {1, 1}, {1, 0} };
	fz_matrix imgmat;
	fz_matrix invmat;
	fz_point v[4];
	int y0, y1, x0, x1, y;
	int i;

	imgmat.a = 1.0 / tile->w;
	imgmat.b = 0.0;
	imgmat.c = 0.0;
	imgmat.d = -1.0 / tile->h;
	imgmat.e = 0.0;
	imgmat.f = 1.0;
	invmat = fz_invertmatrix(fz_concat(imgmat, ctm));

	for (i = 0; i < 4; i++)
		v[i] = fz_transformpoint(ctm, rect[i]);

	y0 = fz_floor(MIN4(v[0].y, v[1].y, v[2].y, v[3].y));
	y1 = fz_ceil(MAX4(v[0].y, v[1].y, v[2].y, v[3].y));
	x0 = fz_floor(MIN4(v[0].x, v[1].x, v[2].x, v[3].x));
	x1 = fz_ceil(MAX4(v[0].x, v[1].x, v[2].x, v[3].x));

	y0 = CLAMP(y0, out->y, out->y + out->h - 1);
	y1 = CLAMP(y1, out->y, out->y + out->h - 1);
	x0 = CLAMP(x0, out->x, out->x + out->w - 1);
	x1 = CLAMP(x1, out->x, out->x + out->w - 1);

	for (y = y0; y <= y1; y++)
	{
		if (over && tile->n == 4)
			srgbover(&invmat, out, tile, y, x0, x1);
		else if (over && tile->n == 1 && gc->hasrgb)
			smaskrgbover(&invmat, out, tile, y, x0, x1, gc);
		else if (over && tile->n == 1 && !gc->hasrgb)
			smaskover(&invmat, out, tile, y, x0, x1);
		else
			sgeneral(&invmat, out, tile, y, x0, x1);
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
	int dx, dy;
	fz_rect bbox;
	fz_irect r;

	float sx = sqrt(ctm.a * ctm.a + ctm.b * ctm.b);
	float sy = sqrt(ctm.c * ctm.c + ctm.d * ctm.d);

	dx = 1;
	while ( ( (w + dx - 1) / dx ) / sx > 2.0 && (w+dx-1)/dx > 1)
		dx++;

	dy = 1;
	while ( ( (h + dy - 1) / dy ) / sy > 2.0 && (h+dy-1)/dy > 1)
		dy++;

printf("renderimage n=%d a=%d s=%gx%g/%dx%d d=%d,%d\n", n, a, sx, sy, w, h, dx, dy);

	error = fz_newpixmap(&tile1, 0, 0, w, h, n + 1);

printf("  load tile %d x %d\n", w, h);
	error = image->loadtile(image, tile1);

	if (dx != 1 || dy != 1)
	{
printf("  scale tile 1/%d x 1/%d\n", dx, dy);
		error = fz_scalepixmap(&tile2, tile1, dx, dy);
		fz_droppixmap(tile1);
	}
	else
		tile2 = tile1;

	bbox.min.x = 0;
	bbox.min.y = 0;
	bbox.max.x = 1;
	bbox.max.y = 1;
	bbox = fz_transformaabb(ctm, bbox);
	r = fz_intersectirects(fz_roundrect(bbox), gc->clip);

	/* render image mask */
	if (n == 0 && a == 1)
	{
		if (gc->acc && !gc->model)
		{
printf("  draw image mask over\n");
			error = drawtile(gc, gc->acc, tile2, ctm, 1);
		}
		else if (gc->acc && gc->hasrgb)
		{
printf("  draw image mask + color over\n");
			error = drawtile(gc, gc->acc, tile2, ctm, 1);
		}
		else
		{
printf("  draw image mask\n");
			error = fz_newpixmap(&gc->tmp, r.min.x, r.min.y, r.max.x - r.min.x, r.max.y - r.min.y, 1);
			fz_clearpixmap(gc->tmp);
			error = drawtile(gc, gc->tmp, tile2, ctm, 0);
		}
	}

	/* render rgb over */
	else if (gc->acc)
	{
		if (n == 3 && a == 0)
		{
printf("  draw image rgb over\n");
			error = drawtile(gc, gc->acc, tile2, ctm, 1);
		}

		/* render generic image */
		else
		{
printf("  draw image rgb over after cs transform\n");
			error = fz_newpixmap(&tile3, tile2->x, tile2->y, tile2->w, tile2->h, gc->model->n + 1);
			fz_convertpixmap(cs, tile2, gc->model, tile3);
			error = drawtile(gc, gc->acc, tile3, ctm, 1);
			fz_droppixmap(tile3);
		}
	}

	/* render generic image */
	else
	{
printf("  draw image after cs transform\n");
		error = fz_newpixmap(&tile3, tile2->x, tile2->y, tile2->w, tile2->h, gc->model->n + 1);
		fz_convertpixmap(cs, tile2, gc->model, tile3);
		error = fz_newpixmap(&gc->tmp, r.min.x, r.min.y,
					r.max.x - r.min.x, r.max.y - r.min.y, gc->model->n + 1);
		fz_clearpixmap(gc->tmp);
		error = drawtile(gc, gc->tmp, tile3, ctm, 0);
		fz_droppixmap(tile3);
	}

	fz_droppixmap(tile2);
	return nil;
}

fz_error *
fz_rendercolorimage(fz_renderer *gc, fz_imagenode *node, fz_colornode *color, fz_matrix ctm)
{
	fz_error *error;
	float rgb[3];

	assert(gc->model);

	fz_convertcolor(color->cs, color->samples, gc->model, rgb);
	gc->r = rgb[0] * 255;
	gc->g = rgb[1] * 255;
	gc->b = rgb[2] * 255;

	gc->hasrgb = 1;

	error = fz_renderimage(gc, node, ctm);

	gc->hasrgb = 0;

	return error;
}

