#include <fitz.h>

enum { HS = 17, VS = 15 };

static fz_error *pathtogel(fz_gel *gel, fz_pathnode *path, fz_matrix ctm)
{
	float flatness = 0.3 / ctm.a;
	if (flatness < 0.1)
		flatness = 0.1;

	if (path->paint == FZ_STROKE)
	{
		if (path->dash)
			return fz_dashpath(gel, path, ctm, flatness);
		return fz_strokepath(gel, path, ctm, flatness);
	}
	return fz_fillpath(gel, path, ctm, flatness);
}

static void blitcolorspan(int y, int x0, int n, short *list, void *userdata)
{
	fz_renderer *gc = userdata;
	fz_pixmap *pix = gc->acc;
	unsigned char sa;
	unsigned char ssa;
	unsigned char *p;
	unsigned char r = gc->r;
	unsigned char g = gc->g;
	unsigned char b = gc->b;

	sa = 0;

	while (x0 < pix->x)
	{
		sa += *list++;
		x0 ++;
		n --;
	}

	if (n > pix->w)
		n = pix->w;

	p = &pix->samples[(y - pix->y) * pix->stride + (x0 - pix->x) * 4];

	while (n--)
	{
		sa += *list++;
		ssa = 255 - sa;

		p[0] = fz_mul255(r, sa) + fz_mul255(p[0], ssa);
		p[1] = fz_mul255(g, sa) + fz_mul255(p[1], ssa);
		p[2] = fz_mul255(b, sa) + fz_mul255(p[2], ssa);
		p[3] = sa + fz_mul255(p[3], ssa);

		p += 4;
	}
}

static void blitalphaspan(int y, int x0, int n, short *list, void *userdata)
{
	fz_pixmap *pix = userdata;
	unsigned char a;
	unsigned char *p;

	a = 0;

	while (x0 < pix->x)
	{
		a += *list++;
		x0 ++;
		n --;
	}

	if (n > pix->w)
		n = pix->w;

	p = &pix->samples[(y - pix->y) * pix->stride + (x0 - pix->x) * 4];

	while (n--)
	{
		a += *list++;
		*p++ = a;
	}
}

fz_error *
fz_rendercolorpath(fz_renderer *gc, fz_pathnode *path, fz_colornode *color, fz_matrix ctm)
{
	fz_error *error;
	float rgb[3];

	fz_resetgel(gc->gel, HS, VS);

	error = pathtogel(gc->gel, path, ctm);
	if (error)
		return error;

	fz_sortgel(gc->gel);

	fz_convertcolor(color->cs, color->samples, gc->model, rgb);
	gc->r = rgb[0] * 255;
	gc->g = rgb[1] * 255;
	gc->b = rgb[2] * 255;

	fz_scanconvert(gc->gel, gc->ael,
		path->paint == FZ_EOFILL,
		gc->y, gc->y + gc->h,
		blitcolorspan, gc);

	return nil;
}

fz_error *
fz_renderpath(fz_renderer *gc, fz_pathnode *path, fz_matrix ctm)
{
	fz_error *error;

	fz_resetgel(gc->gel, HS, VS);

	error = pathtogel(gc->gel, path, ctm);
	if (error)
		return error;

	fz_sortgel(gc->gel);

	error = fz_newpixmap(&gc->tmp, nil, gc->x, gc->y, gc->w, gc->h, 0, 1);
	if (error)
		return error;

	fz_clearpixmap(gc->tmp);

	fz_scanconvert(gc->gel, gc->ael,
		path->paint == FZ_EOFILL,
		gc->y, gc->y + gc->h,
		blitalphaspan, gc->tmp);

	return nil;
}

