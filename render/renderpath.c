#include <fitz.h>

// enum { HS = 1, VS = 1, SF = 255 };
enum { HS = 17, VS = 15, SF = 1 };

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

static void blitcolorspan(int y, int x, int n, unsigned char *alpha, void *userdata)
{
	fz_renderer *gc = userdata;
	fz_pixmap *pix = gc->acc;
	unsigned char sa;
	unsigned char ssa;
	unsigned char *p;
	unsigned char r = gc->r;
	unsigned char g = gc->g;
	unsigned char b = gc->b;

	if (x < pix->x)
	{
		alpha += pix->x - x;
		n -= pix->x - x;
		x = pix->x;
	}

	if (x + n > pix->x + pix->w)
		n = pix->x + pix->w - x;

	if (n < 0)
		return;

	p = pix->samples + ((y - pix->y) * pix->w + (x - pix->x)) * pix->n;

	while (n--)
	{
		sa = *alpha++ * SF;
		ssa = 255 - sa;

		p[0] = sa + fz_mul255(p[0], ssa);
		p[1] = fz_mul255(r, sa) + fz_mul255(p[1], ssa);
		p[2] = fz_mul255(g, sa) + fz_mul255(p[2], ssa);
		p[3] = fz_mul255(b, sa) + fz_mul255(p[3], ssa);

		p += 4;
	}
}

static void blitalphaspan(int y, int x, int n, unsigned char *alpha, void *userdata)
{
	fz_pixmap *pix = userdata;
	unsigned char *p;

	if (x < pix->x)
	{
		alpha += pix->x - x;
		n -= pix->x - x;
		x = pix->x;
	}

	if (x + n > pix->x + pix->w)
		n = pix->x + pix->w - x;

	if (n < 0)
		return;

	p = pix->samples + (y - pix->y) * pix->w + (x - pix->x);
	while (n--)
		*p++ = *alpha++ * SF;
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

	error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, 1);
	if (error)
		return error;

	fz_clearpixmap(gc->tmp);

	fz_scanconvert(gc->gel, gc->ael,
		path->paint == FZ_EOFILL,
		gc->y, gc->y + gc->h,
		blitalphaspan, gc->tmp);

	return nil;
}

