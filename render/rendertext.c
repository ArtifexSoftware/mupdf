#include <fitz.h>

static void blitalphaglyph(fz_pixmap *out, fz_glyph *gl, int xo, int yo)
{
	int sx, sy, dx, dy, a, b, c;

	for (sy = 0; sy < gl->h; sy++)
	{
		for (sx = 0; sx < gl->w; sx++)
		{
			dx = xo + sx + gl->lsb - out->x;
			dy = yo - sy + gl->top - out->y;

			if (dx < 0) continue;
			if (dy < 0) continue;
			if (dx >= out->w) continue;
			if (dy >= out->h) continue;

			a = gl->bitmap[sx + sy * gl->w];
			b = out->samples[dx + dy * out->w];
			c = a + fz_mul255(b, 255 - a);
			out->samples[dx + dy * out->w] = c;
		}
	}
}

static void blitcolorglyph(fz_pixmap *out, fz_glyph *gl, int xo, int yo, fz_renderer *gc)
{
	int sx, sy, dx, dy, sa, ssa;
	unsigned char *p;

	for (sy = 0; sy < gl->h; sy++)
	{
		for (sx = 0; sx < gl->w; sx++)
		{
			dy = yo - sy + gl->top - out->y;
			if (dy < 0) continue;
			if (dy >= out->h) break;

			dx = xo + sx + gl->lsb - out->x;
			if (dx < 0) continue;
			if (dx >= out->w) break;

			sa = gl->bitmap[sx + sy * gl->w];
			ssa = 255 - sa;

			p = out->samples + dx * 4 + dy * out->w * out->n;
			p[0] = sa + fz_mul255(ssa, p[0]);
			p[1] = fz_mul255(gc->r, sa) + fz_mul255(p[1], ssa);
			p[2] = fz_mul255(gc->g, sa) + fz_mul255(p[2], ssa);
			p[3] = fz_mul255(gc->b, sa) + fz_mul255(p[3], ssa);
		}
	}
}

fz_error *
fz_rendertext(fz_renderer *gc, fz_textnode *text, fz_matrix ctm)
{
	fz_error *error;
	fz_glyph gl;
	float x, y;
	int g, i, ix, iy;
	fz_matrix tm, trm;

	error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, 1);
	if (error)
		return error;

	tm = text->trm;

	for (i = 0; i < text->len; i++)
	{
		g = text->els[i].cid;
		x = text->els[i].x;
		y = text->els[i].y;

		tm.e = x;
		tm.f = y;
		trm = fz_concat(tm, ctm);

		ix = floor(trm.e);
		iy = floor(trm.f);

		trm.e = (trm.e - floor(trm.e));
		trm.f = (trm.f - floor(trm.f));

		error = fz_renderglyph(gc->cache, &gl, text->font, g, trm);
		if (error)
			return error;

		blitalphaglyph(gc->tmp, &gl, ix, iy);
	}

	return nil;
}

fz_error *
fz_rendercolortext(fz_renderer *gc, fz_textnode *text, fz_colornode *color, fz_matrix ctm)
{
	fz_error *error;
	fz_glyph gl;
	float x, y;
	int g, i, ix, iy;
	fz_matrix tm, trm;
	float rgb[3];

	fz_convertcolor(color->cs, color->samples, gc->model, rgb);
	gc->r = rgb[0] * 255;
	gc->g = rgb[1] * 255;
	gc->b = rgb[2] * 255;

	tm = text->trm;

	for (i = 0; i < text->len; i++)
	{
		g = text->els[i].cid;
		x = text->els[i].x;
		y = text->els[i].y;

		tm.e = x;
		tm.f = y;
		trm = fz_concat(tm, ctm);

		ix = floor(trm.e);
		iy = floor(trm.f);

		trm.e = (trm.e - floor(trm.e));
		trm.f = (trm.f - floor(trm.f));

		error = fz_renderglyph(gc->cache, &gl, text->font, g, trm);
		if (error)
			return error;

		blitcolorglyph(gc->acc, &gl, ix, iy, gc);
	}

	return nil;
}

