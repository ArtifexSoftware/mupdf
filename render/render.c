#include <fitz.h>

enum { NONE, OVER, MASK };

struct fz_renderer_s
{
	fz_glyphcache *cache;
	fz_gel *gel;
	fz_ael *ael;
	int mode;
	int x, y, w, h;
	fz_pixmap *tmp;
	fz_pixmap *acc;
	short r, g, b;
};

fz_error *
fz_newrenderer(fz_renderer **gcp)
{
	fz_error *error;
	fz_renderer *gc;

	gc = *gcp = fz_malloc(sizeof(fz_renderer));
	if (!gc)
		return fz_outofmem;

	gc->cache = nil;
	gc->gel = nil;
	gc->ael = nil;
	gc->mode = NONE;
	gc->tmp = nil;
	gc->acc = nil;

	error = fz_newglyphcache(&gc->cache, 1024, 65536);
	if (error)
		goto cleanup;

	error = fz_newgel(&gc->gel);
	if (error)
		goto cleanup;

	error = fz_newael(&gc->ael);
	if (error)
		goto cleanup;

	return nil;

cleanup:
	if (gc->cache)
		fz_freeglyphcache(gc->cache);
	if (gc->gel)
		fz_freegel(gc->gel);
	if (gc->ael)
		fz_freeael(gc->ael);
	fz_free(gc);

	return error;
}

void
fz_freerenderer(fz_renderer *gc)
{
	if (gc->cache)
		fz_freeglyphcache(gc->cache);
	if (gc->gel)
		fz_freegel(gc->gel);
	if (gc->ael)
		fz_freeael(gc->ael);
	if (gc->tmp)
		fz_freepixmap(gc->tmp);
	if (gc->acc)
		fz_freepixmap(gc->acc);
	fz_free(gc);
}

static void blitglyph(fz_pixmap *out, fz_glyph *gl, int xo, int yo)
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

			a = gl->bitmap[sx + sy * gl->w] * 64;
			b = out->samples[dx + dy * out->stride];
			c = MAX(a, b);
			out->samples[dx + dy * out->stride] = c;
		}
	}
}

static void blitcolorglyph(fz_pixmap *out, fz_glyph *gl, int xo, int yo, short r, short g, short b)
{
	int sx, sy, dx, dy, sa, ssa;
	short *p;

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

			sa = gl->bitmap[sx + sy * gl->w] * 64;
			ssa = (1 << 14) - sa;

			p = out->samples + dx * 4 + dy * out->stride;
			p[0] = ((r * sa) >> 14) + ((p[0] * ssa) >> 14);
			p[1] = ((g * sa) >> 14) + ((p[1] * ssa) >> 14);
			p[2] = ((b * sa) >> 14) + ((p[2] * ssa) >> 14);
			p[3] = sa + ((ssa * p[3]) >> 14);
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

puts("render text");

	error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, 0, 1);
	if (error)
		return error;

	tm = text->trm;

	for (i = 0; i < text->len; i++)
	{
		g = text->els[i].g;
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

		blitglyph(gc->tmp, &gl, ix, iy);
	}

	return nil;
}

static fz_error *
rcolortext(fz_renderer *gc, fz_textnode *text, fz_colornode *color, fz_matrix ctm)
{
	fz_error *error;
	fz_glyph gl;
	float x, y;
	int g, i, ix, iy;
	fz_matrix tm, trm;

puts("render (mask color text)");

	gc->r = color->r * (1 << 14);
	gc->g = color->g * (1 << 14);
	gc->b = color->b * (1 << 14);

	tm = text->trm;

	for (i = 0; i < text->len; i++)
	{
		g = text->els[i].g;
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

		blitcolorglyph(gc->acc, &gl, ix, iy, gc->r, gc->g, gc->b);
	}

	return nil;
}

static void blitspan(int y, int x, int n, short *list, void *userdata)
{
	fz_pixmap *pix = (fz_pixmap*)userdata;

	if (y < 0) return;
	if (y >= pix->h) return;
	short d = 0;
	while (x < 0 && n) {
		d += *list++; n--; x ++;
	}
	if (x + n >= pix->w)
		n = pix->w - x;
	short *p = pix->samples + (y - pix->y) * pix->stride + (x - pix->x);
	while (n--)
	{
		d += *list++;
		*p++ = d * 64;
	}
}

fz_error *
fz_renderpath(fz_renderer *gc, fz_pathnode *path, fz_matrix ctm)
{
	fz_error *error;

puts("render path");

	fz_resetgel(gc->gel, 17, 15);

	if (path->paint == FZ_STROKE)
	{
		if (path->dash)
			fz_dashpath(gc->gel, path, ctm, 0.2);
		else
			fz_strokepath(gc->gel, path, ctm, 0.2);
	}
	else
		fz_fillpath(gc->gel, path, ctm, 0.2);

	fz_sortgel(gc->gel);

	error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, 0, 1);
	if (error)
		return error;

	fz_clearpixmap(gc->tmp);

	fz_scanconvert(gc->gel, gc->ael, path->paint == FZ_EOFILL, blitspan, gc->tmp);

	return nil;
}

static void blitcolorspan(int y, int x, int n, short *list, void *userdata)
{
	fz_renderer *gc = userdata;
	fz_pixmap *pix = gc->acc;
	short r = gc->r;
	short g = gc->g;
	short b = gc->b;
	short *p;
	short d, sa, ssa;

	assert(pix->n == 3);
	assert(pix->a == 1);

	p = pix->samples + (y - pix->y) * pix->stride + (x - pix->x) * 4;
	d = 0;

	while (n --)
	{
		d += *list++;

		sa = d * 64;
		ssa = (1 << 14) - sa;

		p[0] = ((r * sa) >> 14) + ((p[0] * ssa) >> 14);
		p[1] = ((g * sa) >> 14) + ((p[1] * ssa) >> 14);
		p[2] = ((b * sa) >> 14) + ((p[2] * ssa) >> 14);
		p[3] = sa + ((ssa * p[3]) >> 14);

		p += 4;
	}
}

static fz_error *
rcolorpath(fz_renderer *gc, fz_pathnode *path, fz_colornode *color, fz_matrix ctm)
{
puts("render (mask color path)");

	fz_resetgel(gc->gel, 17, 15);

	if (path->paint == FZ_STROKE)
	{
		if (path->dash)
			fz_dashpath(gc->gel, path, ctm, 0.2);
		else
			fz_strokepath(gc->gel, path, ctm, 0.2);
	}
	else
		fz_fillpath(gc->gel, path, ctm, 0.2);

	fz_sortgel(gc->gel);

	gc->r = color->r * (1 << 14);
	gc->g = color->g * (1 << 14);
	gc->b = color->b * (1 << 14);

	fz_scanconvert(gc->gel, gc->ael, path->paint == FZ_EOFILL, blitcolorspan, gc);

	return nil;
}

fz_error *
fz_rendercolor(fz_renderer *gc, fz_colornode *color, fz_matrix ctm)
{
	fz_error *error;
	short r = color->r * (1 << 14);
	short g = color->g * (1 << 14);
	short b = color->b * (1 << 14);
	int x, y;

puts("render color");

	error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, 3, 1);
	if (error)
		return error;

	for (y = 0; y < gc->tmp->h; y++)
	{
		short *p = &gc->tmp->samples[y * gc->tmp->stride];
		for (x = 0; x < gc->tmp->w; x++)
		{
			*p++ = r;
			*p++ = g;
			*p++ = b;
			*p++ = 1 << 14;
		}
	}

	return nil;
}

static fz_error *
fz_renderoverchild(fz_renderer *gc, fz_node *node, fz_matrix ctm)
{
	fz_error *error;

	if (node->next)
	{
		error = fz_renderoverchild(gc, node->next, ctm);
		if (error)
			return error;
	}

	gc->tmp = nil;
	error = fz_rendernode(gc, node, ctm);
	if (error)
		return error;

	if (gc->tmp)
	{
		fz_blendover(gc->tmp, gc->acc);
		fz_freepixmap(gc->tmp);
		gc->tmp = nil;
	}

	return nil;
}

fz_error *
fz_renderover(fz_renderer *gc, fz_overnode *over, fz_matrix ctm)
{
	fz_error *error;
	fz_pixmap *oldacc = nil;
	int oldmode;


	/* uh-oh! we have a new over cluster */
	if (gc->mode != OVER)
	{
puts("render over");
		oldacc = gc->acc;
		error = fz_newpixmap(&gc->acc, gc->x, gc->y, gc->w, gc->h, 3, 1);
		if (error)
			return error;
		fz_clearpixmap(gc->acc);
	}

	oldmode = gc->mode;
	gc->mode = OVER;

	gc->tmp = nil;

	if (over->super.child)
	{
		error = fz_renderoverchild(gc, over->super.child, ctm);
		if (error)
			return error;
	}

	gc->mode = oldmode;

	/* uh-oh! end of over cluster */
	if (gc->mode != OVER)
	{
printf("end over\n");
		gc->tmp = gc->acc;
		gc->acc = oldacc;
	}

	return nil;
}

fz_error *
fz_rendermask(fz_renderer *gc, fz_masknode *mask, fz_matrix ctm)
{
	fz_error *error;
	fz_pixmap *colorpix;
	fz_pixmap *shapepix;
	fz_node *color;
	fz_node *shape;
	int oldmode;

	color = mask->super.child;
	shape = color->next;

	if (gc->mode == OVER)
	{
		if (fz_ispathnode(shape) && fz_iscolornode(color))
			return rcolorpath(gc, (fz_pathnode*)shape, (fz_colornode*)color, ctm);
		if (fz_istextnode(shape) && fz_iscolornode(color))
			return rcolortext(gc, (fz_textnode*)shape, (fz_colornode*)color, ctm);
	}

	oldmode = gc->mode;
	gc->mode = MASK;

	gc->tmp = nil;
	error = fz_rendernode(gc, color, ctm);
	if (error)
		return error;
	colorpix = gc->tmp;

	gc->tmp = nil;
	error = fz_rendernode(gc, shape, ctm);
	if (error)
		return error;
	shapepix = gc->tmp;

	error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, colorpix->n, 1);
	if (error)
		return error;

	fz_blendmask(gc->tmp, colorpix, shapepix);

	fz_freepixmap(shapepix);
	fz_freepixmap(colorpix);

	gc->mode = oldmode;

	return nil;
}

fz_error *
fz_rendertransform(fz_renderer *gc, fz_transformnode *transform, fz_matrix ctm)
{
puts("render transform");
	ctm = fz_concat(transform->m, ctm);
	return fz_rendernode(gc, transform->super.child, ctm);
}

fz_error *
fz_rendernode(fz_renderer *gc, fz_node *node, fz_matrix ctm)
{
	assert(gc->tmp == nil);

	if (!node)
		return nil;

	switch (node->kind)
	{
	case FZ_NOVER:
		return fz_renderover(gc, (fz_overnode*)node, ctm);
	case FZ_NMASK:
		return fz_rendermask(gc, (fz_masknode*)node, ctm);
	case FZ_NTRANSFORM:
		return fz_rendertransform(gc, (fz_transformnode*)node, ctm);
	case FZ_NCOLOR:
		return fz_rendercolor(gc, (fz_colornode*)node, ctm);
	case FZ_NPATH:
		return fz_renderpath(gc, (fz_pathnode*)node, ctm);
	case FZ_NTEXT:
		return fz_rendertext(gc, (fz_textnode*)node, ctm);
	default:
		return nil;
	}
}

fz_error *
fz_rendertree(fz_pixmap **outp, fz_renderer *gc, fz_tree *tree, fz_matrix ctm, fz_rect bbox)
{
	fz_error *error;

	gc->x = floor(bbox.min.x);
	gc->y = floor(bbox.min.y);
	gc->w = ceil(bbox.max.x) - floor(bbox.min.x);
	gc->h = ceil(bbox.max.y) - floor(bbox.min.y);

	error = fz_rendernode(gc, tree->root, ctm);
	if (error)
		return error;

	*outp = gc->tmp;
	gc->tmp = nil;

	return nil;
}

