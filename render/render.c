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
		fz_droppixmap(gc->tmp);
	if (gc->acc)
		fz_droppixmap(gc->acc);
	fz_free(gc);
}

fz_error *
fz_renderover(fz_renderer *gc, fz_overnode *over, fz_matrix ctm)
{
	fz_error *error;
	fz_node *node;
	int oldmode;

	oldmode = gc->mode;
	gc->mode = OVER;

printf("renderover ; acc=3,1\n");

	error = fz_newpixmap(&gc->acc, gc->x, gc->y, gc->w, gc->h, 3, 1);
	if (error)
		return error;

	fz_clearpixmap(gc->acc);

	for (node = over->super.child; node; node = node->next)
	{
		gc->tmp = nil;
		error = fz_rendernode(gc, node, ctm);
		if (error)
			return error;
		if (gc->tmp)
		{
printf("  over -> %d,%d\n", gc->tmp->n, gc->tmp->a);
			fz_blendover(gc->acc, gc->tmp, gc->acc);
			fz_droppixmap(gc->tmp);
		}
else printf("  -> nil\n");
	}

	gc->tmp = gc->acc;
	gc->acc = nil;

	gc->mode = oldmode;

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

//	if (fz_ispathnode(shape) && fz_iscolornode(color))
//		return rcolorpath(gc, shape, color, ctm);
//	if (fz_istextnode(shape) && fz_iscolornode(color))
//		return rcolortext(gc, shape, color, ctm);

	oldmode = gc->mode;
	gc->mode = MASK;

printf("rendermask\n");

	gc->tmp = nil;
	error = fz_rendernode(gc, color, ctm);
	if (error)
		return error;
	colorpix = gc->tmp;

printf("  -> color %d,%d\n", colorpix->n, colorpix->a);

	gc->tmp = nil;
	error = fz_rendernode(gc, shape, ctm);
	if (error)
		return error;
	shapepix = gc->tmp;

printf("  -> shape %d,%d\n", shapepix->n, shapepix->a);

	error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, colorpix->n, 1);
	if (error)
		return error;

printf("  -> blend %d,%d\n", gc->tmp->n, gc->tmp->a);

	fz_blendmask(gc->tmp, colorpix, shapepix);

	fz_droppixmap(shapepix);
	fz_droppixmap(colorpix);

	gc->mode = oldmode;

	return nil;
}

fz_error *
fz_rendertransform(fz_renderer *gc, fz_transformnode *transform, fz_matrix ctm)
{
printf("rendertransform\n");
	ctm = fz_concat(ctm, transform->m);
	return fz_rendernode(gc, transform->super.child, ctm);
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

			a = gl->bitmap[sx + sy * gl->w];
			b = out->samples[dx + dy * out->stride];
			c = MAX(a, b);
			out->samples[dx + dy * out->stride] = c;
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

printf("rendertext ; tmp=0,1\n");

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

fz_error *
fz_renderpath(fz_renderer *gc, fz_pathnode *path, fz_matrix ctm)
{
printf("renderpath ; tmp=nil\n");
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

printf("rendercolor %d %d %d ; tmp=3,0\n", r, g, b);

	error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, 3, 0);
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
		}
	}

	return nil;
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

	return nil;
}

