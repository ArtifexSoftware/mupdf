#include <fitz.h>

struct fz_renderer_s
{
	fz_glyphcache *cache;
	fz_gel *gel;
	fz_ael *ael;
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
	fz_free(gc);
}

fz_error *
fz_renderover(fz_renderer *gc, fz_over *over, fz_matrix ctm, fz_pixmap *out)
{
	fz_error *error;
	fz_node *node;

	for (node = over->child; node; node = node->next)
	{
		error = fz_rendernode(gc, node, ctm, out);
		if (error)
			return error;
	}

	return nil;
}

fz_error *
fz_rendermask(fz_renderer *gc, fz_mask *mask, fz_matrix ctm, fz_pixmap *out)
{
	fz_error *error;
	fz_node *node;

	for (node = mask->child; node; node = node->next)
	{
		error = fz_rendernode(gc, node, ctm, out);
		if (error)
			return error;
	}

	return nil;
}

fz_error *
fz_rendertransform(fz_renderer *gc, fz_transform *xform, fz_matrix ctm, fz_pixmap *out)
{
	ctm = fz_concat(ctm, xform->m);
	return fz_rendernode(gc, xform->child, ctm, out);
}


void composite(fz_pixmap *out, fz_glyph *gl, int xo, int yo)
{
	int sx, sy, dx, dy, a, b, c;

	for (sy = 0; sy < gl->h; sy++)
	{
		for (sx = 0; sx < gl->w; sx++)
		{
			dx = xo + sx + gl->lsb;
			dy = yo - sy + gl->top;

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
fz_rendertext(fz_renderer *gc, fz_text *text, fz_matrix ctm, fz_pixmap *out)
{
	fz_error *error;
	fz_glyph gl;
	float x, y;
	int g, i, ix, iy;
	fz_matrix tm, trm;

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

		composite(out, &gl, ix, iy);
	}

	return nil;
}

fz_error *
fz_rendernode(fz_renderer *gc, fz_node *node, fz_matrix ctm, fz_pixmap *out)
{
	if (!node)
		return nil;

	switch (node->kind)
	{
	case FZ_NOVER:
		return fz_renderover(gc, (fz_over*)node, ctm, out);
	case FZ_NMASK:
		return fz_rendermask(gc, (fz_mask*)node, ctm, out);
	case FZ_NTRANSFORM:
		return fz_rendertransform(gc, (fz_transform*)node, ctm, out);
	case FZ_NTEXT:
		return fz_rendertext(gc, (fz_text*)node, ctm, out);
	default:
		return nil;
	}
}

