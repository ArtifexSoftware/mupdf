#include <fitz.h>

#define noDEBUG(args...) printf(args)
#ifndef DEBUG
#define DEBUG(args...)
#endif

#define QUANT(x,a) (((int)((x) * (a))) / (a))
#define HSUBPIX 5.0
#define VSUBPIX 5.0

#define FNONE 0
#define FOVER 1
#define FRGB 4

static fz_error *rendernode(fz_renderer *gc, fz_node *node, fz_matrix ctm);

fz_error *
fz_newrenderer(fz_renderer **gcp, fz_colorspace *pcm, int maskonly, int gcmem)
{
	fz_error *error;
	fz_renderer *gc;

	gc = fz_malloc(sizeof(fz_renderer));
	if (!gc)
		return fz_outofmem;

	gc->maskonly = maskonly;
	gc->model = pcm;
	gc->cache = nil;
	gc->gel = nil;
	gc->ael = nil;

	error = fz_newglyphcache(&gc->cache, gcmem / 24, gcmem);
	if (error)
		goto cleanup;

	error = fz_newgel(&gc->gel);
	if (error)
		goto cleanup;

	error = fz_newael(&gc->ael);
	if (error)
		goto cleanup;

	gc->dest = nil;
	gc->over = nil;
	gc->rgb[0] = 0;
	gc->rgb[1] = 0;
	gc->rgb[2] = 0;
	gc->flag = 0;

	*gcp = gc;
	return nil;

cleanup:
	if (gc->model) fz_dropcolorspace(gc->model);
	if (gc->cache) fz_dropglyphcache(gc->cache);
	if (gc->gel) fz_dropgel(gc->gel);
	if (gc->ael) fz_dropael(gc->ael);
	fz_free(gc);
	return error;
}

void
fz_droprenderer(fz_renderer *gc)
{
	if (gc->dest) fz_droppixmap(gc->dest);
	if (gc->over) fz_droppixmap(gc->over);

	if (gc->model) fz_dropcolorspace(gc->model);
	if (gc->cache) fz_dropglyphcache(gc->cache);
	if (gc->gel) fz_dropgel(gc->gel);
	if (gc->ael) fz_dropael(gc->ael);
	fz_free(gc);
}

/*
 * Transform
 */

static fz_error *
rendertransform(fz_renderer *gc, fz_transformnode *transform, fz_matrix ctm)
{
	fz_error *error;
DEBUG("transform [%g %g %g %g %g %g]\n",
transform->m.a, transform->m.b,
transform->m.c, transform->m.d,
transform->m.e, transform->m.f);
DEBUG("{\n");
	ctm = fz_concat(transform->m, ctm);
	error = rendernode(gc, transform->super.first, ctm);
DEBUG("}\n");
	return error;
}

/*
 * Color
 */

static fz_error *
rendercolor(fz_renderer *gc, fz_colornode *color, fz_matrix ctm)
{
	fz_error *error;
	float rgb[3];
	unsigned char *p;
	int n;

	if (gc->maskonly)
		return fz_throw("assert: mask only renderer");
	if (gc->model->n != 3)
		return fz_throw("assert: non-rgb renderer");

	fz_convertcolor(color->cs, color->samples, gc->model, rgb);
	gc->rgb[0] = rgb[0] * 255;
	gc->rgb[1] = rgb[1] * 255;
	gc->rgb[2] = rgb[2] * 255;

DEBUG("color %s [%d %d %d];\n", color->cs->name, gc->rgb[0], gc->rgb[1], gc->rgb[2]);

	if (gc->flag == FOVER)
	{
		p = gc->over->samples;
		n = gc->over->w * gc->over->h;
	}
	else
	{
		error = fz_newpixmapwithrect(&gc->dest, gc->clip, 4);
		if (error)
			return error;
		p = gc->dest->samples;
		n = gc->dest->w * gc->dest->h;
	}

	while (n--)
	{
		p[0] = 255;
		p[1] = gc->rgb[0];
		p[2] = gc->rgb[1];
		p[3] = gc->rgb[2];
		p += 4;
	}

	return nil;
}

/*
 * Path
 */

enum { HS = 17, VS = 15, SF = 1 };

static fz_error *
renderpath(fz_renderer *gc, fz_pathnode *path, fz_matrix ctm)
{
	fz_error *error;
	float flatness;
	fz_irect gbox;
	fz_irect clip;

	flatness = 0.3 / fz_matrixexpansion(ctm);
	if (flatness < 0.1)
		flatness = 0.1;

	fz_resetgel(gc->gel, HS, VS);

	if (path->paint == FZ_STROKE)
	{
		if (path->dash)
			error = fz_dashpath(gc->gel, path, ctm, flatness);
		else
			error = fz_strokepath(gc->gel, path, ctm, flatness);
	}
	else
		error = fz_fillpath(gc->gel, path, ctm, flatness);
	if (error)
		return error;

	fz_sortgel(gc->gel);

	gbox = fz_boundgel(gc->gel);
	clip = fz_intersectirects(gc->clip, gbox);

	if (fz_isemptyrect(clip))
		return nil;

DEBUG("path %s;\n", path->paint == FZ_STROKE ? "stroke" : "fill");

	if (gc->flag & FRGB)
	{
		return fz_scanconvert(gc->gel, gc->ael, path->paint == FZ_EOFILL,
					clip, gc->over, gc->rgb, 1);
	}
	else if (gc->flag & FOVER)
	{
		return fz_scanconvert(gc->gel, gc->ael, path->paint == FZ_EOFILL,
					clip, gc->over, nil, 1);
	}
	else
	{
		error = fz_newpixmapwithrect(&gc->dest, clip, 1);
		if (error)
			return error;
		fz_clearpixmap(gc->dest);
		return fz_scanconvert(gc->gel, gc->ael, path->paint == FZ_EOFILL,
					clip, gc->dest, nil, 0);
	}
}

/*
 * Text
 */

static void drawglyph(fz_renderer *gc, fz_pixmap *dst, fz_glyph *src, int xorig, int yorig)
{
	unsigned char *dp, *sp;
	int w, h;

	int dx0 = dst->x;
	int dy0 = dst->y;
	int dx1 = dst->x + dst->w;
	int dy1 = dst->y + dst->h;

	int x0 = xorig + src->x;
	int y0 = yorig + src->y;
	int x1 = x0 + src->w;
	int y1 = y0 + src->h;

	int sx0 = 0;
	int sy0 = 0;
	int sx1 = src->w;
	int sy1 = src->h;

	if (x1 <= dx0 || x0 >= dx1) return;
	if (y1 <= dy0 || y0 >= dy1) return;
	if (x0 < dx0) { sx0 += dx0 - x0; x0 = dx0; }
	if (y0 < dy0) { sy0 += dy0 - y0; y0 = dy0; }
	if (x1 > dx1) { sx1 += dx1 - x1; x1 = dx1; }
	if (y1 > dy1) { sy1 += dy1 - y1; y1 = dy1; }

	sp = src->samples + (sy0 * src->w + sx0);
	dp = dst->samples + ((y0 - dst->y) * dst->w + (x0 - dst->x)) * dst->n;

	w = sx1 - sx0;
	h = sy1 - sy0;

	switch (gc->flag)
	{
	case FNONE:
		assert(dst->n == 1);
		fz_text_1c1(sp, src->w, dp, dst->w, w, h);
		break;

	case FOVER:
		assert(dst->n == 1);
		fz_text_1o1(sp, src->w, dp, dst->w, w, h);
		break;

	case FOVER | FRGB:
		assert(dst->n == 4);
		fz_text_w3i1o4(gc->rgb, sp, src->w, dp, dst->w * 4, w, h);
		break;

	default:
		assert(!"impossible flag in text span function");
	}
}

static fz_error *
rendertext(fz_renderer *gc, fz_textnode *text, fz_matrix ctm)
{
	fz_error *error;
	fz_irect tbox;
	fz_irect clip;
	fz_matrix tm, trm;
	fz_glyph glyph;
	int i, x, y, cid;

	tbox = fz_roundrect(fz_boundnode((fz_node*)text, ctm));
	clip = fz_intersectirects(gc->clip, tbox);

DEBUG("text %s n=%d [%g %g %g %g];\n",
text->font->name, text->len,
text->trm.a, text->trm.b, text->trm.c, text->trm.d);

	if (fz_isemptyrect(clip))
		return nil;

	if (!(gc->flag & FOVER))
	{
		error = fz_newpixmapwithrect(&gc->dest, clip, 1);
		if (error)
			return error;
		fz_clearpixmap(gc->dest);
	}

	tm = text->trm;

	for (i = 0; i < text->len; i++)
	{
		cid = text->els[i].cid;
		tm.e = text->els[i].x;
		tm.f = text->els[i].y;
		trm = fz_concat(tm, ctm);
		x = fz_floor(trm.e);
		y = fz_floor(trm.f);
		trm.e = QUANT(trm.e - fz_floor(trm.e), HSUBPIX);
		trm.f = QUANT(trm.f - fz_floor(trm.f), VSUBPIX);

		error = fz_renderglyph(gc->cache, &glyph, text->font, cid, trm);
		if (error)
			return error;

		if (!(gc->flag & FOVER))
			drawglyph(gc, gc->dest, &glyph, x, y);
		else
			drawglyph(gc, gc->over, &glyph, x, y);
	}

	return nil;
}

/*
 * Image
 */

static inline void
calcimagescale(fz_matrix ctm, int w, int h, int *odx, int *ody)
{
	float sx, sy;
	int dx, dy;

	sx = sqrt(ctm.a * ctm.a + ctm.b * ctm.b);
	dx = 1;
	while (((w+dx-1)/dx)/sx > 2.0 && (w+dx-1)/dx > 1)
		dx++;

	sy = sqrt(ctm.c * ctm.c + ctm.d * ctm.d);
	dy = 1;
	while (((h+dy-1)/dy)/sy > 2.0 && (h+dy-1)/dy > 1)
		dy++;

	*odx = dx;
	*ody = dy;
}

static fz_error *
renderimage(fz_renderer *gc, fz_imagenode *node, fz_matrix ctm)
{
	fz_error *error;
	fz_image *image = node->image;
	fz_irect bbox;
	fz_irect clip;
	int dx, dy;
	fz_pixmap *tile;
	fz_pixmap *temp;
	fz_matrix imgmat;
	fz_matrix invmat;
	int fa, fb, fc, fd;
	int u0, v0;
	int x0, y0;
	int w, h;

DEBUG("image %dx%d %d+%d %s\n{\n", image->w, image->h, image->n, image->a, image->cs?image->cs->name:"(nil)");

	bbox = fz_roundrect(fz_boundnode((fz_node*)node, ctm));
	clip = fz_intersectirects(gc->clip, bbox);

	if (fz_isemptyrect(clip))
		return nil;

	calcimagescale(ctm, image->w, image->h, &dx, &dy);

DEBUG("  load image\n");
	error = fz_newpixmap(&tile, 0, 0, image->w, image->h, image->n + 1);
	if (error)
		return error;

	error = image->loadtile(image, tile);
	if (error)
		goto cleanup;

	if (dx != 1 || dy != 1)
	{
DEBUG("  scale image 1/%d 1/%d\n", dx, dy);
		error = fz_scalepixmap(&temp, tile, dx, dy);
		if (error)
			goto cleanup;
		fz_droppixmap(tile);
		tile = temp;
	}

	if (image->cs && image->cs != gc->model)
	{
DEBUG("  convert from %s to %s\n", image->cs->name, gc->model->name);
		error = fz_newpixmap(&temp, tile->x, tile->y, tile->w, tile->h, gc->model->n + 1);
		if (error)
			goto cleanup;
		fz_convertpixmap(image->cs, tile, gc->model, temp);
		fz_droppixmap(tile);
		tile = temp;
	}

	imgmat.a = 1.0 / tile->w;
	imgmat.b = 0.0;
	imgmat.c = 0.0;
	imgmat.d = -1.0 / tile->h;
	imgmat.e = 0.0;
	imgmat.f = 1.0;
	invmat = fz_invertmatrix(fz_concat(imgmat, ctm));

	w = clip.max.x - clip.min.x;
	h = clip.max.y - clip.min.y;
	x0 = clip.min.x;
	y0 = clip.min.y;
	u0 = (invmat.a * (x0+0.5) + invmat.c * (y0+0.5) + invmat.e) * 65536;
	v0 = (invmat.b * (x0+0.5) + invmat.d * (y0+0.5) + invmat.f) * 65536;
	fa = invmat.a * 65536;
	fb = invmat.b * 65536;
	fc = invmat.c * 65536;
	fd = invmat.d * 65536;

#define PSRC tile->samples, tile->w, tile->h
#define PDST(p) p->samples + ((y0-p->y) * p->w + (x0-p->x)) * p->n, p->w * p->n
#define PCTM u0, v0, fa, fb, fc, fd, w, h

	switch (gc->flag)
	{
	case FNONE:
		{
DEBUG("  fnone %d x %d\n", w, h);
			if (image->cs)
				error = fz_newpixmapwithrect(&gc->dest, clip, gc->model->n + 1);
			else
				error = fz_newpixmapwithrect(&gc->dest, clip, 1);
			if (error)
				goto cleanup;

			if (image->cs)
				fz_img_4c4(PSRC, PDST(gc->dest), PCTM);
			else
				fz_img_1c1(PSRC, PDST(gc->dest), PCTM);
		}
		break;

	case FOVER:
		{
DEBUG("  fover %d x %d\n", w, h);
			if (image->cs)
				fz_img_4o4(PSRC, PDST(gc->over), PCTM);
			else
				fz_img_1o1(PSRC, PDST(gc->over), PCTM);
		}
		break;

	case FOVER | FRGB:
DEBUG("  fover+rgb %d x %d\n", w, h);
		fz_img_w3i1o4(gc->rgb, PSRC, PDST(gc->over), PCTM);
		break;

	default:
		assert(!"impossible flag in image span function");
	}

DEBUG("}\n");

	fz_droppixmap(tile);
	return nil;

cleanup:
	fz_droppixmap(tile);
	return error;
}

/*
 * Shade
 */

static fz_error *
rendershade(fz_renderer *gc, fz_shadenode *node, fz_matrix ctm)
{
	fz_error *error;
	fz_irect bbox;

	assert(!gc->maskonly);

	bbox = fz_roundrect(fz_boundnode((fz_node*)node, ctm));
	bbox = fz_intersectirects(gc->clip, bbox);

	error = fz_newpixmapwithrect(&gc->dest, bbox, gc->model->n + 1);
	if (error)
		return error;

	return fz_rendershade(node->shade, ctm, gc->model, gc->dest);
}

/*
 * Over, Mask and Blend
 */

static void
blendover(fz_renderer *gc, fz_pixmap *src, fz_pixmap *dst)
{
	unsigned char *sp, *dp;
	fz_irect sr, dr;
	int x, y, w, h;

	sr.min.x = src->x;
	sr.min.y = src->y;
	sr.max.x = src->x + src->w;
	sr.max.y = src->y + src->h;

	dr.min.x = dst->x;
	dr.min.y = dst->y;
	dr.max.x = dst->x + dst->w;
	dr.max.y = dst->y + dst->h;

	dr = fz_intersectirects(sr, dr);
	x = dr.min.x;
	y = dr.min.y;
	w = dr.max.x - dr.min.x;
	h = dr.max.y - dr.min.y;

	sp = src->samples + ((y - src->y) * src->w + (x - src->x)) * src->n;
	dp = dst->samples + ((y - dst->y) * dst->w + (x - dst->x)) * dst->n;

	if (src->n == 1 && dst->n == 1)
		fz_duff_1o1(sp, src->w, dp, dst->w, w, h);
	else if (src->n == 4 && dst->n == 4)
		fz_duff_4o4(sp, src->w * 4, dp, dst->w * 4, w, h);
	else if (src->n == dst->n)
		fz_duff_non(sp, src->w * src->n, src->n, dp, dst->w * dst->n, w, h);
	else
		assert(!"blendover src and dst mismatch");
}

static void
blendmask(fz_renderer *gc, fz_pixmap *src, fz_pixmap *msk, fz_pixmap *dst, int over)
{
	unsigned char *sp, *dp, *mp;
	fz_irect sr, dr, mr;
	int x, y, w, h;

	sr.min.x = src->x;
	sr.min.y = src->y;
	sr.max.x = src->x + src->w;
	sr.max.y = src->y + src->h;

	dr.min.x = dst->x;
	dr.min.y = dst->y;
	dr.max.x = dst->x + dst->w;
	dr.max.y = dst->y + dst->h;

	mr.min.x = msk->x;
	mr.min.y = msk->y;
	mr.max.x = msk->x + msk->w;
	mr.max.y = msk->y + msk->h;

	dr = fz_intersectirects(sr, dr);
	dr = fz_intersectirects(dr, mr);
	x = dr.min.x;
	y = dr.min.y;
	w = dr.max.x - dr.min.x;
	h = dr.max.y - dr.min.y;

	sp = src->samples + ((y - src->y) * src->w + (x - src->x)) * src->n;
	mp = msk->samples + ((y - msk->y) * msk->w + (x - msk->x)) * msk->n;
	dp = dst->samples + ((y - dst->y) * dst->w + (x - dst->x)) * dst->n;

	if (over)
	{
		if (src->n == 1 && msk->n == 1 && dst->n == 1)
			fz_duff_1i1o1(sp, src->w, mp, msk->w, dp, dst->w, w, h);
		else if (src->n == 4 && msk->n == 1 && dst->n == 4)
			fz_duff_4i1o4(sp, src->w * 4, mp, msk->w, dp, dst->w * 4, w, h);
		else if (src->n == dst->n)
			fz_duff_nimon(sp, src->w * src->n, src->n, mp, msk->w * msk->n, msk->n, dp, dst->w * dst->n, w, h);
		else
			assert(!"blendmaskover src and msk and dst mismatch");
	}
	else
	{
		if (src->n == 1 && msk->n == 1 && dst->n == 1)
			fz_duff_1i1c1(sp, src->w, mp, msk->w, dp, dst->w, w, h);
		else if (src->n == 4 && msk->n == 1 && dst->n == 4)
			fz_duff_4i1c4(sp, src->w * 4, mp, msk->w, dp, dst->w * 4, w, h);
		else if (src->n == dst->n)
			fz_duff_nimcn(sp, src->w * src->n, src->n, mp, msk->w * msk->n, msk->n, dp, dst->w * dst->n, w, h);
		else
			assert(!"blendmask src and msk and dst mismatch");
	}
}

static fz_error *
renderover(fz_renderer *gc, fz_overnode *over, fz_matrix ctm)
{
	fz_error *error;
	fz_node *child;
	int cluster = 0;

	if (!gc->over)
	{
DEBUG("over cluster %d\n{\n", gc->maskonly ? 1 : 4);
		cluster = 1;
		if (gc->maskonly)
			error = fz_newpixmapwithrect(&gc->over, gc->clip, 1);
		else
			error = fz_newpixmapwithrect(&gc->over, gc->clip, 4);
		if (error)
			return error;
		fz_clearpixmap(gc->over);
	}
else DEBUG("over\n{\n");

	for (child = over->super.first; child; child = child->next)
	{
		error = rendernode(gc, child, ctm);
		if (error)
			return error;
		if (gc->dest)
		{
			blendover(gc, gc->dest, gc->over);
			fz_droppixmap(gc->dest);
			gc->dest = nil;
		}
	}

	if (cluster)
	{
		gc->dest = gc->over;
		gc->over = nil;
	}

DEBUG("}\n");

	return nil;
}

static fz_error *
rendermask(fz_renderer *gc, fz_masknode *mask, fz_matrix ctm)
{
	fz_error *error;
	int oldmaskonly;
	fz_pixmap *oldover;
	fz_irect oldclip;
	fz_irect bbox;
	fz_irect clip;
	fz_pixmap *shapepix = nil;
	fz_pixmap *colorpix = nil;
	fz_node *shape;
	fz_node *color;
	float rgb[3];

	shape = mask->super.first;
	color = shape->next;

	/* special case black voodo */
	if (gc->flag & FOVER)
	{
		if (fz_iscolornode(color))
		{
			fz_colornode *colorn = (fz_colornode*)color;

			fz_convertcolor(colorn->cs, colorn->samples, gc->model, rgb);
			gc->rgb[0] = rgb[0] * 255;
			gc->rgb[1] = rgb[1] * 255;
			gc->rgb[2] = rgb[2] * 255;
			gc->flag |= FRGB;

			/* we know these can handle the FRGB shortcut */
			if (fz_ispathnode(shape))
				return renderpath(gc, (fz_pathnode*)shape, ctm);
			if (fz_istextnode(shape))
				return rendertext(gc, (fz_textnode*)shape, ctm);
			if (fz_isimagenode(shape))
				return renderimage(gc, (fz_imagenode*)shape, ctm);
		}
	}

	oldclip = gc->clip;
	oldover = gc->over;

	bbox = fz_roundrect(fz_boundnode(shape, ctm));
	clip = fz_intersectirects(bbox, gc->clip);
	bbox = fz_roundrect(fz_boundnode(color, ctm));
	clip = fz_intersectirects(bbox, clip);

	if (fz_isemptyrect(clip))
		return nil;

DEBUG("mask [%d %d %d %d]\n{\n", clip.min.x, clip.min.y, clip.max.x, clip.max.y);

{
fz_irect sbox = fz_roundrect(fz_boundnode(shape, ctm));
fz_irect cbox = fz_roundrect(fz_boundnode(color, ctm));
if (cbox.min.x >= sbox.min.x && cbox.max.x <= sbox.max.x)
if (cbox.min.y >= sbox.min.y && cbox.max.y <= sbox.max.y)
DEBUG("potentially useless mask\n");
}

	gc->clip = clip;
	gc->over = nil;

	oldmaskonly = gc->maskonly;
	gc->maskonly = 1;

	error = rendernode(gc, shape, ctm);
	if (error)
		goto cleanup;
	shapepix = gc->dest;
	gc->dest = nil;

	gc->maskonly = oldmaskonly;

	error = rendernode(gc, color, ctm);
	if (error)
		goto cleanup;
	colorpix = gc->dest;
	gc->dest = nil;

	gc->clip = oldclip;
	gc->over = oldover;

	if (shapepix && colorpix)
	{
		if (gc->over)
		{
			blendmask(gc, colorpix, shapepix, gc->over, 1);
		}
		else
		{
			clip.min.x = MAX(colorpix->x, shapepix->x);
			clip.min.y = MAX(colorpix->y, shapepix->y);
			clip.max.x = MIN(colorpix->x+colorpix->w, shapepix->x+shapepix->w);
			clip.max.y = MIN(colorpix->y+colorpix->h, shapepix->y+shapepix->h);
			error = fz_newpixmapwithrect(&gc->dest, clip, colorpix->n);
			if (error)
				goto cleanup;
			blendmask(gc, colorpix, shapepix, gc->dest, 0);
		}
	}

DEBUG("}\n");

	if (shapepix) fz_droppixmap(shapepix);
	if (colorpix) fz_droppixmap(colorpix);
	return nil;

cleanup:
	if (shapepix) fz_droppixmap(shapepix);
	if (colorpix) fz_droppixmap(colorpix);
	return error;
}

/*
 * Dispatch
 */

static fz_error *
rendernode(fz_renderer *gc, fz_node *node, fz_matrix ctm)
{
	if (!node)
		return nil;

	gc->flag = FNONE;
	if (gc->over)
		gc->flag |= FOVER;

	switch (node->kind)
	{
	case FZ_NOVER:
		return renderover(gc, (fz_overnode*)node, ctm);
	case FZ_NMASK:
		return rendermask(gc, (fz_masknode*)node, ctm);
	case FZ_NTRANSFORM:
		return rendertransform(gc, (fz_transformnode*)node, ctm);
	case FZ_NCOLOR:
		return rendercolor(gc, (fz_colornode*)node, ctm);
	case FZ_NPATH:
		return renderpath(gc, (fz_pathnode*)node, ctm);
	case FZ_NTEXT:
		return rendertext(gc, (fz_textnode*)node, ctm);
	case FZ_NIMAGE:
		return renderimage(gc, (fz_imagenode*)node, ctm);
	case FZ_NSHADE:
		return rendershade(gc, (fz_shadenode*)node, ctm);
	case FZ_NLINK:
		return rendernode(gc, ((fz_linknode*)node)->tree->root, ctm);
	case FZ_NMETA:
		return rendernode(gc, node->first, ctm);
	}

	return nil;
}

fz_error *
fz_rendertree(fz_pixmap **outp,
	fz_renderer *gc, fz_tree *tree, fz_matrix ctm,
	fz_irect bbox, int white)
{
	fz_error *error;

	gc->clip = bbox;
	gc->over = nil;

	if (gc->maskonly)
		error = fz_newpixmapwithrect(&gc->over, bbox, 1);
	else
		error = fz_newpixmapwithrect(&gc->over, bbox, 4);
	if (error)
		return error;

	if (white)
		memset(gc->over->samples, 0xff, gc->over->w * gc->over->h * gc->over->n);
	else
		memset(gc->over->samples, 0x00, gc->over->w * gc->over->h * gc->over->n);

DEBUG("tree %d [%d %d %d %d]\n{\n",
gc->maskonly ? 1 : 4,
bbox.min.x, bbox.min.y, bbox.max.x, bbox.max.y);

	error = rendernode(gc, tree->root, ctm);
	if (error)
		return error;

DEBUG("}\n");

	if (gc->dest)
	{
		blendover(gc, gc->dest, gc->over);
		fz_droppixmap(gc->dest);
		gc->dest = nil;
	}

	*outp = gc->over;
	gc->over = nil;

	return nil;
}

fz_error *
fz_rendertreeover(fz_renderer *gc, fz_pixmap *dest, fz_tree *tree, fz_matrix ctm)
{
	fz_error *error;

	assert(!gc->maskonly);
	assert(dest->n == 4);

	gc->clip.min.x = dest->x;
	gc->clip.min.y = dest->y;
	gc->clip.max.x = dest->x + dest->w;
	gc->clip.max.y = dest->y + dest->h;

	gc->over = dest;

	error = rendernode(gc, tree->root, ctm);
	if (error)
	{
		gc->over = nil;
		return error;
	}

	if (gc->dest)
	{
		blendover(gc, gc->dest, gc->over);
		fz_droppixmap(gc->dest);
		gc->dest = nil;
	}

	gc->over = nil;

	return nil;
}

