#include <fitz.h>

#define FNONE 0
#define FOVER 1
#define FMASK 2
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

	error = fz_newglyphcache(&gc->cache, gcmem / 32, gcmem);
	if (error)
		goto cleanup;

	error = fz_newgel(&gc->gel);
	if (error)
		goto cleanup;

	error = fz_newael(&gc->ael);
	if (error)
		goto cleanup;

	fz_defaultrastfuncs(&gc->rast);

	gc->dest = nil;
	gc->mask = nil;
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
	if (gc->mask) fz_droppixmap(gc->mask);
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
printf("transform [%g %g %g %g %g %g]\n",
transform->m.a, transform->m.b,
transform->m.c, transform->m.d,
transform->m.e, transform->m.f);
puts("{");
	ctm = fz_concat(transform->m, ctm);
	error = rendernode(gc, transform->super.first, ctm);
puts("}");
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

printf("color %s [%d %d %d]\n", color->cs->name, gc->rgb[0], gc->rgb[1], gc->rgb[2]);

	error = fz_newpixmapwithrect(&gc->dest, gc->clip, 4);
	if (error)
		return error;

	p = gc->dest->samples;
	n = gc->dest->w * gc->dest->h;

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

struct spandata
{
	fz_rastfuncs *rast;
	int x, n;
	fz_pixmap *dst;
	fz_pixmap *msk;
	unsigned char *rgb;
	int flag;
};

static void spanfunc(int y, int x, int n, unsigned char *path, void *userdata)
{
	struct spandata *user = userdata;
	fz_rastfuncs *rast = user->rast;
	fz_pixmap *dst = user->dst;
	fz_pixmap *msk = user->msk;
	unsigned char *d;
	unsigned char *m = nil;

	path += user->x;

	d = dst->samples + ( (y - dst->y) * dst->w + (x - dst->x) ) * dst->n;
	if (msk)
		m = msk->samples + ( (y - msk->y) * msk->w + (x - msk->x) ) * msk->n;

	switch (user->flag)
	{
	case FNONE:
		rast->mask_g(user->n, path, d); break;
	case FOVER:
		rast->mask_o1(user->n, path, d); break;
	case FOVER | FMASK:
		rast->mask_i1o1(user->n, path, m, d); break;
	case FOVER | FRGB:
		rast->mask_o4w3(user->n, path, d, user->rgb); break;
	case FOVER | FMASK | FRGB:
		rast->mask_i1o4w3(user->n, path, m, d, user->rgb); break;
	default:
		assert(!"impossible flag in path span function");
	}
}

static fz_error *
renderpath(fz_renderer *gc, fz_pathnode *path, fz_matrix ctm)
{
	struct spandata user;
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

	if (clip.max.x <= clip.min.x)
		return nil;
	if (clip.max.y <= clip.min.y)
		return nil;

//printf("path clip[%d %d %d %d]\n", clip.min.x, clip.min.y, clip.max.x, clip.max.y);

	user.rast = &gc->rast;
	user.x = clip.min.x - gbox.min.x;
	user.n = clip.max.x - clip.min.x;
	user.flag = gc->flag;

	if (gc->flag == FNONE)
	{
		error = fz_newpixmapwithrect(&gc->dest, clip, 1);
		if (error)
			return error;
		fz_clearpixmap(gc->dest);
		user.dst = gc->dest;
		user.msk = nil;
		user.rgb = gc->rgb;
	}
	else
	{
		user.dst = gc->over;
		user.msk = gc->mask;
		user.rgb = gc->rgb;
	}

	error = fz_scanconvert(gc->gel, gc->ael, path->paint == FZ_EOFILL,
				clip.min.y, clip.max.y, spanfunc, &user);
	if (error)
		return error;

	return nil;
}

/*
 * Text
 */

static void drawglyph(fz_renderer *gc, fz_pixmap *dst, fz_glyph *src, int xorig, int yorig)
{
	unsigned char *dp, *sp;
	int w, h;

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

	if (x1 < dst->x || x0 >= dx1) return;
	if (y1 < dst->y || y0 >= dy1) return;

	if (x0 < dst->x) { sx0 += dst->x - x0; x0 = dst->x; }
	if (y0 < dst->y) { sy0 += dst->y - y0; y0 = dst->y; }

	if (x1 >= dx1) { sx1 -= dx1 - x1; x1 = dx1; }
	if (y1 >= dy1) { sy1 -= dy1 - y1; y1 = dy1; }

	sp = src->samples + (sy0 * src->w + sx0);
	dp = dst->samples + ((y0 - dst->y) * dst->w + (x0 - dst->x)) * dst->n;

	w = sx1 - sx0;
	h = sy1 - sy0;

	switch (gc->flag)
	{
	case FNONE:
		while (h--)
		{
			gc->rast.mask_g(w, sp, dp);
			sp += src->w;
			dp += dst->w * dst->n;
		}
		break;

	case FOVER:
		while (h--)
		{
			gc->rast.mask_o1(w, sp, dp);
			sp += src->w;
			dp += dst->w * dst->n;
		}
		break;

	case FOVER | FRGB:
		while (h--)
		{
			gc->rast.mask_o4w3(w, sp, dp, gc->rgb);
			sp += src->w;
			dp += dst->w * dst->n;
		}
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

printf("text %s n=%d [%g %g %g %g] clip[%d %d %d %d]\n",
	text->font->name, text->len,
	text->trm.a, text->trm.b, text->trm.c, text->trm.d,
	clip.min.x, clip.min.y, clip.max.x, clip.max.y);

	if (clip.max.x <= clip.min.x)
		return nil;
	if (clip.max.y <= clip.min.y)
		return nil;

	clip.min.x ++;
	clip.min.y ++;
	clip.max.x ++;
	clip.max.y ++;

	if (gc->flag == FNONE)
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
		trm.e = (trm.e - fz_floor(trm.e));
		trm.f = (trm.f - fz_floor(trm.f));

		error = fz_renderglyph(gc->cache, &glyph, text->font, cid, trm);
		if (error)
			return error;

		if (gc->flag == FNONE)
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
	fz_matrix imgmat;
	fz_matrix invmat;
	int fa, fb, fc, fd;
	int u0, v0;
	int x0, y0;
	int w, h;

	/* TODO: check validity of xxx->n + 1 */

printf("renderimage %dx%d %d+%d %s\n", image->w, image->h, image->n, image->a, image->cs?image->cs->name:"(nil)");

    bbox = fz_roundrect(fz_boundnode((fz_node*)node, ctm));
    clip = fz_intersectirects(gc->clip, bbox);

	if (clip.max.x <= clip.min.x)
		return nil;
	if (clip.max.y <= clip.min.y)
		return nil;

	calcimagescale(ctm, image->w, image->h, &dx, &dy);

printf("  load image\n");
	error = fz_newpixmap(&tile, 0, 0, image->w, image->h, image->n + 1);
	error = image->loadtile(image, tile);

	if (dx != 1 || dy != 1)
	{
printf("  scale image 1/%d 1/%d\n", dx, dy);
		fz_pixmap *temp;
		error = fz_scalepixmap(&temp, tile, dx, dy);
		fz_droppixmap(tile);
		tile = temp;
	}

	if (image->cs && image->cs != gc->model)
	{
		fz_pixmap *temp;
printf("  convert from %s to %s\n", image->cs->name, gc->model->name);
		error = fz_newpixmap(&temp, tile->x, tile->y, tile->w, tile->h, gc->model->n + 1);
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

	switch (gc->flag)
	{
	case FNONE:
		{
printf("  fnone %d x %d\n", w, h);
			if (image->cs)
				error = fz_newpixmapwithrect(&gc->dest, clip, gc->model->n + 1);
			else
				error = fz_newpixmapwithrect(&gc->dest, clip, 1);
			fz_clearpixmap(gc->dest);

			if (image->cs)
				gc->rast.img4_g(
					tile->samples, tile->w, tile->h, w, h,
					gc->dest->samples, gc->dest->w * gc->dest->n,
					u0, v0, fa, fb, fc, fd);
			else
				gc->rast.img1_g(
					tile->samples, tile->w, tile->h, w, h,
					gc->dest->samples, gc->dest->w * gc->dest->n,
					u0, v0, fa, fb, fc, fd);
		}
		break;

	case FOVER:
		{
printf("  fover %d x %d\n", w, h);
			if (image->cs)
				gc->rast.img4_o4(
					tile->samples, tile->w, tile->h, w, h,
					gc->over->samples + ((y0 - gc->over->y) * gc->over->w + (x0 - gc->over->x)) * 4,
					gc->over->w * gc->over->n,
					u0, v0, fa, fb, fc, fd);
			else
				gc->rast.img1_o1(
					tile->samples, tile->w, tile->h, w, h,
					gc->over->samples + ((y0 - gc->over->y) * gc->over->w + (x0 - gc->over->x)),
					gc->over->w * gc->over->n,
					u0, v0, fa, fb, fc, fd);
		}
		break;

	case FOVER | FRGB:
		{
printf("  fover+rgb %d x %d\n", w, h);
			gc->rast.img1_o4w3(
				tile->samples, tile->w, tile->h, w, h,
				gc->over->samples + ((y0 - gc->over->y) * gc->over->w + (x0 - gc->over->x)) * 4,
				gc->over->w * gc->over->n,
				u0, v0, fa, fb, fc, fd, gc->rgb);
		}
		break;
	default:
		assert(!"impossible flag in image span function");
	}

	fz_droppixmap(tile);

	return nil;
}

/*
 * Over, Mask and Blend
 */

static fz_error *
renderover(fz_renderer *gc, fz_overnode *over, fz_matrix ctm)
{
	fz_error *error;
	fz_node *child;
	int cluster = 0;;

printf("over\n{\n");

	if (!gc->over)
	{
printf("  alloc dest!\n");
		error = fz_newpixmapwithrect(&gc->over, gc->clip, gc->maskonly ? 1 : 4);
		if (error)
			return error;
		fz_clearpixmap(gc->over);
		cluster = 1;
	}

	for (child = over->super.first; child; child = child->next)
	{
		error = rendernode(gc, child, ctm);
		if (error)
			return error;
		if (gc->dest)
		{
			fz_blendover(gc->dest, gc->over);
			fz_droppixmap(gc->dest);
			gc->dest = nil;
		}
	}

	if (cluster)
	{
		gc->dest = gc->over;
		gc->over = nil;
	}

printf("}\n");

	return nil;
}

static fz_error *
rendermask(fz_renderer *gc, fz_masknode *mask, fz_matrix ctm)
{
	fz_error *error;
	fz_pixmap *oldover;
	fz_pixmap *oldmask;
	fz_irect oldclip;
	fz_irect newclip;
	fz_pixmap *shapepix;
	fz_pixmap *colorpix;
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

			/* we know these handle FOVER | FRGB */
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
	oldmask = gc->mask;

	newclip = fz_roundrect(fz_boundnode(shape, ctm));
	newclip = fz_intersectirects(newclip, gc->clip);

	gc->clip = newclip;
	gc->over = nil;
	gc->mask = nil;

printf("mask\n{\n");

	error = rendernode(gc, color, ctm);
	if (error)
		return error;
	colorpix = gc->dest;
	gc->dest = nil;

	error = rendernode(gc, shape, ctm);
	if (error)
		return error;
	shapepix = gc->dest;
	gc->dest = nil;

	if (colorpix && shapepix)
	{
		error = fz_newpixmapwithrect(&gc->dest, gc->clip, colorpix->n);
		if (error)
			return error;

		fz_clearpixmap(gc->dest);

		fz_blendmask(gc->dest, colorpix, shapepix);
	}

	if (shapepix) fz_droppixmap(shapepix);
	if (colorpix) fz_droppixmap(colorpix);

	gc->over = oldover;
	gc->mask = oldmask;
	gc->clip = oldclip;

printf("}\n");

	return nil;
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
	if (gc->over) gc->flag |= FOVER;
	if (gc->mask) gc->flag |= FMASK;

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
	case FZ_NLINK:
		return rendernode(gc, ((fz_linknode*)node)->tree->root, ctm);
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

	if (white)
	{
		assert(gc->maskonly == 0);

		error = fz_newpixmapwithrect(&gc->over, bbox, 4);
		if (error)
			return error;

		memset(gc->over->samples, 0xff, gc->over->w * gc->over->h * gc->over->n);
	}

	error = rendernode(gc, tree->root, ctm);
	if (error)
		return error;

	if (white)
	{
		*outp = gc->over;
		gc->over = nil;
	}
	else
	{
		*outp = gc->dest;
		gc->dest = nil;
	}

	return nil;
}

