#include <fitz.h>

fz_error *fz_rendercolortext(fz_renderer*, fz_textnode*, fz_colornode*, fz_matrix);
fz_error *fz_rendercolorpath(fz_renderer*, fz_pathnode*, fz_colornode*, fz_matrix);
fz_error *fz_rendertext(fz_renderer*, fz_textnode*, fz_matrix);
fz_error *fz_renderpath(fz_renderer*, fz_pathnode*, fz_matrix);

fz_error *fz_renderimageover(fz_renderer*, fz_imagenode*, fz_matrix);
fz_error *fz_renderimage(fz_renderer*, fz_imagenode*, fz_matrix);

fz_error *
fz_newrenderer(fz_renderer **gcp, fz_colorspace *processcolormodel)
{
	fz_error *error;
	fz_renderer *gc;

	gc = *gcp = fz_malloc(sizeof(fz_renderer));
	if (!gc)
		return fz_outofmem;

	gc->model = processcolormodel;
	gc->cache = nil;
	gc->gel = nil;
	gc->ael = nil;
	gc->mode = FZ_RNONE;
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

fz_error *
fz_rendercolor(fz_renderer *gc, fz_colornode *color, fz_matrix ctm)
{
	fz_error *error;
	int x, y;
	float rgb[3];

	fz_convertcolor(color->cs, color->samples, gc->model, rgb);
	gc->r = rgb[0] * 255;
	gc->g = rgb[1] * 255;
	gc->b = rgb[2] * 255;

puts("render color");

	error = fz_newpixmap(&gc->tmp, color->cs, gc->x, gc->y, gc->w, gc->h, 3, 1);
	if (error)
		return error;

	for (y = 0; y < gc->tmp->h; y++)
	{
		unsigned char *p = &gc->tmp->samples[y * gc->tmp->stride];
		for (x = 0; x < gc->tmp->w; x++)
		{
			*p++ = gc->r;
			*p++ = gc->g;
			*p++ = gc->b;
			*p++ = 255;
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
	if (gc->mode != FZ_ROVER)
	{
		oldacc = gc->acc;
		error = fz_newpixmap(&gc->acc, gc->model, gc->x, gc->y, gc->w, gc->h, 3, 1);
		if (error)
			return error;
		fz_clearpixmap(gc->acc);
	}

	oldmode = gc->mode;
	gc->mode = FZ_ROVER;

	gc->tmp = nil;

	if (over->super.child)
	{
		error = fz_renderoverchild(gc, over->super.child, ctm);
		if (error)
			return error;
	}

	gc->mode = oldmode;

	/* uh-oh! end of over cluster */
	if (gc->mode != FZ_ROVER)
	{
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

	if (gc->mode == FZ_ROVER)
	{
		if (fz_ispathnode(shape) && fz_iscolornode(color))
			return fz_rendercolorpath(gc, (fz_pathnode*)shape, (fz_colornode*)color, ctm);
		if (fz_istextnode(shape) && fz_iscolornode(color))
			return fz_rendercolortext(gc, (fz_textnode*)shape, (fz_colornode*)color, ctm);
	}

	oldmode = gc->mode;
	gc->mode = FZ_RMASK;

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

	error = fz_newpixmap(&gc->tmp, colorpix->cs, gc->x, gc->y, gc->w, gc->h, colorpix->n, 1);
	if (error)
		return error;

	fz_blendmask(gc->tmp, colorpix, shapepix);

//printf("mask color");fz_debugpixmap(colorpix);getchar();
//printf("mask shape");fz_debugpixmap(shapepix);getchar();
//printf("mask blend");fz_debugpixmap(gc->tmp);getchar();

	fz_freepixmap(shapepix);
	fz_freepixmap(colorpix);

	gc->mode = oldmode;

	return nil;
}

fz_error *
fz_rendertransform(fz_renderer *gc, fz_transformnode *transform, fz_matrix ctm)
{
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
	case FZ_NIMAGE:
		return fz_renderimage(gc, (fz_imagenode*)node, ctm);
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

	/* compensate for rounding */
	ctm.e -= bbox.min.x - floor(bbox.min.x);
	ctm.f -= bbox.min.y - floor(bbox.min.y);

	error = fz_rendernode(gc, tree->root, ctm);
	if (error)
		return error;

	*outp = gc->tmp;
	gc->tmp = nil;
	return nil;
}

