#include <fitz.h>

fz_error *fz_rendercolortext(fz_renderer*, fz_textnode*, fz_colornode*, fz_matrix);
fz_error *fz_rendercolorpath(fz_renderer*, fz_pathnode*, fz_colornode*, fz_matrix);
fz_error *fz_rendertext(fz_renderer*, fz_textnode*, fz_matrix);
fz_error *fz_renderpath(fz_renderer*, fz_pathnode*, fz_matrix);

fz_error *fz_renderimageover(fz_renderer*, fz_imagenode*, fz_matrix);
fz_error *fz_renderimage(fz_renderer*, fz_imagenode*, fz_matrix);

fz_error *
fz_newrenderer(fz_renderer **gcp, fz_colorspace *processcolormodel, int gcmem)
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

	error = fz_newglyphcache(&gc->cache, gcmem / 32, gcmem);
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
		fz_dropglyphcache(gc->cache);
	if (gc->gel)
		fz_dropgel(gc->gel);
	if (gc->ael)
		fz_dropael(gc->ael);
	fz_free(gc);

	return error;
}

void
fz_droprenderer(fz_renderer *gc)
{
	if (gc->cache)
		fz_dropglyphcache(gc->cache);
	if (gc->gel)
		fz_dropgel(gc->gel);
	if (gc->ael)
		fz_dropael(gc->ael);
	if (gc->tmp)
		fz_droppixmap(gc->tmp);
	if (gc->acc)
		fz_droppixmap(gc->acc);
	fz_free(gc);
}

fz_error *
fz_rendercolor(fz_renderer *gc, fz_colornode *color, fz_matrix ctm)
{
	fz_error *error;
	int x, y;
	float rgb[3];

printf("render color\n");

	assert(gc->model);

	fz_convertcolor(color->cs, color->samples, gc->model, rgb);
	gc->r = rgb[0] * 255;
	gc->g = rgb[1] * 255;
	gc->b = rgb[2] * 255;

	error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, 4);
	if (error)
		return error;

	unsigned char *p = gc->tmp->samples;

	for (y = 0; y < gc->tmp->h; y++)
	{
		for (x = 0; x < gc->tmp->w; x++)
		{
			*p++ = 255;
			*p++ = gc->r;
			*p++ = gc->g;
			*p++ = gc->b;
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
//printf("over src ");fz_debugpixmap(gc->tmp);getchar();
//printf("over dst ");fz_debugpixmap(gc->acc);getchar();
		fz_blendover(gc->tmp, gc->acc);
//printf("over res ");fz_debugpixmap(gc->acc);getchar();
		fz_droppixmap(gc->tmp);
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

//printf("begin over\n");

	/* uh-oh! we have a new over cluster */
	if (gc->mode != FZ_ROVER)
	{
printf("begin over accumulator\n");
		oldacc = gc->acc;
		error = fz_newpixmap(&gc->acc, gc->x, gc->y, gc->w, gc->h, gc->model ? 4 : 1);
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
printf("end over accumulator\n");
		gc->tmp = gc->acc;
		gc->acc = oldacc;
	}

//printf("end over\n");

	return nil;
}

fz_error *
fz_rendermask(fz_renderer *gc, fz_masknode *mask, fz_matrix ctm)
{
	fz_error *error;
	fz_pixmap *oldacc;
	fz_pixmap *colorpix;
	fz_pixmap *shapepix;
	fz_node *color;
	fz_node *shape;
	int oldmode;
	fz_rect bbox;
	int ox, oy, ow, oh;

	color = mask->super.child;
	shape = color->next;

	if (gc->mode == FZ_ROVER)
	{
		if (fz_ispathnode(shape) && fz_iscolornode(color))
			return fz_rendercolorpath(gc, (fz_pathnode*)shape, (fz_colornode*)color, ctm);
		if (fz_istextnode(shape) && fz_iscolornode(color))
			return fz_rendercolortext(gc, (fz_textnode*)shape, (fz_colornode*)color, ctm);
		if (fz_isimagenode(shape) && fz_iscolornode(color))
			puts("could optimize image mask!");
	}

printf("begin mask\n");

	oldacc = gc->acc;
	oldmode = gc->mode;
	gc->acc = nil;
	gc->mode = FZ_RMASK;

	// TODO: set clip bbox to that of shape

	bbox = fz_boundnode(shape, ctm);
	bbox = fz_intersectrects(bbox, (fz_rect){{gc->x,gc->y},{gc->x+gc->w,gc->y+gc->h}});
	printf("mask bbox [%g %g %g %g]\n", bbox.min.x, bbox.min.y, bbox.max.x, bbox.max.y);
	ox = gc->x;
	oy = gc->y;
	ow = gc->w;
	oh = gc->h;

	gc->x = fz_floor(bbox.min.x) - 1;
	gc->y = fz_floor(bbox.min.y) - 1;
	gc->w = fz_ceil(bbox.max.x) - fz_floor(bbox.min.x) + 1;
	gc->h = fz_ceil(bbox.max.y) - fz_floor(bbox.min.y) + 1;
	ctm.e -= bbox.min.x - fz_floor(bbox.min.x);
	ctm.f -= bbox.min.y - fz_floor(bbox.min.y);

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

if (!shapepix) return nil;

	error = fz_newpixmap(&gc->tmp, gc->x, gc->y, gc->w, gc->h, colorpix->n);
	if (error)
		return error;

	fz_blendmask(gc->tmp, colorpix, shapepix);

//printf("mask color");fz_debugpixmap(colorpix);getchar();
//printf("mask shape");fz_debugpixmap(shapepix);getchar();
//printf("mask blend");fz_debugpixmap(gc->tmp);getchar();

	fz_droppixmap(shapepix);
	fz_droppixmap(colorpix);

	gc->acc = oldacc;
	gc->mode = oldmode;

	gc->x = ox;
	gc->y = oy;
	gc->w = ow;
	gc->h = oh;

printf("end mask\n");

	return nil;
}

fz_error *
fz_rendertransform(fz_renderer *gc, fz_transformnode *transform, fz_matrix ctm)
{
//printf("render transform\n");
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
	case FZ_NLINK:
		return fz_rendernode(gc, ((fz_linknode*)node)->tree->root, ctm);
	default:
		return nil;
	}
}

fz_error *
fz_rendertree(fz_pixmap **outp, fz_renderer *gc, fz_tree *tree, fz_matrix ctm, fz_rect bbox)
{
	fz_error *error;

	gc->x = fz_floor(bbox.min.x);
	gc->y = fz_floor(bbox.min.y);
	gc->w = fz_ceil(bbox.max.x) - fz_floor(bbox.min.x);
	gc->h = fz_ceil(bbox.max.y) - fz_floor(bbox.min.y);

	/* compensate for rounding */
	ctm.e -= bbox.min.x - gc->x;
	ctm.f -= bbox.min.y - gc->y;

printf("render tree\n");

	error = fz_rendernode(gc, tree->root, ctm);
	if (error)
		return error;

	*outp = gc->tmp;
	gc->tmp = nil;
	return nil;
}

