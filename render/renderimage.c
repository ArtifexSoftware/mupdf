#include <fitz.h>

static int cmpy(const void *a, const void *b)
{
	const fz_point *ap = a;
	const fz_point *bp = b;
	return bp->y - ap->y;
}

static void
drawtile(fz_pixmap *out, fz_pixmap *tile, fz_matrix ctm)
{
	static const fz_point rect[4] = { {0, 0}, {0, 1}, {1, 1}, {1, 0} };
	fz_point v[4];
	int i;

	for (i = 0; i < 4; i++)
		v[i] = fz_transformpoint(ctm, rect[i]);

	qsort(v, 4, sizeof(fz_point), cmpy);

	for (i = 0; i < 4; i++)
		printf("%d: %g %g\n", i, v[i].x, v[i].y);

}

fz_error *
fz_renderimage(fz_renderer *gc, fz_imagenode *node, fz_matrix ctm)
{
	fz_error *error;
	fz_pixmap *tile;
	fz_image *image = node->image;
	fz_colorspace *cs = image->cs;
	int w = image->w;
	int h = image->h;
	int n = image->n;

	error = fz_newpixmap(&tile, cs, 0, 0, w, h, n, 1);
	if (error)
		return error;

	error = fz_newpixmap(&gc->tmp, cs, gc->x, gc->y, gc->w, gc->h, n, 1);
	if (error)
		goto cleanup;

	error = image->loadtile(image, tile);
	if (error)
		goto cleanup;

	drawtile(gc->tmp, tile, ctm);

	fz_freepixmap(tile);
	return nil;

cleanup:
	fz_freepixmap(tile);
	return error;
}

