#include <fitz.h>

fz_error *
fz_newimage(fz_node **nodep, int w, int h, int n, int bpc, int cs)
{
	fz_image *node;

	node = fz_malloc(sizeof (fz_image));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NIMAGE);
	node->w = w;
	node->h = h;
	node->n = n;
	node->bpc = bpc;
	node->cs = cs;
	node->data = nil;

	return nil;
}

void
fz_freeimage(fz_image *node)
{
	fz_free(node->data);
	fz_free(node);
}

fz_rect
fz_boundimage(fz_image *node, fz_matrix ctm)
{
	fz_point ll, lr, ul, ur;
	fz_rect r;

	ll = fz_transformpoint(ctm, (fz_point){0,0});
	lr = fz_transformpoint(ctm, (fz_point){1,0});
	ul = fz_transformpoint(ctm, (fz_point){0,1});
	ur = fz_transformpoint(ctm, (fz_point){1,1});

	r.min.x = MIN4(ll.x, lr.x, ul.x, ur.x);
	r.min.y = MIN4(ll.y, lr.y, ul.y, ur.y);
	r.max.x = MAX4(ll.x, lr.x, ul.x, ur.x);
	r.max.y = MAX4(ll.y, lr.y, ul.y, ur.y);

	return r;
}

