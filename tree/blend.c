#include <fitz.h>

fz_error *
fz_newblend(fz_node **nodep, fz_blendkind b, int k, int i)
{
	fz_blend *node;

	node = fz_malloc(sizeof (fz_blend));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NBLEND);
	node->child = nil;
	node->mode = b;
	node->knockout = k;
	node->isolated = i;

	return nil;
}

void
fz_freeblend(fz_blend *node)
{
	if (node->child)
		fz_freenode(node->child);
	fz_free(node);
}

fz_rect
fz_boundblend(fz_blend *node, fz_matrix ctm)
{
	fz_node *child;
	fz_rect bbox;
	fz_rect r;

	bbox = FZ_INFRECT;

	for (child = node->child; child; child = child->next)
	{
		r = fz_boundnode(child, ctm);
		if (r.max.x >= r.min.x)
		{
			if (bbox.max.x >= bbox.min.x)
				bbox = fz_mergerects(r, bbox);
			else
				bbox = r;
		}   
	}

	return bbox;
}

