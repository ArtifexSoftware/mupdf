#include <fitz.h>

fz_error *
fz_newover(fz_node **nodep)
{
	fz_over *node;

	node = fz_malloc(sizeof (fz_over));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NOVER);
	node->child = nil;

	return nil;
}

void
fz_freeover(fz_over *node)
{
	if (node->child)
		fz_freenode(node->child);
	fz_free(node);
}

fz_rect
fz_boundover(fz_over* node, fz_matrix ctm)
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

