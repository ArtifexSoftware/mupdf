#include <fitz.h>

fz_error *
fz_newmask(fz_node **nodep)
{
	fz_mask *node;

	node = fz_malloc(sizeof (fz_mask));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NMASK);
	node->child = nil;

	return nil;
}

void
fz_freemask(fz_mask *node)
{
	if (node->child)
		fz_freenode(node->child);
	fz_free(node);
}

fz_rect
fz_boundmask(fz_mask* node, fz_matrix ctm)
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
				bbox = fz_intersectrects(r, bbox);
			else
				bbox = r;
		}
	}

	return bbox;
}

