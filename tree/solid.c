#include <fitz.h>

fz_error *
fz_newsolid(fz_node **nodep, float r, float g, float b)
{
	fz_solid *node;

	node = fz_malloc(sizeof (fz_solid));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NSOLID);
	node->r = r;
	node->g = g;
	node->b = b;

	return nil;
}

void
fz_freesolid(fz_solid *node)
{
	fz_free(node);
}

fz_rect
fz_boundsolid(fz_solid *node, fz_matrix ctm)
{
        /* min > max => no bounds */
        return (fz_rect) { {1,1}, {-1,-1} };
}

