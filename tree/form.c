#include <fitz.h>

fz_error *
fz_newform(fz_node **nodep, fz_tree *child)
{
	fz_form *node;

	node = fz_malloc(sizeof (fz_form));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NFORM);
	node->tree = child;

	return nil;
}

void
fz_freeform(fz_form *node)
{
	fz_free(node);
}

fz_rect
fz_boundform(fz_form *node, fz_matrix ctm)
{
	return fz_boundtree(node->tree, ctm);
}

