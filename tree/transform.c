#include <fitz.h>

fz_error *
fz_newtransform(fz_node **nodep, fz_matrix m)
{
	fz_transform *node;

	node = fz_malloc(sizeof (fz_transform));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NTRANSFORM);
	node->child = nil;
	node->m = m;

	return nil;
}

void
fz_freetransform(fz_transform *node)
{
	if (node->child)
		fz_freenode(node->child);
	fz_free(node);
}

fz_rect
fz_boundtransform(fz_transform *node, fz_matrix ctm)
{
	if (!node->child)
		return FZ_INFRECT;
	return fz_boundnode(node->child, fz_concat(node->m, ctm));
}

