#include <fitz.h>

fz_error *
fz_newmeta(fz_node **nodep, fz_obj *info)
{
	fz_meta *node;

	node = fz_malloc(sizeof (fz_meta));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NMETA);
	node->info = fz_keepobj(info);
	node->child = nil;

	return nil;
}

void
fz_freemeta(fz_meta *node)
{
	if (node->child)
		fz_freenode(node->child);
	if (node->info)
		fz_dropobj(node->info);
	fz_free(node);
}

fz_rect
fz_boundmeta(fz_meta *node, fz_matrix ctm)
{
	if (!node->child)
		return FZ_INFRECT;
	return fz_boundnode(node->child, ctm);
}

