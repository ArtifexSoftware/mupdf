#include <fitz.h>

fz_error *
fz_newtree(fz_tree **treep)
{
	fz_tree *tree;

	tree = *treep = fz_malloc(sizeof (fz_tree));
	if (!tree)
		return fz_outofmem;

	tree->root = nil;
	tree->head = nil;

	return nil;
}

void
fz_freetree(fz_tree *tree)
{
	if (tree->root)
		fz_freenode(tree->root);
	fz_free(tree);
}

fz_rect
fz_boundtree(fz_tree *tree, fz_matrix ctm)
{
	if (tree->root)
		return fz_boundnode(tree->root, ctm);
	return FZ_INFRECT;
}

void
fz_insertnode(fz_node *node, fz_node *child)
{
	child->parent = node;

	if (fz_isover(node))
	{
		child->next = ((fz_over*)node)->child;
		((fz_over*)node)->child = child;
	}

	if (fz_ismask(node))
	{
		child->next = ((fz_mask*)node)->child;
		((fz_mask*)node)->child = child;
	}

	if (fz_isblend(node))
	{
		child->next = ((fz_blend*)node)->child;
		((fz_blend*)node)->child = child;
	}

	if (fz_istransform(node))
	{
		child->next = ((fz_transform*)node)->child;
		((fz_transform*)node)->child = child;
	}
}

