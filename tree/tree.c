#include <fitz.h>

fz_error *
fz_newtree(fz_tree **treep)
{
	fz_tree *tree;

	tree = *treep = fz_malloc(sizeof (fz_tree));
	if (!tree)
		return fz_outofmem;

	tree->refcount = 1;
	tree->root = nil;
	tree->head = nil;

	return nil;
}

fz_tree *
fz_keeptree(fz_tree *tree)
{
	tree->refcount ++;
	return tree;
}

void
fz_droptree(fz_tree *tree)
{
	tree->refcount --;

	if (tree->refcount == 0)
	{
		if (tree->root)
			fz_dropnode(tree->root);
		fz_free(tree);
	}
}

fz_rect
fz_boundtree(fz_tree *tree, fz_matrix ctm)
{
	if (tree->root)
		return fz_boundnode(tree->root, ctm);
	return fz_infiniterect();
}

void
fz_insertnode(fz_node *parent, fz_node *child)
{
	assert(fz_istransformnode(parent) ||
		fz_isovernode(parent) ||
		fz_ismasknode(parent) ||
		fz_isblendnode(parent) ||
		fz_ismetanode(parent));

	child->parent = parent;
	child->next = parent->child;
	parent->child = child;
}

