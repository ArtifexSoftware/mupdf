#include <fitz.h>

/*
 * Remove useless overs that only have one child.
 */

static void cleanovers(fz_node *node)
{
	fz_node *prev;
	fz_node *over;
	fz_node *child;

	prev = nil;
	for (over = node->first; over; over = prev->next)
	{
		cleanovers(over);

		if (fz_isovernode(over))
		{
			if (over->first == over->last)
			{
				printf("  remove unused over node\n");
				child = over->first;
				fz_removenode(over);
				if (child)
				{
					if (prev)
						fz_insertnodeafter(prev, child);
					else
						fz_insertnodefirst(node, child);
				}
				over = nil;
			}
		}

		if (over)
			prev = over;
	}
}

fz_error *
fz_optimizetree(fz_tree *tree)
{
	printf("optimizing tree\n");

//printf("before:\n");
//fz_debugtree(tree);

	cleanovers(tree->root);

//printf("after:\n");
//fz_debugtree(tree);

	return nil;
}

