#include <fitz.h>

/*
 * Remove useless overs that only have one child.
 */

static void cleanovers(fz_node *node)
{
	fz_node *prev;
	fz_node *next;
	fz_node *current;
	fz_node *child;

	prev = nil;
	for (current = node->first; current; current = next)
	{
		next = current->next;

		if (fz_isovernode(current))
		{
			if (current->first == current->last)
			{
				child = current->first;
				fz_removenode(current);
				if (child)
				{
					if (prev)
						fz_insertnodeafter(prev, child);
					else
						fz_insertnodefirst(node, child);
				}
				current = child;
			}
		}

		if (current)
			prev = current;
	}

	for (current = node->first; current; current = current->next)
		cleanovers(current);
}

/*
 * Remove rectangular clip-masks whose contents fit...
 */

static int getrect(fz_pathnode *path, fz_rect *bboxp)
{
	float x, y, w, h;

	/* move x y, line x+w y, line x+w y+h, line x y+h, close */

	if (path->len != 13)
		return 0;

	if (path->els[0].k != FZ_MOVETO) return 0;
	x = path->els[1].v;
	y = path->els[2].v;

	if (path->els[3].k != FZ_LINETO) return 0;
	w = path->els[4].v - x;
	if (path->els[5].v != y) return 0;

	if (path->els[6].k != FZ_LINETO) return 0;
	if (path->els[7].v != x + w) return 0;
	h = path->els[8].v - y;

	if (path->els[9].k != FZ_LINETO) return 0;
	if (path->els[10].v != x) return 0;
	if (path->els[11].v != y + h) return 0;

	if (path->els[12].k != FZ_CLOSEPATH) return 0;

	bboxp->min.x = MIN(x, x + w);
	bboxp->min.y = MIN(y, y + h);
	bboxp->max.x = MAX(x, x + w);
	bboxp->max.y = MAX(y, y + h);

	return 1;
}

static int fitsinside(fz_node *node, fz_rect clip)
{
	fz_rect bbox;
	bbox = fz_boundnode(node, fz_identity());
	if (fz_isinfiniterect(bbox)) return 0;
	if (fz_isemptyrect(bbox)) return 1;
	if (bbox.min.x < clip.min.x) return 0;
	if (bbox.max.x > clip.max.x) return 0;
	if (bbox.min.y < clip.min.y) return 0;
	if (bbox.max.y > clip.max.y) return 0;
	return 1;
}

static void cleanmasks(fz_node *node)
{
	fz_node *prev;
	fz_node *current;
	fz_node *shape;
	fz_node *color;
	fz_rect bbox;

	prev = nil;
	for (current = node->first; current; current = current->next)
	{
retry:
		if (fz_ismasknode(current))
		{
			shape = current->first;
			color = shape->next;

			if (fz_ispathnode(shape))
			{
				if (getrect((fz_pathnode*)shape, &bbox))
				{
					if (fitsinside(color, bbox))
					{
						fz_removenode(current);
						if (prev)
							fz_insertnodeafter(prev, color);
						else
							fz_insertnodefirst(node, color);
						current = color;
						goto retry;
					}
				}
			}
		}

		prev = current;
	}

	for (current = node->first; current; current = current->next)
		cleanmasks(current);
}

/*
 *
 */

fz_error *
fz_optimizetree(fz_tree *tree)
{
	if (getenv("DONTOPT"))
		return nil;
	cleanovers(tree->root);
	cleanmasks(tree->root);
	return nil;
}

