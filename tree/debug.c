#include <fitz.h>

static void indent(int level)
{
	while (level--)
		putchar(' ');
}

static void lispnode(fz_node *node, int level);

static void lispmeta(fz_meta *node, int level)
{
	fz_node *child;
	indent(level);
	printf("(meta ");
	fz_debugobj(node->info);
	printf("\n");
	for (child = node->child; child; child = child->next)
		lispnode(child, level + 1);
	indent(level);
	printf(")\n");
}

static void lispover(fz_over *node, int level)
{
	fz_node *child;
	indent(level);
	printf("(over\n");
	for (child = node->child; child; child = child->next)
		lispnode(child, level + 1);
	indent(level);
	printf(")\n");
}

static void lispmask(fz_mask *node, int level)
{
	fz_node *child;
	indent(level);
	printf("(mask\n");
	for (child = node->child; child; child = child->next)
		lispnode(child, level + 1);
	indent(level);
	printf(")\n");
}

static void lispblend(fz_blend *node, int level)
{
	fz_node *child;
	indent(level);
	printf("(blend-%d\n", node->mode);
	for (child = node->child; child; child = child->next)
		lispnode(child, level + 1);
	indent(level);
	printf(")\n");
}

static void lisptransform(fz_transform *node, int level)
{
	indent(level);
	printf("(transform %g %g %g %g %g %g\n",
		node->m.a, node->m.b,
		node->m.c, node->m.d,
		node->m.e, node->m.f);
	lispnode(node->child, level + 1);
	indent(level);
	printf(")\n");
}

static void lispsolid(fz_solid *node, int level)
{
	indent(level);
	printf("(solid %g %g %g)\n", node->r, node->g, node->b);
}

static void lispform(fz_form *node, int level)
{
	indent(level);
	printf("(form %p)\n", node->tree);
}

static void lisppath(fz_path *node, int level)
{
	int i;

	indent(level);

	if (node->paint == FZ_STROKE)
	{
		printf("(path 'stroke %d %d %g %g ",
			node->stroke->linecap,
			node->stroke->linejoin,
			node->stroke->linewidth,
			node->stroke->miterlimit);
		if (node->dash)
		{
			printf("%g '( ", node->dash->phase);
			for (i = 0; i < node->dash->len; i++)
				printf("%g ", node->dash->array[i]);
			printf(")");
		}
		else
			printf("0 '()");
	}
	else
	{
		printf("(path '%s", node->paint == FZ_FILL ? "fill" : "eofill");
	}

	printf("\n");
	fz_debugpath(node);

	indent(level);
	printf(")\n");
}

static void lisptext(fz_text *node, int level)
{
	int i;

	indent(level);
	printf("(text %s [%g %g %g %g]\n", node->font->name,
		node->trm.a, node->trm.b, node->trm.c, node->trm.d);

	for (i = 0; i < node->len; i++)
	{
		indent(level + 1);
		printf("(g %d %g %g)\n", node->els[i].g, node->els[i].x, node->els[i].y);
	}

	indent(level);
	printf(")\n");
}

static void lispimage(fz_image *node, int level)
{
	indent(level);
	printf("(image %d %d %d %d '", node->w, node->h, node->n, node->bpc);
	switch (node->cs)
	{
	case FZ_CSGRAY: printf("gray"); break;
	case FZ_CSRGB: printf("rgb"); break;
	case FZ_CSCMYK: printf("cmyk"); break;
	default: printf("unknown"); break;
	}
	printf(")\n");
}

static void lispnode(fz_node *node, int level)
{
	if (!node)
	{
		indent(level);
		printf("(nil)\n");
		return;
	}

	switch (node->kind)
	{
	case FZ_NMETA: lispmeta((fz_meta*)node, level); break;
	case FZ_NOVER: lispover((fz_over*)node, level); break;
	case FZ_NMASK: lispmask((fz_mask*)node, level); break;
	case FZ_NBLEND: lispblend((fz_blend*)node, level); break;
	case FZ_NTRANSFORM: lisptransform((fz_transform*)node, level); break;
	case FZ_NSOLID: lispsolid((fz_solid*)node, level); break;
	case FZ_NPATH: lisppath((fz_path*)node, level); break;
	case FZ_NTEXT: lisptext((fz_text*)node, level); break;
	case FZ_NIMAGE: lispimage((fz_image*)node, level); break;
	case FZ_NFORM: lispform((fz_form*)node, level); break;
	}
}

void
fz_debugtree(fz_tree *tree)
{
	lispnode(tree->root, 0);
}

