#include <fitz.h>

static struct { char c; double f[6]; } cmd[] = {
#include "tiger.h"
};

static fz_pathbuilder *pbuild;
static fz_textbuilder *tbuild;
static fz_tree *tree;

static fz_stroke stroke = { 0, 0, 1.0, 10.0 };
static float frgb[3] = { 0, 0, 0 };
static float srgb[3] = { 0, 0, 0 };
static fz_node *gstack[32];
static int gtop = 0;

void gsave(void)
{
	gstack[gtop++] = tree->head;
}

void grestore(void)
{
	tree->head = gstack[--gtop];
}

void dostroke(void)
{
	fz_node *path;
	fz_node *solid;
	fz_node *mask;

	fz_makepath(&path, pbuild, FZ_PSTROKE, &stroke, nil);
	fz_newsolid(&solid, 1.0f, srgb[0], srgb[1], srgb[2]);
	fz_newblend(&mask, FZ_BMASK);

	fz_insertnode(mask, path);
	fz_insertnode(mask, solid);
	fz_insertnode(tree->head, mask);
}

void dofill(void)
{
	fz_node *path;
	fz_node *solid;
	fz_node *mask;

	fz_makepath(&path, pbuild, FZ_PFILL, nil, nil);
	fz_newsolid(&solid, 1.0f, frgb[0], frgb[1], frgb[2]);
	fz_newblend(&mask, FZ_BMASK);

	fz_insertnode(mask, path);
	fz_insertnode(mask, solid);
	fz_insertnode(tree->head, mask);
}

void doxform(fz_matrix ctm)
{
	fz_node *xform;
	fz_node *over;

	fz_newtransform(&xform, ctm);
	fz_newblend(&over, FZ_BOVER);

	fz_insertnode(xform, over);
	fz_insertnode(tree->head, xform);

	tree->head = over;
}

int main(int argc, char **argv)
{
	fz_node *node;
	fz_matrix ctm;
	fz_rect r;
	int i;

	fz_newpathbuilder(&pbuild);
	fz_newtextbuilder(&tbuild);
	fz_newtree(&tree);

	fz_newblend(&node, FZ_BOVER);
	tree->root = tree->head = node;

	fz_newsolid(&node, 1, .8, .8, .8);
	fz_insertnode(tree->head, node);

	for (i = 0; cmd[i].c != '!'; i++)
	{
		switch (cmd[i].c)
		{
		case 'q':
			gsave();
			break;
		case 'Q':
			grestore();
			break;

		/* 'cm' -> 'T' ... insert xform node */
		case 'T':
			ctm.xx = cmd[i].f[0];
			ctm.xy = cmd[i].f[1];
			ctm.yx = cmd[i].f[2];
			ctm.yy = cmd[i].f[3];
			ctm.tx = cmd[i].f[4];
			ctm.ty = cmd[i].f[5];
			doxform(ctm);
			break;

		/* current color */
		case 'g':
			frgb[1] = cmd[i].f[0];
			frgb[2] = cmd[i].f[0];
			frgb[3] = cmd[i].f[0];
			break;
		case 'G':
			srgb[1] = cmd[i].f[0];
			srgb[2] = cmd[i].f[0];
			srgb[3] = cmd[i].f[0];
			break;
		case 'r':
			frgb[1] = cmd[i].f[0];
			frgb[2] = cmd[i].f[1];
			frgb[3] = cmd[i].f[2];
			break;
		case 'R':
			srgb[1] = cmd[i].f[0];
			srgb[2] = cmd[i].f[1];
			srgb[3] = cmd[i].f[2];
			break;
		case 'a':
			frgb[0] = cmd[i].f[0];
			break;
		case 'A':
			srgb[0] = cmd[i].f[0];
			break;

		/* line attrs */
		case 'w': stroke.linewidth = cmd[i].f[0]; break;
		case 'J': stroke.linecap = cmd[i].f[0]; break;
		case 'j': stroke.linejoin = cmd[i].f[0]; break;
		case 'M': stroke.miterlimit = cmd[i].f[0]; break;
		case 'i': break;

		/* path construction */
		case 'm':
			fz_moveto(pbuild, cmd[i].f[0], cmd[i].f[1]);
			break;
		case 'l':
			fz_lineto(pbuild, cmd[i].f[0], cmd[i].f[1]);
			break;
		case 'c':
			fz_curveto(pbuild,
				cmd[i].f[0], cmd[i].f[1],
				cmd[i].f[2], cmd[i].f[3],
				cmd[i].f[4], cmd[i].f[5]);
			break;
		case 'v':
			fz_curvetov(pbuild,
				cmd[i].f[0], cmd[i].f[1],
				cmd[i].f[2], cmd[i].f[3]);
			break;
		case 'y':
			fz_curvetoy(pbuild,
				cmd[i].f[0], cmd[i].f[1],
				cmd[i].f[2], cmd[i].f[3]);
			break;
		case 'h':
			fz_closepath(pbuild);
			break;

		/* insert path nodes */
		case 's':
			fz_closepath(pbuild);
		case 'S':
			dostroke();
			break;

		case 'f':
			dofill();
			break;
		}
	}

	r = fz_boundtree(tree, fz_scale(1, -1));
	printf("/* [%g %g  %g %g] */\n", r.min.x, r.min.y, r.max.x, r.max.y);
	fz_debugtree(tree);

	r.min.x -= 10;
	r.min.y -= 10;
	r.max.x += 10;
	r.max.y += 10;

#if 0
	{
		fz_pixmap *img;
		img = fz_newpixmap(r.min.x, r.min.y,
				r.max.x - r.min.x, r.max.y - r.min.y);
		fz_clearpixmap(img);

		fz_rendernode(tree, tree->root, fz_scale(1, -1), img);

		f = fopen("o.ppm", "w");
		fz_savepixmap(img, f);
		fclose(f);

		fz_freepixmap(img);
	}
#endif

	return 0;
}

