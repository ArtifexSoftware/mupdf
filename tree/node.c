#include <fitz.h>

void fz_freeover(fz_over* node);
void fz_freemask(fz_mask* node);
void fz_freeblend(fz_blend* node);
void fz_freetransform(fz_transform* node);
void fz_freeform(fz_form* node);
void fz_freesolid(fz_solid* node);
void fz_freepath(fz_path* node);
void fz_freetext(fz_text* node);
void fz_freeimage(fz_image* node);

fz_rect fz_boundover(fz_over* node, fz_matrix ctm);
fz_rect fz_boundmask(fz_mask* node, fz_matrix ctm);
fz_rect fz_boundblend(fz_blend* node, fz_matrix ctm);
fz_rect fz_boundtransform(fz_transform* node, fz_matrix ctm);
fz_rect fz_boundform(fz_form* node, fz_matrix ctm);
fz_rect fz_boundsolid(fz_solid* node, fz_matrix ctm);
fz_rect fz_boundpath(fz_path* node, fz_matrix ctm);
fz_rect fz_boundtext(fz_text* node, fz_matrix ctm);
fz_rect fz_boundimage(fz_image* node, fz_matrix ctm);

void
fz_initnode(fz_node *node, fz_nodekind kind)
{
	node->kind = kind;
	node->parent = nil;
}

void
fz_freenode(fz_node *node)
{
	if (node->next)
		fz_freenode(node->next);

	switch (node->kind)
	{
	case FZ_NOVER:
		fz_freeover((fz_over *) node);
		break;
	case FZ_NMASK:
		fz_freemask((fz_mask *) node);
		break;
	case FZ_NBLEND:
		fz_freeblend((fz_blend *) node);
		break;
	case FZ_NTRANSFORM:
		fz_freetransform((fz_transform *) node);
		break;
	case FZ_NFORM:
		fz_freeform((fz_form *) node);
		break;
	case FZ_NSOLID:
		fz_freesolid((fz_solid *) node);
		break;
	case FZ_NPATH:
		fz_freepath((fz_path *) node);
		break;
	case FZ_NTEXT:
		fz_freetext((fz_text *) node);
		break;
	case FZ_NIMAGE:
		fz_freeimage((fz_image *) node);
		break;
	}
}

fz_rect
fz_boundnode(fz_node *node, fz_matrix ctm)
{
	switch (node->kind)
	{
	case FZ_NOVER:
		return fz_boundover((fz_over *) node, ctm);
	case FZ_NMASK:
		return fz_boundmask((fz_mask *) node, ctm);
	case FZ_NBLEND:
		return fz_boundblend((fz_blend *) node, ctm);
	case FZ_NTRANSFORM:
		return fz_boundtransform((fz_transform *) node, ctm);
	case FZ_NFORM:
		return fz_boundform((fz_form *) node, ctm);
	case FZ_NSOLID:
		return fz_boundsolid((fz_solid *) node, ctm);
	case FZ_NPATH:
		return fz_boundpath((fz_path *) node, ctm);
	case FZ_NTEXT:
		return fz_boundtext((fz_text *) node, ctm);
	case FZ_NIMAGE:
		return fz_boundimage((fz_image *) node, ctm);
	}
	return FZ_INFRECT;
}

int
fz_isover(fz_node *node)
{
	return node ? node->kind == FZ_NOVER : 0;
}

int
fz_ismask(fz_node *node)
{
	return node ? node->kind == FZ_NMASK : 0;
}

int
fz_isblend(fz_node *node)
{
	return node ? node->kind == FZ_NBLEND : 0;
}

int
fz_istransform(fz_node *node)
{
	return node ? node->kind == FZ_NTRANSFORM : 0;
}

int
fz_isform(fz_node *node)
{
	return node ? node->kind == FZ_NFORM : 0;
}

int
fz_issolid(fz_node *node)
{
	return node ? node->kind == FZ_NSOLID : 0;
}

int
fz_ispath(fz_node *node)
{
	return node ? node->kind == FZ_NPATH : 0;
}

int
fz_istext(fz_node *node)
{
	return node ? node->kind == FZ_NTEXT : 0;
}

int
fz_isimage(fz_node *node)
{
	return node ? node->kind == FZ_NIMAGE : 0;
}

