#include <fitz.h>

/*
 * Over
 */

fz_error *
fz_newovernode(fz_node **nodep)
{
	fz_node *node;

	node = *nodep = fz_malloc(sizeof (fz_overnode));
	if (!node)
		return fz_outofmem;

	fz_initnode(node, FZ_NOVER);

	return nil;
}

fz_rect
fz_boundovernode(fz_overnode *node, fz_matrix ctm)
{
	fz_node *child;
	fz_rect bbox;
	fz_rect r;

	bbox = fz_infiniterect();

	for (child = node->super.child; child; child = child->next)
	{
		r = fz_boundnode(child, ctm);
		if (r.max.x >= r.min.x)
		{
			if (bbox.max.x >= bbox.min.x)
				bbox = fz_mergerects(r, bbox);
			else
				bbox = r;
		}
	}

	return bbox;
}

/*
 * Mask
 */

fz_error *
fz_newmasknode(fz_node **nodep)
{
	fz_node *node;

	node = *nodep = fz_malloc(sizeof (fz_masknode));
	if (!node)
		return fz_outofmem;

	fz_initnode(node, FZ_NMASK);

	return nil;
}

fz_rect
fz_boundmasknode(fz_masknode *node, fz_matrix ctm)
{
	fz_node *child;
	fz_rect bbox;
	fz_rect r;

	bbox = fz_infiniterect();

	for (child = node->super.child; child; child = child->next)
	{
		r = fz_boundnode(child, ctm);
		if (r.max.x >= r.min.x)
		{
			if (bbox.max.x >= bbox.min.x)
				bbox = fz_intersectrects(r, bbox);
			else
				bbox = r;
		}
	}

	return bbox;
}

/*
 * Blend
 */

fz_error *
fz_newblendnode(fz_node **nodep, fz_colorspace *cs, fz_blendkind b, int k, int i)
{
	fz_blendnode *node;

	node = fz_malloc(sizeof (fz_blendnode));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NBLEND);
	node->cs = cs;
	node->mode = b;
	node->knockout = k;
	node->isolated = i;

	return nil;
}

fz_rect
fz_boundblendnode(fz_blendnode *node, fz_matrix ctm)
{
	fz_node *child;
	fz_rect bbox;
	fz_rect r;

	bbox = fz_infiniterect();

	for (child = node->super.child; child; child = child->next)
	{
		r = fz_boundnode(child, ctm);
		if (r.max.x >= r.min.x)
		{
			if (bbox.max.x >= bbox.min.x)
				bbox = fz_mergerects(r, bbox);
			else
				bbox = r;
		}   
	}

	return bbox;
}

/*
 * Transform
 */

fz_error *
fz_newtransformnode(fz_node **nodep, fz_matrix m)
{
	fz_transformnode *node;

	node = fz_malloc(sizeof (fz_transformnode));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NTRANSFORM);
	node->m = m;

	return nil;
}

fz_rect
fz_boundtransformnode(fz_transformnode *node, fz_matrix ctm)
{
	if (!node->super.child)
		return fz_infiniterect();
	return fz_boundnode(node->super.child, fz_concat(node->m, ctm));
}

/*
 * Meta info
 */

fz_error *
fz_newmetanode(fz_node **nodep, fz_obj *name, fz_obj *dict)
{
	fz_metanode *node;

	node = fz_malloc(sizeof (fz_metanode));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NMETA);
	node->name = nil;
	node->dict = nil;

	if (name)
		node->name = fz_keepobj(name);
	if (dict)
		node->dict = fz_keepobj(dict);

	return nil;
}

void
fz_dropmetanode(fz_metanode *node)
{
	if (node->name)
		fz_dropobj(node->name);
	if (node->dict)
		fz_dropobj(node->dict);
}

fz_rect
fz_boundmetanode(fz_metanode *node, fz_matrix ctm)
{
	if (!node->super.child)
		return fz_infiniterect();
	return fz_boundnode(node->super.child, ctm);
}

/*
 * Link to tree
 */

fz_error *
fz_newlinknode(fz_node **nodep, fz_tree *subtree)
{
	fz_linknode *node;

	node = fz_malloc(sizeof (fz_linknode));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NLINK);
	node->tree = fz_keeptree(subtree);

	return nil;
}

void
fz_droplinknode(fz_linknode *node)
{
	fz_droptree(node->tree);
}

fz_rect
fz_boundlinknode(fz_linknode *node, fz_matrix ctm)
{
	return fz_boundtree(node->tree, ctm);
}

/*
 * Solid color
 */

fz_error *
fz_newcolornode(fz_node **nodep, fz_colorspace *cs, int n, float *v)
{
	fz_colornode *node;
	int i;

	node = fz_malloc(sizeof(fz_colornode) + sizeof(float) * n);
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NCOLOR);
	node->cs = cs;
	node->n = n;
	for (i = 0; i < n; i++)
		node->samples[i] = v[i];

	return nil;
}

fz_rect
fz_boundcolornode(fz_colornode *node, fz_matrix ctm)
{
	return fz_infiniterect();
}

/*
 * Image node
 */

fz_error *
fz_newimagenode(fz_node **nodep, fz_image *image)
{
	fz_imagenode *node;

	node = fz_malloc(sizeof (fz_imagenode));
	if (!node)
		return fz_outofmem;
	*nodep = (fz_node*)node;

	fz_initnode((fz_node*)node, FZ_NIMAGE);
	node->image = image;

	return nil;
}

void
fz_dropimagenode(fz_imagenode *node)
{
	// XXX fz_dropimage(node->image);
}

fz_rect
fz_boundimagenode(fz_imagenode *node, fz_matrix ctm)
{
	fz_point ll, lr, ul, ur;
	fz_rect r;

	ll = fz_transformpoint(ctm, (fz_point){0,0});
	lr = fz_transformpoint(ctm, (fz_point){1,0});
	ul = fz_transformpoint(ctm, (fz_point){0,1});
	ur = fz_transformpoint(ctm, (fz_point){1,1});

	r.min.x = MIN4(ll.x, lr.x, ul.x, ur.x);
	r.min.y = MIN4(ll.y, lr.y, ul.y, ur.y);
	r.max.x = MAX4(ll.x, lr.x, ul.x, ur.x);
	r.max.y = MAX4(ll.y, lr.y, ul.y, ur.y);

	return r;
}

