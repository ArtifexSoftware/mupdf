#include "fitz.h"
#include "mupdf.h"

struct info
{
	fz_obj *resources;
	fz_obj *mediabox;
	fz_obj *cropbox;
	fz_obj *rotate;
};

int
pdf_get_page_count(pdf_xref *xref)
{
	return xref->page_len;
}

fz_obj *
pdf_get_page_object(pdf_xref *xref, int number)
{
	if (number > 0 && number <= xref->page_len)
		return xref->page_objs[number - 1];
	return NULL;
}

fz_obj *
pdf_get_page_ref(pdf_xref *xref, int number)
{
	if (number > 0 && number <= xref->page_len)
		return xref->page_refs[number - 1];
	return NULL;
}

int
pdf_find_page_object(pdf_xref *xref, fz_obj *page)
{
	int num = fz_to_num(page);
	int gen = fz_to_gen(page);
	int i;
	for (i = 0; i < xref->page_len; i++)
		if (num == fz_to_num(xref->page_refs[i]) && gen == fz_to_gen(xref->page_refs[i]))
			return i + 1;
	return 0;
}

static void
pdf_load_page_tree_node(pdf_xref *xref, fz_obj *node, struct info info)
{
	fz_obj *dict, *kids, *count;
	fz_obj *obj, *tmp;
	int i, n;

	/* prevent infinite recursion */
	if (fz_dict_gets(node, ".seen"))
		return;

	kids = fz_dict_gets(node, "Kids");
	count = fz_dict_gets(node, "Count");

	if (fz_is_array(kids) && fz_is_int(count))
	{
		obj = fz_dict_gets(node, "Resources");
		if (obj)
			info.resources = obj;
		obj = fz_dict_gets(node, "MediaBox");
		if (obj)
			info.mediabox = obj;
		obj = fz_dict_gets(node, "CropBox");
		if (obj)
			info.cropbox = obj;
		obj = fz_dict_gets(node, "Rotate");
		if (obj)
			info.rotate = obj;

		tmp = fz_new_null();
		fz_dict_puts(node, ".seen", tmp);
		fz_drop_obj(tmp);

		n = fz_array_len(kids);
		for (i = 0; i < n; i++)
		{
			obj = fz_array_get(kids, i);
			pdf_load_page_tree_node(xref, obj, info);
		}

		fz_dict_dels(node, ".seen");
	}
	else
	{
		dict = fz_resolve_indirect(node);

		if (info.resources && !fz_dict_gets(dict, "Resources"))
			fz_dict_puts(dict, "Resources", info.resources);
		if (info.mediabox && !fz_dict_gets(dict, "MediaBox"))
			fz_dict_puts(dict, "MediaBox", info.mediabox);
		if (info.cropbox && !fz_dict_gets(dict, "CropBox"))
			fz_dict_puts(dict, "CropBox", info.cropbox);
		if (info.rotate && !fz_dict_gets(dict, "Rotate"))
			fz_dict_puts(dict, "Rotate", info.rotate);

		if (xref->page_len == xref->page_cap)
		{
			fz_warn("found more pages than expected");
			xref->page_cap ++;
			xref->page_refs = fz_realloc(xref->page_refs, xref->page_cap, sizeof(fz_obj*));
			xref->page_objs = fz_realloc(xref->page_objs, xref->page_cap, sizeof(fz_obj*));
		}

		xref->page_refs[xref->page_len] = fz_keep_obj(node);
		xref->page_objs[xref->page_len] = fz_keep_obj(dict);
		xref->page_len ++;
	}
}

fz_error
pdf_load_page_tree(pdf_xref *xref)
{
	struct info info;
	fz_obj *catalog = fz_dict_gets(xref->trailer, "Root");
	fz_obj *pages = fz_dict_gets(catalog, "Pages");
	fz_obj *count = fz_dict_gets(pages, "Count");

	if (!fz_is_dict(pages))
		return fz_throw("missing page tree");
	if (!fz_is_int(count))
		return fz_throw("missing page count");

	xref->page_cap = fz_to_int(count);
	xref->page_len = 0;
	xref->page_refs = fz_calloc(xref->page_cap, sizeof(fz_obj*));
	xref->page_objs = fz_calloc(xref->page_cap, sizeof(fz_obj*));

	info.resources = NULL;
	info.mediabox = NULL;
	info.cropbox = NULL;
	info.rotate = NULL;

	pdf_load_page_tree_node(xref, pages, info);

	return fz_okay;
}
