#include "fitz.h"
#include "mupdf.h"

static fz_outline *
pdf_load_outline_imp(pdf_xref *xref, fz_obj *dict)
{
	pdf_link *link;
	fz_outline *node;
	fz_obj *obj;

	if (fz_is_null(dict))
		return NULL;

	node = fz_malloc(sizeof(fz_outline));
	node->title = NULL;
	node->page = 0;
	node->down = NULL;
	node->next = NULL;

	obj = fz_dict_gets(dict, "Title");
	if (obj)
		node->title = pdf_to_utf8(obj);

	if (fz_dict_gets(dict, "Dest") || fz_dict_gets(dict, "A"))
	{
		link = pdf_load_link(xref, dict);
		if (link->kind == PDF_LINK_GOTO)
			node->page = pdf_find_page_number(xref, fz_array_get(link->dest, 0));
		pdf_free_link(link);
	}

	obj = fz_dict_gets(dict, "First");
	if (obj)
		node->down = pdf_load_outline_imp(xref, obj);

	obj = fz_dict_gets(dict, "Next");
	if (obj)
		node->next = pdf_load_outline_imp(xref, obj);

	return node;
}

fz_outline *
pdf_load_outline(pdf_xref *xref)
{
	fz_obj *root, *obj, *first;

	root = fz_dict_gets(xref->trailer, "Root");
	obj = fz_dict_gets(root, "Outlines");
	first = fz_dict_gets(obj, "First");
	if (first)
		return pdf_load_outline_imp(xref, first);

	return NULL;
}
