#include "fitz.h"
#include "mupdf.h"

static fz_outline *
pdf_load_outline_imp(pdf_xref *xref, fz_obj *dict)
{
	fz_context *ctx = xref->ctx;
	fz_outline *node, **prev, *first;
	fz_obj *obj;

	if (fz_is_null(dict))
		return NULL;

	first = NULL;
	prev = &first;
	while (dict)
	{
		node = fz_malloc_struct(ctx, fz_outline);
		node->ctx = ctx;
		node->title = NULL;
		node->dest.kind = FZ_LINK_NONE;
		node->down = NULL;
		node->next = NULL;
		*prev = node;
		prev = &node->next;

		obj = fz_dict_gets(dict, "Title");
		if (obj)
			node->title = pdf_to_utf8(ctx, obj);

		if ((obj = fz_dict_gets(dict, "Dest")))
			node->dest = pdf_parse_link_dest(xref, obj);
		else if ((obj = fz_dict_gets(dict, "A")))
			node->dest = pdf_parse_action(xref, obj);

		obj = fz_dict_gets(dict, "First");
		if (obj)
			node->down = pdf_load_outline_imp(xref, obj);

		dict = fz_dict_gets(dict, "Next");
	}

	return first;
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
