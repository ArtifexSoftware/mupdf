#include "fitz.h"
#include "mupdf.h"

static pdf_outline *
pdf_load_outline_imp(pdf_xref *xref, fz_obj *dict)
{
	pdf_outline *node;
	fz_obj *obj;
	fz_context *ctx = xref->ctx;

	if (fz_is_null(ctx, dict))
		return NULL;

	node = fz_malloc(ctx, sizeof(pdf_outline));
	node->title = NULL;
	node->link = NULL;
	node->child = NULL;
	node->next = NULL;
	node->count = 0;

	obj = fz_dict_gets(ctx, dict, "Title");
	if (obj)
		node->title = pdf_to_utf8(ctx, obj);

	obj = fz_dict_gets(ctx, dict, "Count");
	if (obj)
		node->count = fz_to_int(ctx, obj);

	if (fz_dict_gets(ctx, dict, "Dest") || fz_dict_gets(ctx, dict, "A"))
		node->link = pdf_load_link(xref, dict);

	obj = fz_dict_gets(ctx, dict, "First");
	if (obj)
		node->child = pdf_load_outline_imp(xref, obj);

	obj = fz_dict_gets(ctx, dict, "Next");
	if (obj)
		node->next = pdf_load_outline_imp(xref, obj);

	return node;
}

pdf_outline *
pdf_load_outline(pdf_xref *xref)
{
	fz_obj *root, *obj, *first;
	fz_context *ctx = xref->ctx;

	root = fz_dict_gets(ctx, xref->trailer, "Root");
	obj = fz_dict_gets(ctx, root, "Outlines");
	first = fz_dict_gets(ctx, obj, "First");
	if (first)
		return pdf_load_outline_imp(xref, first);

	return NULL;
}

void
pdf_free_outline(fz_context *ctx, pdf_outline *outline)
{
	if (outline->child)
		pdf_free_outline(ctx, outline->child);
	if (outline->next)
		pdf_free_outline(ctx, outline->next);
	if (outline->link)
		pdf_free_link(ctx, outline->link);
	fz_free(ctx, outline->title);
	fz_free(ctx, outline);
}

void
pdf_debug_outline(fz_context *ctx, pdf_outline *outline, int level)
{
	int i;
	while (outline)
	{
		for (i = 0; i < level; i++)
			putchar(' ');

		if (outline->title)
			printf("%s ", outline->title);
		else
			printf("<NULL> ");

		if (outline->link)
			fz_debug_obj(ctx, outline->link->dest);
		else
			printf("<NULL>\n");

		if (outline->child)
			pdf_debug_outline(ctx, outline->child, level + 2);

		outline = outline->next;
	}
}
