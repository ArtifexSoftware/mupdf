#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

static fz_outline *
pdf_load_outline_imp(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	fz_outline *node, **prev, *first;
	pdf_obj *obj;
	pdf_obj *odict = dict;

	fz_var(dict);
	fz_var(first);

	fz_try(ctx)
	{
		first = NULL;
		prev = &first;
		while (dict && pdf_is_dict(ctx, dict))
		{
			if (pdf_mark_obj(ctx, dict))
				break;
			node = fz_new_outline(ctx);
			*prev = node;
			prev = &node->next;

			obj = pdf_dict_get(ctx, dict, PDF_NAME_Title);
			if (obj)
				node->title = pdf_to_utf8(ctx, obj);

			if ((obj = pdf_dict_get(ctx, dict, PDF_NAME_Dest)) != NULL)
				node->uri = pdf_parse_link_dest(ctx, doc, obj);
			else if ((obj = pdf_dict_get(ctx, dict, PDF_NAME_A)) != NULL)
				node->uri = pdf_parse_link_action(ctx, doc, obj, -1);
			else
				node->uri = NULL;

			if (node->uri)
				node->page = pdf_resolve_link(ctx, doc, node->uri, NULL, NULL);
			else
				node->page = -1;

			obj = pdf_dict_get(ctx, dict, PDF_NAME_First);
			if (obj)
			{
				node->down = pdf_load_outline_imp(ctx, doc, obj);

				obj = pdf_dict_get(ctx, dict, PDF_NAME_Count);
				if (pdf_to_int(ctx, obj) > 0)
					node->is_open = 1;
			}

			dict = pdf_dict_get(ctx, dict, PDF_NAME_Next);
		}
	}
	fz_always(ctx)
	{
		for (dict = odict; dict && pdf_obj_marked(ctx, dict); dict = pdf_dict_get(ctx, dict, PDF_NAME_Next))
			pdf_unmark_obj(ctx, dict);
	}
	fz_catch(ctx)
	{
		fz_drop_outline(ctx, first);
		fz_rethrow(ctx);
	}

	return first;
}

fz_outline *
pdf_load_outline(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *root, *obj, *first;
	fz_outline *outline = NULL;

	pdf_load_page_tree(ctx, doc); /* cache page tree for fast link destination lookups */
	fz_try(ctx)
	{
		root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
		obj = pdf_dict_get(ctx, root, PDF_NAME_Outlines);
		first = pdf_dict_get(ctx, obj, PDF_NAME_First);
		if (first)
			outline = pdf_load_outline_imp(ctx, doc, first);
	}
	fz_always(ctx)
		pdf_drop_page_tree(ctx, doc);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return outline;
}
