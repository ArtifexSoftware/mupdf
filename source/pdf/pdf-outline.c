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
			node = fz_malloc_struct(ctx, fz_outline);
			node->title = NULL;
			node->dest.kind = FZ_LINK_NONE;
			node->down = NULL;
			node->next = NULL;
			node->is_open = 0;
			*prev = node;
			prev = &node->next;

			obj = pdf_dict_get(ctx, dict, PDF_NAME_Title);
			if (obj)
				node->title = pdf_to_utf8(ctx, doc, obj);

			if ((obj = pdf_dict_get(ctx, dict, PDF_NAME_Dest)) != NULL)
				node->dest = pdf_parse_link_dest(ctx, doc, FZ_LINK_GOTO, obj);
			else if ((obj = pdf_dict_get(ctx, dict, PDF_NAME_A)) != NULL)
				node->dest = pdf_parse_action(ctx, doc, obj);

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

	root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
	obj = pdf_dict_get(ctx, root, PDF_NAME_Outlines);
	first = pdf_dict_get(ctx, obj, PDF_NAME_First);
	if (first)
		return pdf_load_outline_imp(ctx, doc, first);

	return NULL;
}
