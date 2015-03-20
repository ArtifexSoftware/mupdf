#include "mupdf/pdf.h"

static pdf_obj *
pdf_lookup_name_imp(fz_context *ctx, pdf_obj *node, pdf_obj *needle)
{
	pdf_obj *kids = pdf_dict_get(ctx, node, PDF_NAME_Kids);
	pdf_obj *names = pdf_dict_get(ctx, node, PDF_NAME_Names);

	if (pdf_is_array(ctx, kids))
	{
		int l = 0;
		int r = pdf_array_len(ctx, kids) - 1;

		while (l <= r)
		{
			int m = (l + r) >> 1;
			pdf_obj *kid = pdf_array_get(ctx, kids, m);
			pdf_obj *limits = pdf_dict_get(ctx, kid, PDF_NAME_Limits);
			pdf_obj *first = pdf_array_get(ctx, limits, 0);
			pdf_obj *last = pdf_array_get(ctx, limits, 1);

			if (pdf_objcmp(ctx, needle, first) < 0)
				r = m - 1;
			else if (pdf_objcmp(ctx, needle, last) > 0)
				l = m + 1;
			else
			{
				pdf_obj *obj;

				if (pdf_mark_obj(ctx, node))
					break;
				obj = pdf_lookup_name_imp(ctx, kid, needle);
				pdf_unmark_obj(ctx, node);
				return obj;
			}
		}
	}

	if (pdf_is_array(ctx, names))
	{
		int l = 0;
		int r = (pdf_array_len(ctx, names) / 2) - 1;

		while (l <= r)
		{
			int m = (l + r) >> 1;
			int c;
			pdf_obj *key = pdf_array_get(ctx, names, m * 2);
			pdf_obj *val = pdf_array_get(ctx, names, m * 2 + 1);

			c = pdf_objcmp(ctx, needle, key);
			if (c < 0)
				r = m - 1;
			else if (c > 0)
				l = m + 1;
			else
				return val;
		}

		/* Spec says names should be sorted (hence the binary search,
		 * above), but Acrobat copes with non-sorted. Drop back to a
		 * simple search if the binary search fails. */
		r = pdf_array_len(ctx, names)/2;
		for (l = 0; l < r; l++)
			if (!pdf_objcmp(ctx, needle, pdf_array_get(ctx, names, l * 2)))
				return pdf_array_get(ctx, names, l * 2 + 1);
	}

	return NULL;
}

pdf_obj *
pdf_lookup_name(fz_context *ctx, pdf_document *doc, pdf_obj *which, pdf_obj *needle)
{
	pdf_obj *root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
	pdf_obj *names = pdf_dict_get(ctx, root, PDF_NAME_Names);
	pdf_obj *tree = pdf_dict_get(ctx, names, which);
	return pdf_lookup_name_imp(ctx, tree, needle);
}

pdf_obj *
pdf_lookup_dest(fz_context *ctx, pdf_document *doc, pdf_obj *needle)
{
	pdf_obj *root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
	pdf_obj *dests = pdf_dict_get(ctx, root, PDF_NAME_Dests);
	pdf_obj *names = pdf_dict_get(ctx, root, PDF_NAME_Names);
	pdf_obj *dest = NULL;

	/* PDF 1.1 has destinations in a dictionary */
	if (dests)
	{
		if (pdf_is_name(ctx, needle))
			return pdf_dict_get(ctx, dests, needle);
		else
			return pdf_dict_gets(ctx, dests, pdf_to_str_buf(ctx, needle));
	}

	/* PDF 1.2 has destinations in a name tree */
	if (names && !dest)
	{
		pdf_obj *tree = pdf_dict_get(ctx, names, PDF_NAME_Dests);
		return pdf_lookup_name_imp(ctx, tree, needle);
	}

	return NULL;
}

static void
pdf_load_name_tree_imp(fz_context *ctx, pdf_obj *dict, pdf_document *doc, pdf_obj *node)
{
	pdf_obj *kids = pdf_dict_get(ctx, node, PDF_NAME_Kids);
	pdf_obj *names = pdf_dict_get(ctx, node, PDF_NAME_Names);
	int i;

	UNUSED(ctx);

	if (kids && !pdf_mark_obj(ctx, node))
	{
		int len = pdf_array_len(ctx, kids);
		for (i = 0; i < len; i++)
			pdf_load_name_tree_imp(ctx, dict, doc, pdf_array_get(ctx, kids, i));
		pdf_unmark_obj(ctx, node);
	}

	if (names)
	{
		int len = pdf_array_len(ctx, names);
		for (i = 0; i + 1 < len; i += 2)
		{
			pdf_obj *key = pdf_array_get(ctx, names, i);
			pdf_obj *val = pdf_array_get(ctx, names, i + 1);
			if (pdf_is_string(ctx, key))
			{
				key = pdf_to_utf8_name(ctx, doc, key);
				pdf_dict_put(ctx, dict, key, val);
				pdf_drop_obj(ctx, key);
			}
			else if (pdf_is_name(ctx, key))
			{
				pdf_dict_put(ctx, dict, key, val);
			}
		}
	}
}

pdf_obj *
pdf_load_name_tree(fz_context *ctx, pdf_document *doc, pdf_obj *which)
{
	pdf_obj *root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
	pdf_obj *names = pdf_dict_get(ctx, root, PDF_NAME_Names);
	pdf_obj *tree = pdf_dict_get(ctx, names, which);
	if (pdf_is_dict(ctx, tree))
	{
		pdf_obj *dict = pdf_new_dict(ctx, doc, 100);
		pdf_load_name_tree_imp(ctx, dict, doc, tree);
		return dict;
	}
	return NULL;
}
