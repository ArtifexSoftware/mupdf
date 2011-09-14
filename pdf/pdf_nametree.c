#include "fitz.h"
#include "mupdf.h"

static fz_obj *
pdf_lookup_name_imp(fz_context *ctx, fz_obj *node, fz_obj *needle)
{
	fz_obj *kids = fz_dict_gets(ctx, node, "Kids");
	fz_obj *names = fz_dict_gets(ctx, node, "Names");

	if (fz_is_array(ctx, kids))
	{
		int l = 0;
		int r = fz_array_len(ctx, kids) - 1;

		while (l <= r)
		{
			int m = (l + r) >> 1;
			fz_obj *kid = fz_array_get(ctx, kids, m);
			fz_obj *limits = fz_dict_gets(ctx, kid, "Limits");
			fz_obj *first = fz_array_get(ctx, limits, 0);
			fz_obj *last = fz_array_get(ctx, limits, 1);

			if (fz_objcmp(needle, first) < 0)
				r = m - 1;
			else if (fz_objcmp(needle, last) > 0)
				l = m + 1;
			else
			return pdf_lookup_name_imp(ctx, kid, needle);
		}
	}

	if (fz_is_array(ctx, names))
	{
		int l = 0;
		int r = (fz_array_len(ctx, names) / 2) - 1;

		while (l <= r)
		{
			int m = (l + r) >> 1;
			int c;
			fz_obj *key = fz_array_get(ctx, names, m * 2);
			fz_obj *val = fz_array_get(ctx, names, m * 2 + 1);

			c = fz_objcmp(needle, key);
			if (c < 0)
				r = m - 1;
			else if (c > 0)
				l = m + 1;
			else
				return val;
		}
	}

	return NULL;
}

fz_obj *
pdf_lookup_name(pdf_xref *xref, char *which, fz_obj *needle)
{
	fz_context *ctx = xref->ctx;

	fz_obj *root = fz_dict_gets(ctx, xref->trailer, "Root");
	fz_obj *names = fz_dict_gets(ctx, root, "Names");
	fz_obj *tree = fz_dict_gets(ctx, names, which);
	return pdf_lookup_name_imp(ctx, tree, needle);
}

fz_obj *
pdf_lookup_dest(pdf_xref *xref, fz_obj *needle)
{
	fz_context *ctx = xref->ctx;

	fz_obj *root = fz_dict_gets(ctx, xref->trailer, "Root");
	fz_obj *dests = fz_dict_gets(ctx, root, "Dests");
	fz_obj *names = fz_dict_gets(ctx, root, "Names");
	fz_obj *dest = NULL;

	/* PDF 1.1 has destinations in a dictionary */
	if (dests)
	{
		if (fz_is_name(ctx, needle))
			return fz_dict_get(ctx, dests, needle);
		else
			return fz_dict_gets(ctx, dests, fz_to_str_buf(ctx, needle));
	}

	/* PDF 1.2 has destinations in a name tree */
	if (names && !dest)
	{
		fz_obj *tree = fz_dict_gets(ctx, names, "Dests");
		return pdf_lookup_name_imp(ctx, tree, needle);
	}

	return NULL;
}

static void
pdf_load_name_tree_imp(fz_obj *dict, pdf_xref *xref, fz_obj *node)
{
	fz_context *ctx = xref->ctx;
	fz_obj *kids = fz_dict_gets(ctx, node, "Kids");
	fz_obj *names = fz_dict_gets(ctx, node, "Names");
	int i;

	if (kids)
	{
		for (i = 0; i < fz_array_len(ctx, kids); i++)
			pdf_load_name_tree_imp(dict, xref, fz_array_get(ctx, kids, i));
	}

	if (names)
	{
		for (i = 0; i + 1 < fz_array_len(ctx, names); i += 2)
		{
			fz_obj *key = fz_array_get(ctx, names, i);
			fz_obj *val = fz_array_get(ctx, names, i + 1);
			if (fz_is_string(ctx, key))
			{
				key = pdf_to_utf8_name(ctx, key);
				fz_dict_put(ctx, dict, key, val);
				fz_drop_obj(ctx, key);
			}
			else if (fz_is_name(ctx, key))
			{
				fz_dict_put(ctx, dict, key, val);
			}
		}
	}
}

fz_obj *
pdf_load_name_tree(pdf_xref *xref, char *which)
{
	fz_context *ctx = xref->ctx;

	fz_obj *root = fz_dict_gets(ctx, xref->trailer, "Root");
	fz_obj *names = fz_dict_gets(ctx, root, "Names");
	fz_obj *tree = fz_dict_gets(ctx, names, which);
	if (fz_is_dict(ctx, tree))
	{
		fz_obj *dict = fz_new_dict(ctx, 100);
		pdf_load_name_tree_imp(dict, xref, tree);
		return dict;
	}
	return NULL;
}
