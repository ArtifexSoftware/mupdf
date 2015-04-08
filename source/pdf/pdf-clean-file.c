#include "mupdf/pdf.h"

typedef struct globals_s
{
	pdf_document *doc;
	fz_context *ctx;
} globals;

static int
string_in_names_list(fz_context *ctx, pdf_obj *p, pdf_obj *names_list)
{
	int n = pdf_array_len(ctx, names_list);
	int i;
	char *str = pdf_to_str_buf(ctx, p);

	for (i = 0; i < n ; i += 2)
	{
		if (!strcmp(pdf_to_str_buf(ctx, pdf_array_get(ctx, names_list, i)), str))
			return 1;
	}
	return 0;
}

/*
 * Recreate page tree to only retain specified pages.
 */

static void retainpage(fz_context *ctx, pdf_document *doc, pdf_obj *parent, pdf_obj *kids, int page)
{
	pdf_obj *pageref = pdf_lookup_page_obj(ctx, doc, page-1);
	pdf_obj *pageobj = pdf_resolve_indirect(ctx, pageref);

	pdf_dict_put(ctx, pageobj, PDF_NAME_Parent, parent);

	/* Store page object in new kids array */
	pdf_array_push(ctx, kids, pageref);
}

static void retainpages(fz_context *ctx, globals *glo, int argc, char **argv)
{
	pdf_obj *oldroot, *root, *pages, *kids, *countobj, *parent, *olddests;
	pdf_document *doc = glo->doc;
	int argidx = 0;
	pdf_obj *names_list = NULL;
	int pagecount;
	int i;

	/* Keep only pages/type and (reduced) dest entries to avoid
	 * references to unretained pages */
	oldroot = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
	pages = pdf_dict_get(ctx, oldroot, PDF_NAME_Pages);
	olddests = pdf_load_name_tree(ctx, doc, PDF_NAME_Dests);

	root = pdf_new_dict(ctx, doc, 2);
	pdf_dict_put(ctx, root, PDF_NAME_Type, pdf_dict_get(ctx, oldroot, PDF_NAME_Type));
	pdf_dict_put(ctx, root, PDF_NAME_Pages, pdf_dict_get(ctx, oldroot, PDF_NAME_Pages));

	pdf_update_object(ctx, doc, pdf_to_num(ctx, oldroot), root);

	pdf_drop_obj(ctx, root);

	/* Create a new kids array with only the pages we want to keep */
	parent = pdf_new_indirect(ctx, doc, pdf_to_num(ctx, pages), pdf_to_gen(ctx, pages));
	kids = pdf_new_array(ctx, doc, 1);

	/* Retain pages specified */
	while (argc - argidx)
	{
		int page, spage, epage;
		char *spec, *dash;
		char *pagelist = argv[argidx];

		pagecount = pdf_count_pages(ctx, doc);
		spec = fz_strsep(&pagelist, ",");
		while (spec)
		{
			dash = strchr(spec, '-');

			if (dash == spec)
				spage = epage = pagecount;
			else
				spage = epage = atoi(spec);

			if (dash)
			{
				if (strlen(dash) > 1)
					epage = atoi(dash + 1);
				else
					epage = pagecount;
			}

			spage = fz_clampi(spage, 1, pagecount);
			epage = fz_clampi(epage, 1, pagecount);

			if (spage < epage)
				for (page = spage; page <= epage; ++page)
					retainpage(ctx, doc, parent, kids, page);
			else
				for (page = spage; page >= epage; --page)
					retainpage(ctx, doc, parent, kids, page);

			spec = fz_strsep(&pagelist, ",");
		}

		argidx++;
	}

	pdf_drop_obj(ctx, parent);

	/* Update page count and kids array */
	countobj = pdf_new_int(ctx, doc, pdf_array_len(ctx, kids));
	pdf_dict_put(ctx, pages, PDF_NAME_Count, countobj);
	pdf_drop_obj(ctx, countobj);
	pdf_dict_put(ctx, pages, PDF_NAME_Kids, kids);
	pdf_drop_obj(ctx, kids);

	/* Also preserve the (partial) Dests name tree */
	if (olddests)
	{
		pdf_obj *names = pdf_new_dict(ctx, doc, 1);
		pdf_obj *dests = pdf_new_dict(ctx, doc, 1);
		int len = pdf_dict_len(ctx, olddests);

		names_list = pdf_new_array(ctx, doc, 32);

		for (i = 0; i < len; i++)
		{
			pdf_obj *key = pdf_dict_get_key(ctx, olddests, i);
			pdf_obj *val = pdf_dict_get_val(ctx, olddests, i);
			pdf_obj *dest = pdf_dict_get(ctx, val, PDF_NAME_D);

			dest = pdf_array_get(ctx, dest ? dest : val, 0);
			if (pdf_array_contains(ctx, pdf_dict_get(ctx, pages, PDF_NAME_Kids), dest))
			{
				pdf_obj *key_str = pdf_new_string(ctx, doc, pdf_to_name(ctx, key), strlen(pdf_to_name(ctx, key)));
				pdf_array_push(ctx, names_list, key_str);
				pdf_array_push(ctx, names_list, val);
				pdf_drop_obj(ctx, key_str);
			}
		}

		root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
		pdf_dict_put(ctx, dests, PDF_NAME_Names, names_list);
		pdf_dict_put(ctx, names, PDF_NAME_Dests, dests);
		pdf_dict_put(ctx, root, PDF_NAME_Names, names);

		pdf_drop_obj(ctx, names);
		pdf_drop_obj(ctx, dests);
		pdf_drop_obj(ctx, names_list);
		pdf_drop_obj(ctx, olddests);
	}

	/* Force the next call to pdf_count_pages to recount */
	glo->doc->page_count = 0;

	/* Edit each pages /Annot list to remove any links that point to
	 * nowhere. */
	pagecount = pdf_count_pages(ctx, doc);
	for (i = 0; i < pagecount; i++)
	{
		pdf_obj *pageref = pdf_lookup_page_obj(ctx, doc, i);
		pdf_obj *pageobj = pdf_resolve_indirect(ctx, pageref);

		pdf_obj *annots = pdf_dict_get(ctx, pageobj, PDF_NAME_Annots);

		int len = pdf_array_len(ctx, annots);
		int j;

		for (j = 0; j < len; j++)
		{
			pdf_obj *o = pdf_array_get(ctx, annots, j);
			pdf_obj *p;

			if (!pdf_name_eq(ctx, pdf_dict_get(ctx, o, PDF_NAME_Subtype), PDF_NAME_Link))
				continue;

			p = pdf_dict_get(ctx, o, PDF_NAME_A);
			if (!pdf_name_eq(ctx, pdf_dict_get(ctx, p, PDF_NAME_S), PDF_NAME_GoTo))
				continue;

			if (string_in_names_list(ctx, pdf_dict_get(ctx, p, PDF_NAME_D), names_list))
				continue;

			/* FIXME: Should probably look at Next too */

			/* Remove this annotation */
			pdf_array_delete(ctx, annots, j);
			j--;
		}
	}
}

void pdf_clean_file(fz_context *ctx, char *infile, char *outfile, char *password, fz_write_options *opts, char *argv[], int argc)
{
	globals glo = { 0 };

	glo.ctx = ctx;

	fz_try(ctx)
	{
		glo.doc = pdf_open_document(ctx, infile);
		if (pdf_needs_password(ctx, glo.doc))
			if (!pdf_authenticate_password(ctx, glo.doc, password))
				fz_throw(glo.ctx, FZ_ERROR_GENERIC, "cannot authenticate password: %s", infile);

		/* Only retain the specified subset of the pages */
		if (argc)
			retainpages(ctx, &glo, argc, argv);

		pdf_write_document(ctx, glo.doc, outfile, opts);
	}
	fz_always(ctx)
	{
		pdf_close_document(ctx, glo.doc);
	}
	fz_catch(ctx)
	{
		if (opts && opts->errors)
			*opts->errors = *opts->errors+1;
	}
}
