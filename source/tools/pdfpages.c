/*
 * Information tool.
 * Print information about pages of a pdf.
 */

#include "mupdf/pdf.h"

static void
infousage(void)
{
	fprintf(stderr,
		"usage: mutool pages [options] file.pdf [pages]\n"
		"\t-p -\tpassword for decryption\n"
		"\tpages\tcomma separated list of page numbers and ranges\n"
		);
	exit(1);
}

static int
showbox(fz_context *ctx, fz_output *out, pdf_obj *page, char *text, pdf_obj *name)
{
	fz_rect bbox;
	pdf_obj *obj;
	int failed = 0;

	fz_try(ctx)
	{
		obj = pdf_dict_get(ctx, page, name);
		if (!pdf_is_array(ctx, obj))
			break;

		pdf_to_rect(ctx, obj, &bbox);

		fz_printf(ctx, out, "<%s l=\"%g\" b=\"%g\" r=\"%g\" t=\"%g\" />\n", text, bbox.x0, bbox.y0, bbox.x1, bbox.y1);
	}
	fz_catch(ctx)
	{
		failed = 1;
	}

	return failed;
}

static int
shownum(fz_context *ctx, fz_output *out, pdf_obj *page, char *text, pdf_obj *name)
{
	pdf_obj *obj;
	int failed = 0;

	fz_try(ctx)
	{
		obj = pdf_dict_get(ctx, page, name);
		if (!pdf_is_number(ctx, obj))
			break;

		fz_printf(ctx, out, "<%s v=\"%g\" />\n", text, pdf_to_real(ctx, obj));
	}
	fz_catch(ctx)
	{
		failed = 1;
	}

	return failed;
}

static int
showpage(fz_context *ctx, pdf_document *doc, fz_output *out, int page)
{
	pdf_obj *pageobj;
	pdf_obj *pageref;
	int failed = 0;

	fz_printf(ctx, out, "<page pagenum=\"%d\">\n", page);
	fz_try(ctx)
	{
		pageref = pdf_lookup_page_obj(ctx, doc, page-1);
		pageobj = pdf_resolve_indirect(ctx, pageref);

		if (!pageobj)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot retrieve info from page %d", page);
	}
	fz_catch(ctx)
	{
		fz_printf(ctx, out, "Failed to gather information for page %d\n", page);
		failed = 1;
	}

	if (!failed)
	{
		failed |= showbox(ctx, out, pageobj, "MediaBox", PDF_NAME_MediaBox);
		failed |= showbox(ctx, out, pageobj, "CropBox", PDF_NAME_CropBox);
		failed |= showbox(ctx, out, pageobj, "ArtBox", PDF_NAME_ArtBox);
		failed |= showbox(ctx, out, pageobj, "BleedBox", PDF_NAME_BleedBox);
		failed |= showbox(ctx, out, pageobj, "TrimBox", PDF_NAME_TrimBox);
		failed |= shownum(ctx, out, pageobj, "Rotate", PDF_NAME_Rotate);
		failed |= shownum(ctx, out, pageobj, "UserUnit", PDF_NAME_UserUnit);
	}

	fz_printf(ctx, out, "</page>\n");

	return failed;
}

static int
showpages(fz_context *ctx, pdf_document *doc, fz_output *out, char *pagelist)
{
	int page, spage, epage;
	char *spec, *dash;
	int pagecount;
	int ret = 0;

	if (!doc)
		infousage();

	pagecount = pdf_count_pages(ctx, doc);
	spec = fz_strsep(&pagelist, ",");
	while (spec && pagecount)
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

		if (spage > epage)
			page = spage, spage = epage, epage = page;

		spage = fz_clampi(spage, 1, pagecount);
		epage = fz_clampi(epage, 1, pagecount);

		for (page = spage; page <= epage; page++)
		{
			ret |= showpage(ctx, doc, out, page);
		}

		spec = fz_strsep(&pagelist, ",");
	}

	return ret;
}

static int arg_is_page_range(const char *arg)
{
	int c;

	while ((c = *arg++) != 0)
	{
		if ((c < '0' || c > '9') && (c != '-') && (c != ','))
			return 0;
	}
	return 1;
}

static int
pdfpages_pages(fz_context *ctx, fz_output *out, char *filename, char *password, char *argv[], int argc)
{
	enum { NO_FILE_OPENED, NO_INFO_GATHERED, INFO_SHOWN } state;
	int argidx = 0;
	pdf_document *doc = NULL;
	int ret = 0;

	state = NO_FILE_OPENED;
	while (argidx < argc)
	{
		if (state == NO_FILE_OPENED || !arg_is_page_range(argv[argidx]))
		{
			if (state == NO_INFO_GATHERED)
			{
				showpages(ctx, doc, out, "1-");
			}

			pdf_close_document(ctx, doc);

			filename = argv[argidx];
			fz_printf(ctx, out, "%s:\n", filename);
			doc = pdf_open_document(ctx, filename);
			if (pdf_needs_password(ctx, doc))
				if (!pdf_authenticate_password(ctx, doc, password))
					fz_throw(ctx, FZ_ERROR_GENERIC, "cannot authenticate password: %s", filename);

			state = NO_INFO_GATHERED;
		}
		else
		{
			ret |= showpages(ctx, doc, out, argv[argidx]);
			state = INFO_SHOWN;
		}

		argidx++;
	}

	if (state == NO_INFO_GATHERED)
		showpages(ctx, doc, out, "1-");

	pdf_close_document(ctx, doc);

	return ret;
}

int pdfpages_main(int argc, char **argv)
{
	char *filename = "";
	char *password = "";
	int c;
	fz_output *out = NULL;
	int ret;
	fz_context *ctx;

	while ((c = fz_getopt(argc, argv, "p:")) != -1)
	{
		switch (c)
		{
		case 'p': password = fz_optarg; break;
		default:
			infousage();
			break;
		}
	}

	if (fz_optind == argc)
		infousage();

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	fz_var(out);

	ret = 0;
	fz_try(ctx)
	{
		out = fz_new_output_with_file(ctx, stdout, 0);
		ret = pdfpages_pages(ctx, out, filename, password, &argv[fz_optind], argc-fz_optind);
	}
	fz_catch(ctx)
	{
		ret = 1;
	}
	fz_drop_output(ctx, out);
	fz_drop_context(ctx);
	return ret;
}
