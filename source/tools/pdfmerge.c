/*
 * PDF merge tool: Tool for merging pdf content.
 *
 * Simple test bed to work with merging pages from multiple PDFs into a single PDF.
 */

#include "mupdf/pdf.h"

static void usage(void)
{
	fprintf(stderr,
		"usage: mutool merge [-o output.pdf] [-adlsz] input.pdf [pages] [input2.pdf] [pages2] ...\n"
		"\t-o\tname of PDF file to create\n"
		"\t-a\tascii hex encode binary streams\n"
		"\t-d\tdecompress all streams\n"
		"\t-l\tlinearize PDF\n"
		"\t-s\tclean content streams\n"
		"\t-z\tdeflate uncompressed streams\n"
		"\tinput.pdf name of first PDF file from which we are copying pages\n"
		);
	exit(1);
}

static fz_context *ctx = NULL;
static pdf_document *doc_des = NULL;
static pdf_document *doc_src = NULL;

/* This isrange is a duplicate with mudraw.c Not sure how we want to organize or if
 * we are fine with the small amount of code duplication */
static int isrange(char *s)
{
	while (*s)
	{
		if ((*s < '0' || *s > '9') && *s != '-' && *s != ',')
			return 0;
		s++;
	}
	return 1;
}

static void page_merge(int page_from, int page_to, pdf_graft_map *graft_map)
{
	pdf_obj *pageref = NULL;
	pdf_obj *page_dict;
	pdf_obj *obj = NULL, *ref = NULL;
	/* Include minimal number of objects for page.  Do not include items that
	 * reference other pages */
	pdf_obj *known_page_objs[] = { PDF_NAME_Contents, PDF_NAME_Resources,
		PDF_NAME_MediaBox, PDF_NAME_CropBox, PDF_NAME_BleedBox, PDF_NAME_TrimBox,
		PDF_NAME_ArtBox, PDF_NAME_Rotate, PDF_NAME_UserUnit};
	int n = nelem(known_page_objs);
	int i;
	int num;

	fz_var(obj);
	fz_var(ref);

	fz_try(ctx)
	{
		pageref = pdf_lookup_page_obj(ctx, doc_src, page_from - 1);

		/* Make a new dictionary and copy over the items from the source object to
		* the new dict that we want to deep copy. */
		page_dict = pdf_new_dict(ctx, doc_des, 4);

		pdf_dict_put_drop(ctx, page_dict, PDF_NAME_Type, PDF_NAME_Page);

		for (i = 0; i < n; i++)
		{
			obj = pdf_dict_get(ctx, pageref, known_page_objs[i]);
			if (obj != NULL)
				pdf_dict_put_drop(ctx, page_dict, known_page_objs[i], pdf_graft_object(ctx, doc_des, doc_src, obj, graft_map));
		}

		/* Add the dictionary */
		obj = pdf_add_object_drop(ctx, doc_des, page_dict);

		/* Get indirect ref */
		num = pdf_to_num(ctx, obj);
		ref = pdf_new_indirect(ctx, doc_des, num, 0);

		/* Insert */
		pdf_insert_page(ctx, doc_des, page_to - 1, ref);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, obj);
		pdf_drop_obj(ctx, ref);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void merge_range(char *range)
{
	int page, spage, epage, src_pagecount, des_pagecount;
	char *spec, *dash;
	pdf_graft_map *graft_map;

	src_pagecount = fz_count_pages(ctx, (fz_document*) doc_src);
	des_pagecount = fz_count_pages(ctx, (fz_document*) doc_des);
	spec = fz_strsep(&range, ",");
	graft_map = pdf_new_graft_map(ctx, doc_src);

	fz_try(ctx)
	{
		while (spec)
		{
			dash = strchr(spec, '-');

			if (dash == spec)
				spage = epage = src_pagecount;
			else
				spage = epage = atoi(spec);

			if (dash)
			{
				if (strlen(dash) > 1)
					epage = atoi(dash + 1);
				else
					epage = src_pagecount;
			}

			spage = fz_clampi(spage, 1, src_pagecount);
			epage = fz_clampi(epage, 1, src_pagecount);

			if (spage < epage)
				for (page = spage; page <= epage; page++, des_pagecount++)
					page_merge(page, des_pagecount + 1, graft_map);
			else
				for (page = spage; page >= epage; page--, des_pagecount++)
					page_merge(page, des_pagecount + 1, graft_map);
			spec = fz_strsep(&range, ",");
		}
	}
	fz_always(ctx)
	{
		pdf_drop_graft_map(ctx, graft_map);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

int pdfmerge_main(int argc, char **argv)
{
	pdf_write_options opts = { 0 };
	char *output = "out.pdf";
	char *infile_src;
	int c;

	while ((c = fz_getopt(argc, argv, "adlszo:")) != -1)
	{
		switch (c)
		{
		case 'o': output = fz_optarg; break;
		case 'a': opts.do_ascii ++; break;
		case 'd': opts.do_expand ^= PDF_EXPAND_ALL; break;
		case 'l': opts.do_linear ++; break;
		case 's': opts.do_clean ++; break;
		case 'z': opts.do_deflate ++; break;
		default: usage(); break;
		}
	}

	if (fz_optind == argc)
		usage();

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "Cannot initialise context\n");
		exit(1);
	}

	fz_try(ctx)
	{
		doc_des = pdf_create_document(ctx);
	}
	fz_catch(ctx)
	{
		fprintf(stderr, "Failed to allocate destination document file %s\n", output);
		exit(1);
	}

	/* Step through the source files */
	while (fz_optind < argc)
	{
		fz_try(ctx)
		{
			infile_src = argv[fz_optind++];
			pdf_drop_document(ctx, doc_src);
			doc_src = pdf_open_document(ctx, infile_src);

			if (fz_optind == argc || !isrange(argv[fz_optind]))
				merge_range("1-");
			else
				merge_range(argv[fz_optind++]);
		}
		fz_catch(ctx)
		{
			fprintf(stderr, "Failed merging document %s\n", infile_src);
			exit(1);
		}
	}

	fz_try(ctx)
	{
		pdf_save_document(ctx, doc_des, output, &opts);
	}
	fz_always(ctx)
	{
		pdf_drop_document(ctx, doc_des);
		pdf_drop_document(ctx, doc_src);
	}
	fz_catch(ctx)
	{
		fprintf(stderr, "Error encountered during file save.\n");
		exit(1);
	}
	fz_flush_warnings(ctx);
	fz_drop_context(ctx);

	return 0;
}
