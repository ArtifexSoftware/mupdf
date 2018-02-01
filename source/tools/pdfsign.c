/*
 * PDF signature tool: verify and sign digital signatures in PDF files.
 */

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"
#include "mupdf/helpers/pkcs7-check.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static char *filename = NULL;

static void usage(void)
{
	fprintf(stderr,
		"usage: mutool sign input.pdf\n"
		"\t-p -\tpassword\n"
		   );
	exit(1);
}

void verify_signature(fz_context *ctx, pdf_document *doc, int n, pdf_widget *widget)
{
	char msg[256];
	printf("verifying signature on page %d\n", n+1);
	pdf_check_signature(ctx, doc, widget, msg, sizeof msg);
	printf("  result: '%s'\n", msg);
}

void verify_page(fz_context *ctx, pdf_document *doc, int n, pdf_page *page)
{
	pdf_annot *annot;
	for (annot = pdf_first_annot(ctx, page); annot; annot = pdf_next_annot(ctx, annot))
		if (pdf_annot_type(ctx, annot) == PDF_ANNOT_WIDGET)
			if (pdf_widget_type(ctx, annot) == PDF_WIDGET_TYPE_SIGNATURE)
				verify_signature(ctx, doc, n, annot);
}

int pdfsign_main(int argc, char **argv)
{
	fz_context *ctx = NULL;
	pdf_document *doc = NULL;
	char *password = "";
	int i, n, c;

	while ((c = fz_getopt(argc, argv, "p:")) != -1)
	{
		switch (c)
		{
		case 'p': password = fz_optarg; break;
		default: usage(); break;
		}
	}

	if (argc - fz_optind < 1)
		usage();

	filename = argv[fz_optind++];

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialize context\n");
		exit(1);
	}

	fz_try(ctx)
	{
		doc = pdf_open_document(ctx, filename);
		if (pdf_needs_password(ctx, doc))
			if (!pdf_authenticate_password(ctx, doc, password))
				fz_warn(ctx, "cannot authenticate password: %s", filename);

		n = pdf_count_pages(ctx, doc);
		for (i = 0; i < n; ++i)
		{
			pdf_page *page = pdf_load_page(ctx, doc, i);
			verify_page(ctx, doc, i, page);
			fz_drop_page(ctx, (fz_page*)page);
		}
	}
	fz_catch(ctx)
	{
	}

	pdf_drop_document(ctx, doc);
	fz_flush_warnings(ctx);
	fz_drop_context(ctx);
	return 0;
}
