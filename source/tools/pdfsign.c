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

void verify_signature(fz_context *ctx, pdf_document *doc, pdf_obj *signature)
{
	char name[500];
	enum pdf_signature_error err;
	int edits;

	printf("verifying signature %d\n", pdf_to_num(ctx, signature));

	pdf_signature_designated_name(ctx, doc, signature, name, sizeof name);
	printf("  Designated name: %s\n", name);

	err = pdf_check_certificate(ctx, doc, signature);
	if (err)
		printf("  Certificate error: %s\n", pdf_signature_error_description(err));
	else
		printf("  Certificate is trusted.\n");

	fz_try(ctx)
	{
		err = pdf_check_digest(ctx, doc, signature);
		edits = pdf_signature_incremental_change_since_signing(ctx, doc, signature);
		if (err)
			printf("  Digest error: %s\n", pdf_signature_error_description(err));
		else if (edits)
			printf("  The signature is valid but there have been edits since signing.\n");
		else
			printf("  The document is unchanged since signing.\n");
	}
	fz_catch(ctx)
		printf("  Digest error: %s\n", fz_caught_message(ctx));
}

void verify_field(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	pdf_obj *ft, *kids;
	int i, n;

	ft = pdf_dict_get(ctx, field, PDF_NAME(FT));
	if (ft == PDF_NAME(Sig))
		verify_signature(ctx, doc, field);

	kids = pdf_dict_get(ctx, field, PDF_NAME(Kids));
	n = pdf_array_len(ctx, kids);
	for (i = 0; i < n; ++i)
		verify_field(ctx, doc, pdf_array_get(ctx, kids, i));
}

void verify_acro_form(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *trailer = pdf_trailer(ctx, doc);
	pdf_obj *root = pdf_dict_get(ctx, trailer, PDF_NAME(Root));
	pdf_obj *acroform = pdf_dict_get(ctx, root, PDF_NAME(AcroForm));
	pdf_obj *fields = pdf_dict_get(ctx, acroform, PDF_NAME(Fields));
	int i, n = pdf_array_len(ctx, fields);
	for (i = 0; i < n; ++i)
		verify_field(ctx, doc, pdf_array_get(ctx, fields, i));
}

int pdfsign_main(int argc, char **argv)
{
	fz_context *ctx;
	pdf_document *doc;
	char *password = "";
	int c;
	pdf_page *page = NULL;

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

	fz_var(page);

	doc = pdf_open_document(ctx, filename);
	fz_try(ctx)
	{
		if (pdf_needs_password(ctx, doc))
			if (!pdf_authenticate_password(ctx, doc, password))
				fz_warn(ctx, "cannot authenticate password: %s", filename);
		verify_acro_form(ctx, doc);
	}
	fz_always(ctx)
		pdf_drop_document(ctx, doc);
	fz_catch(ctx)
	{
		fz_drop_page(ctx, (fz_page*)page);
		fprintf(stderr, "error verifying signatures: %s\n", fz_caught_message(ctx));
	}

	fz_flush_warnings(ctx);
	fz_drop_context(ctx);
	return 0;
}
