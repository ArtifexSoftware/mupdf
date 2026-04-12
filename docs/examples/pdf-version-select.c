/*
How to use pdf_select_version() to enumerate historical versions
of a PDF document and inspect each one.

To build this example in a source tree, run:
make examples
./build/debug/pdf-version-select document.pdf

To build from installed sources:
gcc -I/usr/local/include -o pdf-version-select \
	/usr/local/share/doc/mupdf/examples/pdf-version-select.c \
	/usr/local/lib/libmupdf.a \
	/usr/local/lib/libmupdfthird.a \
	-lm
./pdf-version-select document.pdf
*/

#include <mupdf/fitz.h>
#include <mupdf/pdf.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	fz_context *ctx;
	fz_document *doc;
	pdf_document *pdoc;
	int num_versions, page_count, i;

	if (argc < 2)
	{
		fprintf(stderr, "usage: pdf-version-select input.pdf\n");
		return EXIT_FAILURE;
	}

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "cannot create mupdf context\n");
		return EXIT_FAILURE;
	}

	fz_try(ctx)
		fz_register_document_handlers(ctx);
	fz_catch(ctx)
	{
		fz_report_error(ctx);
		fprintf(stderr, "cannot register document handlers\n");
		fz_drop_context(ctx);
		return EXIT_FAILURE;
	}

	fz_try(ctx)
		doc = fz_open_document(ctx, argv[1]);
	fz_catch(ctx)
	{
		fz_report_error(ctx);
		fprintf(stderr, "cannot open document: %s\n", argv[1]);
		fz_drop_context(ctx);
		return EXIT_FAILURE;
	}

	pdoc = pdf_document_from_fz_document(ctx, doc);
	if (!pdoc)
	{
		fprintf(stderr, "not a PDF document: %s\n", argv[1]);
		fz_drop_document(ctx, doc);
		fz_drop_context(ctx);
		return EXIT_FAILURE;
	}

	fz_try(ctx)
	{
		num_versions = pdf_count_versions(ctx, pdoc);
		printf("Document has %d version(s)\n", num_versions);
		printf("Currently selected version: %d\n\n", pdf_selected_version(ctx, pdoc));

		for (i = 0; i < num_versions; i++)
		{
			pdf_select_version(ctx, pdoc, i);
			page_count = fz_count_pages(ctx, doc);
			printf("Version %d: %d page(s) (selectedVersion=%d)\n",
				i, page_count, pdf_selected_version(ctx, pdoc));
		}

		/* Reset to latest version. */
		pdf_select_version(ctx, pdoc, 0);
		printf("\nReset to version 0 (latest): %d page(s)\n",
			fz_count_pages(ctx, doc));

		/* Demonstrate error handling for out-of-range version. */
		printf("\n");
		fz_try(ctx)
		{
			pdf_select_version(ctx, pdoc, num_versions);
			printf("ERROR: out-of-range pdf_select_version did not throw\n");
		}
		fz_catch(ctx)
			printf("Out-of-range version correctly rejected\n");

		/* Demonstrate that modifications are rejected during historical view. */
		pdf_select_version(ctx, pdoc, 1);
		fz_try(ctx)
		{
			pdf_create_object(ctx, pdoc);
			printf("ERROR: pdf_create_object during historical view did not throw\n");
		}
		fz_catch(ctx)
			printf("Modification during historical view correctly rejected\n");

		pdf_select_version(ctx, pdoc, 0);
		printf("Restored to version 0 after error handling demos\n");
	}
	fz_catch(ctx)
	{
		fz_report_error(ctx);
		fprintf(stderr, "error inspecting versions\n");
		fz_drop_document(ctx, doc);
		fz_drop_context(ctx);
		return EXIT_FAILURE;
	}

	fz_drop_document(ctx, doc);
	fz_drop_context(ctx);
	return EXIT_SUCCESS;
}
