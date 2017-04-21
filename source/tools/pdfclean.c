/*
 * PDF cleaning tool: general purpose pdf syntax washer.
 *
 * Rewrite PDF with pretty printed objects.
 * Garbage collect unreachable objects.
 * Inflate compressed streams.
 * Create subset documents.
 *
 * TODO: linearize document for fast web view
 */

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static void usage(void)
{
	fprintf(stderr,
		"usage: mutool clean [options] input.pdf [output.pdf] [pages]\n"
		"\t-p -\tpassword\n"
		"\t-g\tgarbage collect unused objects\n"
		"\t-gg\tin addition to -g compact xref table\n"
		"\t-ggg\tin addition to -gg merge duplicate objects\n"
		"\t-gggg\tin addition to -ggg check streams for duplication\n"
		"\t-l\tlinearize PDF\n"
		"\t-a\tascii hex encode binary streams\n"
		"\t-d\tdecompress streams\n"
		"\t-z\tdeflate uncompressed streams\n"
		"\t-f\tcompress font streams\n"
		"\t-i\tcompress image streams\n"
		"\t-s\tclean content streams\n"
		"\tpages\tcomma separated list of page numbers and ranges\n"
		);
	exit(1);
}

int pdfclean_main(int argc, char **argv)
{
	char *infile;
	char *outfile = "out.pdf";
	char *password = "";
	int c;
	pdf_write_options opts = { 0 };
	int errors = 0;
	fz_context *ctx;

	opts.continue_on_error = 1;
	opts.errors = &errors;

	while ((c = fz_getopt(argc, argv, "adfgilp:sz")) != -1)
	{
		switch (c)
		{
		case 'p': password = fz_optarg; break;

		case 'd': opts.do_decompress += 1; break;
		case 'z': opts.do_compress += 1; break;
		case 'f': opts.do_compress_fonts += 1; break;
		case 'i': opts.do_compress_images += 1; break;
		case 'a': opts.do_ascii += 1; break;
		case 'g': opts.do_garbage += 1; break;
		case 'l': opts.do_linear += 1; break;
		case 's': opts.do_clean += 1; break;
		default: usage(); break;
		}
	}

	if ((opts.do_ascii || opts.do_decompress) && !opts.do_compress)
		opts.do_pretty = 1;

	if (argc - fz_optind < 1)
		usage();

	infile = argv[fz_optind++];

	if (argc - fz_optind > 0 &&
		(strstr(argv[fz_optind], ".pdf") || strstr(argv[fz_optind], ".PDF")))
	{
		outfile = argv[fz_optind++];
	}

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	fz_try(ctx)
	{
		pdf_clean_file(ctx, infile, outfile, password, &opts, &argv[fz_optind], argc - fz_optind);
	}
	fz_catch(ctx)
	{
		errors++;
	}
	fz_drop_context(ctx);

	return errors != 0;
}
