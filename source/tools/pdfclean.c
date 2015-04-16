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

#include "mupdf/pdf.h"

static void usage(void)
{
	fprintf(stderr,
		"usage: mutool clean [options] input.pdf [output.pdf] [pages]\n"
		"\t-p -\tpassword\n"
		"\t-g\tgarbage collect unused objects\n"
		"\t-gg\tin addition to -g compact xref table\n"
		"\t-ggg\tin addition to -gg merge duplicate objects\n"
		"\t-s\tclean content streams\n"
		"\t-d\tdecompress all streams\n"
		"\t-l\tlinearize PDF\n"
		"\t-i\ttoggle decompression of image streams\n"
		"\t-f\ttoggle decompression of font streams\n"
		"\t-a\tascii hex encode binary streams\n"
		"\t-z\tdeflate uncompressed streams\n"
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
	fz_write_options opts;
	int errors = 0;
	fz_context *ctx;

	opts.do_incremental = 0;
	opts.do_garbage = 0;
	opts.do_expand = 0;
	opts.do_ascii = 0;
	opts.do_deflate = 0;
	opts.do_linear = 0;
	opts.continue_on_error = 1;
	opts.errors = &errors;
	opts.do_clean = 0;

	while ((c = fz_getopt(argc, argv, "adfgilp:sz")) != -1)
	{
		switch (c)
		{
		case 'p': password = fz_optarg; break;
		case 'g': opts.do_garbage ++; break;
		case 'd': opts.do_expand ^= fz_expand_all; break;
		case 'f': opts.do_expand ^= fz_expand_fonts; break;
		case 'i': opts.do_expand ^= fz_expand_images; break;
		case 'l': opts.do_linear ++; break;
		case 'a': opts.do_ascii ++; break;
		case 'z': opts.do_deflate ++; break;
		case 's': opts.do_clean ++; break;
		default: usage(); break;
		}
	}

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
