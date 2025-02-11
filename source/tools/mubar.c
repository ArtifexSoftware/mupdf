// Copyright (C) 2025 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 39 Mesa Street, Suite 108A, San Francisco,
// CA 94129, USA, for further information.

/*
 * mudraw -- command line tool for drawing and converting documents
 */

#include "mupdf/fitz.h"
#include "mupdf/fitz/barcode.h"

#if FZ_ENABLE_PDF
#include "mupdf/pdf.h" /* for pdf output */
#endif

/* Globals */
static int create;
static const char *output;
static char *bartypestring;
static fz_barcode_type bartype;
static int rotation;
static int quiet;
static int hrt;
static int ec_level;
static int size;

static int usage(void)
{
	int i, n;

	fprintf(stderr,
		"usage: mubar [options] <file>\n"
		"\t-v\tversion\n"
		"\t-h\tdisplay this help\n"
		"\t-c\tencode barcode from data in file (otherwise decode barcode from file)\n"
		"ENCODING:\n"
		"\t-F -\tbar code format (defaults to qrcode)\n");
	n = nelem(fz_barcode_type_strings);
	for (i = 1; i < n; i++)
	{
		fprintf(stderr, "\t\t%s\n", fz_barcode_type_strings[i]);
	}
	fprintf(stderr,
		"\t-q\tAdd quiet zones\n"
		"\t-t\tAdd human readable text\n"
		"\t-e -\tError correction level (0-8)\n"
		"\t-s -\tSize\n"
		"\t-o -\toutput file name (default: out.png)\n"
		"DECODING:\n"
		"\t-r -\trotation\n"
		);
	return 1;
}

int mubar_main(int argc, char **argv)
{
	fz_document *doc = NULL;
	fz_page *page = NULL;
	int c;
	fz_context *ctx;
	int errored = 0;
	char *text = NULL;
	const char *infile;
	fz_image *image = NULL;
	fz_pixmap *pixmap = NULL;
	fz_buffer *buf = NULL;
	const char *format;
	fz_document_writer *writer = NULL;
	fz_device *dev = NULL;
	fz_rect bounds;

	fz_var(doc);
	fz_var(errored);
	fz_var(page);
	fz_var(text);
	fz_var(image);
	fz_var(pixmap);
	fz_var(buf);
	fz_var(writer);
	fz_var(dev);

	while ((c = fz_getopt(argc, argv, "co:r:F:vdqte:s:")) != -1)
	{
		switch (c)
		{
		default: return usage();

		case 'c': create = 1; break;
		case 'o': output = fz_optarg; break;
		case 'F': bartypestring = fz_optarg; break;
		case 'r': rotation = fz_atof(fz_optarg); break;
		case 'q': quiet = 1; break;
		case 't': hrt = 1; break;
		case 'e': ec_level = fz_atoi(fz_optarg); break;
		case 's': size = fz_atoi(fz_optarg); break;

		case 'v': fprintf(stderr, "mudraw version %s\n", FZ_VERSION); return 1;
		case 'h': usage(); return 1;
		}
	}

	if (fz_optind == argc)
		return usage();

	infile = argv[fz_optind];

	ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	fz_try(ctx)
	{
		fz_register_document_handlers(ctx);

		if (create)
		{
			if (bartypestring)
			{
				bartype = fz_barcode_from_string(ctx, bartypestring);
				if (bartype == FZ_BARCODE_NONE)
					fz_throw(ctx, FZ_ERROR_ARGUMENT, "Unknown bar code type");
			}
			else
				bartype = FZ_BARCODE_QRCODE;

			buf = fz_read_file(ctx, infile);
			fz_terminate_buffer(ctx, buf);

			if (output == NULL)
				output = "out.png";
			format = strrchr(output, '.');
			if (format != NULL)
				format++;
			if (format == NULL || format[1] == 0)
				format = "png";

			if (fz_strcasecmp(format, "png") == 0)
			{
				pixmap = fz_new_barcode_pixmap(ctx, bartype, (const char *)buf->data, size, ec_level, quiet, hrt);
				fz_save_pixmap_as_png(ctx, pixmap, output);
			}
			else
			{
				fz_matrix ctm;
				image = fz_new_barcode_image(ctx, bartype, (const char *)buf->data, size, ec_level, quiet, hrt);
				ctm.a = image->w;
				ctm.b = 0;
				ctm.c = 0;
				ctm.d = image->h;
				ctm.e = 0;
				ctm.f = 0;

				bounds.x0 = 0;
				bounds.y0 = 0;
				bounds.x1 = image->w;
				bounds.y1 = image->h;

				writer = fz_new_document_writer(ctx, output, format, "");
				dev = fz_begin_page(ctx, writer, bounds);
				fz_fill_image(ctx, dev, image, ctm, 1, fz_default_color_params);
				fz_end_page(ctx, writer);
				dev = NULL;
				fz_close_document_writer(ctx, writer);
				fz_drop_document_writer(ctx, writer);
				writer = NULL;
			}
		}
		else
		{
			doc = fz_open_document(ctx, infile);
			page = fz_load_page(ctx, doc, 0);
			text = fz_decode_barcode_from_page(ctx, &bartype, page, fz_infinite_rect, rotation);
			if (text)
				printf("Decoded as: '%s'\n", text);
			else
				printf("No barcode found\n");
		}
	}
	fz_always(ctx)
	{
		fz_free(ctx, text);
		fz_drop_image(ctx, image);
		fz_drop_pixmap(ctx, pixmap);
		fz_drop_buffer(ctx, buf);
		fz_drop_page(ctx, page);
		fz_drop_document(ctx, doc);
		fz_drop_document_writer(ctx, writer);
	}
	fz_catch(ctx)
	{
		fz_report_error(ctx);
		if (!errored) {
			fprintf(stderr, "Rendering failed\n");
			errored = 1;
		}
	}

	fz_drop_context(ctx);

	return (errored != 0);
}
