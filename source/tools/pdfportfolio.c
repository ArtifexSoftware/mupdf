/*
 * pdfportfolio -- manipulate embedded files in a PDF
 */

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <stdlib.h>
#include <stdio.h>

static pdf_document *doc = NULL;
static fz_context *ctx = NULL;

static void usage(void)
{
	fprintf(stderr, "usage: mutool portfolio [options] portfolio.pdf [actions]\n");
	fprintf(stderr, "\nOptions are:\n");
	fprintf(stderr, "\t-p -\tpassword\n");
	fprintf(stderr, "\t-o -\toutput (defaults to input file)\n");
	fprintf(stderr, "\t-O -\tPDF output options (see mutool create)\n");
	fprintf(stderr, "\nActions are:\n");
	fprintf(stderr, "\tt\tdisplay a table listing the contents of the portfolio\n");
	fprintf(stderr, "\tx N <file>\n\t\textract Nth entry to <file>\n");
	fprintf(stderr, "\ta <file> <name>\n\t\tadd contents of <file> as an entry named <name>\n");
	fprintf(stderr, "\nFor safety, only use ASCII characters in entry names for now.\n");
	exit(1);
}

static void
safe_print_pdf_string(fz_context *ctx, unsigned char *str, int len)
{
	int c;

	if (len > 1 && str[0] == 0xFE && str[1] == 0xFF)
	{
		str += 2;
		len -= 2;
		while (len)
		{
			c = (*str++<<8);
			c += *str++;
			if (c >= 32 && c != 127 && c < 256)
				fprintf(stderr, "%c", c);
			else
				fprintf(stderr, "<%04x>", c);
			len -= 2;
		};
	}
	else
	{
		while (len)
		{
			c = *str++;
			if (c >= 32 && c != 127 && c < 256)
				fprintf(stderr, "%c", c);
			else
				fprintf(stderr, "<%02x>", c);
			len--;
		};
	}
}

static void
safe_print_pdf_obj(fz_context *ctx, pdf_obj *obj, const char *dflt)
{
	if (obj == NULL)
		fprintf(stderr, "%s", dflt);
	else if (pdf_is_string(ctx, obj))
		safe_print_pdf_string(ctx, (unsigned char *)pdf_to_str_buf(ctx, obj), pdf_to_str_len(ctx, obj));
	else
		pdf_print_obj(ctx, fz_stderr(ctx), obj, 1);
}

static void
pdfportfolio_list()
{
	/* List files */
	int m = pdf_count_portfolio_schema(ctx, doc);
	int n = pdf_count_portfolio_entries(ctx, doc);
	int i, j;

	for (i = 0; i < n; i++)
	{
		pdf_obj *name = pdf_portfolio_entry_name(ctx, doc, i);

		fprintf(stderr, " %s%d: ", i < 10 ? " " : "", i);
		safe_print_pdf_obj(ctx, name, "(Unnamed)");
		fprintf(stderr, "\n");
		for (j = 0; j < m; j++)
		{
			pdf_portfolio_schema info;
			pdf_obj *obj;
			char *type;

			pdf_portfolio_schema_info(ctx, doc, j, &info);
			obj = pdf_portfolio_entry_info(ctx, doc, i, j);
			fprintf(stderr, "    ");
			safe_print_pdf_obj(ctx, info.name, "(Unnamed)");
			switch(info.type)
			{
			case PDF_SCHEMA_TEXT:
				type = "T";
				break;
			case PDF_SCHEMA_DATE:
				type = "D";
				break;
			case PDF_SCHEMA_NUMBER:
				type = "N";
				break;
			case PDF_SCHEMA_FILENAME:
				type = "F";
				break;
			case PDF_SCHEMA_DESC:
				type = "E";
				break;
			case PDF_SCHEMA_MODDATE:
				type = "M";
				break;
			case PDF_SCHEMA_CREATIONDATE:
				type = "C";
				break;
			case PDF_SCHEMA_SIZE:
				type = "S";
				break;
			default:
				type = "?";
				break;
			}
			fprintf(stderr, ":%s:", type);
			safe_print_pdf_obj(ctx, obj, "");
			if (info.editable)
				fprintf(stderr, " (Editable)");
			if (info.visible)
				fprintf(stderr, " (Visible)");
			fprintf(stderr, "\n");
		}
	}
}

static void
pdfportfolio_extract(int argc, char **argv)
{
	int entry;
	const char *filename;
	fz_buffer *buf;
	unsigned char *data;
	int len;
	FILE *file;

	if (fz_optind > argc-2)
		usage();

	entry = fz_atoi(argv[fz_optind++]);
	filename = argv[fz_optind++];

	buf = pdf_portfolio_entry(ctx, doc, entry);
	len = fz_buffer_storage(ctx, buf, &data);

	file = fopen(filename, "wb");
	if (file == NULL)
	{
		fprintf(stderr, "Failed to open '%s' for writing\n", filename);
		exit(1);
	}
	fwrite(data, 1, len, file);
	fclose(file);
	fz_drop_buffer(ctx, buf);
}

static void
pdfportfolio_add(int argc, char **argv)
{
	const char *filename;
	const char *ename;
	fz_buffer *buf;

	if (fz_optind > argc-2)
		usage();

	filename = argv[fz_optind++];
	ename = argv[fz_optind++];

	if (ename == NULL)
		ename = filename;

	buf = fz_read_file(ctx, filename);
	pdf_add_portfolio_entry(ctx, doc,
			ename, strlen(ename), /* name */
			ename, strlen(ename), /* desc */
			ename, strlen(ename), /* filename */
			ename, strlen(ename), /* unifile */
			buf);
	fz_drop_buffer(ctx, buf);
}

int pdfportfolio_main(int argc, char **argv)
{
	char *password = "";
	char *outfile = NULL;
	char *outopts = "compress";
	char *infile;
	int exit_code = 0;
	int do_save = 0;
	int has_old_file = 0;
	int c;

	while ((c = fz_getopt(argc, argv, "p:o:O:")) != -1)
	{
		switch (c)
		{
		case 'p': password = fz_optarg; break;
		case 'o': outfile = fz_optarg; break;
		case 'O': outopts = fz_optarg; break;
		default: usage(); break;
		}
	}

	if (fz_optind == argc)
		usage();

	infile = argv[fz_optind++];
	if (!outfile)
		outfile = infile;

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	if (fz_file_exists(ctx, infile))
	{
		doc = pdf_open_document(ctx, infile);
		if (pdf_needs_password(ctx, doc))
			if (!pdf_authenticate_password(ctx, doc, password))
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot authenticate password: %s", infile);
		has_old_file = 1;
	}
	else
	{
		doc = pdf_create_document(ctx);

		/* add a blank page */
		{
			const char *template = "BT /Tm 16 Tf 50 434 TD (This is a portfolio document.) Tj ET\n";
			const char *data;
			int size;
			fz_font *font;
			pdf_obj *font_obj, *page_obj;
			pdf_obj *resources;
			fz_buffer *contents;
			fz_rect mediabox = { 0, 0, 400, 500 };

			data = fz_lookup_base14_font(ctx, "Times-Roman", &size);
			font = fz_new_font_from_memory(ctx, "Times-Roman", data, size, 0, 0);
			font_obj = pdf_add_simple_font(ctx, doc, font);
			fz_drop_font(ctx, font);

			resources = pdf_add_object_drop(ctx, doc, pdf_new_dict(ctx, doc, 1));
			pdf_dict_putp_drop(ctx, resources, "Font/Tm", font_obj);

			contents = fz_new_buffer_from_shared_data(ctx, template, strlen(template));

			page_obj = pdf_add_page(ctx, doc, &mediabox, 0, resources, contents);
			pdf_insert_page(ctx, doc, -1, page_obj);
			pdf_drop_obj(ctx, page_obj);
			fz_drop_buffer(ctx, contents);
		}
	}

	if (fz_optind == argc)
		usage();

	while (fz_optind < argc)
	{
		fz_optarg = argv[fz_optind++];
		fz_try(ctx)
		{
			switch (*fz_optarg)
			{
			default:
				usage();
				break;
			case 't':
				pdfportfolio_list();
				break;
			case 'x':
				pdfportfolio_extract(argc, argv);
				break;
			case 'a':
				pdfportfolio_add(argc, argv);
				do_save = 1;
				break;
			}
		}
		fz_catch(ctx)
		{
			/* Swallow any errors */
			exit_code = 1;
		}
	}

	if (do_save && !exit_code)
	{
		pdf_write_options opts;
		pdf_parse_write_options(ctx, &opts, outopts);
		if (has_old_file && infile == outfile)
			 opts.do_incremental = 1;
		pdf_save_document(ctx, doc, outfile, &opts);
	}

	pdf_drop_document(ctx, doc);
	fz_flush_warnings(ctx);
	fz_drop_context(ctx);
	return exit_code;
}
