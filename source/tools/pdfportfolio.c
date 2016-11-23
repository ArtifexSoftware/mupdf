/*
 * pdfportfolio -- manipulate embedded files in a PDF
 */

#include "mupdf/pdf.h"

static pdf_document *doc = NULL;
static fz_context *ctx = NULL;

static void usage(void)
{
	fprintf(stderr, "usage: mutool portfolio [options] infile.pdf [actions]\n");
	fprintf(stderr, "\tOptions are:\n");
	fprintf(stderr, "\t-p -\tpassword\n");
	fprintf(stderr, "Actions are:\n");
	fprintf(stderr, "\tl\tlist embedded files\n");
	fprintf(stderr, "\tx N <filename>\n\t\textract Nth embedded file as <filename>\n");
	fprintf(stderr, "\te outfile.pdf <filename> <embed>\n\t\tembed <filename> as <embed>, saving the result as outfile.pdf\n");
	fprintf(stderr, "\nFor safety, keep all filenames as 7 bit clean for now.\n");
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

int pdfportfolio_main(int argc, char **argv)
{
	char *infile;
	char *password = "";
	int c;
	int exit_code = 0;

	while ((c = fz_getopt(argc, argv, "p:")) != -1)
	{
		switch (c)
		{
		case 'p': password = fz_optarg; break;
		default: usage(); break;
		}
	}

	if (fz_optind == argc)
		usage();

	infile = argv[fz_optind++];

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	doc = pdf_open_document(ctx, infile);
	if (pdf_needs_password(ctx, doc))
		if (!pdf_authenticate_password(ctx, doc, password))
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot authenticate password: %s", infile);

	if (fz_optind == argc)
		usage();
	fz_optarg = argv[fz_optind++];
	if (*fz_optarg == 0 || (*fz_optarg != 'l' && *fz_optarg != 'x' && *fz_optarg != 'e') || fz_optarg[1] != 0)
		usage();

	fz_try(ctx)
	{
		switch (*fz_optarg)
		{
		case 'l':
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
			break;
		}
		case 'x':
		{
			int entry;
			char *filename;
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
			break;
		}
		case 'e':
		{
			char *outfile;
			char *filename;
			char *ename;
			fz_buffer *buf;

			if (fz_optind > argc-3)
				usage();

			outfile = argv[fz_optind++];
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
			pdf_save_document(ctx, doc, outfile, NULL);
			break;
		}
		}
	}
	fz_catch(ctx)
	{
		/* Swallow any errors */
		exit_code = 1;
	}

	pdf_drop_document(ctx, doc);
	fz_flush_warnings(ctx);
	fz_drop_context(ctx);
	return exit_code;
}
