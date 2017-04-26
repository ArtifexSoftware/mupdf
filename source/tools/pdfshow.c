/*
 * pdfshow -- the ultimate pdf debugging tool
 */

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <stdlib.h>
#include <stdio.h>

static pdf_document *doc = NULL;
static fz_context *ctx = NULL;
static fz_output *out = NULL;
static int showbinary = 0;
static int showdecode = 1;
static int showcolumn;

static void usage(void)
{
	fprintf(stderr, "usage: mutool show [options] file.pdf [grep] [xref] [trailer] [pagetree] [outline] [object numbers]\n");
	fprintf(stderr, "\t-p -\tpassword\n");
	fprintf(stderr, "\t-o -\toutput file\n");
	fprintf(stderr, "\t-b\tprint streams as binary data\n");
	fprintf(stderr, "\t-e\tprint encoded streams (don't decode)\n");
	exit(1);
}

static void showtrailer(void)
{
	if (!doc)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no file specified");
	fz_write_printf(ctx, out, "trailer\n");
	pdf_print_obj(ctx, out, pdf_trailer(ctx, doc), 0);
	fz_write_printf(ctx, out, "\n");
}

static void showencrypt(void)
{
	pdf_obj *encrypt;

	if (!doc)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no file specified");
	encrypt = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Encrypt);
	if (!encrypt)
		fz_throw(ctx, FZ_ERROR_GENERIC, "document not encrypted");
	fz_write_printf(ctx, out, "encryption dictionary\n");
	pdf_print_obj(ctx, out, pdf_resolve_indirect(ctx, encrypt), 0);
	fz_write_printf(ctx, out, "\n");
}

void
pdf_print_xref(fz_context *ctx, pdf_document *doc)
{
	int i;
	int xref_len = pdf_xref_len(ctx, doc);
	printf("xref\n0 %d\n", xref_len);
	for (i = 0; i < xref_len; i++)
	{
		pdf_xref_entry *entry = pdf_get_xref_entry(ctx, doc, i);
		printf("%05d: %010d %05d %c (stm_ofs=%d; stm_buf=%p)\n", i,
				(int)entry->ofs,
				entry->gen,
				entry->type ? entry->type : '-',
				(int)entry->stm_ofs,
				entry->stm_buf);
	}
}

static void showxref(void)
{
	if (!doc)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no file specified");
	pdf_print_xref(ctx, doc);
	fz_write_printf(ctx, out, "\n");
}

static void showpagetree(void)
{
	pdf_obj *ref;
	int count;
	int i;

	if (!doc)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no file specified");

	count = pdf_count_pages(ctx, doc);
	for (i = 0; i < count; i++)
	{
		ref = pdf_lookup_page_obj(ctx, doc, i);
		fz_write_printf(ctx, out, "page %d = %d 0 R\n", i + 1, pdf_to_num(ctx, ref));
	}
	fz_write_printf(ctx, out, "\n");
}

static void showsafe(unsigned char *buf, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		if (buf[i] == '\r' || buf[i] == '\n') {
			putchar('\n');
			showcolumn = 0;
		}
		else if (buf[i] < 32 || buf[i] > 126) {
			putchar('.');
			showcolumn ++;
		}
		else {
			putchar(buf[i]);
			showcolumn ++;
		}
		if (showcolumn == 79) {
			putchar('\n');
			showcolumn = 0;
		}
	}
}

static void showstream(int num)
{
	fz_stream *stm;
	unsigned char buf[2048];
	size_t n;

	showcolumn = 0;

	if (showdecode)
		stm = pdf_open_stream_number(ctx, doc, num);
	else
		stm = pdf_open_raw_stream_number(ctx, doc, num);

	while (1)
	{
		n = fz_read(ctx, stm, buf, sizeof buf);
		if (n == 0)
			break;
		if (showbinary)
			fz_write_data(ctx, out, buf, n);
		else
			showsafe(buf, n);
	}

	fz_drop_stream(ctx, stm);
}

static void showobject(int num)
{
	pdf_obj *obj;

	if (!doc)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no file specified");

	obj = pdf_load_object(ctx, doc, num);

	if (pdf_is_stream(ctx, obj))
	{
		if (showbinary)
		{
			showstream(num);
		}
		else
		{
			fz_write_printf(ctx, out, "%d 0 obj\n", num);
			pdf_print_obj(ctx, out, obj, 0);
			fz_write_printf(ctx, out, "\nstream\n");
			showstream(num);
			fz_write_printf(ctx, out, "endstream\n");
			fz_write_printf(ctx, out, "endobj\n\n");
		}
	}
	else
	{
		fz_write_printf(ctx, out, "%d 0 obj\n", num);
		pdf_print_obj(ctx, out, obj, 0);
		fz_write_printf(ctx, out, "\nendobj\n\n");
	}

	pdf_drop_obj(ctx, obj);
}

static void showgrep(char *filename)
{
	pdf_obj *obj;
	int i, len;

	len = pdf_count_objects(ctx, doc);
	for (i = 0; i < len; i++)
	{
		pdf_xref_entry *entry = pdf_get_xref_entry(ctx, doc, i);
		if (entry->type == 'n' || entry->type == 'o')
		{
			fz_try(ctx)
			{
				obj = pdf_load_object(ctx, doc, i);
			}
			fz_catch(ctx)
			{
				fz_warn(ctx, "skipping object (%d 0 R)", i);
				continue;
			}

			pdf_sort_dict(ctx, obj);

			fz_write_printf(ctx, out, "%s:%d: ", filename, i);
			pdf_print_obj(ctx, out, obj, 1);
			fz_write_printf(ctx, out, "\n");

			pdf_drop_obj(ctx, obj);
		}
	}

	fz_write_printf(ctx, out, "%s:trailer: ", filename);
	pdf_print_obj(ctx, out, pdf_trailer(ctx, doc), 1);
	fz_write_printf(ctx, out, "\n");
}

static void
fz_print_outline(fz_context *ctx, fz_output *out, fz_outline *outline, int level)
{
	int i;
	while (outline)
	{
		for (i = 0; i < level; i++)
			fz_write_printf(ctx, out, "\t");
		fz_write_printf(ctx, out, "%s\t%s\n", outline->title, outline->uri);
		if (outline->down)
			fz_print_outline(ctx, out, outline->down, level + 1);
		outline = outline->next;
	}
}

static void showoutline(void)
{
	fz_outline *outline = fz_load_outline(ctx, (fz_document*)doc);
	fz_output *out = NULL;

	fz_var(out);
	fz_try(ctx)
	{
		out = fz_stdout(ctx);
		fz_print_outline(ctx, out, outline, 0);
	}
	fz_always(ctx)
	{
		fz_drop_output(ctx, out);
		fz_drop_outline(ctx, outline);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

int pdfshow_main(int argc, char **argv)
{
	char *password = NULL; /* don't throw errors if encrypted */
	char *filename = NULL;
	char *output = NULL;
	int c;

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	while ((c = fz_getopt(argc, argv, "p:o:be")) != -1)
	{
		switch (c)
		{
		case 'p': password = fz_optarg; break;
		case 'o': output = fz_optarg; break;
		case 'b': showbinary = 1; break;
		case 'e': showdecode = 0; break;
		default: usage(); break;
		}
	}

	if (fz_optind == argc)
		usage();

	filename = argv[fz_optind++];

	if (output)
		out = fz_new_output_with_path(ctx, output, 0);
	else
		out = fz_stdout(ctx);

	fz_var(doc);
	fz_try(ctx)
	{
		doc = pdf_open_document(ctx, filename);
		if (pdf_needs_password(ctx, doc))
			if (!pdf_authenticate_password(ctx, doc, password))
				fz_warn(ctx, "cannot authenticate password: %s", filename);

		if (fz_optind == argc)
			showtrailer();

		while (fz_optind < argc)
		{
			switch (argv[fz_optind][0])
			{
			case 't': showtrailer(); break;
			case 'e': showencrypt(); break;
			case 'x': showxref(); break;
			case 'p': showpagetree(); break;
			case 'g': showgrep(filename); break;
			case 'o': showoutline(); break;
			default: showobject(atoi(argv[fz_optind])); break;
			}
			fz_optind++;
		}
	}
	fz_catch(ctx)
	{
	}

	fz_drop_output(ctx, out);
	pdf_drop_document(ctx, doc);
	fz_drop_context(ctx);
	return 0;
}
