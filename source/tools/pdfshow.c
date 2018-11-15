/*
 * pdfshow -- the ultimate pdf debugging tool
 */

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static pdf_document *doc = NULL;
static fz_context *ctx = NULL;
static fz_output *out = NULL;
static int showbinary = 0;
static int showdecode = 1;
static int tight = 0;
static int showcolumn;

static void usage(void)
{
	fprintf(stderr,
		"usage: mutool show [options] file.pdf ( xref | outline | grep | <path> ) *\n"
		"\t-p -\tpassword\n"
		"\t-o -\toutput file\n"
		"\t-e\tleave stream contents in their original form\n"
		"\t-b\tprint only stream contents, as raw binary data\n"
		"\t-g\tprint only object, one line per object, suitable for grep\n"
		"\tpath: path to an object, starting with either an object number,\n"
		"\t\t'pages', 'trailer', or a property in the trailer;\n"
		"\t\tpath elements separated by '.' or '/'. Path elements must be\n"
		"\t\tarray index numbers, dictionary property names, or '*'.\n"
	);
	exit(1);
}

static void showtrailer(void)
{
	if (tight)
		fz_write_printf(ctx, out, "trailer ");
	else
		fz_write_printf(ctx, out, "trailer\n");
	pdf_print_obj(ctx, out, pdf_trailer(ctx, doc), tight);
	fz_write_printf(ctx, out, "\n");
}

static void showxref(void)
{
	int i;
	int xref_len = pdf_xref_len(ctx, doc);
	printf("xref\n0 %d\n", xref_len);
	for (i = 0; i < xref_len; i++)
	{
		pdf_xref_entry *entry = pdf_get_xref_entry(ctx, doc, i);
		fz_write_printf(ctx, out, "%05d: %010d %05d %c \n",
				i,
				(int)entry->ofs,
				entry->gen,
				entry->type ? entry->type : '-');
	}
}

static void showpages(void)
{
	pdf_obj *ref;
	int i, n = pdf_count_pages(ctx, doc);
	for (i = 0; i < n; ++i)
	{
		ref = pdf_lookup_page_obj(ctx, doc, i);
		fz_write_printf(ctx, out, "page %d = %d 0 R\n", i + 1, pdf_to_num(ctx, ref));
	}
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

static void showobject(pdf_obj *ref)
{
	pdf_obj *obj = pdf_resolve_indirect(ctx, ref);
	int num = pdf_to_num(ctx, ref);
	if (pdf_is_stream(ctx, ref))
	{
		if (showbinary)
		{
			showstream(num);
		}
		else
		{
			if (tight)
			{
				fz_write_printf(ctx, out, "%d 0 obj ", num);
				pdf_print_obj(ctx, out, obj, 1);
				fz_write_printf(ctx, out, " stream\n");
			}
			else
			{
				fz_write_printf(ctx, out, "%d 0 obj\n", num);
				pdf_print_obj(ctx, out, obj, 0);
				fz_write_printf(ctx, out, "\nstream\n");
				showstream(num);
				fz_write_printf(ctx, out, "endstream\n");
				fz_write_printf(ctx, out, "endobj\n");
			}
		}
	}
	else
	{
		if (tight)
		{
			fz_write_printf(ctx, out, "%d 0 obj ", num);
			pdf_print_obj(ctx, out, obj, 1);
			fz_write_printf(ctx, out, "\n");
		}
		else
		{
			fz_write_printf(ctx, out, "%d 0 obj\n", num);
			pdf_print_obj(ctx, out, obj, 0);
			fz_write_printf(ctx, out, "\nendobj\n");
		}
	}
}

static void showgrep(void)
{
	pdf_obj *ref, *obj;
	int i, len;

	len = pdf_count_objects(ctx, doc);
	for (i = 0; i < len; i++)
	{
		pdf_xref_entry *entry = pdf_get_xref_entry(ctx, doc, i);
		if (entry->type == 'n' || entry->type == 'o')
		{
			fz_try(ctx)
			{
				ref = pdf_new_indirect(ctx, doc, i, 0);
				obj = pdf_resolve_indirect(ctx, ref);
			}
			fz_catch(ctx)
			{
				pdf_drop_obj(ctx, ref);
				fz_warn(ctx, "skipping object (%d 0 R)", i);
				continue;
			}

			pdf_sort_dict(ctx, obj);

			fz_write_printf(ctx, out, "%d 0 obj ", i);
			pdf_print_obj(ctx, out, obj, 1);
			if (pdf_is_stream(ctx, ref))
				fz_write_printf(ctx, out, " stream");
			fz_write_printf(ctx, out, "\n");

			pdf_drop_obj(ctx, ref);
		}
	}

	fz_write_printf(ctx, out, "trailer ");
	pdf_print_obj(ctx, out, pdf_trailer(ctx, doc), 1);
	fz_write_printf(ctx, out, "\n");
}

static void
fz_print_outline(fz_context *ctx, fz_output *out, fz_outline *outline, int level)
{
	int i;
	while (outline)
	{
		if (outline->down)
			fz_write_byte(ctx, out, outline->is_open ? '-' : '+');
		else
			fz_write_byte(ctx, out, '|');

		for (i = 0; i < level; i++)
			fz_write_byte(ctx, out, '\t');
		fz_write_printf(ctx, out, "%q\t%s\n", outline->title, outline->uri);
		if (outline->down)
			fz_print_outline(ctx, out, outline->down, level + 1);
		outline = outline->next;
	}
}

static void showoutline(void)
{
	fz_outline *outline = fz_load_outline(ctx, (fz_document*)doc);
	fz_try(ctx)
		fz_print_outline(ctx, fz_stdout(ctx), outline, 1);
	fz_always(ctx)
		fz_drop_outline(ctx, outline);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

#define SEP ".[]/"

static int isnumber(char *s)
{
	while (*s)
	{
		if (*s < '0' || *s > '9')
			return 0;
		++s;
	}
	return 1;
}

static void showpath(char *path, pdf_obj *obj)
{
	if (path && path[0])
	{
		char *part = fz_strsep(&path, SEP);
		if (part && part[0])
		{
			if (!strcmp(part, "*"))
			{
				int i, n;
				char buf[1000];
				if (pdf_is_array(ctx, obj))
				{
					n = pdf_array_len(ctx, obj);
					for (i = 0; i < n; ++i)
					{
						if (path)
						{
							fz_strlcpy(buf, path, sizeof buf);
							showpath(buf, pdf_array_get(ctx, obj, i));
						}
						else
							showpath(NULL, pdf_array_get(ctx, obj, i));
					}
				}
				else if (pdf_is_dict(ctx, obj))
				{
					n = pdf_dict_len(ctx, obj);
					for (i = 0; i < n; ++i)
					{
						if (path)
						{
							fz_strlcpy(buf, path, sizeof buf);
							showpath(buf, pdf_dict_get_val(ctx, obj, i));
						}
						else
							showpath(NULL, pdf_dict_get_val(ctx, obj, i));
					}
				}
				else
				{
					printf("null\n");
				}
			}
			else if (isnumber(part))
				showpath(path, pdf_array_get(ctx, obj, atoi(part)));
			else
				showpath(path, pdf_dict_gets(ctx, obj, part));
		}
		else
			printf("null\n");
	}
	else
	{
		if (pdf_is_indirect(ctx, obj))
			showobject(obj);
		else
		{
			pdf_print_obj(ctx, out, obj, tight);
			printf("\n");
		}
	}
}

static void showpathpage(char *path)
{
	if (path)
	{
		char *part = fz_strsep(&path, SEP);
		if (part && part[0])
		{
			if (!strcmp(part, "*"))
			{
				int i, n;
				char buf[1000];
				n = pdf_count_pages(ctx, doc);
				for (i = 0; i < n; ++i)
				{
					if (path)
					{
						fz_strlcpy(buf, path, sizeof buf);
						showpath(buf, pdf_lookup_page_obj(ctx, doc, i));
					}
					else
						showpath(NULL, pdf_lookup_page_obj(ctx, doc, i));
				}
			}
			else if (isnumber(part))
				showpath(path, pdf_lookup_page_obj(ctx, doc, atoi(part)-1));
			else
				printf("null\n");
		}
		else
			printf("null\n");
	}
	else
	{
		showpages();
	}
}

static void showpathroot(char *path)
{
	char buf[2000], *list = buf, *part;
	fz_strlcpy(buf, path, sizeof buf);
	part = fz_strsep(&list, SEP);
	if (part && part[0])
	{
		if (!strcmp(part, "trailer"))
			showpath(list, pdf_trailer(ctx, doc));
		else if (!strcmp(part, "pages"))
			showpathpage(list);
		else if (isnumber(part))
		{
			pdf_obj *num = pdf_new_indirect(ctx, doc, atoi(part), 0);
			showpath(list, num);
			pdf_drop_obj(ctx, num);
		}
		else
			showpath(list, pdf_dict_gets(ctx, pdf_trailer(ctx, doc), part));
	}
	else
		printf("null\n");
}

static void show(char *sel)
{
	if (!strcmp(sel, "trailer"))
		showtrailer();
	else if (!strcmp(sel, "xref"))
		showxref();
	else if (!strcmp(sel, "pages"))
		showpages();
	else if (!strcmp(sel, "grep"))
		showgrep();
	else if (!strcmp(sel, "outline"))
		showoutline();
	else
		showpathroot(sel);
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

	while ((c = fz_getopt(argc, argv, "p:o:beg")) != -1)
	{
		switch (c)
		{
		case 'p': password = fz_optarg; break;
		case 'o': output = fz_optarg; break;
		case 'b': showbinary = 1; break;
		case 'e': showdecode = 0; break;
		case 'g': tight = 1; break;
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
			show(argv[fz_optind++]);

		fz_close_output(ctx, out);
	}
	fz_catch(ctx)
	{
	}

	fz_drop_output(ctx, out);
	pdf_drop_document(ctx, doc);
	fz_drop_context(ctx);
	return 0;
}
