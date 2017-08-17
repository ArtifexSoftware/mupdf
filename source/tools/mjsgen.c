/*
 * mjs test file generation tool
 */

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
	A useful bit of bash script to call this to generate mjs files:
	for f in tests_private/pdf/forms/v1.3/ *.pdf ; do g=${f%.*} ; echo $g ; ./mjsgen $g.pdf $g.mjs ; done

	Remove the space from "/ *.pdf" before running - can't leave that
	in here, as it causes a warning about a possibly malformed comment.
*/

static char lorem[] =
"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum "
"vehicula augue id est lobortis mollis. Aenean vestibulum metus sed est "
"gravida non tempus lacus aliquet. Nulla vehicula lobortis tincidunt. "
"Donec malesuada nisl et lacus condimentum nec tincidunt urna gravida. "
"Sed dapibus magna eu velit ultrices non rhoncus risus lacinia. Fusce "
"vitae nulla volutpat elit dictum ornare at eu libero. Maecenas felis "
"enim, tempor a tincidunt id, commodo consequat lectus.\n"
"Morbi tincidunt adipiscing lacus eu dignissim. Pellentesque augue elit, "
"ultrices vitae fermentum et, faucibus et purus. Nam ante libero, lacinia "
"id tincidunt at, ultricies a lorem. Donec non neque at purus condimentum "
"eleifend quis sit amet libero. Sed semper, mi ut tempus tincidunt, lacus "
"eros pellentesque lacus, id vehicula est diam eu quam. Integer tristique "
"fringilla rhoncus. Phasellus convallis, justo ut mollis viverra, dui odio "
"euismod ante, nec fringilla nisl mi ac diam.\n"
"Maecenas mi urna, ornare commodo feugiat id, cursus in massa. Vivamus "
"augue augue, aliquam at varius eu, venenatis fermentum felis. Sed varius "
"turpis a felis ultrices quis aliquet nunc tincidunt. Suspendisse posuere "
"commodo nunc non viverra. Praesent condimentum varius quam, vel "
"consectetur odio volutpat in. Sed malesuada augue ut lectus commodo porta. "
"Vivamus eget mauris sit amet diam ultrices sollicitudin. Cras pharetra leo "
"non elit lacinia vulputate.\n"
"Donec ac enim justo, ornare scelerisque diam. Ut vel ante at lorem "
"placerat bibendum ultricies mattis metus. Phasellus in imperdiet odio. "
"Proin semper lacinia libero, sed rutrum eros blandit non. Duis tincidunt "
"ligula est, non pellentesque mauris. Aliquam in erat scelerisque lacus "
"dictum suscipit eget semper magna. Nullam luctus imperdiet risus a "
"semper.\n"
"Curabitur sit amet tempor sapien. Quisque et tortor in lacus dictum "
"pulvinar. Nunc at nisl ut velit vehicula hendrerit. Mauris elementum "
"sollicitudin leo ac ullamcorper. Proin vel leo nec justo tempus aliquet "
"nec ut mi. Pellentesque vel nisl id dui hendrerit fermentum nec quis "
"tortor. Proin eu sem luctus est consequat euismod. Vestibulum ante ipsum "
"primis in faucibus orci luctus et ultrices posuere cubilia Curae; Fusce "
"consectetur ultricies nisl ornare dictum. Cras sagittis consectetur lorem "
"sed posuere. Mauris accumsan laoreet arcu, id molestie lorem faucibus eu. "
"Vivamus commodo, neque nec imperdiet pretium, lorem metus viverra turpis, "
"malesuada vulputate justo eros sit amet neque. Nunc quis justo elit, non "
"rutrum mauris. Maecenas blandit condimentum nibh, nec vulputate orci "
"pulvinar at. Proin sed arcu vel odio tempus lobortis sed posuere ipsum. Ut "
"feugiat pellentesque tortor nec ornare.\n";


static void usage(void)
{
	fprintf(stderr, "usage: mjsgen [-p password] input.pdf output.mjs\n");
	exit(1);
}

static void escape_string(FILE *out, int len, const char *string)
{
	while (len-- && *string)
	{
		char c = *string++;
		switch (c)
		{
		case '\n':
			fputc('\\', out);
			fputc('n', out);
			break;
		case '\r':
			fputc('\\', out);
			fputc('r', out);
			break;
		case '\t':
			fputc('\\', out);
			fputc('t', out);
			break;
		default:
			fputc(c, out);
		}
	}
}

static void processpage(fz_context *ctx, FILE *output, fz_document *doc, int pagenum)
{
	fz_page *page = fz_load_page(ctx, doc, pagenum - 1);
	pdf_document *inter = pdf_specifics(ctx, doc);
	pdf_widget *widget = NULL;
	int needshot = 0;
	int count = 0;

	if (inter)
		widget = pdf_first_widget(ctx, inter, (pdf_page *)page);

	if (widget)
	{
		fprintf(output, "GOTO %d\n", pagenum);
		needshot = 1;
	}
	for (;widget; widget = pdf_next_widget(ctx, widget))
	{
		fz_rect rect;
		int w, h, len;
		int type = pdf_widget_type(ctx, widget);

		pdf_bound_widget(ctx, widget, &rect);
		w = (rect.x1 - rect.x0);
		h = (rect.y1 - rect.y0);
		++count;
		switch (type)
		{
		default:
			fprintf(output, "%% UNKNOWN %0.2f %0.2f %0.2f %0.2f\n", rect.x0, rect.y0, rect.x1, rect.y1);
			break;
		case PDF_WIDGET_TYPE_PUSHBUTTON:
			fprintf(output, "%% PUSHBUTTON %0.2f %0.2f %0.2f %0.2f\n", rect.x0, rect.y0, rect.x1, rect.y1);
			break;
		case PDF_WIDGET_TYPE_CHECKBOX:
			fprintf(output, "%% CHECKBOX %0.2f %0.2f %0.2f %0.2f\n", rect.x0, rect.y0, rect.x1, rect.y1);
			break;
		case PDF_WIDGET_TYPE_RADIOBUTTON:
			fprintf(output, "%% RADIOBUTTON %0.2f %0.2f %0.2f %0.2f\n", rect.x0, rect.y0, rect.x1, rect.y1);
			break;
		case PDF_WIDGET_TYPE_TEXT:
		{
			int maxlen = pdf_text_widget_max_len(ctx, inter, widget);
			int texttype = pdf_text_widget_content_type(ctx, inter, widget);

			/* If height is low, assume a single row, and base
			 * the width off that. */
			if (h < 10)
			{
				w = (w+h-1) / (h ? h : 1);
				h = 1;
			}
			/* Otherwise, if width is low, work off height */
			else if (w < 10)
			{
				h = (w+h-1) / (w ? w : 1);
				w = 1;
			}
			else
			{
				w = (w+9)/10;
				h = (h+9)/10;
			}
			len = w*h;
			if (len < 2)
				len = 2;
			if (len > maxlen)
				len = maxlen;
			fprintf(output, "%% TEXT %0.2f %0.2f %0.2f %0.2f\n", rect.x0, rect.y0, rect.x1, rect.y1);
			switch (texttype)
			{
			default:
			case PDF_WIDGET_CONTENT_UNRESTRAINED:
				fprintf(output, "TEXT %d ", count);
				escape_string(output, len-3, lorem);
				fprintf(output, "\n");
				break;
			case PDF_WIDGET_CONTENT_NUMBER:
				fprintf(output, "TEXT %d\n", count);
				break;
			case PDF_WIDGET_CONTENT_SPECIAL:
#ifdef __MINGW32__
				fprintf(output, "TEXT %I64d\n", 46702919800LL + count);
#else
				fprintf(output, "TEXT %lld\n", 46702919800LL + count);
#endif
				break;
			case PDF_WIDGET_CONTENT_DATE:
				fprintf(output, "TEXT Jun %d 1979\n", 1 + ((13 + count) % 30));
				break;
			case PDF_WIDGET_CONTENT_TIME:
				++count;
				fprintf(output, "TEXT %02d:%02d\n", ((count/60) % 24), count % 60);
				break;
			}
			break;
		}
		case PDF_WIDGET_TYPE_LISTBOX:
			fprintf(output, "%% LISTBOX %0.2f %0.2f %0.2f %0.2f\n", rect.x0, rect.y0, rect.x1, rect.y1);
			break;
		case PDF_WIDGET_TYPE_COMBOBOX:
			fprintf(output, "%% COMBOBOX %0.2f %0.2f %0.2f %0.2f\n", rect.x0, rect.y0, rect.x1, rect.y1);
			break;
		}
		fprintf(output, "CLICK %0.2f %0.2f\n", (rect.x0+rect.x1)/2, (rect.y0+rect.y1)/2);
	}

	fz_flush_warnings(ctx);

	if (output && needshot)
	{
		fprintf(output, "SCREENSHOT\n");
	}
}

static void processpages(fz_context *ctx, FILE *output, fz_document *doc)
{
	int page, pagecount;
	pagecount = fz_count_pages(ctx, doc);
	for (page = 1; page <= pagecount; ++page)
		processpage(ctx, output, doc, page);
}

static void processscript(fz_context *ctx, FILE *output, char *filename, char *password)
{
	fz_document *doc = NULL;

	fz_var(doc);

	fz_try(ctx)
	{
		fz_register_document_handlers(ctx);

		doc = fz_open_document(ctx, filename);

		if (fz_needs_password(ctx, doc))
		{
			if (!fz_authenticate_password(ctx, doc, password))
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot authenticate password: %s", filename);
			fprintf(output, "PASSWORD %s\n", password);
		}

		fprintf(output, "OPEN %s\n", filename);

		processpages(ctx, output, doc);
	}
	fz_always(ctx)
		fz_drop_document(ctx, doc);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

int main(int argc, char **argv)
{
	char *password = "";
	fz_context *ctx;
	int c;
	static char *filename;
	int exitcode = 0;
	char *mujstest_filename = NULL;
	FILE *output = NULL;

	while ((c = fz_getopt(argc, argv, "p:")) != -1)
	{
		switch (c)
		{
		default: usage(); break;
		case 'p': password = fz_optarg; break;
		}
	}

	if (fz_optind + 2 != argc)
		usage();

	filename = argv[fz_optind];
	mujstest_filename = argv[fz_optind+1];

	if (strcmp(mujstest_filename, "-") == 0)
		output = stdout;
	else
		output = fopen(mujstest_filename, "wb");

	ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	fz_try(ctx)
		processscript(ctx, output, filename, password);
	fz_catch(ctx)
	{
		fprintf(stderr, "mjsgen: cannot process document: %s\n", filename);
		exitcode = 1;
	}

	fz_drop_context(ctx);

	if (fclose(output))
	{
		fprintf(stderr, "mjsgen: could not close output file '%s'\n", mujstest_filename);
		return 1;
	}

	return exitcode;
}

#ifdef _MSC_VER
int wmain(int argc, wchar_t *wargv[])
{
	char **argv = fz_argv_from_wargv(argc, wargv);
	int ret = main(argc, argv);
	fz_free_argv(argc, argv);
	return ret;
}
#endif
