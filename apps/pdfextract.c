/*
 * pdfextract -- the ultimate way to extract images and fonts from pdfs
 */

#include "fitz.h"
#include "mupdf.h"

static pdf_xref *xref = NULL;
static fz_context *ctx = NULL;
static int dorgb = 0;

void die(fz_error error)
{
	fz_error_handle(error, "aborting");
	if (xref)
		pdf_free_xref(xref);
	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "usage: pdfextract [options] file.pdf [object numbers]\n");
	fprintf(stderr, "\t-p\tpassword\n");
	fprintf(stderr, "\t-r\tconvert images to rgb\n");
	exit(1);
}

static int isimage(fz_obj *obj)
{
	fz_obj *type = fz_dict_gets(obj, "Subtype");
	return fz_is_name(type) && !strcmp(fz_to_name(type), "Image");
}

static int isfontdesc(fz_obj *obj)
{
	fz_obj *type = fz_dict_gets(obj, "Type");
	return fz_is_name(type) && !strcmp(fz_to_name(type), "FontDescriptor");
}

static void saveimage(int num)
{
	fz_pixmap *img;
	fz_obj *ref;
	char name[1024];

	ref = fz_new_indirect(ctx, num, 0, xref);

	/* TODO: detect DCTD and save as jpeg */

	fz_try(ctx)
	{
		img = pdf_load_image(xref, ref);
	}
	fz_catch(ctx)
	{
		die(1);
	}

	if (dorgb && img->colorspace && img->colorspace != fz_device_rgb)
	{
		fz_pixmap *temp;
		temp = fz_new_pixmap_with_rect(ctx, fz_device_rgb, fz_bound_pixmap(img));
		fz_convert_pixmap(ctx, img, temp);
		fz_drop_pixmap(ctx, img);
		img = temp;
	}

	if (img->n <= 4)
	{
		sprintf(name, "img-%04d.png", num);
		printf("extracting image %s\n", name);
		fz_write_png(ctx, img, name, 0);
	}
	else
	{
		sprintf(name, "img-%04d.pam", num);
		printf("extracting image %s\n", name);
		fz_write_pam(ctx, img, name, 0);
	}

	fz_drop_pixmap(ctx, img);
	fz_drop_obj(ref);
}

static void savefont(fz_obj *dict, int num)
{
	char name[1024];
	char *subtype;
	fz_buffer *buf;
	fz_obj *stream = NULL;
	fz_obj *obj;
	char *ext = "";
	FILE *f;
	char *fontname = "font";
	int n;

	obj = fz_dict_gets(dict, "FontName");
	if (obj)
		fontname = fz_to_name(obj);

	obj = fz_dict_gets(dict, "FontFile");
	if (obj)
	{
		stream = obj;
		ext = "pfa";
	}

	obj = fz_dict_gets(dict, "FontFile2");
	if (obj)
	{
		stream = obj;
		ext = "ttf";
	}

	obj = fz_dict_gets(dict, "FontFile3");
	if (obj)
	{
		stream = obj;

		obj = fz_dict_gets(obj, "Subtype");
		if (obj && !fz_is_name(obj))
			die(fz_error_make("Invalid font descriptor subtype"));

		subtype = fz_to_name(obj);
		if (!strcmp(subtype, "Type1C"))
			ext = "cff";
		else if (!strcmp(subtype, "CIDFontType0C"))
			ext = "cid";
		else
			die(fz_error_make("Unhandled font type '%s'", subtype));
	}

	if (!stream)
	{
		fz_warn(ctx, "Unhandled font type");
		return;
	}

	fz_try(ctx)
	{
		buf = pdf_load_stream(xref, fz_to_num(stream), fz_to_gen(stream));
	}
	fz_catch(ctx)
	{
		die(1);
	}

	sprintf(name, "%s-%04d.%s", fontname, num, ext);
	printf("extracting font %s\n", name);

	f = fopen(name, "wb");
	if (f == NULL)
		die(fz_error_make("Error creating font file"));

	n = fwrite(buf->data, 1, buf->len, f);
	if (n < buf->len)
		die(fz_error_make("Error writing font file"));

	if (fclose(f) < 0)
		die(fz_error_make("Error closing font file"));

	fz_drop_buffer(ctx, buf);
}

static void showobject(int num)
{
	fz_obj *obj;

	if (!xref)
		die(fz_error_make("no file specified"));

	fz_try(ctx)
	{
		obj = pdf_load_object(xref, num, 0);
	}
	fz_catch(ctx)
	{
		die(1);
	}

	if (isimage(obj))
		saveimage(num);
	else if (isfontdesc(obj))
		savefont(obj, num);

	fz_drop_obj(obj);
}

int main(int argc, char **argv)
{
	char *infile;
	char *password = "";
	int c, o;

	while ((c = fz_getopt(argc, argv, "p:r")) != -1)
	{
		switch (c)
		{
		case 'p': password = fz_optarg; break;
		case 'r': dorgb++; break;
		default: usage(); break;
		}
	}

	if (fz_optind == argc)
		usage();

	infile = argv[fz_optind++];

	ctx = fz_new_context();
	if (ctx == NULL)
		die(fz_error_note(1, "failed to initialise context"));

	fz_try(ctx)
	{
		xref = pdf_open_xref(ctx, infile, password);
	}
	fz_catch(ctx)
	{
		die(fz_error_note(1, "cannot open input file '%s'", infile));
	}

	if (fz_optind == argc)
	{
		for (o = 0; o < xref->len; o++)
			showobject(o);
	}
	else
	{
		while (fz_optind < argc)
		{
			showobject(atoi(argv[fz_optind]));
			fz_optind++;
		}
	}

	pdf_free_xref(xref);
	fz_flush_warnings(ctx);
	fz_free_context(ctx);
	return 0;
}
