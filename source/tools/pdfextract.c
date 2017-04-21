/*
 * pdfextract -- the ultimate way to extract images and fonts from pdfs
 */

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <stdlib.h>
#include <stdio.h>

static pdf_document *doc = NULL;
static fz_context *ctx = NULL;
static int dorgb = 0;

static void usage(void)
{
	fprintf(stderr, "usage: mutool extract [options] file.pdf [object numbers]\n");
	fprintf(stderr, "\t-p\tpassword\n");
	fprintf(stderr, "\t-r\tconvert images to rgb\n");
	exit(1);
}

static int isimage(pdf_obj *obj)
{
	pdf_obj *type = pdf_dict_get(ctx, obj, PDF_NAME_Subtype);
	return pdf_name_eq(ctx, type, PDF_NAME_Image);
}

static int isfontdesc(pdf_obj *obj)
{
	pdf_obj *type = pdf_dict_get(ctx, obj, PDF_NAME_Type);
	return pdf_name_eq(ctx, type, PDF_NAME_FontDescriptor);
}

static void writepixmap(fz_context *ctx, fz_pixmap *pix, char *file, int dorgb)
{
	char buf[1024];
	fz_pixmap *rgb = NULL;

	if (!pix)
		return;

	if (dorgb && pix->colorspace && pix->colorspace != fz_device_rgb(ctx))
	{
		rgb = fz_convert_pixmap(ctx, pix, fz_device_rgb(ctx), 1);
		pix = rgb;
	}

	if (pix->n - pix->alpha <= 3)
	{
		snprintf(buf, sizeof(buf), "%s.png", file);
		printf("extracting image %s\n", buf);
		fz_save_pixmap_as_png(ctx, pix, buf);
	}
	else
	{
		snprintf(buf, sizeof(buf), "%s.pam", file);
		printf("extracting image %s\n", buf);
		fz_save_pixmap_as_pam(ctx, pix, buf);
	}

	fz_drop_pixmap(ctx, rgb);
}

static void
writejpeg(fz_context *ctx, const unsigned char *data, size_t len, const char *file)
{
	char buf[1024];
	fz_output *out = NULL;

	fz_var(out);

	snprintf(buf, sizeof(buf), "%s.jpg", file);

	fz_try(ctx)
	{
		out = fz_new_output_with_path(ctx, buf, 0);
		fz_write_data(ctx, out, data, len);
	}
	fz_always(ctx)
	{
		fz_drop_output(ctx, out);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void saveimage(int num)
{
	fz_image *image = NULL;
	fz_pixmap *pix = NULL;
	pdf_obj *ref;
	char buf[32];
	fz_compressed_buffer *cbuf;
	int type;

	ref = pdf_new_indirect(ctx, doc, num, 0);

	fz_var(image);
	fz_var(pix);

	fz_try(ctx)
	{
		image = pdf_load_image(ctx, doc, ref);
		cbuf = fz_compressed_image_buffer(ctx, image);
		snprintf(buf, sizeof(buf), "img-%04d", num);
		type = cbuf == NULL ? FZ_IMAGE_UNKNOWN : cbuf->params.type;
		if (image->use_colorkey)
			type = FZ_IMAGE_UNKNOWN;
		if (image->use_decode)
			type = FZ_IMAGE_UNKNOWN;
		if (image->mask)
			type = FZ_IMAGE_UNKNOWN;
		switch (type)
		{
		case FZ_IMAGE_JPEG:
		{
			unsigned char *data;
			size_t len = fz_buffer_storage(ctx, cbuf->buffer, &data);
			snprintf(buf, sizeof(buf), "img-%04d", num);
			writejpeg(ctx, data, len, buf);
			break;
		}
		default:
			pix = fz_get_pixmap_from_image(ctx, image, NULL, NULL, 0, 0);
			writepixmap(ctx, pix, buf, dorgb);
		}
	}
	fz_always(ctx)
	{
		fz_drop_image(ctx, image);
		fz_drop_pixmap(ctx, pix);
		pdf_drop_obj(ctx, ref);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void savefont(pdf_obj *dict, int num)
{
	char namebuf[1024];
	fz_buffer *buf;
	pdf_obj *stream = NULL;
	pdf_obj *obj;
	char *ext = "";
	fz_output *out;
	char *fontname = "font";
	size_t len;
	unsigned char *data;

	obj = pdf_dict_get(ctx, dict, PDF_NAME_FontName);
	if (obj)
		fontname = pdf_to_name(ctx, obj);

	obj = pdf_dict_get(ctx, dict, PDF_NAME_FontFile);
	if (obj)
	{
		stream = obj;
		ext = "pfa";
	}

	obj = pdf_dict_get(ctx, dict, PDF_NAME_FontFile2);
	if (obj)
	{
		stream = obj;
		ext = "ttf";
	}

	obj = pdf_dict_get(ctx, dict, PDF_NAME_FontFile3);
	if (obj)
	{
		stream = obj;

		obj = pdf_dict_get(ctx, obj, PDF_NAME_Subtype);
		if (obj && !pdf_is_name(ctx, obj))
			fz_throw(ctx, FZ_ERROR_GENERIC, "invalid font descriptor subtype");

		if (pdf_name_eq(ctx, obj, PDF_NAME_Type1C))
			ext = "cff";
		else if (pdf_name_eq(ctx, obj, PDF_NAME_CIDFontType0C))
			ext = "cid";
		else if (pdf_name_eq(ctx, obj, PDF_NAME_OpenType))
			ext = "otf";
		else
			fz_throw(ctx, FZ_ERROR_GENERIC, "unhandled font type '%s'", pdf_to_name(ctx, obj));
	}

	if (!stream)
	{
		fz_warn(ctx, "unhandled font type");
		return;
	}

	buf = pdf_load_stream(ctx, stream);
	len = fz_buffer_storage(ctx, buf, &data);
	fz_try(ctx)
	{
		snprintf(namebuf, sizeof(namebuf), "%s-%04d.%s", fontname, num, ext);
		printf("extracting font %s\n", namebuf);
		out = fz_new_output_with_path(ctx, namebuf, 0);
		fz_try(ctx)
			fz_write_data(ctx, out, data, len);
		fz_always(ctx)
			fz_drop_output(ctx, out);
		fz_catch(ctx)
			fz_rethrow(ctx);
	}
	fz_always(ctx)
		fz_drop_buffer(ctx, buf);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void showobject(int num)
{
	pdf_obj *obj;

	if (!doc)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no file specified");

	fz_try(ctx)
	{
		obj = pdf_load_object(ctx, doc, num);

		if (isimage(obj))
			saveimage(num);
		else if (isfontdesc(obj))
			savefont(obj, num);

		pdf_drop_obj(ctx, obj);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "ignoring object %d", num);
	}
}

int pdfextract_main(int argc, char **argv)
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
	{
		int len = pdf_count_objects(ctx, doc);
		for (o = 1; o < len; o++)
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

	pdf_drop_document(ctx, doc);
	fz_flush_warnings(ctx);
	fz_drop_context(ctx);
	return 0;
}
