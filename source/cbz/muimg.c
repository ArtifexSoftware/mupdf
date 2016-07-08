#include "mupdf/fitz.h"

#define DPI 72.0f

typedef struct img_document_s img_document;
typedef struct img_page_s img_page;

struct img_page_s
{
	fz_page super;
	fz_image *image;
};

struct img_document_s
{
	fz_document super;
	fz_image *image;
};

static void
img_drop_document(fz_context *ctx, img_document *doc)
{
	fz_drop_image(ctx, doc->image);
	fz_free(ctx, doc);
}

static int
img_count_pages(fz_context *ctx, img_document *doc)
{
	return 1;
}

static fz_rect *
img_bound_page(fz_context *ctx, img_page *page, fz_rect *bbox)
{
	fz_image *image = page->image;
	int xres, yres;
	fz_image_resolution(image, &xres, &yres);
	bbox->x0 = bbox->y0 = 0;
	bbox->x1 = image->w * DPI / xres;
	bbox->y1 = image->h * DPI / yres;
	return bbox;
}

static void
img_run_page(fz_context *ctx, img_page *page, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	fz_matrix local_ctm = *ctm;
	fz_image *image = page->image;
	int xres, yres;
	float w, h;
	fz_image_resolution(image, &xres, &yres);
	w = image->w * DPI / xres;
	h = image->h * DPI / yres;
	fz_pre_scale(&local_ctm, w, h);
	fz_fill_image(ctx, dev, image, &local_ctm, 1);
}

static void
img_drop_page(fz_context *ctx, img_page *page)
{
	fz_drop_image(ctx, page->image);
}

static img_page *
img_load_page(fz_context *ctx, img_document *doc, int number)
{
	img_page *page;

	if (number != 0)
		return NULL;

	page = fz_new_page(ctx, sizeof *page);

	page->super.bound_page = (fz_page_bound_page_fn *)img_bound_page;
	page->super.run_page_contents = (fz_page_run_page_contents_fn *)img_run_page;
	page->super.drop_page = (fz_page_drop_page_fn *)img_drop_page;

	page->image = fz_keep_image(ctx, doc->image);

	return page;
}

static int
img_lookup_metadata(fz_context *ctx, img_document *doc, const char *key, char *buf, int size)
{
	if (!strcmp(key, "format"))
		return (int)fz_strlcpy(buf, "Image", size);
	return -1;
}

static img_document *
img_new_document(fz_context *ctx, fz_image *image)
{
	img_document *doc = fz_new_document(ctx, img_document);

	doc->super.drop_document = (fz_document_drop_fn *)img_drop_document;
	doc->super.count_pages = (fz_document_count_pages_fn *)img_count_pages;
	doc->super.load_page = (fz_document_load_page_fn *)img_load_page;
	doc->super.lookup_metadata = (fz_document_lookup_metadata_fn *)img_lookup_metadata;

	doc->image = fz_keep_image(ctx, image);

	return doc;
}

static img_document *
img_open_document_with_stream(fz_context *ctx, fz_stream *stm)
{
	fz_buffer *buffer = NULL;
	fz_image *image = NULL;
	img_document *doc;

	fz_var(buffer);
	fz_var(image);

	fz_try(ctx)
	{
		buffer = fz_read_all(ctx, stm, 1024);
		image = fz_new_image_from_buffer(ctx, buffer);
		doc = img_new_document(ctx, image);
	}
	fz_always(ctx)
	{
		fz_drop_image(ctx, image);
		fz_drop_buffer(ctx, buffer);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);

	return doc;
}

static img_document *
img_open_document(fz_context *ctx, const char *filename)
{
	fz_stream *stm;
	img_document *doc;

	stm = fz_open_file(ctx, filename);

	fz_try(ctx)
		doc = img_open_document_with_stream(ctx, stm);
	fz_always(ctx)
		fz_drop_stream(ctx, stm);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return doc;
}

static int
img_recognize(fz_context *doc, const char *magic)
{
	char *ext = strrchr(magic, '.');

	if (ext)
	{
		if (!fz_strcasecmp(ext, ".png") || !fz_strcasecmp(ext, ".jpg") ||
			!fz_strcasecmp(ext, ".jpeg") || !fz_strcasecmp(ext, ".jfif") ||
			!fz_strcasecmp(ext, ".jfif-tbnl") || !fz_strcasecmp(ext, ".jpe") ||
			!fz_strcasecmp(ext, ".gif") || !fz_strcasecmp(ext, ".bmp") ||
			!fz_strcasecmp(ext, ".jpx") || !fz_strcasecmp(ext, ".jp2") ||
			!fz_strcasecmp(ext, ".j2k") || !fz_strcasecmp(ext, ".wdp") ||
			!fz_strcasecmp(ext, ".hdp") || !fz_strcasecmp(ext, ".jxr") ||
			!fz_strcasecmp(ext, ".pbm") || !fz_strcasecmp(ext, ".pgm") ||
			!fz_strcasecmp(ext, ".ppm") || !fz_strcasecmp(ext, ".pam") ||
			!fz_strcasecmp(ext, ".pnm"))
			return 100;
	}
	if (!strcmp(magic, "png") || !strcmp(magic, "image/png") ||
		!strcmp(magic, "jpg") || !strcmp(magic, "image/jpeg") ||
		!strcmp(magic, "jpeg") || !strcmp(magic, "image/pjpeg") ||
		!strcmp(magic, "jpe") || !strcmp(magic, "jfif") ||
		!strcmp(magic, "gif") || !strcmp(magic, "image/gif") ||
		!strcmp(magic, "bmp") || !strcmp(magic, "image/bmp") ||
		!strcmp(magic, "jpx") || !strcmp(magic, "image/jpx") ||
		!strcmp(magic, "jp2") || !strcmp(magic, "image/jp2") ||
		!strcmp(magic, "j2k") || !strcmp(magic, "wdp") ||
		!strcmp(magic, "hdp") || !strcmp(magic, "image/vnd.ms-photo") ||
		!strcmp(magic, "jxr") || !strcmp(magic, "image/jxr") ||
		!strcmp(magic, "pbm") || !strcmp(magic, "image/x-portable-bitmap") ||
		!strcmp(magic, "pgm") || !strcmp(magic, "image/x-portable-greymap") ||
		!strcmp(magic, "ppm") || !strcmp(magic, "image/x-portable-pixmap") ||
		!strcmp(magic, "pam") || !strcmp(magic, "image/x-portable-arbitrarymap") ||
		!strcmp(magic, "pnm"))
		return 100;

	return 0;
}

fz_document_handler img_document_handler =
{
	(fz_document_recognize_fn *)&img_recognize,
	(fz_document_open_fn *)&img_open_document,
	(fz_document_open_with_stream_fn *)&img_open_document_with_stream
};
