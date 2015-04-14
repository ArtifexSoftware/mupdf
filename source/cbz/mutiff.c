#include "mupdf/fitz.h"

typedef struct tiff_document_s tiff_document;
typedef struct tiff_page_s tiff_page;

#define DPI 72.0f

struct tiff_page_s
{
	fz_page super;
	fz_image *image;
};

struct tiff_document_s
{
	fz_document super;
	fz_buffer *buffer;
	int page_count;
};

static fz_rect *
tiff_bound_page(fz_context *ctx, tiff_page *page, fz_rect *bbox)
{
	fz_image *image = page->image;
	int xres, yres;

	fz_image_get_sanitised_res(image, &xres, &yres);
	bbox->x0 = bbox->y0 = 0;
	bbox->x1 = image->w * DPI / xres;
	bbox->y1 = image->h * DPI / yres;
	return bbox;
}

static void
tiff_run_page(fz_context *ctx, tiff_page *page, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	fz_matrix local_ctm = *ctm;
	fz_image *image = page->image;
	int xres, yres;
	float w, h;

	fz_image_get_sanitised_res(image, &xres, &yres);
	w = image->w * DPI / xres;
	h = image->h * DPI / yres;
	fz_pre_scale(&local_ctm, w, h);
	fz_fill_image(ctx, dev, image, &local_ctm, 1);
}

static void
tiff_drop_page_imp(fz_context *ctx, tiff_page *page)
{
	if (!page)
		return;
	fz_drop_image(ctx, page->image);
}

static tiff_page *
tiff_load_page(fz_context *ctx, tiff_document *doc, int number)
{
	fz_pixmap *pixmap = NULL;
	fz_image *image = NULL;
	tiff_page *page = NULL;

	if (number < 0 || number >= doc->page_count)
		return NULL;

	fz_var(pixmap);
	fz_var(image);
	fz_var(page);

	fz_try(ctx)
	{
		pixmap = fz_load_tiff_subimage(ctx, doc->buffer->data, doc->buffer->len, number);
		image = fz_new_image_from_pixmap(ctx, pixmap, NULL);

		page = fz_new_page(ctx, sizeof *page);
		page->super.bound_page = (fz_page_bound_page_fn *)tiff_bound_page;
		page->super.run_page_contents = (fz_page_run_page_contents_fn *)tiff_run_page;
		page->super.drop_page_imp = (fz_page_drop_page_imp_fn *)tiff_drop_page_imp;
		page->image = fz_keep_image(ctx, image);
	}
	fz_always(ctx)
	{
		fz_drop_image(ctx, image);
		fz_drop_pixmap(ctx, pixmap);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, page);
		fz_rethrow(ctx);
	}

	return page;
}

static int
tiff_count_pages(fz_context *ctx, tiff_document *doc)
{
	return doc->page_count;
}

static int
tiff_lookup_metadata(fz_context *ctx, tiff_document *doc, const char *key, char *buf, int size)
{
	if (!strcmp(key, "format"))
		return fz_strlcpy(buf, "TIFF", size);
	return -1;
}

static void
tiff_close_document(fz_context *ctx, tiff_document *doc)
{
	fz_drop_buffer(ctx, doc->buffer);
	fz_free(ctx, doc);
}

static tiff_document *
tiff_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	tiff_document *doc;

	doc = fz_new_document(ctx, sizeof *doc);

	doc->super.close = (fz_document_close_fn *)tiff_close_document;
	doc->super.count_pages = (fz_document_count_pages_fn *)tiff_count_pages;
	doc->super.load_page = (fz_document_load_page_fn *)tiff_load_page;
	doc->super.lookup_metadata = (fz_document_lookup_metadata_fn *)tiff_lookup_metadata;

	fz_try(ctx)
	{
		doc->buffer = fz_read_all(ctx, file, 1024);
		doc->page_count = fz_load_tiff_subimage_count(ctx, doc->buffer->data, doc->buffer->len);
	}
	fz_catch(ctx)
	{
		tiff_close_document(ctx, doc);
		fz_rethrow(ctx);
	}

	return doc;
}

static tiff_document *
tiff_open_document(fz_context *ctx, const char *filename)
{
	fz_stream *file;
	tiff_document *doc;

	file = fz_open_file(ctx, filename);

	fz_try(ctx)
		doc = tiff_open_document_with_stream(ctx, file);
	fz_always(ctx)
		fz_drop_stream(ctx, file);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return doc;
}

static int
tiff_recognize(fz_context *doc, const char *magic)
{
	char *ext = strrchr(magic, '.');

	if (ext)
	{
		if (!fz_strcasecmp(ext, ".tiff") || !fz_strcasecmp(ext, ".tif"))
			return 100;
	}
	if (!strcmp(magic, "tif") || !strcmp(magic, "image/tiff") ||
		!strcmp(magic, "tiff") || !strcmp(magic, "image/x-tiff"))
		return 100;

	return 0;
}

fz_document_handler tiff_document_handler =
{
	(fz_document_recognize_fn *)&tiff_recognize,
	(fz_document_open_fn *)&tiff_open_document,
	(fz_document_open_with_stream_fn *)&tiff_open_document_with_stream
};
