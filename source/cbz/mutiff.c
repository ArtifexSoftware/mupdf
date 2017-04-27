#include "mupdf/fitz.h"

#include <string.h>

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
tiff_bound_page(fz_context *ctx, fz_page *page_, fz_rect *bbox)
{
	tiff_page *page = (tiff_page*)page_;
	fz_image *image = page->image;
	int xres, yres;

	fz_image_resolution(image, &xres, &yres);
	bbox->x0 = bbox->y0 = 0;
	bbox->x1 = image->w * DPI / xres;
	bbox->y1 = image->h * DPI / yres;
	return bbox;
}

static void
tiff_run_page(fz_context *ctx, fz_page *page_, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	tiff_page *page = (tiff_page*)page_;
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
tiff_drop_page(fz_context *ctx, fz_page *page_)
{
	tiff_page *page = (tiff_page*)page_;
	fz_drop_image(ctx, page->image);
}

static fz_page *
tiff_load_page(fz_context *ctx, fz_document *doc_, int number)
{
	tiff_document *doc = (tiff_document*)doc_;
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
		size_t len;
		unsigned char *data;
		len = fz_buffer_storage(ctx, doc->buffer, &data);
		pixmap = fz_load_tiff_subimage(ctx, data, len, number);
		image = fz_new_image_from_pixmap(ctx, pixmap, NULL);

		page = fz_new_derived_page(ctx, tiff_page);
		page->super.bound_page = tiff_bound_page;
		page->super.run_page_contents = tiff_run_page;
		page->super.drop_page = tiff_drop_page;
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

	return (fz_page*)page;
}

static int
tiff_count_pages(fz_context *ctx, fz_document *doc_)
{
	tiff_document *doc = (tiff_document*)doc_;
	return doc->page_count;
}

static int
tiff_lookup_metadata(fz_context *ctx, fz_document *doc_, const char *key, char *buf, int size)
{
	if (!strcmp(key, "format"))
		return (int)fz_strlcpy(buf, "TIFF", size);
	return -1;
}

static void
tiff_drop_document(fz_context *ctx, fz_document *doc_)
{
	tiff_document *doc = (tiff_document*)doc_;
	fz_drop_buffer(ctx, doc->buffer);
}

static fz_document *
tiff_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	tiff_document *doc;

	doc = fz_new_derived_document(ctx, tiff_document);

	doc->super.drop_document = tiff_drop_document;
	doc->super.count_pages = tiff_count_pages;
	doc->super.load_page = tiff_load_page;
	doc->super.lookup_metadata = tiff_lookup_metadata;

	fz_try(ctx)
	{
		size_t len;
		unsigned char *data;
		doc->buffer = fz_read_all(ctx, file, 1024);
		len = fz_buffer_storage(ctx, doc->buffer, &data);
		doc->page_count = fz_load_tiff_subimage_count(ctx, data, len);
	}
	fz_catch(ctx)
	{
		fz_drop_document(ctx, (fz_document*)doc);
		fz_rethrow(ctx);
	}

	return (fz_document*)doc;
}

static const char *tiff_extensions[] =
{
	"tif",
	"tiff",
	NULL
};

static const char *tiff_mimetypes[] =
{
	"image/tiff",
	"image/x-tiff",
	NULL
};

fz_document_handler tiff_document_handler =
{
	NULL,
	NULL,
	tiff_open_document_with_stream,
	tiff_extensions,
	tiff_mimetypes
};
