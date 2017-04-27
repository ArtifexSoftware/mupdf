#include "mupdf/fitz.h"

#include <string.h>

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
img_drop_document(fz_context *ctx, fz_document *doc_)
{
	img_document *doc = (img_document*)doc_;
	fz_drop_image(ctx, doc->image);
}

static int
img_count_pages(fz_context *ctx, fz_document *doc_)
{
	return 1;
}

static fz_rect *
img_bound_page(fz_context *ctx, fz_page *page_, fz_rect *bbox)
{
	img_page *page = (img_page*)page_;
	fz_image *image = page->image;
	int xres, yres;
	fz_image_resolution(image, &xres, &yres);
	bbox->x0 = bbox->y0 = 0;
	bbox->x1 = image->w * DPI / xres;
	bbox->y1 = image->h * DPI / yres;
	return bbox;
}

static void
img_run_page(fz_context *ctx, fz_page *page_, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	img_page *page = (img_page*)page_;
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
img_drop_page(fz_context *ctx, fz_page *page_)
{
	img_page *page = (img_page*)page_;
	fz_drop_image(ctx, page->image);
}

static fz_page *
img_load_page(fz_context *ctx, fz_document *doc_, int number)
{
	img_document *doc = (img_document*)doc_;
	img_page *page;

	if (number != 0)
		return NULL;

	page = fz_new_derived_page(ctx, img_page);

	page->super.bound_page = img_bound_page;
	page->super.run_page_contents = img_run_page;
	page->super.drop_page = img_drop_page;

	page->image = fz_keep_image(ctx, doc->image);

	return (fz_page*)page;
}

static int
img_lookup_metadata(fz_context *ctx, fz_document *doc_, const char *key, char *buf, int size)
{
	if (!strcmp(key, "format"))
		return (int)fz_strlcpy(buf, "Image", size);
	return -1;
}

static img_document *
img_new_document(fz_context *ctx, fz_image *image)
{
	img_document *doc = fz_new_derived_document(ctx, img_document);

	doc->super.drop_document = img_drop_document;
	doc->super.count_pages = img_count_pages;
	doc->super.load_page = img_load_page;
	doc->super.lookup_metadata = img_lookup_metadata;

	doc->image = fz_keep_image(ctx, image);

	return doc;
}

static fz_document *
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

	return (fz_document*)doc;
}

static const char *img_extensions[] =
{
	"bmp",
	"gif",
	"hdp",
	"j2k",
	"jfif",
	"jfif-tbnl",
	"jp2",
	"jpe",
	"jpeg",
	"jpg",
	"jpx",
	"jxr",
	"pam",
	"pbm",
	"pgm",
	"png",
	"pnm",
	"ppm",
	"wdp",
	NULL
};

static const char *img_mimetypes[] =
{
	"image/bmp",
	"image/gif",
	"image/jp2",
	"image/jpeg",
	"image/jpx",
	"image/jxr",
	"image/pjpeg",
	"image/png",
	"image/vnd.ms-photo",
	"image/x-portable-arbitrarymap",
	"image/x-portable-bitmap",
	"image/x-portable-greymap",
	"image/x-portable-pixmap",
	NULL
};

fz_document_handler img_document_handler =
{
	NULL,
	NULL,
	img_open_document_with_stream,
	img_extensions,
	img_mimetypes
};
