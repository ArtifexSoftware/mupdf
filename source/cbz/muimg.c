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
	fz_buffer *buffer;
	const char *format;
	int page_count;
	fz_pixmap *(*load_subimage)(fz_context *ctx, const unsigned char *p, size_t total, int subimage);
};

static void
img_drop_document(fz_context *ctx, fz_document *doc_)
{
	img_document *doc = (img_document*)doc_;
	fz_drop_buffer(ctx, doc->buffer);
}

static int
img_count_pages(fz_context *ctx, fz_document *doc_)
{
	img_document *doc = (img_document*)doc_;
	return doc->page_count;
}

static fz_rect
img_bound_page(fz_context *ctx, fz_page *page_)
{
	img_page *page = (img_page*)page_;
	fz_image *image = page->image;
	int xres, yres;
	fz_rect bbox;

	fz_image_resolution(image, &xres, &yres);
	bbox.x0 = bbox.y0 = 0;
	bbox.x1 = image->w * DPI / xres;
	bbox.y1 = image->h * DPI / yres;
	return bbox;
}

static void
img_run_page(fz_context *ctx, fz_page *page_, fz_device *dev, fz_matrix ctm, fz_cookie *cookie)
{
	img_page *page = (img_page*)page_;
	fz_image *image = page->image;
	int xres, yres;
	float w, h;

	fz_image_resolution(image, &xres, &yres);
	w = image->w * DPI / xres;
	h = image->h * DPI / yres;
	ctm = fz_pre_scale(ctm, w, h);
	fz_fill_image(ctx, dev, image, ctm, 1, NULL);
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
	fz_pixmap *pixmap = NULL;
	fz_image *image = NULL;
	img_page *page = NULL;

	if (number < 0 || number >= doc->page_count)
		return NULL;

	fz_var(pixmap);
	fz_var(image);
	fz_var(page);

	fz_try(ctx)
	{
		if (doc->load_subimage)
		{
			size_t len;
			unsigned char *data;
			len = fz_buffer_storage(ctx, doc->buffer, &data);
			pixmap = doc->load_subimage(ctx, data, len, number);
			image = fz_new_image_from_pixmap(ctx, pixmap, NULL);
		}
		else
		{
			image = fz_new_image_from_buffer(ctx, doc->buffer);
		}

		page = fz_new_derived_page(ctx, img_page);
		page->super.bound_page = img_bound_page;
		page->super.run_page_contents = img_run_page;
		page->super.drop_page = img_drop_page;
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
img_lookup_metadata(fz_context *ctx, fz_document *doc_, const char *key, char *buf, int size)
{
	img_document *doc = (img_document*)doc_;
	if (!strcmp(key, "format"))
		return (int)fz_strlcpy(buf, doc->format, size);
	return -1;
}

static fz_document *
img_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	img_document *doc = NULL;

	doc = fz_new_derived_document(ctx, img_document);

	doc->super.drop_document = img_drop_document;
	doc->super.count_pages = img_count_pages;
	doc->super.load_page = img_load_page;
	doc->super.lookup_metadata = img_lookup_metadata;

	fz_try(ctx)
	{
		int fmt;
		size_t len;
		unsigned char *data;

		doc->buffer = fz_read_all(ctx, file, 1024);
		len = fz_buffer_storage(ctx, doc->buffer, &data);

		fmt = FZ_IMAGE_UNKNOWN;
		if (len >= 8)
			fmt = fz_recognize_image_format(ctx, data);
		if (fmt == FZ_IMAGE_TIFF)
		{
			doc->page_count = fz_load_tiff_subimage_count(ctx, data, len);
			doc->load_subimage = fz_load_tiff_subimage;
			doc->format = "TIFF";
		}
		else if (fmt == FZ_IMAGE_PNM)
		{
			doc->page_count = fz_load_pnm_subimage_count(ctx, data, len);
			doc->load_subimage = fz_load_pnm_subimage;
			doc->format = "PNM";
		}
		else
		{
			doc->page_count = 1;
			doc->format = "Image";
		}
	}
	fz_catch(ctx)
	{
		fz_drop_document(ctx, (fz_document*)doc);
		fz_rethrow(ctx);
	}

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
	"tif",
	"tiff",
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
	"image/tiff",
	"image/vnd.ms-photo",
	"image/x-portable-anymap",
	"image/x-portable-arbitrarymap",
	"image/x-portable-bitmap",
	"image/x-portable-greymap",
	"image/x-portable-pixmap",
	"image/x-tiff",
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
