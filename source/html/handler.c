#include "mupdf/html.h"

#define DEFW (450)
#define DEFH (600)
#define DEFEM (12)

typedef struct html_document_s html_document;

struct html_document_s
{
	fz_document super;
	fz_context *ctx;
	html_context htx;
	struct box *box;
};

static void
htdoc_close_document(html_document *doc)
{
	fz_context *ctx = doc->ctx;
	html_fini(ctx, &doc->htx);
	fz_free(ctx, doc);
}

static int
htdoc_count_pages(html_document *doc)
{
	int count;

	// TODO: reflow

	count = ceilf(doc->box->h / doc->htx.page_h);
printf("count pages! %g / %g = %d\n", doc->box->h, doc->htx.page_h, count);
	return count;
}

static void *
htdoc_load_page(html_document *doc, int number)
{
printf("load page %d\n", number);
	// TODO: reflow
	return (void*)((intptr_t)number + 1);
}

static void
htdoc_free_page(html_document *doc, void *page)
{
}

static void
htdoc_layout(html_document *doc, float w, float h, float em)
{
	html_layout(doc->ctx, &doc->htx, doc->box, w, h, em);
}

static fz_rect *
htdoc_bound_page(html_document *doc, void *page, fz_rect *bbox)
{
	// TODO: reflow
	printf("html: bound page\n");
	bbox->x0 = bbox->y0 = 0;
	bbox->x1 = doc->htx.page_w;
	bbox->y1 = doc->htx.page_h;
	return bbox;
}

static void
htdoc_run_page(html_document *doc, void *page, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	int n = ((intptr_t)page) - 1;
	printf("html: run page %d\n", n);
	html_draw(doc->ctx, &doc->htx, doc->box, n * doc->htx.page_h, (n+1) * doc->htx.page_h, dev, ctm);
}


static html_document *
htdoc_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	html_document *doc;
	fz_archive *zip;
	fz_buffer *buf;

	zip = fz_open_directory(ctx, ".");

	doc = fz_malloc_struct(ctx, html_document);
	doc->ctx = ctx;
	html_init(ctx, &doc->htx, zip);

	doc->super.close = (void*)htdoc_close_document;
	doc->super.layout = (void*)htdoc_layout;
	doc->super.count_pages = (void*)htdoc_count_pages;
	doc->super.load_page = (void*)htdoc_load_page;
	doc->super.bound_page = (void*)htdoc_bound_page;
	doc->super.run_page_contents = (void*)htdoc_run_page;
	doc->super.free_page = (void*)htdoc_free_page;

	buf = fz_read_all(file, 0);
	fz_write_buffer_byte(ctx, buf, 0);
	doc->box = html_generate(ctx, &doc->htx, ".", buf);
	fz_drop_buffer(ctx, buf);

	return doc;
}

static html_document *
htdoc_open_document(fz_context *ctx, const char *filename)
{
	char dirname[2048];
	fz_archive *zip;
	fz_buffer *buf;
	html_document *doc;

	fz_dirname(dirname, filename, sizeof dirname);
	zip = fz_open_directory(ctx, dirname);

	doc = fz_malloc_struct(ctx, html_document);
	doc->ctx = ctx;
	html_init(ctx, &doc->htx, zip);

	doc->super.close = (void*)htdoc_close_document;
	doc->super.layout = (void*)htdoc_layout;
	doc->super.count_pages = (void*)htdoc_count_pages;
	doc->super.load_page = (void*)htdoc_load_page;
	doc->super.bound_page = (void*)htdoc_bound_page;
	doc->super.run_page_contents = (void*)htdoc_run_page;
	doc->super.free_page = (void*)htdoc_free_page;

	buf = fz_read_file(ctx, filename);
	fz_write_buffer_byte(ctx, buf, 0);
	doc->box = html_generate(ctx, &doc->htx, ".", buf);
	fz_drop_buffer(ctx, buf);

	htdoc_layout(doc, DEFW, DEFH, DEFEM);

	return doc;
}

static int
htdoc_recognize(fz_context *doc, const char *magic)
{
	char *ext = strrchr(magic, '.');

	if (ext)
	{
		if (!fz_strcasecmp(ext, ".xml") || !fz_strcasecmp(ext, ".xhtml") || !fz_strcasecmp(ext, ".html"))
			return 100;
	}
	if (!strcmp(magic, "application/html+xml") || !strcmp(magic, "application/xml") || !strcmp(magic, "text/xml"))
		return 100;

	return 0;
}

fz_document_handler html_document_handler =
{
	(fz_document_recognize_fn *)&htdoc_recognize,
	(fz_document_open_fn *)&htdoc_open_document,
	(fz_document_open_with_stream_fn *)&htdoc_open_document_with_stream
};
