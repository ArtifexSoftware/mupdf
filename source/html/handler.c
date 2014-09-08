#include "mupdf/html.h"

struct html_page_s
{
};

void
html_close_document(html_document *doc)
{
	fz_context *ctx = doc->ctx;
	fz_free(ctx, doc);
}

int
html_count_pages(html_document *doc)
{
	return 1;
}

html_page *
html_load_page(html_document *doc, int number)
{
	printf("html: load page %d\n", number);
	return "nothing";
}

void
html_free_page(html_document *doc, html_page *page)
{
}

fz_rect *
html_bound_page(html_document *doc, html_page *page, fz_rect *bbox)
{
	printf("html: bound page\n");
	bbox->x0 = bbox->y0 = 0;
	bbox->x1 = 400;
	bbox->y1 = 600;
	return bbox;
}

void
html_run_page(html_document *doc, html_page *page, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	printf("html: run page\n");
}

html_document *
html_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	html_document *doc;
	fz_buffer *buf;
	fz_xml *root;

	buf = fz_read_all(file, 0);
	root = fz_parse_xml(ctx, buf->data, buf->len, 1);
	fz_drop_buffer(ctx, buf);

	doc = fz_malloc_struct(ctx, html_document);
	doc->ctx = ctx;
	doc->root = root;

	doc->super.close = (void*)html_close_document;
	doc->super.count_pages = (void*)html_count_pages;
	doc->super.load_page = (void*)html_load_page;
	doc->super.bound_page = (void*)html_bound_page;
	doc->super.run_page_contents = (void*)html_run_page;
	doc->super.free_page = (void*)html_free_page;

	html_layout_document(doc, 400, 600);

	return doc;
}

html_document *
html_open_document(fz_context *ctx, const char *filename)
{
	fz_stream *file;
	html_document *doc;

	file = fz_open_file(ctx, filename);
	if (!file)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open file '%s': %s", filename, strerror(errno));

	fz_try(ctx)
	{
		doc = html_open_document_with_stream(ctx, file);
	}
	fz_always(ctx)
	{
		fz_close(file);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return doc;
}

static int
html_recognize(fz_context *doc, const char *magic)
{
	char *ext = strrchr(magic, '.');

	if (ext)
	{
		if (!fz_strcasecmp(ext, ".xhtml") || !fz_strcasecmp(ext, ".html"))
			return 100;
	}
	if (!strcmp(magic, "application/html+xml") || !strcmp(magic, "application/xml") || !strcmp(magic, "text/xml"))
		return 100;

	return 0;
}

fz_document_handler html_document_handler =
{
	(fz_document_recognize_fn *)&html_recognize,
	(fz_document_open_fn *)&html_open_document,
	(fz_document_open_with_stream_fn *)&html_open_document_with_stream
};
