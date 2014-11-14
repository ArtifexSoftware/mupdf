#include "mupdf/html.h"

void
html_close_document(html_document *doc)
{
	fz_context *ctx = doc->ctx;
	fz_free(ctx, doc);
}

int
html_count_pages(html_document *doc)
{
	int count;

	if (!doc->box) html_layout_document(doc, 400, 400);

	count = ceilf(doc->box->h / doc->page_h);
printf("count pages! %g / %g = %d\n", doc->box->h, doc->page_h, count);
	return count;
}

html_page *
html_load_page(html_document *doc, int number)
{
printf("load page %d\n", number);
	if (!doc->box) html_layout_document(doc, 400, 400);
	return (void*)((intptr_t)number + 1);
}

void
html_free_page(html_document *doc, html_page *page)
{
}

fz_rect *
html_bound_page(html_document *doc, html_page *page, fz_rect *bbox)
{
	if (!doc->box) html_layout_document(doc, 400, 400);
	printf("html: bound page\n");
	bbox->x0 = bbox->y0 = 0;
	bbox->x1 = doc->page_w;
	bbox->y1 = doc->page_h;
	return bbox;
}

void
html_run_page(html_document *doc, html_page *page, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	int n = ((intptr_t)page) - 1;
	printf("html: run page %d\n", n);
	html_run_box(doc->ctx, doc->box, n * doc->page_h, (n+1) * doc->page_h, dev, ctm);
}

html_document *
html_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	html_document *doc;
	fz_buffer *buf;
	fz_xml *xml;

	buf = fz_read_all(file, 0);
	fz_write_buffer_byte(ctx, buf, 0);

printf("html: parsing XHTML.\n");
	xml = fz_parse_xml(ctx, buf->data, buf->len, 1);
	fz_drop_buffer(ctx, buf);

	doc = fz_malloc_struct(ctx, html_document);
	doc->ctx = ctx;
	doc->dirname = NULL;

	doc->super.close = (void*)html_close_document;
	doc->super.count_pages = (void*)html_count_pages;
	doc->super.load_page = (void*)html_load_page;
	doc->super.bound_page = (void*)html_bound_page;
	doc->super.run_page_contents = (void*)html_run_page;
	doc->super.free_page = (void*)html_free_page;

	doc->xml = xml;
	doc->box = NULL;

	return doc;
}

html_document *
html_open_document(fz_context *ctx, const char *filename)
{
	fz_stream *file;
	html_document *doc;
	char *s;

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

	doc->dirname = fz_strdup(ctx, filename);
	s = strrchr(doc->dirname, '/');
	if (!s) s = strrchr(doc->dirname, '\\');
	if (s) s[1] = 0;
	else doc->dirname[0] = 0;

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
