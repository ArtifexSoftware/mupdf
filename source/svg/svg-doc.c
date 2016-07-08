#include "mupdf/svg.h"

typedef struct svg_page_s svg_page;

struct svg_page_s
{
	fz_page super;
	svg_document *doc;
};

static void
svg_drop_document(fz_context *ctx, fz_document *doc_)
{
	svg_document *doc = (svg_document*)doc_;
	fz_drop_tree(ctx, doc->idmap, NULL);
	fz_drop_xml(ctx, doc->root);
	fz_free(ctx, doc);
}

static int
svg_count_pages(fz_context *ctx, fz_document *doc_)
{
	return 1;
}

static fz_rect *
svg_bound_page(fz_context *ctx, fz_page *page_, fz_rect *rect)
{
	svg_page *page = (svg_page*)page_;
	svg_document *doc = page->doc;

	svg_parse_document_bounds(ctx, doc, doc->root);

	rect->x0 = 0;
	rect->y0 = 0;
	rect->x1 = doc->width;
	rect->y1 = doc->height;
	return rect;
}

static void
svg_run_page(fz_context *ctx, fz_page *page_, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	svg_page *page = (svg_page*)page_;
	svg_document *doc = page->doc;
	svg_run_document(ctx, doc, doc->root, dev, ctm);
}

static void
svg_drop_page(fz_context *ctx, fz_page *page_)
{
	/* nothing */
}

static fz_page *
svg_load_page(fz_context *ctx, fz_document *doc_, int number)
{
	svg_document *doc = (svg_document*)doc_;
	svg_page *page;

	if (number != 0)
		return NULL;

	page = fz_new_page(ctx, sizeof *page);
	page->super.bound_page = svg_bound_page;
	page->super.run_page_contents = svg_run_page;
	page->super.drop_page = svg_drop_page;
	page->doc = doc;

	return (fz_page*)page;
}

static void
svg_build_id_map(fz_context *ctx, svg_document *doc, fz_xml *root)
{
	fz_xml *node;

	char *id_att = fz_xml_att(root, "id");
	if (id_att)
		doc->idmap = fz_tree_insert(ctx, doc->idmap, id_att, root);

	for (node = fz_xml_down(root); node; node = fz_xml_next(node))
		svg_build_id_map(ctx, doc, node);
}

static fz_document *
svg_open_document_with_buffer(fz_context *ctx, fz_buffer *buf)
{
	svg_document *doc;
	fz_xml *root;

	root = fz_parse_xml(ctx, buf->data, buf->len, 0);

	doc = fz_new_document(ctx, svg_document);
	doc->super.drop_document = svg_drop_document;
	doc->super.count_pages = svg_count_pages;
	doc->super.load_page = svg_load_page;

	doc->root = root;
	doc->idmap = NULL;

	svg_build_id_map(ctx, doc, root);

	return (fz_document*)doc;
}

static fz_document *
svg_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	fz_buffer *buf;
	fz_document *doc;

	buf = fz_read_all(ctx, file, 0);
	fz_try(ctx)
		doc = svg_open_document_with_buffer(ctx, buf);
	fz_always(ctx)
		fz_drop_buffer(ctx, buf);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return doc;
}

static fz_document *
svg_open_document(fz_context *ctx, const char *filename)
{
	fz_stream *file;
	fz_document *doc;

	file = fz_open_file(ctx, filename);
	fz_try(ctx)
		doc = svg_open_document_with_stream(ctx, file);
	fz_always(ctx)
		fz_drop_stream(ctx, file);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return doc;
}

static int
svg_recognize(fz_context *ctx, const char *magic)
{
	char *ext = strrchr(magic, '.');
	if (ext && !fz_strcasecmp(ext, ".svg"))
		return 100;
	if (!strcmp(magic, "svg") || !strcmp(magic, "image/svg+xml"))
		return 100;
	return 0;
}

fz_display_list *
fz_new_display_list_from_svg(fz_context *ctx, fz_buffer *buf, float *w, float *h)
{
	fz_document *doc;
	fz_display_list *list;

	doc = svg_open_document_with_buffer(ctx, buf);
	fz_try(ctx)
	{
		list = fz_new_display_list_from_page_number(ctx, doc, 0);
		*w = ((svg_document*)doc)->width;
		*h = ((svg_document*)doc)->height;
	}
	fz_always(ctx)
		fz_drop_document(ctx, doc);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return list;
}

fz_image *
fz_new_image_from_svg(fz_context *ctx, fz_buffer *buf)
{
	fz_display_list *list;
	fz_image *image;
	float w, h;

	list = fz_new_display_list_from_svg(ctx, buf, &w, &h);
	fz_try(ctx)
		image = fz_new_image_from_display_list(ctx, w, h, list);
	fz_always(ctx)
		fz_drop_display_list(ctx, list);
	fz_catch(ctx)
		fz_rethrow(ctx);
	return image;
}

fz_document_handler svg_document_handler =
{
	&svg_recognize,
	&svg_open_document,
	&svg_open_document_with_stream
};
