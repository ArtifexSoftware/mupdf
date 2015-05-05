#include "mupdf/html.h"

enum { T, R, B, L };

typedef struct epub_document_s epub_document;
typedef struct epub_chapter_s epub_chapter;
typedef struct epub_page_s epub_page;

struct epub_document_s
{
	fz_document super;
	fz_archive *zip;
	fz_html_font_set *set;
	float page_w, page_h, em;
	float page_margin[4];
	int count;
	epub_chapter *spine;
};

struct epub_chapter_s
{
	int start;
	fz_html *box;
	epub_chapter *next;
};

struct epub_page_s
{
	fz_page super;
	epub_document *doc;
	int number;
};

static void
epub_layout(fz_context *ctx, fz_document *doc_, float w, float h, float em)
{
	epub_document *doc = (epub_document*)doc_;
	epub_chapter *ch;

	doc->page_margin[T] = em;
	doc->page_margin[B] = em;
	doc->page_margin[L] = 0;
	doc->page_margin[R] = 0;

	doc->page_w = w - doc->page_margin[L] - doc->page_margin[R];
	doc->page_h = h - doc->page_margin[T] - doc->page_margin[B];
	doc->em = em;

	printf("epub: laying out chapters.\n");
	for (ch = doc->spine; ch; ch = ch->next)
		fz_layout_html(ctx, ch->box, doc->page_w, doc->page_h, doc->em);
	printf("epub: done.\n");
}

static int
epub_count_pages(fz_context *ctx, fz_document *doc_)
{
	epub_document *doc = (epub_document*)doc_;
	epub_chapter *ch;
	int count = 0;
	for (ch = doc->spine; ch; ch = ch->next)
		count += ceilf(ch->box->h / doc->page_h);
	return count;
}

static void
epub_drop_page_imp(fz_context *ctx, fz_page *page_)
{
}

static fz_rect *
epub_bound_page(fz_context *ctx, fz_page *page_, fz_rect *bbox)
{
	epub_page *page = (epub_page*)page_;
	epub_document *doc = page->doc;
	bbox->x0 = 0;
	bbox->y0 = 0;
	bbox->x1 = doc->page_w + doc->page_margin[L] + doc->page_margin[R];
	bbox->y1 = doc->page_h + doc->page_margin[T] + doc->page_margin[B];
	return bbox;
}

static void
epub_run_page(fz_context *ctx, fz_page *page_, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	epub_page *page = (epub_page*)page_;
	epub_document *doc = page->doc;
	epub_chapter *ch;
	fz_matrix local_ctm = *ctm;
	int n = page->number;
	int count = 0;

	fz_pre_translate(&local_ctm, doc->page_margin[L], doc->page_margin[T]);

	for (ch = doc->spine; ch; ch = ch->next)
	{
		int cn = ceilf(ch->box->h / doc->page_h);
		if (n < count + cn)
		{
			fz_draw_html(ctx, ch->box, (n-count) * doc->page_h, (n-count+1) * doc->page_h, dev, &local_ctm);
			break;
		}
		count += cn;
	}
}

static fz_page *
epub_load_page(fz_context *ctx, fz_document *doc_, int number)
{
	epub_document *doc = (epub_document*)doc_;
	epub_page *page = fz_new_page(ctx, sizeof *page);
	page->super.bound_page = epub_bound_page;
	page->super.run_page_contents = epub_run_page;
	page->super.drop_page_imp = epub_drop_page_imp;
	page->doc = doc;
	page->number = number;
	return (fz_page*)page;
}

static void
epub_close_document(fz_context *ctx, fz_document *doc_)
{
	epub_document *doc = (epub_document*)doc_;
	epub_chapter *ch, *next;
	ch = doc->spine;
	while (ch)
	{
		next = ch->next;
		fz_drop_html(ctx, ch->box);
		fz_free(ctx, ch);
		ch = next;
	}
	fz_drop_archive(ctx, doc->zip);
	fz_drop_html_font_set(ctx, doc->set);
	fz_free(ctx, doc);
}

static const char *
rel_path_from_idref(fz_xml *manifest, const char *idref)
{
	fz_xml *item;
	if (!idref)
		return NULL;
	item = fz_xml_find_down(manifest, "item");
	while (item)
	{
		const char *id = fz_xml_att(item, "id");
		if (id && !strcmp(id, idref))
			return fz_xml_att(item, "href");
		item = fz_xml_find_next(item, "item");
	}
	return NULL;
}

static const char *
path_from_idref(char *path, fz_xml *manifest, const char *base_uri, const char *idref, int n)
{
	const char *rel_path = rel_path_from_idref(manifest, idref);
	if (!rel_path)
	{
		path[0] = 0;
		return NULL;
	}
	fz_strlcpy(path, base_uri, n);
	fz_strlcat(path, "/", n);
	fz_strlcat(path, rel_path, n);
	return fz_cleanname(fz_urldecode(path));
}

static epub_chapter *
epub_parse_chapter(fz_context *ctx, epub_document *doc, const char *path)
{
	fz_archive *zip = doc->zip;
	fz_buffer *buf;
	epub_chapter *ch;
	char base_uri[2048];

	fz_dirname(base_uri, path, sizeof base_uri);

	buf = fz_read_archive_entry(ctx, zip, path);
	fz_write_buffer_byte(ctx, buf, 0);

	ch = fz_malloc_struct(ctx, epub_chapter);
	ch->box = fz_parse_html(ctx, doc->set, zip, base_uri, buf, NULL);
	ch->next = NULL;

	fz_drop_buffer(ctx, buf);

	return ch;
}

static void
epub_parse_header(fz_context *ctx, epub_document *doc)
{
	fz_archive *zip = doc->zip;
	fz_buffer *buf;
	fz_xml *container_xml, *content_opf;
	fz_xml *container, *rootfiles, *rootfile;
	fz_xml *package, *manifest, *spine, *itemref;
	char base_uri[2048];
	const char *full_path;
	const char *version;
	char ncx[2048], s[2048];
	epub_chapter *head, *tail;

	if (fz_has_archive_entry(ctx, zip, "META-INF/rights.xml"))
		fz_throw(ctx, FZ_ERROR_GENERIC, "EPUB is locked by DRM");
	if (fz_has_archive_entry(ctx, zip, "META-INF/encryption.xml"))
		fz_throw(ctx, FZ_ERROR_GENERIC, "EPUB is locked by DRM");

	/* parse META-INF/container.xml to find OPF */

	buf = fz_read_archive_entry(ctx, zip, "META-INF/container.xml");
	fz_write_buffer_byte(ctx, buf, 0);
	container_xml = fz_parse_xml(ctx, buf->data, buf->len, 0);
	fz_drop_buffer(ctx, buf);

	container = fz_xml_find(container_xml, "container");
	rootfiles = fz_xml_find_down(container, "rootfiles");
	rootfile = fz_xml_find_down(rootfiles, "rootfile");
	full_path = fz_xml_att(rootfile, "full-path");
	if (!full_path)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find root file in EPUB");

	printf("epub: found root: %s\n", full_path);

	fz_dirname(base_uri, full_path, sizeof base_uri);

	/* parse OPF to find NCX and spine */

	buf = fz_read_archive_entry(ctx, zip, full_path);
	fz_write_buffer_byte(ctx, buf, 0);
	content_opf = fz_parse_xml(ctx, buf->data, buf->len, 0);
	fz_drop_buffer(ctx, buf);

	package = fz_xml_find(content_opf, "package");
	version = fz_xml_att(package, "version");
	if (!version || strcmp(version, "2.0"))
		fz_warn(ctx, "unknown epub version: %s", version ? version : "<none>");

	manifest = fz_xml_find_down(package, "manifest");
	spine = fz_xml_find_down(package, "spine");

	if (path_from_idref(ncx, manifest, base_uri, fz_xml_att(spine, "toc"), sizeof ncx))
	{
		/* TODO: parse NCX to create fz_outline */
		printf("epub: found outline: %s\n", ncx);
	}

	head = tail = NULL;
	itemref = fz_xml_find_down(spine, "itemref");
	while (itemref)
	{
		if (path_from_idref(s, manifest, base_uri, fz_xml_att(itemref, "idref"), sizeof s))
		{
			printf("epub: found spine %s\n", s);
			if (!head)
				head = tail = epub_parse_chapter(ctx, doc, s);
			else
				tail = tail->next = epub_parse_chapter(ctx, doc, s);
		}
		itemref = fz_xml_find_next(itemref, "itemref");
	}

	doc->spine = head;

	printf("epub: done.\n");

	fz_drop_xml(ctx, container_xml);
	fz_drop_xml(ctx, content_opf);
}

static fz_document *
epub_init(fz_context *ctx, fz_archive *zip)
{
	epub_document *doc;

	doc = fz_malloc_struct(ctx, epub_document);
	doc->zip = zip;
	doc->set = fz_new_html_font_set(ctx);

	doc->super.close = epub_close_document;
	doc->super.layout = epub_layout;
	doc->super.count_pages = epub_count_pages;
	doc->super.load_page = epub_load_page;

	fz_try(ctx)
	{
		epub_parse_header(ctx, doc);
	}
	fz_catch(ctx)
	{
		epub_close_document(ctx, (fz_document*)doc);
		fz_rethrow(ctx);
	}

	return (fz_document*)doc;
}

static fz_document *
epub_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	return epub_init(ctx, fz_open_archive_with_stream(ctx, file));
}

static fz_document *
epub_open_document(fz_context *ctx, const char *filename)
{
	if (strstr(filename, "META-INF/container.xml") || strstr(filename, "META-INF\\container.xml"))
	{
		char dirname[2048], *p;
		fz_strlcpy(dirname, filename, sizeof dirname);
		p = strstr(dirname, "META-INF");
		*p = 0;
		if (!dirname[0])
			fz_strlcpy(dirname, ".", sizeof dirname);
		return epub_init(ctx, fz_open_directory(ctx, dirname));
	}

	return epub_init(ctx, fz_open_archive(ctx, filename));
}

static int
epub_recognize(fz_context *doc, const char *magic)
{
	char *ext = strrchr(magic, '.');
	if (ext)
		if (!fz_strcasecmp(ext, ".epub"))
			return 100;
	if (strstr(magic, "META-INF/container.xml") || strstr(magic, "META-INF\\container.xml"))
		return 200;
	if (!strcmp(magic, "application/epub+zip"))
		return 100;
	return 0;
}

fz_document_handler epub_document_handler =
{
	&epub_recognize,
	&epub_open_document,
	&epub_open_document_with_stream
};
