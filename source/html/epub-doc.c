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
	int count;
	epub_chapter *spine;
	fz_outline *outline;
	char *dc_title, *dc_creator;
};

struct epub_chapter_s
{
	char *path;
	int start;
	float page_w, page_h, em;
	float page_margin[4];
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
epub_update_link_dests(fz_context *ctx, epub_document *doc, fz_outline *node)
{
	epub_chapter *ch;

	while (node)
	{
		if (node->dest.kind == FZ_LINK_GOTO)
		{
			for (ch = doc->spine; ch; ch = ch->next)
			{
				if (!strcmp(ch->path, node->dest.ld.gotor.dest))
				{
					node->dest.ld.gotor.page = ch->start;
					break;
				}
			}
		}
		epub_update_link_dests(ctx, doc, node->down);
		node = node->next;
	}
}

static void
epub_layout(fz_context *ctx, fz_document *doc_, float w, float h, float em)
{
	epub_document *doc = (epub_document*)doc_;
	epub_chapter *ch;
	int count = 0;

	for (ch = doc->spine; ch; ch = ch->next)
	{
		ch->start = count;
		ch->em = em;
		ch->page_margin[T] = fz_from_css_number(ch->box->style.margin[T], em, em);
		ch->page_margin[B] = fz_from_css_number(ch->box->style.margin[B], em, em);
		ch->page_margin[L] = fz_from_css_number(ch->box->style.margin[L], em, em);
		ch->page_margin[R] = fz_from_css_number(ch->box->style.margin[R], em, em);
		ch->page_w = w - ch->page_margin[L] - ch->page_margin[R];
		ch->page_h = h - ch->page_margin[T] - ch->page_margin[B];
		fz_layout_html(ctx, ch->box, ch->page_w, ch->page_h, ch->em);
		count += ceilf(ch->box->h / ch->page_h);
	}

	epub_update_link_dests(ctx, doc, doc->outline);
}

static int
epub_count_pages(fz_context *ctx, fz_document *doc_)
{
	epub_document *doc = (epub_document*)doc_;
	epub_chapter *ch;
	int count = 0;
	for (ch = doc->spine; ch; ch = ch->next)
		count += ceilf(ch->box->h / ch->page_h);
	return count;
}

static void
epub_drop_page(fz_context *ctx, fz_page *page_)
{
}

static fz_rect *
epub_bound_page(fz_context *ctx, fz_page *page_, fz_rect *bbox)
{
	epub_page *page = (epub_page*)page_;
	epub_document *doc = page->doc;
	epub_chapter *ch;
	int n = page->number;
	int count = 0;

	for (ch = doc->spine; ch; ch = ch->next)
	{
		int cn = ceilf(ch->box->h / ch->page_h);
		if (n < count + cn)
		{
			bbox->x0 = 0;
			bbox->y0 = 0;
			bbox->x1 = ch->page_w + ch->page_margin[L] + ch->page_margin[R];
			bbox->y1 = ch->page_h + ch->page_margin[T] + ch->page_margin[B];
			return bbox;
		}
		count += cn;
	}

	*bbox = fz_unit_rect;
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

	for (ch = doc->spine; ch; ch = ch->next)
	{
		int cn = ceilf(ch->box->h / ch->page_h);
		if (n < count + cn)
		{
			fz_pre_translate(&local_ctm, ch->page_margin[L], ch->page_margin[T]);
			fz_draw_html(ctx, dev, &local_ctm, ch->box, (n-count) * ch->page_h, (n-count+1) * ch->page_h);
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
	page->super.drop_page = epub_drop_page;
	page->doc = doc;
	page->number = number;
	return (fz_page*)page;
}

static void
epub_drop_document(fz_context *ctx, fz_document *doc_)
{
	epub_document *doc = (epub_document*)doc_;
	epub_chapter *ch, *next;
	ch = doc->spine;
	while (ch)
	{
		next = ch->next;
		fz_drop_html(ctx, ch->box);
		fz_free(ctx, ch->path);
		fz_free(ctx, ch);
		ch = next;
	}
	fz_drop_archive(ctx, doc->zip);
	fz_drop_html_font_set(ctx, doc->set);
	fz_drop_outline(ctx, doc->outline);
	fz_free(ctx, doc->dc_title);
	fz_free(ctx, doc->dc_creator);
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
	ch->path = fz_strdup(ctx, path);
	ch->box = fz_parse_html(ctx, doc->set, zip, base_uri, buf, fz_user_css(ctx));
	ch->next = NULL;

	fz_drop_buffer(ctx, buf);

	return ch;
}

static fz_outline *
epub_parse_ncx_imp(fz_context *ctx, epub_document *doc, fz_xml *node, char *base_uri)
{
	fz_outline *outline, *head, *tail;
	char path[2048], *s;

	head = NULL;

	node = fz_xml_find_down(node, "navPoint");
	while (node)
	{
		char *text = fz_xml_text(fz_xml_down(fz_xml_find_down(fz_xml_find_down(node, "navLabel"), "text")));
		char *content = fz_xml_att(fz_xml_find_down(node, "content"), "src");
		if (text && content)
		{
			fz_strlcpy(path, base_uri, sizeof path);
			fz_strlcat(path, "/", sizeof path);
			fz_strlcat(path, content, sizeof path);
			fz_urldecode(path);
			fz_cleanname(path);
			s = strchr(path, '#');
			if (s)
				*s = 0;

			outline = fz_new_outline(ctx);
			outline->title = fz_strdup(ctx, text);
			outline->dest.kind = FZ_LINK_GOTO;
			outline->dest.ld.gotor.dest = fz_strdup(ctx, path);
			outline->dest.ld.gotor.page = 0; /* computed in epub_layout */
			outline->down = epub_parse_ncx_imp(ctx, doc, node, base_uri);

			if (!head)
				head = tail = outline;
			else
				tail = tail->next = outline;
		}
		node = fz_xml_find_next(node, "navPoint");
	}

	return head;
}

static void
epub_parse_ncx(fz_context *ctx, epub_document *doc, const char *path)
{
	fz_archive *zip = doc->zip;
	fz_buffer *buf;
	fz_xml *ncx;
	char base_uri[2048];

	fz_dirname(base_uri, path, sizeof base_uri);

	buf = fz_read_archive_entry(ctx, zip, path);
	fz_write_buffer_byte(ctx, buf, 0);
	ncx = fz_parse_xml(ctx, buf->data, buf->len, 0);
	fz_drop_buffer(ctx, buf);

	doc->outline = epub_parse_ncx_imp(ctx, doc, fz_xml_find_down(ncx, "navMap"), base_uri);

	fz_drop_xml(ctx, ncx);
}

static char *
find_metadata(fz_context *ctx, fz_xml *metadata, char *key)
{
	char *text = fz_xml_text(fz_xml_down(fz_xml_find_down(metadata, key)));
	if (text)
		return fz_strdup(ctx, text);
	return NULL;
}

static void
epub_parse_header(fz_context *ctx, epub_document *doc)
{
	fz_archive *zip = doc->zip;
	fz_buffer *buf;
	fz_xml *container_xml, *content_opf;
	fz_xml *container, *rootfiles, *rootfile;
	fz_xml *package, *manifest, *spine, *itemref, *metadata;
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

	metadata = fz_xml_find_down(package, "metadata");
	if (metadata)
	{
		doc->dc_title = find_metadata(ctx, metadata, "title");
		doc->dc_creator = find_metadata(ctx, metadata, "creator");
	}

	manifest = fz_xml_find_down(package, "manifest");
	spine = fz_xml_find_down(package, "spine");

	if (path_from_idref(ncx, manifest, base_uri, fz_xml_att(spine, "toc"), sizeof ncx))
	{
		epub_parse_ncx(ctx, doc, ncx);
	}

	head = tail = NULL;
	itemref = fz_xml_find_down(spine, "itemref");
	while (itemref)
	{
		if (path_from_idref(s, manifest, base_uri, fz_xml_att(itemref, "idref"), sizeof s))
		{
			if (!head)
				head = tail = epub_parse_chapter(ctx, doc, s);
			else
				tail = tail->next = epub_parse_chapter(ctx, doc, s);
		}
		itemref = fz_xml_find_next(itemref, "itemref");
	}

	doc->spine = head;

	fz_drop_xml(ctx, container_xml);
	fz_drop_xml(ctx, content_opf);
}

static fz_outline *
epub_load_outline(fz_context *ctx, fz_document *doc_)
{
	epub_document *doc = (epub_document*)doc_;
	return fz_keep_outline(ctx, doc->outline);
}

static int
epub_lookup_metadata(fz_context *ctx, fz_document *doc_, const char *key, char *buf, int size)
{
	epub_document *doc = (epub_document*)doc_;
	if (!strcmp(key, FZ_META_FORMAT))
		return (int)fz_strlcpy(buf, "EPUB", size);
	if (!strcmp(key, FZ_META_INFO_TITLE) && doc->dc_title)
		return (int)fz_strlcpy(buf, doc->dc_title, size);
	if (!strcmp(key, FZ_META_INFO_AUTHOR) && doc->dc_creator)
		return (int)fz_strlcpy(buf, doc->dc_creator, size);
	return -1;
}

static fz_document *
epub_init(fz_context *ctx, fz_archive *zip)
{
	epub_document *doc;

	doc = fz_new_document(ctx, epub_document);
	doc->zip = zip;
	doc->set = fz_new_html_font_set(ctx);

	doc->super.drop_document = epub_drop_document;
	doc->super.layout = epub_layout;
	doc->super.load_outline = epub_load_outline;
	doc->super.count_pages = epub_count_pages;
	doc->super.load_page = epub_load_page;
	doc->super.lookup_metadata = epub_lookup_metadata;

	fz_try(ctx)
	{
		epub_parse_header(ctx, doc);
	}
	fz_catch(ctx)
	{
		epub_drop_document(ctx, (fz_document*)doc);
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
