#include "fitz.h"
#include "muxps.h"

/*
 * The FixedDocumentSequence and FixedDocument parts determine
 * which parts correspond to actual pages, and the page order.
 */

void
xps_debug_page_list(xps_document *doc)
{
	xps_fixdoc *fixdoc = doc->first_fixdoc;
	xps_page *page = doc->first_page;

	if (doc->start_part)
		printf("start part %s\n", doc->start_part);

	while (fixdoc)
	{
		printf("fixdoc %s\n", fixdoc->name);
		fixdoc = fixdoc->next;
	}

	while (page)
	{
		printf("page %s w=%d h=%d\n", page->name, page->width, page->height);
		page = page->next;
	}
}

static void
xps_add_fixed_document(xps_document *doc, char *name)
{
	xps_fixdoc *fixdoc;

	/* Check for duplicates first */
	for (fixdoc = doc->first_fixdoc; fixdoc; fixdoc = fixdoc->next)
		if (!strcmp(fixdoc->name, name))
			return;

	fixdoc = fz_malloc(doc->ctx, sizeof(xps_fixdoc));
	fixdoc->name = fz_strdup(doc->ctx, name);
	fixdoc->next = NULL;

	if (!doc->first_fixdoc)
	{
		doc->first_fixdoc = fixdoc;
		doc->last_fixdoc = fixdoc;
	}
	else
	{
		doc->last_fixdoc->next = fixdoc;
		doc->last_fixdoc = fixdoc;
	}
}

static void
xps_add_fixed_page(xps_document *doc, char *name, int width, int height)
{
	xps_page *page;

	/* Check for duplicates first */
	for (page = doc->first_page; page; page = page->next)
		if (!strcmp(page->name, name))
			return;

	page = fz_malloc(doc->ctx, sizeof(xps_page));
	page->name = fz_strdup(doc->ctx, name);
	page->width = width;
	page->height = height;
	page->root = NULL;
	page->next = NULL;

	if (!doc->first_page)
	{
		doc->first_page = page;
		doc->last_page = page;
	}
	else
	{
		doc->last_page->next = page;
		doc->last_page = page;
	}
}

static void
xps_free_fixed_pages(xps_document *doc)
{
	xps_page *page = doc->first_page;
	while (page)
	{
		xps_page *next = page->next;
		xps_free_page(doc, page);
		fz_free(doc->ctx, page->name);
		fz_free(doc->ctx, page);
		page = next;
	}
	doc->first_page = NULL;
	doc->last_page = NULL;
}

static void
xps_free_fixed_documents(xps_document *doc)
{
	xps_fixdoc *fixdoc = doc->first_fixdoc;
	while (fixdoc)
	{
		xps_fixdoc *next = fixdoc->next;
		fz_free(doc->ctx, fixdoc->name);
		fz_free(doc->ctx, fixdoc);
		fixdoc = next;
	}
	doc->first_fixdoc = NULL;
	doc->last_fixdoc = NULL;
}

void
xps_free_page_list(xps_document *doc)
{
	xps_free_fixed_documents(doc);
	xps_free_fixed_pages(doc);
}

/*
 * Parse the fixed document sequence structure and _rels/.rels to find the start part.
 */

static void
xps_parse_metadata_imp(xps_document *doc, xml_element *item)
{
	while (item)
	{
		xps_parse_metadata_imp(doc, xml_down(item));

		if (!strcmp(xml_tag(item), "Relationship"))
		{
			char *target = xml_att(item, "Target");
			char *type = xml_att(item, "Type");
			if (target && type)
			{
				char tgtbuf[1024];
				xps_absolute_path(tgtbuf, doc->base_uri, target, sizeof tgtbuf);
				if (!strcmp(type, REL_START_PART))
					doc->start_part = fz_strdup(doc->ctx, tgtbuf);
			}
		}

		if (!strcmp(xml_tag(item), "DocumentReference"))
		{
			char *source = xml_att(item, "Source");
			if (source)
			{
				char srcbuf[1024];
				xps_absolute_path(srcbuf, doc->base_uri, source, sizeof srcbuf);
				xps_add_fixed_document(doc, srcbuf);
			}
		}

		if (!strcmp(xml_tag(item), "PageContent"))
		{
			char *source = xml_att(item, "Source");
			char *width_att = xml_att(item, "Width");
			char *height_att = xml_att(item, "Height");
			int width = width_att ? atoi(width_att) : 0;
			int height = height_att ? atoi(height_att) : 0;
			if (source)
			{
				char srcbuf[1024];
				xps_absolute_path(srcbuf, doc->base_uri, source, sizeof srcbuf);
				xps_add_fixed_page(doc, srcbuf, width, height);
			}
		}

		item = xml_next(item);
	}
}

static int
xps_parse_metadata(xps_document *doc, xps_part *part)
{
	xml_element *root;
	char buf[1024];
	char *s;

	/* Save directory name part */
	fz_strlcpy(buf, part->name, sizeof buf);
	s = strrchr(buf, '/');
	if (s)
		s[0] = 0;

	/* _rels parts are voodoo: their URI references are from
	 * the part they are associated with, not the actual _rels
	 * part being parsed.
	 */
	s = strstr(buf, "/_rels");
	if (s)
		*s = 0;

	doc->base_uri = buf;
	doc->part_uri = part->name;

	root = xml_parse_document(doc->ctx, part->data, part->size);
	if (!root)
		return fz_error_note(-1, "cannot parse metadata part '%s'", part->name);

	xps_parse_metadata_imp(doc, root);

	xml_free_element(doc->ctx, root);

	doc->base_uri = NULL;
	doc->part_uri = NULL;

	return fz_okay;
}

static int
xps_read_and_process_metadata_part(xps_document *doc, char *name)
{
	xps_part *part;
	int code;

	part = xps_read_part(doc, name);
	if (!part)
		return fz_error_note(-1, "cannot read zip part '%s'", name);

	code = xps_parse_metadata(doc, part);
	if (code)
		return fz_error_note(code, "cannot process metadata part '%s'", name);

	xps_free_part(doc, part);

	return fz_okay;
}

int
xps_read_page_list(xps_document *doc)
{
	xps_fixdoc *fixdoc;
	int code;

	code = xps_read_and_process_metadata_part(doc, "/_rels/.rels");
	if (code)
		return fz_error_note(code, "cannot process root relationship part");

	if (!doc->start_part)
		return fz_error_make("cannot find fixed document sequence start part");

	code = xps_read_and_process_metadata_part(doc, doc->start_part);
	if (code)
		return fz_error_note(code, "cannot process FixedDocumentSequence part");

	for (fixdoc = doc->first_fixdoc; fixdoc; fixdoc = fixdoc->next)
	{
		code = xps_read_and_process_metadata_part(doc, fixdoc->name);
		if (code)
			return fz_error_note(code, "cannot process FixedDocument part");
	}

	return fz_okay;
}

int
xps_count_pages(xps_document *doc)
{
	xps_page *page;
	int n = 0;
	for (page = doc->first_page; page; page = page->next)
		n ++;
	return n;
}

static int
xps_load_fixed_page(xps_document *doc, xps_page *page)
{
	xps_part *part;
	xml_element *root;
	char *width_att;
	char *height_att;

	part = xps_read_part(doc, page->name);
	if (!part)
		return fz_error_note(-1, "cannot read zip part '%s'", page->name);

	root = xml_parse_document(doc->ctx, part->data, part->size);
	if (!root)
		return fz_error_note(-1, "cannot parse xml part '%s'", page->name);

	xps_free_part(doc, part);

	if (strcmp(xml_tag(root), "FixedPage"))
		return fz_error_make("expected FixedPage element (found %s)", xml_tag(root));

	width_att = xml_att(root, "Width");
	if (!width_att)
		return fz_error_make("FixedPage missing required attribute: Width");

	height_att = xml_att(root, "Height");
	if (!height_att)
		return fz_error_make("FixedPage missing required attribute: Height");

	page->width = atoi(width_att);
	page->height = atoi(height_att);
	page->root = root;

	return 0;
}

int
xps_load_page(xps_page **pagep, xps_document *doc, int number)
{
	xps_page *page;
	int code;
	int n = 0;

	for (page = doc->first_page; page; page = page->next)
	{
		if (n == number)
		{
			if (!page->root)
			{
				code = xps_load_fixed_page(doc, page);
				if (code)
					return fz_error_note(code, "cannot load page %d", number + 1);
			}
			*pagep = page;
			return fz_okay;
		}
		n ++;
	}

	return fz_error_make("cannot find page %d", number + 1);
}

void
xps_free_page(xps_document *doc, xps_page *page)
{
	/* only free the XML contents */
	if (page->root)
		xml_free_element(doc->ctx, page->root);
	page->root = NULL;
}
