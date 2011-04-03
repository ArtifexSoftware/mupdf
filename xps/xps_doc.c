#include "fitz.h"
#include "muxps.h"

xps_part *
xps_new_part(xps_context *ctx, char *name, int size)
{
	xps_part *part;

	part = fz_malloc(sizeof(xps_part));
	part->name = fz_strdup(name);
	part->size = size;
	part->data = fz_malloc(size + 1);
	part->data[size] = 0; /* null-terminate for xml parser */

	return part;
}

void
xps_free_part(xps_context *ctx, xps_part *part)
{
	fz_free(part->name);
	fz_free(part->data);
	fz_free(part);
}

/*
 * The FixedDocumentSequence and FixedDocument parts determine
 * which parts correspond to actual pages, and the page order.
 */

void
xps_debug_fixdocseq(xps_context *ctx)
{
	xps_document *fixdoc = ctx->first_fixdoc;
	xps_page *page = ctx->first_page;

	if (ctx->start_part)
		printf("start part %s\n", ctx->start_part);

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
xps_add_fixed_document(xps_context *ctx, char *name)
{
	xps_document *fixdoc;

	/* Check for duplicates first */
	for (fixdoc = ctx->first_fixdoc; fixdoc; fixdoc = fixdoc->next)
		if (!strcmp(fixdoc->name, name))
			return;

	fixdoc = fz_malloc(sizeof(xps_document));
	fixdoc->name = fz_strdup(name);
	fixdoc->next = NULL;

	if (!ctx->first_fixdoc)
	{
		ctx->first_fixdoc = fixdoc;
		ctx->last_fixdoc = fixdoc;
	}
	else
	{
		ctx->last_fixdoc->next = fixdoc;
		ctx->last_fixdoc = fixdoc;
	}
}

void
xps_free_fixed_documents(xps_context *ctx)
{
	xps_document *node = ctx->first_fixdoc;
	while (node)
	{
		xps_document *next = node->next;
		fz_free(node->name);
		fz_free(node);
		node = next;
	}
	ctx->first_fixdoc = NULL;
	ctx->last_fixdoc = NULL;
}

static void
xps_add_fixed_page(xps_context *ctx, char *name, int width, int height)
{
	xps_page *page;

	/* Check for duplicates first */
	for (page = ctx->first_page; page; page = page->next)
		if (!strcmp(page->name, name))
			return;

	page = fz_malloc(sizeof(xps_page));
	page->name = fz_strdup(name);
	page->width = width;
	page->height = height;
	page->root = NULL;
	page->next = NULL;

	if (!ctx->first_page)
	{
		ctx->first_page = page;
		ctx->last_page = page;
	}
	else
	{
		ctx->last_page->next = page;
		ctx->last_page = page;
	}
}

void
xps_free_fixed_pages(xps_context *ctx)
{
	xps_page *node = ctx->first_page;
	while (node)
	{
		xps_page *next = node->next;
		fz_free(node->name);
		fz_free(node);
		node = next;
	}
	ctx->first_page = NULL;
	ctx->last_page = NULL;
}

/*
 * Parse the fixed document sequence structure and _rels/.rels to find the start part.
 */

static void
xps_parse_metadata_imp(xps_context *ctx, xml_element *item)
{
	while (item)
	{
		xps_parse_metadata_imp(ctx, xml_down(item));

		if (!strcmp(xml_tag(item), "Relationship"))
		{
			char *target = xml_att(item, "Target");
			char *type = xml_att(item, "Type");
			if (target && type)
			{
				char tgtbuf[1024];
				xps_absolute_path(tgtbuf, ctx->base_uri, target, sizeof tgtbuf);
				if (!strcmp(type, REL_START_PART))
					ctx->start_part = fz_strdup(tgtbuf);
			}
		}

		if (!strcmp(xml_tag(item), "DocumentReference"))
		{
			char *source = xml_att(item, "Source");
			if (source)
			{
				char srcbuf[1024];
				xps_absolute_path(srcbuf, ctx->base_uri, source, sizeof srcbuf);
				xps_add_fixed_document(ctx, srcbuf);
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
				xps_absolute_path(srcbuf, ctx->base_uri, source, sizeof srcbuf);
				xps_add_fixed_page(ctx, srcbuf, width, height);
			}
		}

		item = xml_next(item);
	}
}

int
xps_parse_metadata(xps_context *ctx, xps_part *part)
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

	ctx->base_uri = buf;
	ctx->part_uri = part->name;

	root = xml_parse_document(part->data, part->size);
	if (!root)
		return fz_rethrow(-1, "cannot parse metadata part '%s'", part->name);

	xps_parse_metadata_imp(ctx, root);

	xml_free_element(root);

	ctx->base_uri = NULL;
	ctx->part_uri = NULL;

	return fz_okay;
}
