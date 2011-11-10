#include "fitz.h"
#include "muxps.h"

/*
 * Parse the document structure / outline parts referenced from fixdoc relationships.
 */

static fz_outline *
xps_find_last_outline_at_level(fz_outline *node, int level, int target_level)
{
	while (node->next)
		node = node->next;
	if (level == target_level || !node->down)
		return node;
	return xps_find_last_outline_at_level(node->down, level + 1, target_level);
}

static fz_outline *
xps_parse_document_outline(xps_context *ctx, xml_element *root)
{
	xml_element *node;
	fz_outline *head = NULL, *entry, *tail;
	int last_level = 1, this_level;
	for (node = xml_down(root); node; node = xml_next(node))
	{
		if (!strcmp(xml_tag(node), "OutlineEntry"))
		{
			char *level = xml_att(node, "OutlineLevel");
			char *target = xml_att(node, "OutlineTarget");
			char *description = xml_att(node, "Description");
			if (!target || !description)
				continue;

			entry = fz_malloc(sizeof *entry);
			entry->title = fz_strdup(description);
			entry->page = xps_find_link_target(ctx, target);
			entry->down = NULL;
			entry->next = NULL;

			this_level = level ? atoi(level) : 1;

			if (!head)
			{
				head = entry;
			}
			else
			{
				tail = xps_find_last_outline_at_level(head, 1, this_level);
				if (this_level > last_level)
					tail->down = entry;
				else
					tail->next = entry;
			}

			last_level = this_level;
		}
	}
	return head;
}

static fz_outline *
xps_parse_document_structure(xps_context *ctx, xml_element *root)
{
	xml_element *node;
	if (!strcmp(xml_tag(root), "DocumentStructure"))
	{
		node = xml_down(root);
		if (!strcmp(xml_tag(node), "DocumentStructure.Outline"))
		{
			node = xml_down(node);
			if (!strcmp(xml_tag(node), "DocumentOutline"))
				return xps_parse_document_outline(ctx, node);
		}
	}
	return NULL;
}

static fz_outline *
xps_load_document_structure(xps_context *ctx, xps_document *fixdoc)
{
	xps_part *part;
	xml_element *root;
	fz_outline *outline;

	part = xps_read_part(ctx, fixdoc->outline);
	if (!part)
		return NULL;

	root = xml_parse_document(part->data, part->size);
	if (!root) {
		fz_catch(-1, "cannot parse document structure part '%s'", part->name);
		xps_free_part(ctx, part);
		return NULL;
	}

	outline = xps_parse_document_structure(ctx, root);

	xml_free_element(root);
	xps_free_part(ctx, part);

	return outline;

}

fz_outline *
xps_load_outline(xps_context *ctx)
{
	xps_document *fixdoc;
	fz_outline *head = NULL, *tail, *outline;

	for (fixdoc = ctx->first_fixdoc; fixdoc; fixdoc = fixdoc->next) {
		if (fixdoc->outline) {
			outline = xps_load_document_structure(ctx, fixdoc);
			if (outline) {
				if (!head)
					head = outline;
				else
					tail->next = outline;
				tail = outline;
			}
		}
	}
	return head;
}
