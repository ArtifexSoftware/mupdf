#include "muxps-internal.h"

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
xps_parse_document_outline(xps_document *doc, xml_element *root)
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

			entry = fz_malloc_struct(doc->ctx, fz_outline);
			entry->title = fz_strdup(doc->ctx, description);
			entry->dest.kind = FZ_LINK_GOTO;
			entry->dest.ld.gotor.flags = 0;
			entry->dest.ld.gotor.page = xps_lookup_link_target(doc, target);
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
xps_parse_document_structure(xps_document *doc, xml_element *root)
{
	xml_element *node;
	if (!strcmp(xml_tag(root), "DocumentStructure"))
	{
		node = xml_down(root);
		if (!strcmp(xml_tag(node), "DocumentStructure.Outline"))
		{
			node = xml_down(node);
			if (!strcmp(xml_tag(node), "DocumentOutline"))
				return xps_parse_document_outline(doc, node);
		}
	}
	return NULL;
}

static fz_outline *
xps_load_document_structure(xps_document *doc, xps_fixdoc *fixdoc)
{
	xps_part *part;
	xml_element *root;
	fz_outline *outline;

	part = xps_read_part(doc, fixdoc->outline);
	fz_try(doc->ctx)
	{
		root = xml_parse_document(doc->ctx, part->data, part->size);
	}
	fz_catch(doc->ctx)
	{
		xps_free_part(doc, part);
		fz_rethrow(doc->ctx);
	}
	xps_free_part(doc, part);
	if (!root)
		return NULL;

	fz_try(doc->ctx)
	{
		outline = xps_parse_document_structure(doc, root);
	}
	fz_catch(doc->ctx)
	{
		xml_free_element(doc->ctx, root);
		fz_rethrow(doc->ctx);
	}
	xml_free_element(doc->ctx, root);

	return outline;
}

fz_outline *
xps_load_outline(xps_document *doc)
{
	xps_fixdoc *fixdoc;
	fz_outline *head = NULL, *tail, *outline;

	for (fixdoc = doc->first_fixdoc; fixdoc; fixdoc = fixdoc->next) {
		if (fixdoc->outline) {
			outline = xps_load_document_structure(doc, fixdoc);
			if (!outline)
				continue;
			if (!head)
				head = outline;
			else
			{
				while (tail->next)
					tail = tail->next;
				tail->next = outline;
			}
			tail = outline;
		}
	}
	return head;
}
