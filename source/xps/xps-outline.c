#include "mupdf/xps.h"

/*
 * Parse the document structure / outline parts referenced from fixdoc relationships.
 */

static fz_outline *
xps_lookup_last_outline_at_level(fz_context *ctx, xps_document *doc, fz_outline *node, int level, int target_level)
{
	while (node->next)
		node = node->next;
	if (level == target_level || !node->down)
		return node;
	return xps_lookup_last_outline_at_level(ctx, doc, node->down, level + 1, target_level);
}

static fz_outline *
xps_parse_document_outline(fz_context *ctx, xps_document *doc, fz_xml *root)
{
	fz_xml *node;
	fz_outline *head = NULL, *entry, *tail;
	int last_level = 1, this_level;
	for (node = fz_xml_down(root); node; node = fz_xml_next(node))
	{
		if (fz_xml_is_tag(node, "OutlineEntry"))
		{
			char *level = fz_xml_att(node, "OutlineLevel");
			char *target = fz_xml_att(node, "OutlineTarget");
			char *description = fz_xml_att(node, "Description");
			if (!target || !description)
				continue;

			entry = fz_malloc_struct(ctx, fz_outline);
			entry->title = fz_strdup(ctx, description);
			entry->dest.kind = FZ_LINK_GOTO;
			entry->dest.ld.gotor.flags = 0;
			entry->dest.ld.gotor.page = xps_lookup_link_target(ctx, doc, target);
			entry->down = NULL;
			entry->next = NULL;

			this_level = level ? atoi(level) : 1;

			if (!head)
			{
				head = entry;
			}
			else
			{
				tail = xps_lookup_last_outline_at_level(ctx, doc, head, 1, this_level);
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
xps_parse_document_structure(fz_context *ctx, xps_document *doc, fz_xml *root)
{
	fz_xml *node;
	if (fz_xml_is_tag(root, "DocumentStructure"))
	{
		node = fz_xml_down(root);
		if (node && fz_xml_is_tag(node, "DocumentStructure.Outline"))
		{
			node = fz_xml_down(node);
			if (node && fz_xml_is_tag(node, "DocumentOutline"))
				return xps_parse_document_outline(ctx, doc, node);
		}
	}
	return NULL;
}

static fz_outline *
xps_load_document_structure(fz_context *ctx, xps_document *doc, xps_fixdoc *fixdoc)
{
	xps_part *part;
	fz_xml *root;
	fz_outline *outline;

	part = xps_read_part(ctx, doc, fixdoc->outline);
	fz_try(ctx)
	{
		root = fz_parse_xml(ctx, part->data, part->size, 0);
	}
	fz_always(ctx)
	{
		xps_drop_part(ctx, doc, part);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
	if (!root)
		return NULL;

	fz_try(ctx)
	{
		outline = xps_parse_document_structure(ctx, doc, root);
	}
	fz_always(ctx)
	{
		fz_drop_xml(ctx, root);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return outline;
}

fz_outline *
xps_load_outline(fz_context *ctx, xps_document *doc)
{
	xps_fixdoc *fixdoc;
	fz_outline *head = NULL, *tail, *outline;

	for (fixdoc = doc->first_fixdoc; fixdoc; fixdoc = fixdoc->next)
	{
		if (fixdoc->outline)
		{
			fz_try(ctx)
			{
				outline = xps_load_document_structure(ctx, doc, fixdoc);
			}
			fz_catch(ctx)
			{
				fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
				outline = NULL;
			}
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
