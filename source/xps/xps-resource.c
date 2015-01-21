#include "mupdf/xps.h"

static fz_xml *
xps_lookup_resource(fz_context *ctx, xps_document *doc, xps_resource *dict, char *name, char **urip)
{
	xps_resource *head, *node;
	for (head = dict; head; head = head->parent)
	{
		for (node = head; node; node = node->next)
		{
			if (!strcmp(node->name, name))
			{
				if (urip && head->base_uri)
					*urip = head->base_uri;
				return node->data;
			}
		}
	}
	return NULL;
}

static fz_xml *
xps_parse_resource_reference(fz_context *ctx, xps_document *doc, xps_resource *dict, char *att, char **urip)
{
	char name[1024];
	char *s;

	if (strstr(att, "{StaticResource ") != att)
		return NULL;

	fz_strlcpy(name, att + 16, sizeof name);
	s = strrchr(name, '}');
	if (s)
		*s = 0;

	return xps_lookup_resource(ctx, doc, dict, name, urip);
}

void
xps_resolve_resource_reference(fz_context *ctx, xps_document *doc, xps_resource *dict,
		char **attp, fz_xml **tagp, char **urip)
{
	if (*attp)
	{
		fz_xml *rsrc = xps_parse_resource_reference(ctx, doc, dict, *attp, urip);
		if (rsrc)
		{
			*attp = NULL;
			*tagp = rsrc;
		}
	}
}

static xps_resource *
xps_parse_remote_resource_dictionary(fz_context *ctx, xps_document *doc, char *base_uri, char *source_att)
{
	char part_name[1024];
	char part_uri[1024];
	xps_resource *dict;
	xps_part *part;
	fz_xml *xml;
	char *s;

	/* External resource dictionaries MUST NOT reference other resource dictionaries */
	xps_resolve_url(ctx, doc, part_name, base_uri, source_att, sizeof part_name);
	part = xps_read_part(ctx, doc, part_name);
	fz_try(ctx)
	{
		xml = fz_parse_xml(ctx, part->data, part->size, 0);
	}
	fz_always(ctx)
	{
		xps_drop_part(ctx, doc, part);
	}
	fz_catch(ctx)
	{
		fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
		xml = NULL;
	}

	if (!xml)
		return NULL;

	if (strcmp(fz_xml_tag(xml), "ResourceDictionary"))
	{
		fz_drop_xml(ctx, xml);
		fz_throw(ctx, FZ_ERROR_GENERIC, "expected ResourceDictionary element");
	}

	fz_strlcpy(part_uri, part_name, sizeof part_uri);
	s = strrchr(part_uri, '/');
	if (s)
		s[1] = 0;

	dict = xps_parse_resource_dictionary(ctx, doc, part_uri, xml);
	if (dict)
		dict->base_xml = xml; /* pass on ownership */

	return dict;
}

xps_resource *
xps_parse_resource_dictionary(fz_context *ctx, xps_document *doc, char *base_uri, fz_xml *root)
{
	xps_resource *head;
	xps_resource *entry;
	fz_xml *node;
	char *source;
	char *key;

	source = fz_xml_att(root, "Source");
	if (source)
		return xps_parse_remote_resource_dictionary(ctx, doc, base_uri, source);

	head = NULL;

	for (node = fz_xml_down(root); node; node = fz_xml_next(node))
	{
		key = fz_xml_att(node, "x:Key");
		if (key)
		{
			entry = fz_malloc_struct(ctx, xps_resource);
			entry->name = key;
			entry->base_uri = NULL;
			entry->base_xml = NULL;
			entry->data = node;
			entry->next = head;
			entry->parent = NULL;
			head = entry;
		}
	}

	if (head)
		head->base_uri = fz_strdup(ctx, base_uri);

	return head;
}

void
xps_drop_resource_dictionary(fz_context *ctx, xps_document *doc, xps_resource *dict)
{
	xps_resource *next;
	while (dict)
	{
		next = dict->next;
		if (dict->base_xml)
			fz_drop_xml(ctx, dict->base_xml);
		if (dict->base_uri)
			fz_free(ctx, dict->base_uri);
		fz_free(ctx, dict);
		dict = next;
	}
}

void
xps_print_resource_dictionary(fz_context *ctx, xps_document *doc, xps_resource *dict)
{
	while (dict)
	{
		if (dict->base_uri)
			printf("URI = '%s'\n", dict->base_uri);
		printf("KEY = '%s' VAL = %p\n", dict->name, dict->data);
		if (dict->parent)
		{
			printf("PARENT = {\n");
			xps_print_resource_dictionary(ctx, doc, dict->parent);
			printf("}\n");
		}
		dict = dict->next;
	}
}
