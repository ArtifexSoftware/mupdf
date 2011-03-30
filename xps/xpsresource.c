#include "fitz.h"
#include "muxps.h"

static xps_item *
xps_find_resource(xps_context *ctx, xps_resource *dict, char *name, char **urip)
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

static xps_item *
xps_parse_resource_reference(xps_context *ctx, xps_resource *dict, char *att, char **urip)
{
	char name[1024];
	char *s;

	if (strstr(att, "{StaticResource ") != att)
		return NULL;

	xps_strlcpy(name, att + 16, sizeof name);
	s = strrchr(name, '}');
	if (s)
		*s = 0;

	return xps_find_resource(ctx, dict, name, urip);
}

void
xps_resolve_resource_reference(xps_context *ctx, xps_resource *dict,
		char **attp, xps_item **tagp, char **urip)
{
	if (*attp)
	{
		xps_item *rsrc = xps_parse_resource_reference(ctx, dict, *attp, urip);
		if (rsrc)
		{
			*attp = NULL;
			*tagp = rsrc;
		}
	}
}

static int
xps_parse_remote_resource_dictionary(xps_context *ctx, xps_resource **dictp, char *base_uri, char *source_att)
{
	char part_name[1024];
	char part_uri[1024];
	xps_resource *dict;
	xps_part *part;
	xps_item *xml;
	char *s;
	int code;

	/* External resource dictionaries MUST NOT reference other resource dictionaries */
	xps_absolute_path(part_name, base_uri, source_att, sizeof part_name);
	part = xps_read_part(ctx, part_name);
	if (!part)
	{
		return fz_throw("cannot find remote resource part '%s'", part_name);
	}

	xml = xps_parse_xml(ctx, part->data, part->size);
	if (!xml)
	{
		xps_free_part(ctx, part);
		return fz_rethrow(-1, "cannot parse xml");
	}

	if (strcmp(xps_tag(xml), "ResourceDictionary"))
	{
		xps_free_item(ctx, xml);
		xps_free_part(ctx, part);
		return fz_throw("expected ResourceDictionary element (found %s)", xps_tag(xml));
	}

	xps_strlcpy(part_uri, part_name, sizeof part_uri);
	s = strrchr(part_uri, '/');
	if (s)
		s[1] = 0;

	code = xps_parse_resource_dictionary(ctx, &dict, part_uri, xml);
	if (code)
	{
		xps_free_item(ctx, xml);
		xps_free_part(ctx, part);
		return fz_rethrow(code, "cannot parse remote resource dictionary: %s", part_uri);
	}

	dict->base_xml = xml; /* pass on ownership */

	xps_free_part(ctx, part);

	*dictp = dict;
	return fz_okay;
}

int
xps_parse_resource_dictionary(xps_context *ctx, xps_resource **dictp, char *base_uri, xps_item *root)
{
	xps_resource *head;
	xps_resource *entry;
	xps_item *node;
	char *source;
	char *key;
	int code;

	source = xps_att(root, "Source");
	if (source)
	{
		code = xps_parse_remote_resource_dictionary(ctx, dictp, base_uri, source);
		if (code)
			return fz_rethrow(code, "cannot parse remote resource dictionary");
		return fz_okay;
	}

	head = NULL;

	for (node = xps_down(root); node; node = xps_next(node))
	{
		/* Usually "x:Key"; we have already processed and stripped namespace */
		key = xps_att(node, "Key");
		if (key)
		{
			entry = xps_alloc(ctx, sizeof(xps_resource));
			if (!entry)
				return fz_throw("cannot allocate resource entry");
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
	{
		head->base_uri = xps_strdup(ctx, base_uri);
	}

	*dictp = head;
	return fz_okay;
}

void
xps_free_resource_dictionary(xps_context *ctx, xps_resource *dict)
{
	xps_resource *next;
	while (dict)
	{
		next = dict->next;
		if (dict->base_xml)
			xps_free_item(ctx, dict->base_xml);
		if (dict->base_uri)
			xps_free(ctx, dict->base_uri);
		xps_free(ctx, dict);
		dict = next;
	}
}

void
xps_debug_resource_dictionary(xps_resource *dict)
{
	while (dict)
	{
		if (dict->base_uri)
			printf("URI = '%s'\n", dict->base_uri);
		printf("KEY = '%s' VAL = %p\n", dict->name, dict->data);
		if (dict->parent)
		{
			printf("PARENT = {\n");
			xps_debug_resource_dictionary(dict->parent);
			printf("}\n");
		}
		dict = dict->next;
	}
}
