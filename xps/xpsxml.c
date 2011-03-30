/* Simple XML document object model on top of Expat. */

#include "fitz.h"
#include "muxps.h"

#include <expat.h>

#define XMLBUFLEN 4096

#define NS_XPS "http://schemas.microsoft.com/xps/2005/06"
#define NS_MC "http://schemas.openxmlformats.org/markup-compatibility/2006"

typedef struct xps_parser_s xps_parser;

struct xps_parser_s
{
	xps_context *ctx;
	xps_item *root;
	xps_item *head;
	char *error;
	int compat;
	char *base; /* base of relative URIs */
};

struct xps_item_s
{
	char *name;
	char **atts;
	xps_item *up;
	xps_item *down;
	xps_item *next;
};

static char *
skip_namespace(char *s)
{
	char *p = strchr(s, ' ');
	if (p)
		return p + 1;
	return s;
}

static void
on_open_tag(void *zp, char *ns_name, char **atts)
{
	xps_parser *parser = zp;
	xps_item *item;
	xps_item *tail;
	int namelen;
	int attslen;
	int textlen;
	char *name, *p;
	int i;

	if (parser->error)
		return;

	/* check namespace */

	name = NULL;

	p = strstr(ns_name, NS_XPS);
	if (p == ns_name)
	{
		name = strchr(ns_name, ' ') + 1;
	}

	p = strstr(ns_name, NS_MC);
	if (p == ns_name)
	{
		name = strchr(ns_name, ' ') + 1;
		parser->compat = 1;
	}

	if (!name)
	{
		fz_warn("unknown namespace: %s", ns_name);
		name = ns_name;
	}

	/* count size to alloc */

	namelen = strlen(name) + 1; /* zero terminated */
	attslen = sizeof(char*); /* with space for sentinel */
	textlen = 0;
	for (i = 0; atts[i]; i++)
	{
		attslen += sizeof(char*);
		if ((i & 1) == 0)
			textlen += strlen(skip_namespace(atts[i])) + 1;
		else
			textlen += strlen(atts[i]) + 1;
	}

	item = fz_malloc(sizeof(xps_item) + attslen + namelen + textlen);
	if (!item)
	{
		parser->error = "out of memory";
	}

	/* copy strings to new memory */

	item->atts = (char**) (((char*)item) + sizeof(xps_item));
	item->name = ((char*)item) + sizeof(xps_item) + attslen;
	p = ((char*)item) + sizeof(xps_item) + attslen + namelen;

	strcpy(item->name, name);
	for (i = 0; atts[i]; i++)
	{
		item->atts[i] = p;
		if ((i & 1) == 0)
			strcpy(item->atts[i], skip_namespace(atts[i]));
		else
			strcpy(item->atts[i], atts[i]);
		p += strlen(p) + 1;
	}

	item->atts[i] = 0;

	/* link item into tree */

	item->up = parser->head;
	item->down = NULL;
	item->next = NULL;

	if (!parser->head)
	{
		parser->root = item;
		parser->head = item;
		return;
	}

	if (!parser->head->down)
	{
		parser->head->down = item;
		parser->head = item;
		return;
	}

	tail = parser->head->down;
	while (tail->next)
		tail = tail->next;
	tail->next = item;
	parser->head = item;
}

static void
on_close_tag(void *zp, char *name)
{
	xps_parser *parser = zp;

	if (parser->error)
		return;

	if (parser->head)
		parser->head = parser->head->up;
}

static inline int
is_xml_space(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static void
on_text(void *zp, char *buf, int len)
{
	xps_parser *parser = zp;
	char *atts[3];
	int i;

	if (parser->error)
		return;

	for (i = 0; i < len; i++)
	{
		if (!is_xml_space(buf[i]))
		{
			char *tmp = fz_malloc(len + 1);
			if (!tmp)
			{
				parser->error = "out of memory";
				return;
			}

			atts[0] = "";
			atts[1] = tmp;
			atts[2] = NULL;

			memcpy(tmp, buf, len);
			tmp[len] = 0;
			on_open_tag(zp, "", atts);
			on_close_tag(zp, "");
			fz_free(tmp);
			return;
		}
	}
}

static xps_item *
xps_process_compatibility(xps_context *ctx, xps_item *root)
{
	fz_warn("XPS document uses markup compatibility tags");
	return root;
}

xps_item *
xps_parse_xml(xps_context *ctx, byte *buf, int len)
{
	xps_parser parser;
	XML_Parser xp;
	int code;

	parser.ctx = ctx;
	parser.root = NULL;
	parser.head = NULL;
	parser.error = NULL;
	parser.compat = 0;

	xp = XML_ParserCreateNS(NULL, ' ');
	if (!xp)
	{
		fz_throw("xml error: cannot create expat parser");
		return NULL;
	}

	XML_SetUserData(xp, &parser);
	XML_SetParamEntityParsing(xp, XML_PARAM_ENTITY_PARSING_NEVER);
	XML_SetStartElementHandler(xp, (XML_StartElementHandler)on_open_tag);
	XML_SetEndElementHandler(xp, (XML_EndElementHandler)on_close_tag);
	XML_SetCharacterDataHandler(xp, (XML_CharacterDataHandler)on_text);

	code = XML_Parse(xp, (char*)buf, len, 1);
	if (code == 0)
	{
		if (parser.root)
			xps_free_item(ctx, parser.root);
		XML_ParserFree(xp);
		fz_throw("xml error: %s", XML_ErrorString(XML_GetErrorCode(xp)));
		return NULL;
	}

	XML_ParserFree(xp);

	if (parser.compat)
		xps_process_compatibility(ctx, parser.root);

	return parser.root;
}

xps_item *
xps_next(xps_item *item)
{
	return item->next;
}

xps_item *
xps_down(xps_item *item)
{
	return item->down;
}

char *
xps_tag(xps_item *item)
{
	return item->name;
}

char *
xps_att(xps_item *item, const char *att)
{
	int i;
	for (i = 0; item->atts[i]; i += 2)
		if (!strcmp(item->atts[i], att))
			return item->atts[i + 1];
	return NULL;
}

void
xps_free_item(xps_context *ctx, xps_item *item)
{
	xps_item *next;
	while (item)
	{
		next = item->next;
		if (item->down)
			xps_free_item(ctx, item->down);
		fz_free(item);
		item = next;
	}
}

static void indent(int n)
{
	while (n--)
		printf("  ");
}

static void
xps_debug_item_imp(xps_item *item, int level, int loop)
{
	int i;

	while (item)
	{
		indent(level);

		if (strlen(item->name) == 0)
			printf("%s\n", item->atts[1]);
		else
		{
			printf("<%s", item->name);

			for (i = 0; item->atts[i]; i += 2)
				printf(" %s=\"%s\"", item->atts[i], item->atts[i+1]);

			if (item->down)
			{
				printf(">\n");
				xps_debug_item_imp(item->down, level + 1, 1);
				indent(level);
				printf("</%s>\n", item->name);
			}
			else
				printf(" />\n");
		}

		item = item->next;

		if (!loop)
			return;
	}
}

void
xps_debug_item(xps_item *item, int level)
{
	xps_debug_item_imp(item, level, 0);
}
