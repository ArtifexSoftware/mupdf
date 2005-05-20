#include "fitz.h"
#include "samus.h"

#include <expat.h>

#define XMLBUFLEN 4096

struct sa_xmlnode_s
{
	char *name;
	char **atts;
	sa_xmlnode *up;
	sa_xmlnode *down;
	sa_xmlnode *next;
};

struct sa_xmlparser_s
{
	fz_error *error;
	sa_xmlnode *root;
	sa_xmlnode *head;
};

static void onopentag(void *zp, const char *name, const char **atts)
{
	struct sa_xmlparser_s *sp = zp;
	sa_xmlnode *node;
	sa_xmlnode *tail;
	int namelen;
	int attslen;
	int textlen;
	char *p;
	int i;

	if (sp->error)
		return;

	/* count size to alloc */

	namelen = strlen(name) + 1;
	attslen = sizeof(char*);
	textlen = 0;
	for (i = 0; atts[i]; i++)
	{
		attslen += sizeof(char*);
		textlen += strlen(atts[i]) + 1;
	}

	node = fz_malloc(sizeof(sa_xmlnode) + attslen + namelen + textlen);
	if (!node)
	{
		sp->error = fz_outofmem;
		return;
	}

	/* copy strings to new memory */

	node->atts = (char**) (((char*)node) + sizeof(sa_xmlnode));
	node->name = ((char*)node) + sizeof(sa_xmlnode) + attslen;
	p = ((char*)node) + sizeof(sa_xmlnode) + attslen + namelen;

	strcpy(node->name, name);
	for (i = 0; atts[i]; i++)
	{
		node->atts[i] = p;
		strcpy(node->atts[i], atts[i]);
		p += strlen(p) + 1;
	}

	node->atts[i] = 0;

	/* link node into tree */

	node->up = sp->head;
	node->down = nil;
	node->next = nil;

	if (!sp->head)
	{
		sp->root = node;
		sp->head = node;
		return;
	}

	if (!sp->head->down)
	{
		sp->head->down = node;
		sp->head = node;
		return;
	}

	tail = sp->head->down;
	while (tail->next)
		tail = tail->next;
	tail->next = node;
	sp->head = node;
}

static void onclosetag(void *zp, const char *name)
{
	struct sa_xmlparser_s *sp = zp;

	if (sp->error)
		return;

	if (sp->head)
		sp->head = sp->head->up;
}

static inline int isxmlspace(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static void ontext(void *zp, const char *buf, int len)
{
	struct sa_xmlparser_s *sp = zp;
	int i;

	if (sp->error)
		return;

	for (i = 0; i < len; i++)
	{
		if (!isxmlspace(buf[i]))
		{
			char *tmp = fz_malloc(len + 1);
			const char *atts[] = {"", tmp, 0};
			if (!tmp)
			{
				sp->error = fz_outofmem;
				return;
			}
			memcpy(tmp, buf, len);
			tmp[len] = 0;
			onopentag(zp, "", atts);
			onclosetag(zp, "");
			fz_free(tmp);
			return;
		}
	}
}

fz_error *
sa_parsexml(sa_xmlnode **nodep, fz_file *file, int ns)
{
	fz_error *error = nil;
	struct sa_xmlparser_s sp;
	XML_Parser xp;
	char *buf;
	int len;

	sp.error = nil;
	sp.root = nil;
	sp.head = nil;

	if (ns)
		xp = XML_ParserCreateNS(nil, ns);
	else
		xp = XML_ParserCreate(nil);
	if (!xp)
		return fz_outofmem;

	XML_SetUserData(xp, &sp);
	XML_SetParamEntityParsing(xp, XML_PARAM_ENTITY_PARSING_NEVER);

	XML_SetStartElementHandler(xp, onopentag);
	XML_SetEndElementHandler(xp, onclosetag);
	XML_SetCharacterDataHandler(xp, ontext);

	while (1)
	{
		buf = XML_GetBuffer(xp, XMLBUFLEN);

		len = fz_read(file, buf, XMLBUFLEN);
		if (len < 0)
		{
			error = fz_ferror(file);
			goto cleanup;
		}

		if (!XML_ParseBuffer(xp, len, len == 0))
		{
			error = fz_throw("ioerror: xml: %s",
					XML_ErrorString(XML_GetErrorCode(xp)));
			goto cleanup;
		}

		if (sp.error)
		{
			error = sp.error;
			goto cleanup;
		}

		if (len == 0)
			break;
	}

	*nodep = sp.root;
	return nil;

cleanup:
	if (sp.root)
		sa_dropxml(sp.root);
	XML_ParserFree(xp);
	return error;
}

void
sa_dropxml(sa_xmlnode *node)
{
	sa_xmlnode *next;
	while (node)
	{
		next = node->next;
		if (node->down)
			sa_dropxml(node->down);
		fz_free(node);
		node = next;
	}
}

static void indent(int n)
{
	while (n--)
		printf("  ");
}

void
sa_debugxml(sa_xmlnode *node, int level)
{
	int i;

	while (node)
	{
		indent(level);

		if (sa_isxmltext(node))
			printf("%s\n", sa_getxmltext(node));
		else
		{
			printf("<%s", node->name);

			for (i = 0; node->atts[i]; i += 2)
				printf(" %s=\"%s\"", node->atts[i], node->atts[i+1]);

			if (node->down)
			{
				printf(">\n");
				sa_debugxml(node->down, level + 1);
				indent(level);
				printf("</%s>\n", node->name);
			}
			else
				printf(" />\n");
		}

		node = node->next;
	}
}

sa_xmlnode *
sa_xmlup(sa_xmlnode *node)
{
	return node->up;
}

sa_xmlnode *
sa_xmlnext(sa_xmlnode *node)
{
	return node->next;
}

sa_xmlnode *
sa_xmldown(sa_xmlnode *node)
{
	return node->down;
}

int
sa_isxmltext(sa_xmlnode *node)
{
	return node->name[0] == 0;
}

int
sa_isxmltag(sa_xmlnode *node)
{
	return node->name[0] != 0;
}

char *
sa_getxmlname(sa_xmlnode *node)
{
	if (sa_isxmltag(node))
		return node->name;
	return nil;
}

char *
sa_getxmlatt(sa_xmlnode *node, char *att)
{
	int i;
	for (i = 0; node->atts[i]; i += 2)
		if (!strcmp(node->atts[i], att))
			return node->atts[i + 1];
	return nil;
}

char *
sa_getxmltext(sa_xmlnode *node)
{
	if (sa_isxmltext(node))
		return node->atts[1];
	return nil;
}


