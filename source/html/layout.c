#include "mupdf/html.h"

static const char *default_css =
"html,address,blockquote,body,dd,div,dl,dt,h1,h2,h3,h4,h5,h6,ol,p,ul,center,hr,pre{display:block}"
"span{display:inline}"
"li{display:list-item}"
"head{display:none}"
"body{margin:0px}"
"h1{font-size:2em;margin:.67em 0}"
"h2{font-size:1.5em;margin:.75em 0}"
"h3{font-size:1.17em;margin:.83em 0}"
"h4,p,blockquote,ul,ol,dl,dir,menu{margin:1.12em 0}"
"h5{font-size:.83em;margin:1.5em 0}"
"h6{font-size:.75em;margin:1.67em 0}"
"h1,h2,h3,h4,h5,h6,b,strong{font-weight:bold}"
"blockquote{margin-left:40px;margin-right:40px}"
"i,cite,em,var,address{font-style:italic}"
"pre,tt,code,kbd,samp{font-family:monospace}"
"pre{white-space:pre}"
"big{font-size:1.17em}"
"small,sub,sup{font-size:.83em}"
"sub{vertical-align:sub}"
"sup{vertical-align:super}"
"s,strike,del{text-decoration:line-through}"
"hr{border:1px inset}"
"ol,ul,dir,menu,dd{margin-left:40px}"
"ol{list-style-type:decimal}"
"ol ul,ul ol,ul ul,ol ol{margin-top:0;margin-bottom:0}"
"u,ins{text-decoration:underline}"
"center{text-align:center}"
"svg{display:none}";

enum
{
	BOX_BLOCK,	/* block-level: contains other block and anonymous boxes */
	BOX_ANONYMOUS,	/* block-level: contains only inline boxes */
	BOX_INLINE,	/* inline-level: contains only inline boxes */
};

struct box
{
	int type;
	float x, y, w, h;
	struct box *up, *down, *last, *next;
	fz_xml *node;
	struct style style;
};

struct box *new_box(fz_context *ctx, fz_xml *node, struct style *up_style)
{
	struct box *box;

	box = fz_malloc_struct(ctx, struct box);

	box->type = BOX_BLOCK;
	box->x = box->y = 0;
	box->w = box->h = 0;

	box->up = NULL;
	box->last = NULL;
	box->down = NULL;
	box->next = NULL;

	box->node = node;

	box->style.up = up_style;
	box->style.count = 0;

	return box;
}

void insert_box(fz_context *ctx, struct box *box, int type, struct box *top)
{
	box->type = type;

	box->up = top;

	if (top)
	{
		if (!top->last)
		{
			top->down = top->last = box;
		}
		else
		{
			top->last->next = box;
			top->last = box;
		}
	}
}

static struct box *insert_block_box(fz_context *ctx, struct box *box, struct box *top)
{
	if (top->type == BOX_BLOCK)
	{
		insert_box(ctx, box, BOX_BLOCK, top);
	}
	else if (top->type == BOX_ANONYMOUS)
	{
		while (top->type != BOX_BLOCK)
			top = top->up;
		insert_box(ctx, box, BOX_BLOCK, top);
	}
	else if (top->type == BOX_INLINE)
	{
		while (top->type != BOX_BLOCK)
			top = top->up;
		insert_box(ctx, box, BOX_BLOCK, top);
	}
	return top;
}

static void insert_inline_box(fz_context *ctx, struct box *box, struct box *top)
{
	if (top->type == BOX_BLOCK)
	{
		if (top->last && top->last->type == BOX_ANONYMOUS)
		{
			insert_box(ctx, box, BOX_INLINE, top->last);
		}
		else
		{
			struct box *anon = new_box(ctx, NULL, &top->style);
			insert_box(ctx, anon, BOX_ANONYMOUS, top);
			insert_box(ctx, box, BOX_INLINE, anon);
		}
	}
	else if (box->type == BOX_ANONYMOUS)
	{
		insert_box(ctx, box, BOX_INLINE, top);
	}
	else if (box->type == BOX_INLINE)
	{
		insert_box(ctx, box, BOX_INLINE, top);
	}
}

static void generate_boxes(fz_context *ctx, fz_xml *node, struct box *top, struct rule *rule)
{
	struct style *up_style;
	struct box *box;
	int display;

	/* link styles separately because splitting inline blocks breaks the style/box tree symmetry */
	up_style = &top->style;

	while (node)
	{
		box = new_box(ctx, node, up_style);

		if (fz_xml_tag(node))
		{
			apply_styles(ctx, &box->style, rule, node);

			display = get_style_property_display(&box->style);

			// TOOD: <br>
			// TODO: <img>

			if (display != NONE)
			{
				if (display == BLOCK)
				{
					top = insert_block_box(ctx, box, top);
				}
				else if (display == INLINE)
				{
					insert_inline_box(ctx, box, top);
				}
				else
				{
					fz_warn(ctx, "unknown box display type");
					insert_box(ctx, box, BOX_BLOCK, top);
				}

				if (fz_xml_down(node))
					generate_boxes(ctx, fz_xml_down(node), box, rule);
			}
		}
		else
		{
			insert_inline_box(ctx, box, top);
		}

		node = fz_xml_next(node);
	}
}

static void layout_boxes(fz_context *ctx, struct box *top, float w, float h)
{
}

static void indent(int level)
{
	while (level--) printf("    ");
}

static void print_box(fz_context *ctx, struct box *box, int level)
{
	while (box)
	{
		indent(level);
		switch (box->type)
		{
		case BOX_BLOCK: printf("block"); break;
		case BOX_ANONYMOUS: printf("anonymous"); break;
		case BOX_INLINE: printf("inline"); break;
		}
		if (box->node)
		{
			const char *tag = fz_xml_tag(box->node);
			const char *text = fz_xml_text(box->node);
			if (tag) printf(" <%s>", tag);
			if (text) printf(" \"%s\"", text);
		}
		printf("\n");
		if (box->down)
			print_box(ctx, box->down, level + 1);
		box = box->next;
	}
}

static char *concat_text(fz_context *ctx, fz_xml *root)
{
	fz_xml  *node;
	int i = 0, n = 1;
	char *s;
	for (node = fz_xml_down(root); node; node = fz_xml_next(node))
	{
		const char *text = fz_xml_text(node);
		n += text ? strlen(text) : 0;
	}
	s = fz_malloc(ctx, n);
	for (node = fz_xml_down(root); node; node = fz_xml_next(node))
	{
		const char *text = fz_xml_text(node);
		if (text)
		{
			n = strlen(text);
			memcpy(s+i, text, n);
			i += n;
		}
	}
	s[i] = 0;
	return s;
}

static struct rule *load_css(fz_context *ctx, struct rule *css, fz_xml *root)
{
	fz_xml *node;
	for (node = root; node; node = fz_xml_next(node))
	{
		const char *tag = fz_xml_tag(node);
#if 0
		if (tag && !strcmp(tag, "link"))
		{
			char *rel = fz_xml_att(node, "rel");
			if (rel && !strcasecmp(rel, "stylesheet"))
			{
				char *type = fz_xml_att(node, "type");
				if ((type && !strcmp(type, "text/css")) || !type)
				{
					char *href = fz_xml_att(node, "href");
					strcpy(filename, dirname);
					strcat(filename, href);
					css = css_parse_file(css, filename);
				}
			}
		}
#endif
		if (tag && !strcmp(tag, "style"))
		{
			char *s = concat_text(ctx, node);
			css = fz_parse_css(ctx, css, s);
			fz_free(ctx, s);
		}
		if (fz_xml_down(node))
			css = load_css(ctx, css, fz_xml_down(node));
	}
	return css;
}

void
html_layout_document(html_document *doc, float w, float h)
{
	struct rule *css = NULL;
	struct box *root_box;

#if 0
	strcpy(dirname, argv[i]);
	s = strrchr(dirname, '/');
	if (!s) s = strrchr(dirname, '\\');
	if (s) s[1] = 0;
	else strcpy(dirname, "./");
#endif

	css = fz_parse_css(doc->ctx, NULL, default_css);
	css = load_css(doc->ctx, css, doc->root);

//	print_rules(css);

	root_box = new_box(doc->ctx, NULL, NULL);
	generate_boxes(doc->ctx, doc->root, root_box, css);
	layout_boxes(doc->ctx, root_box, w, h);
	print_box(doc->ctx, root_box, 0);
}
