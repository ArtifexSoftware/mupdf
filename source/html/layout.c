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
	BOX_BLOCK,	/* block-level: contains block and flow boxes */
	BOX_FLOW,	/* block-level: contains only inline boxes */
	BOX_INLINE,	/* inline-level: contains only inline boxes */
};

struct box
{
	int type;
	float x, y, w, h;
	struct box *up, *down, *last, *next;
	fz_xml *node;
	struct flow *flow_head, **flow_tail;
	struct computed_style style;
};

enum
{
	FLOW_WORD,
	FLOW_GLUE,
};

struct flow
{
	int type;
	struct computed_style *style;
	char *text, *broken_text;
	float width, broken_width;
	struct flow *next;
};

static int iswhite(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

struct box *new_box(fz_context *ctx, fz_xml *node)
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

	box->flow_head = NULL;
	box->flow_tail = &box->flow_head;

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
	else if (top->type == BOX_FLOW)
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
		if (top->last && top->last->type == BOX_FLOW)
		{
			insert_box(ctx, box, BOX_INLINE, top->last);
		}
		else
		{
			struct box *flow = new_box(ctx, NULL);
			insert_box(ctx, flow, BOX_FLOW, top);
			insert_box(ctx, box, BOX_INLINE, flow);
		}
	}
	else if (top->type == BOX_FLOW)
	{
		insert_box(ctx, box, BOX_INLINE, top);
	}
	else if (top->type == BOX_INLINE)
	{
		insert_box(ctx, box, BOX_INLINE, top);
	}
}

static void generate_boxes(fz_context *ctx, fz_xml *node, struct box *top, struct rule *rule, struct style *up_style)
{
	struct style style;
	struct box *box;
	int display;

	while (node)
	{
		style.up = up_style;
		style.count = 0;

		box = new_box(ctx, node);

		if (fz_xml_tag(node))
		{
			apply_styles(ctx, &style, rule, node);

			display = get_style_property_display(&style);

			// TOOD: <br>
			// TODO: <img>

			if (display != DIS_NONE)
			{
				if (display == DIS_BLOCK)
				{
					top = insert_block_box(ctx, box, top);
				}
				else if (display == DIS_INLINE)
				{
					insert_inline_box(ctx, box, top);
				}
				else
				{
					fz_warn(ctx, "unknown box display type");
					insert_box(ctx, box, BOX_BLOCK, top);
				}

				if (fz_xml_down(node))
					generate_boxes(ctx, fz_xml_down(node), box, rule, &style);
			}
		}
		else
		{
			insert_inline_box(ctx, box, top);
		}

		compute_style(&box->style, &style);

		node = fz_xml_next(node);
	}
}

static struct flow *add_flow(fz_context *ctx, struct box *top, struct computed_style *style, int type)
{
	struct flow *flow = fz_malloc_struct(ctx, struct flow);
	flow->type = type;
	flow->style = style;
	*top->flow_tail = flow;
	top->flow_tail = &flow->next;
	return flow;
}

static void add_flow_space(fz_context *ctx, struct box *top, struct computed_style *style, float em)
{
	struct flow *flow;

	/* delete space at the beginning of the line */
	if (!top->flow_head)
		return;

	flow = add_flow(ctx, top, style, FLOW_GLUE);
	flow->text = " ";
	flow->width = 0.5 * em;
	flow->broken_text = "";
	flow->broken_width = 0;
}

static void add_flow_word(fz_context *ctx, struct box *top, struct computed_style *style, float em, const char *a, const char *b)
{
	struct flow *flow = add_flow(ctx, top, style, FLOW_WORD);
	flow->text = fz_malloc(ctx, b - a + 1);
	memcpy(flow->text, a, b - a);
	flow->text[b - a] = 0;
	flow->width = (b - a) * 0.5 * em;
}

static void layout_text(fz_context *ctx, struct box *top, const char *text, struct computed_style *style, float em)
{
	while (*text)
	{
		if (iswhite(*text))
		{
			++text;
			while (iswhite(*text))
				++text;
			add_flow_space(ctx, top, style, em);
		}
		if (*text)
		{
			const char *mark = text++;
			while (*text && !iswhite(*text))
				++text;
			add_flow_word(ctx, top, style, em, mark, text);
		}
	}
}

static void layout_inline(fz_context *ctx, struct box *box, struct box *top, float em)
{
	struct box *child;
	const char *s;

	em = from_number(box->style.font_size, em, em);

	box->x = top->x + top->w;
	box->y = top->y;
	box->h = em;
	box->w = 0;

	s = fz_xml_text(box->node);
	if (s)
	{
		layout_text(ctx, top, s, &box->style, em);

		box->w += strlen(s) * 0.5 * em;
	}

	for (child = box->down; child; child = child->next)
	{
		layout_inline(ctx, child, top, em);
		if (child->h > box->h)
			box->h = child->h;
		top->w += child->w;
	}
}

static void layout_flow(fz_context *ctx, struct box *box, struct box *top, float em)
{
	struct box *child;

	em = from_number(box->style.font_size, em, em);

	box->x = top->x;
	box->y = top->y + top->h;
	box->h = 0;
	box->w = 0;

	for (child = box->down; child; child = child->next)
	{
		layout_inline(ctx, child, box, em);
		if (child->h > box->h)
			box->h = child->h;
		box->w += child->w;
	}
}

static void layout_block(fz_context *ctx, struct box *box, struct box *top, float em)
{
	struct box *child;
	float margin[4];

	em = from_number(box->style.font_size, em, em);

	margin[0] = from_number(box->style.margin[0], em, top->w);
	margin[1] = from_number(box->style.margin[1], em, top->w);
	margin[2] = from_number(box->style.margin[2], em, top->w);
	margin[3] = from_number(box->style.margin[3], em, top->w);

	box->x = top->x + margin[LEFT];
	box->y = top->y + top->h + margin[TOP];
	box->w = top->w - (margin[LEFT] + margin[RIGHT]);
	box->h = 0;

	for (child = box->down; child; child = child->next)
	{
		if (child->type == BOX_BLOCK)
			layout_block(ctx, child, box, em);
		else if (child->type == BOX_FLOW)
		{
			layout_flow(ctx, child, box, em);
			// TOOD: remove flow box if no flow content
		}
		box->h += child->h;
	}

	box->h += margin[BOTTOM];
}

static void indent(int level)
{
	while (level--) printf("    ");
}

static void print_flow(fz_context *ctx, struct flow *flow, int level)
{
	while (flow)
	{
		printf("           ");
		indent(level);
		switch (flow->type)
		{
		case FLOW_WORD: printf("word \"%s\"\n", flow->text); break;
		case FLOW_GLUE: printf("glue \"%s\" / \"%s\"\n", flow->text, flow->broken_text); break;
		}
		flow = flow->next;
	}
}

static void print_box(fz_context *ctx, struct box *box, int level)
{
	while (box)
	{
		printf("%-5d %-5d", (int)box->x, (int)box->y);
		indent(level);
		switch (box->type)
		{
		case BOX_BLOCK: printf("block"); break;
		case BOX_FLOW: printf("flow"); break;
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
		if (box->flow_head)
			print_flow(ctx, box->flow_head, level + 1);
		box = box->next;
	}
}

void
html_run_box(fz_context *ctx, struct box *box, fz_device *dev, const fz_matrix *ctm)
{

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
	struct box *win_box;
	struct style style;

#if 0
	strcpy(dirname, argv[i]);
	s = strrchr(dirname, '/');
	if (!s) s = strrchr(dirname, '\\');
	if (s) s[1] = 0;
	else strcpy(dirname, "./");
#endif

	css = fz_parse_css(doc->ctx, NULL, default_css);
	css = load_css(doc->ctx, css, doc->xml);

	print_rules(css);

	style.up = NULL;
	style.count = 0;
	root_box = new_box(doc->ctx, NULL);

	generate_boxes(doc->ctx, doc->xml, root_box, css, &style);

	win_box = new_box(doc->ctx, NULL);
	win_box->w = w;
	win_box->h = 0;

	layout_block(doc->ctx, root_box, win_box, 12);

	print_box(doc->ctx, root_box, 0);

	doc->box = root_box;
}
