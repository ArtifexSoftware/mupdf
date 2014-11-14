#include "mupdf/html.h"

static const char *default_css =
"html,address,blockquote,body,dd,div,dl,dt,h1,h2,h3,h4,h5,h6,ol,p,ul,center,hr,pre{display:block}"
"span{display:inline}"
"li{display:list-item}"
"head{display:none}"
"body{margin:1em}"
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

static int iswhite(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
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

static void add_flow_space(fz_context *ctx, struct box *top, struct computed_style *style)
{
	struct flow *flow;

	/* delete space at the beginning of the line */
	if (!top->flow_head)
		return;

	flow = add_flow(ctx, top, style, FLOW_GLUE);
	flow->text = " ";
	flow->broken_text = "";
}

static void add_flow_word(fz_context *ctx, struct box *top, struct computed_style *style, const char *a, const char *b)
{
	struct flow *flow = add_flow(ctx, top, style, FLOW_WORD);
	flow->text = fz_malloc(ctx, b - a + 1);
	memcpy(flow->text, a, b - a);
	flow->text[b - a] = 0;
}

static void generate_text(fz_context *ctx, struct box *box, const char *text)
{
	struct box *flow = box;
	while (flow->type != BOX_FLOW)
		flow = flow->up;

	while (*text)
	{
		if (iswhite(*text))
		{
			++text;
			while (iswhite(*text))
				++text;
			add_flow_space(ctx, flow, &box->style);
		}
		if (*text)
		{
			const char *mark = text++;
			while (*text && !iswhite(*text))
				++text;
			add_flow_word(ctx, flow, &box->style, mark, text);
		}
	}
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

	default_computed_style(&box->style);

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

static void generate_boxes(html_document *doc, fz_xml *node, struct box *top, struct rule *rule, struct style *up_style)
{
	fz_context *ctx = doc->ctx;
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

			// TODO: <br>
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
					generate_boxes(doc, fz_xml_down(node), box, rule, &style);

				// TODO: remove empty flow boxes
			}
		}
		else
		{
			insert_inline_box(ctx, box, top);
			generate_text(ctx, box, fz_xml_text(node));
		}

		compute_style(doc, &box->style, &style);

		node = fz_xml_next(node);
	}
}

static void measure_word(fz_context *ctx, struct flow *node, float em)
{
	const char *s;
	int c, g;
	float w;

	em = from_number(node->style->font_size, em, em);
	node->x = 0;
	node->y = 0;
	node->h = from_number_scale(node->style->line_height, em, em, em);

	w = 0;
	s = node->text;
	while (*s)
	{
		s += fz_chartorune(&c, s);
		g = fz_encode_character(ctx, node->style->font, c);
		w += fz_advance_glyph(ctx, node->style->font, g) * em;
	}
	node->w = w;
	node->em = em;
}

static float layout_line(fz_context *ctx, float indent, float page_w, float line_w, int align, struct flow *node, struct flow *end, struct box *box)
{
	float x = box->x + indent;
	float y = box->y + box->h;
	float h = 0;
	float slop = page_w - line_w;
	float justify = 0;
	int n = 0;

	if (align == TA_JUSTIFY)
	{
		struct flow *it;
		for (it = node; it != end; it = it->next)
			if (it->type == FLOW_GLUE)
				++n;
		justify = slop / n;
	}
	else if (align == TA_RIGHT)
		x += slop;
	else if (align == TA_CENTER)
		x += slop / 2;

	while (node != end)
	{
		node->x = x;
		node->y = y;
		x += node->w;
		if (node->type == FLOW_GLUE)
			x += justify;
		if (node->h > h)
			h = node->h;
		node = node->next;
	}

	return h;
}

static struct flow *find_next_glue(struct flow *node, float *w)
{
	while (node && node->type == FLOW_GLUE)
	{
		*w += node->w;
		node = node->next;
	}
	while (node && node->type != FLOW_GLUE)
	{
		*w += node->w;
		node = node->next;
	}
	return node;
}

static struct flow *find_next_word(struct flow *node, float *w)
{
	while (node && node->type != FLOW_WORD)
	{
		*w += node->w;
		node = node->next;
	}
	return node;
}

static void layout_flow(fz_context *ctx, struct box *box, struct box *top, float em)
{
	struct flow *node, *line_start, *word_start, *word_end, *line_end;
	float glue_w;
	float word_w;
	float line_w;
	float indent;
	int align;

	em = from_number(box->style.font_size, em, em);
	indent = from_number(top->style.text_indent, em, top->w);
	align = top->style.text_align;

	box->x = top->x;
	box->y = top->y + top->h;
	box->w = top->w;
	box->h = 0;

	if (!box->flow_head)
		return;

	for (node = box->flow_head; node; node = node->next)
		measure_word(ctx, node, em);

	line_start = find_next_word(box->flow_head, &glue_w);
	line_end = NULL;

	line_w = indent;
	word_w = 0;
	word_start = line_start;
	while (word_start)
	{
		word_end = find_next_glue(word_start, &word_w);
		if (line_w + word_w <= top->w)
		{
			line_w += word_w;
			glue_w = 0;
			line_end = word_end;
			word_start = find_next_word(word_end, &glue_w);
			word_w = glue_w;
		}
		else
		{
			box->h += layout_line(ctx, indent, top->w, line_w, align, line_start, line_end, box);
			line_start = word_start;
			line_end = NULL;
			indent = 0;
			line_w = 0;
			word_w = 0;
		}
	}

	/* don't justify the last line of a paragraph */
	if (align == TA_JUSTIFY)
		align = TA_LEFT;

	if (line_start)
		box->h += layout_line(ctx, indent, top->w, line_w, align, line_start, line_end, box);
}

static void layout_block(fz_context *ctx, struct box *box, struct box *top, float em, float top_collapse_margin)
{
	struct box *child;
	float box_collapse_margin;

	em = from_number(box->style.font_size, em, em);

	box->margin[0] = from_number(box->style.margin[0], em, top->w);
	box->margin[1] = from_number(box->style.margin[1], em, top->w);
	box->margin[2] = from_number(box->style.margin[2], em, top->w);
	box->margin[3] = from_number(box->style.margin[3], em, top->w);

	box->padding[0] = from_number(box->style.padding[0], em, top->w);
	box->padding[1] = from_number(box->style.padding[1], em, top->w);
	box->padding[2] = from_number(box->style.padding[2], em, top->w);
	box->padding[3] = from_number(box->style.padding[3], em, top->w);

	if (box->padding[TOP] == 0)
		box_collapse_margin = box->margin[TOP];
	else
		box_collapse_margin = 0;

	if (box->margin[TOP] > top_collapse_margin)
		box->margin[TOP] -= top_collapse_margin;
	else
		box->margin[TOP] = 0;

	box->x = top->x + box->margin[LEFT] + box->padding[LEFT];
	box->y = top->y + top->h + box->margin[TOP] + box->padding[TOP];
	box->w = top->w - (box->margin[LEFT] + box->margin[RIGHT] + box->padding[LEFT] + box->padding[RIGHT]);
	box->h = 0;

	for (child = box->down; child; child = child->next)
	{
		if (child->type == BOX_BLOCK)
		{
			layout_block(ctx, child, box, em, box_collapse_margin);
			box->h += child->h + child->padding[TOP] + child->padding[BOTTOM] + child->margin[TOP] + child->margin[BOTTOM];
			box_collapse_margin = child->margin[BOTTOM];
		}
		else if (child->type == BOX_FLOW)
		{
			layout_flow(ctx, child, box, em);
			if (child->h > 0)
			{
				box->h += child->h;
				box_collapse_margin = 0;
			}
		}
	}

	if (box->padding[BOTTOM] == 0)
	{
		if (box->margin[BOTTOM] > 0)
		{
			box->h -= box_collapse_margin;
			if (box->margin[BOTTOM] < box_collapse_margin)
				box->margin[BOTTOM] = box_collapse_margin;
		}
	}
}

static void indent(int level)
{
	while (level--) printf("    ");
}

static void print_flow(fz_context *ctx, struct flow *flow, int level)
{
	while (flow)
	{
		printf("%-5d %-5d", (int)flow->x, (int)flow->y);
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
//		if (box->flow_head)
//			print_flow(ctx, box->flow_head, level + 1);
		box = box->next;
	}
}

static void
draw_flow_box(fz_context *ctx, struct box *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *ctm)
{
	struct flow *node;
	fz_text *text;
	fz_matrix trm;
	const char *s;
	float black[1];
	float x, y;
	int c, g;

	black[0] = 0;

	for (node = box->flow_head; node; node = node->next)
	{
		if (node->y > page_bot || node->y + node->h < page_top)
			continue;

		if (node->type == FLOW_WORD)
		{
			fz_scale(&trm, node->em, -node->em);
			text = fz_new_text(ctx, node->style->font, &trm, 0);

			x = node->x;
			y = node->y + node->em * 0.8;
			s = node->text;
			while (*s)
			{
				s += fz_chartorune(&c, s);
				g = fz_encode_character(ctx, node->style->font, c);
				fz_add_text(ctx, text, g, c, x, y);
				x += fz_advance_glyph(ctx, node->style->font, g) * node->em;
			}

			fz_fill_text(dev, text, ctm, fz_device_gray(ctx), black, 1);

			fz_free_text(ctx, text);
		}
	}
}

static void
draw_block_box(fz_context *ctx, struct box *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *ctm)
{
	fz_path *path;
	float black[1];
	float x0, y0, x1, y1;

	// TODO: background fill
	// TODO: border stroke

	black[0] = 0;

	x0 = box->x - box->padding[LEFT];
	y0 = box->y - box->padding[TOP];
	x1 = box->x + box->w + box->padding[RIGHT];
	y1 = box->y + box->h + box->padding[BOTTOM];

	if (y0 > page_bot || y1 < page_top)
		return;

	path = fz_new_path(ctx);
	fz_moveto(ctx, path, x0, y0);
	fz_lineto(ctx, path, x1, y0);
	fz_lineto(ctx, path, x1, y1);
	fz_lineto(ctx, path, x0, y1);
	fz_closepath(ctx, path);

	fz_fill_path(dev, path, 0, ctm, fz_device_gray(ctx), black, 0.1);

	fz_free_path(ctx, path);

	for (box = box->down; box; box = box->next)
	{
		switch (box->type)
		{
		case BOX_BLOCK: draw_block_box(ctx, box, page_top, page_bot, dev, ctm); break;
		case BOX_FLOW: draw_flow_box(ctx, box, page_top, page_bot, dev, ctm); break;
		}
	}
}

void
html_run_box(fz_context *ctx, struct box *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *inctm)
{
	fz_matrix ctm = *inctm;
	fz_pre_translate(&ctm, 0, -page_top);
	draw_block_box(ctx, box, page_top, page_bot, dev, &ctm);
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

static struct rule *load_css(html_document *doc, struct rule *css, fz_xml *root)
{
	fz_context *ctx = doc->ctx;
	fz_xml *node;
	char filename[2048];

	for (node = root; node; node = fz_xml_next(node))
	{
		const char *tag = fz_xml_tag(node);
#if 1
		if (tag && !strcmp(tag, "link"))
		{
			char *rel = fz_xml_att(node, "rel");
			if (rel && !strcasecmp(rel, "stylesheet"))
			{
				char *type = fz_xml_att(node, "type");
				if ((type && !strcmp(type, "text/css")) || !type)
				{
					char *href = fz_xml_att(node, "href");
					fz_strlcpy(filename, doc->dirname, sizeof filename);
					fz_strlcat(filename, href, sizeof filename);
					css = fz_parse_css_file(ctx, css, filename);
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
			css = load_css(doc, css, fz_xml_down(node));
	}
	return css;
}

void
html_layout_document(html_document *doc, float page_w, float page_h)
{
	struct rule *css = NULL;
	struct box *root_box;
	struct box *page_box;
	struct style style;

	doc->page_w = page_w;
	doc->page_h = page_h;

printf("html: parsing style sheets.\n");
	css = fz_parse_css(doc->ctx, NULL, default_css);
	css = load_css(doc, css, doc->xml);

	// print_rules(css);

	style.up = NULL;
	style.count = 0;

	root_box = new_box(doc->ctx, NULL);

	page_box = new_box(doc->ctx, NULL);
	page_box->w = page_w;
	page_box->h = 0;

printf("html: applying styles and generating boxes.\n");
	generate_boxes(doc, doc->xml, root_box, css, &style);
printf("html: laying out text.\n");
	layout_block(doc->ctx, root_box, page_box, 12, 0);
printf("html: finished.\n");

	// print_box(doc->ctx, root_box, 0);

	doc->box = root_box;
}
