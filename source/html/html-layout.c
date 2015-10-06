#include "mupdf/html.h"

enum { T, R, B, L };

static const char *default_css =
"@page{margin:1em 0}"
"a{color:#06C;text-decoration:underline}"
"address{display:block;font-style:italic}"
"b{font-weight:bold}"
"bdo{direction:rtl;unicode-bidi:bidi-override}"
"blockquote{display:block;margin:1em 40px}"
"body{display:block;margin:1em}"
"cite{font-style:italic}"
"code{font-family:monospace}"
"dd{display:block;margin:0 0 0 40px}"
"del{text-decoration:line-through}"
"div{display:block}"
"dl{display:block;margin:1em 0}"
"dt{display:block}"
"em{font-style:italic}"
"h1{display:block;font-size:2em;font-weight:bold;margin:0.67em 0;page-break-after:avoid}"
"h2{display:block;font-size:1.5em;font-weight:bold;margin:0.83em 0;page-break-after:avoid}"
"h3{display:block;font-size:1.17em;font-weight:bold;margin:1em 0;page-break-after:avoid}"
"h4{display:block;font-size:1em;font-weight:bold;margin:1.33em 0;page-break-after:avoid}"
"h5{display:block;font-size:0.83em;font-weight:bold;margin:1.67em 0;page-break-after:avoid}"
"h6{display:block;font-size:0.67em;font-weight:bold;margin:2.33em 0;page-break-after:avoid}"
"head{display:none}"
"hr{border-style:solid;border-width:1px;display:block;margin-bottom:0.5em;margin-top:0.5em;text-align:center}"
"html{display:block}"
"i{font-style:italic}"
"ins{text-decoration:underline}"
"kbd{font-family:monospace}"
"li{display:list-item}"
"menu{display:block;list-style-type:disc;margin:1em 0;padding:0 0 0 30pt}"
"ol{display:block;list-style-type:decimal;margin:1em 0;padding:0 0 0 30pt}"
"p{display:block;margin:1em 0}"
"pre{display:block;font-family:monospace;margin:1em 0;white-space:pre}"
"samp{font-family:monospace}"
"script{display:none}"
"small{font-size:0.83em}"
"strong{font-weight:bold}"
"style{display:none}"
"sub{font-size:0.83em;vertical-align:sub}"
"sup{font-size:0.83em;vertical-align:super}"
"table{display:table}"
"tbody{display:table-row-group}"
"td{display:table-cell;padding:1px}"
"tfoot{display:table-footer-group}"
"th{display:table-cell;font-weight:bold;padding:1px;text-align:center}"
"thead{display:table-header-group}"
"tr{display:table-row}"
"ul{display:block;list-style-type:disc;margin:1em 0;padding:0 0 0 30pt}"
"var{font-style:italic}"
"svg{display:none}"
;

static int iswhite(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static void fz_drop_html_flow(fz_context *ctx, fz_html_flow *flow)
{
	while (flow)
	{
		fz_html_flow *next = flow->next;
		if (flow->type == FLOW_WORD)
			fz_free(ctx, flow->text);
		if (flow->type == FLOW_IMAGE)
			fz_drop_image(ctx, flow->image);
		fz_free(ctx, flow);
		flow = next;
	}
}

static fz_html_flow *add_flow(fz_context *ctx, fz_html *top, fz_css_style *style, int type)
{
	fz_html_flow *flow = fz_malloc_struct(ctx, fz_html_flow);
	flow->type = type;
	flow->style = style;
	*top->flow_tail = flow;
	top->flow_tail = &flow->next;
	return flow;
}

static void add_flow_glue(fz_context *ctx, fz_html *top, fz_css_style *style, const char *text, int expand)
{
	fz_html_flow *flow = add_flow(ctx, top, style, FLOW_GLUE);
	flow->text = (char*)text;
	flow->expand = expand;
}

static void add_flow_break(fz_context *ctx, fz_html *top, fz_css_style *style)
{
	fz_html_flow *flow = add_flow(ctx, top, style, FLOW_BREAK);
	flow->text = "";
}

static void add_flow_word(fz_context *ctx, fz_html *top, fz_css_style *style, const char *a, const char *b)
{
	fz_html_flow *flow = add_flow(ctx, top, style, FLOW_WORD);
	flow->text = fz_malloc(ctx, b - a + 1);
	memcpy(flow->text, a, b - a);
	flow->text[b - a] = 0;
}

static void add_flow_image(fz_context *ctx, fz_html *top, fz_css_style *style, fz_image *img)
{
	fz_html_flow *flow;
	add_flow_glue(ctx, top, style, "", 0);
	flow = add_flow(ctx, top, style, FLOW_IMAGE);
	flow->image = fz_keep_image(ctx, img);
	add_flow_glue(ctx, top, style, "", 0);
}

static int iscjk(int c)
{
	if (c >= 0x3200 && c <= 0x9FFF) return 1; /* CJK Blocks */
	if (c >= 0xFF00 && c <= 0xFFEF) return 1; /* Halfwidth and Fullwidth Forms */
	return 0;
}

static int not_at_bol(int cat, int c)
{
	if (cat == UCDN_GENERAL_CATEGORY_PF) return 1;
	if (cat == UCDN_GENERAL_CATEGORY_PE) return 1;
	if (c == ')' || c == 0xFF09) return 1;
	if (c == ']' || c == 0xFF3D) return 1;
	if (c == '}' || c == 0xFF5D) return 1;
	if (c == '>' || c == 0xFF1E) return 1;
	if (c == ',' || c == 0xFF0C) return 1;
	if (c == '.' || c == 0xFF0E) return 1;
	if (c == ':' || c == 0xFF1A) return 1;
	if (c == ';' || c == 0xFF1B) return 1;
	if (c == '?' || c == 0xFF1F) return 1;
	if (c == '!' || c == 0xFF01) return 1;
	if (c == '%' || c == 0xFF05) return 1;
	return 0;
}

static int not_at_eol(int cat, int c)
{
	if (cat == UCDN_GENERAL_CATEGORY_PI) return 1;
	if (cat == UCDN_GENERAL_CATEGORY_PS) return 1;
	if (c == '(' || c == 0xFF08) return 1;
	if (c == '[' || c == 0xFF3B) return 1;
	if (c == '{' || c == 0xFF5B) return 1;
	if (c == '<' || c == 0xFF1C) return 1;
	if (c == '$' || c == 0xFF04) return 1;
	if (c >= 0xFFE0 || c == 0xFFE1) return 1; /* cent, pound */
	if (c == 0xFFE5 || c == 0xFFE6) return 1; /* yen, won */
	return 0;
}

static void generate_text(fz_context *ctx, fz_html *box, const char *text)
{
	fz_html *flow;

	int collapse = box->style.white_space & WS_COLLAPSE;
	int bsp = box->style.white_space & WS_ALLOW_BREAK_SPACE;
	int bnl = box->style.white_space & WS_FORCE_BREAK_NEWLINE;

	flow = box;
	while (flow->type != BOX_FLOW)
		flow = flow->up;

	while (*text)
	{
		if (bnl && (*text == '\n' || *text == '\r'))
		{
			if (text[0] == '\r' && text[1] == '\n')
				text += 2;
			else
				text += 1;
			add_flow_break(ctx, flow, &box->style);
		}
		else if (iswhite(*text))
		{
			const char *mark = text++;
			if (collapse)
				while (iswhite(*text))
					++text;
			/* TODO: tabs */
			if (bsp)
				add_flow_glue(ctx, flow, &box->style, " ", 1);
			else
				add_flow_word(ctx, flow, &box->style, mark, text);
		}
		else
		{
			const char *mark = text;
			int c, addglue = 0;
			while (*text && !iswhite(*text))
			{
				/* TODO: Unicode Line Breaking Algorithm (UAX #14) */
				text += fz_chartorune(&c, text);
				if (iscjk(c))
				{
					int cat = ucdn_get_general_category(c);
					if (addglue && !not_at_bol(cat, c))
						add_flow_glue(ctx, flow, &box->style, "", 0);
					add_flow_word(ctx, flow, &box->style, mark, text);
					if (!not_at_eol(cat, c))
						addglue = 1;
					mark = text;
				}
				else
				{
					addglue = 0;
				}
			}
			if (mark != text)
				add_flow_word(ctx, flow, &box->style, mark, text);
		}
	}
}

static void generate_image(fz_context *ctx, fz_archive *zip, const char *base_uri, fz_html *box, const char *src)
{
	fz_image *img;
	fz_buffer *buf;
	char path[2048];

	fz_html *flow = box;
	while (flow->type != BOX_FLOW)
		flow = flow->up;

	fz_strlcpy(path, base_uri, sizeof path);
	fz_strlcat(path, "/", sizeof path);
	fz_strlcat(path, src, sizeof path);
	fz_urldecode(path);
	fz_cleanname(path);

	fz_try(ctx)
	{
		buf = fz_read_archive_entry(ctx, zip, path);
		img = fz_new_image_from_buffer(ctx, buf);
		fz_drop_buffer(ctx, buf);

		add_flow_image(ctx, flow, &box->style, img);
	}
	fz_catch(ctx)
	{
		const char *alt = "[image]";
		fz_warn(ctx, "html: cannot add image src='%s'", src);
		add_flow_word(ctx, flow, &box->style, alt, alt + 7);
	}
}

static void init_box(fz_context *ctx, fz_html *box)
{
	box->type = BOX_BLOCK;
	box->x = box->y = 0;
	box->w = box->h = 0;

	box->up = NULL;
	box->last = NULL;
	box->down = NULL;
	box->next = NULL;

	box->flow_head = NULL;
	box->flow_tail = &box->flow_head;

	fz_default_css_style(ctx, &box->style);
}

void fz_drop_html(fz_context *ctx, fz_html *box)
{
	while (box)
	{
		fz_html *next = box->next;
		fz_drop_html_flow(ctx, box->flow_head);
		fz_drop_html(ctx, box->down);
		fz_free(ctx, box);
		box = next;
	}
}

static fz_html *new_box(fz_context *ctx)
{
	fz_html *box = fz_malloc_struct(ctx, fz_html);
	init_box(ctx, box);
	return box;
}

static void insert_box(fz_context *ctx, fz_html *box, int type, fz_html *top)
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

static fz_html *insert_block_box(fz_context *ctx, fz_html *box, fz_html *top)
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

static fz_html *insert_break_box(fz_context *ctx, fz_html *box, fz_html *top)
{
	if (top->type == BOX_BLOCK)
	{
		insert_box(ctx, box, BOX_BREAK, top);
	}
	else if (top->type == BOX_FLOW)
	{
		while (top->type != BOX_BLOCK)
			top = top->up;
		insert_box(ctx, box, BOX_BREAK, top);
	}
	else if (top->type == BOX_INLINE)
	{
		while (top->type != BOX_BLOCK)
			top = top->up;
		insert_box(ctx, box, BOX_BREAK, top);
	}
	return top;
}

static void insert_inline_box(fz_context *ctx, fz_html *box, fz_html *top)
{
	if (top->type == BOX_BLOCK)
	{
		if (top->last && top->last->type == BOX_FLOW)
		{
			insert_box(ctx, box, BOX_INLINE, top->last);
		}
		else
		{
			fz_html *flow = new_box(ctx);
			flow->is_first_flow = !top->last;
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

static void generate_boxes(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri,
	fz_xml *node, fz_html *top, fz_css_rule *rule, fz_css_match *up_match, int list_counter)
{
	fz_css_match match;
	fz_html *box;
	const char *tag;
	int display;

	while (node)
	{
		match.up = up_match;
		match.count = 0;

		tag = fz_xml_tag(node);
		if (tag)
		{
			fz_match_css(ctx, &match, rule, node);

			display = fz_get_css_match_display(&match);

			if (!strcmp(tag, "br"))
			{
				if (top->type == BOX_INLINE)
				{
					fz_html *flow = top;
					while (flow->type != BOX_FLOW)
						flow = flow->up;
					add_flow_break(ctx, flow, &top->style);
				}
				else
				{
					box = new_box(ctx);
					fz_apply_css_style(ctx, set, &box->style, &match);
					top = insert_break_box(ctx, box, top);
				}
			}

			else if (!strcmp(tag, "img"))
			{
				const char *src = fz_xml_att(node, "src");
				if (src)
				{
					box = new_box(ctx);
					fz_apply_css_style(ctx, set, &box->style, &match);
					insert_inline_box(ctx, box, top);
					generate_image(ctx, zip, base_uri, box, src);
				}
			}

			else if (display != DIS_NONE)
			{
				box = new_box(ctx);
				fz_apply_css_style(ctx, set, &box->style, &match);

				if (display == DIS_BLOCK || display == DIS_INLINE_BLOCK)
				{
					top = insert_block_box(ctx, box, top);
				}
				else if (display == DIS_LIST_ITEM)
				{
					top = insert_block_box(ctx, box, top);
					box->list_item = ++list_counter;
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
				{
					int child_counter = list_counter;
					if (!strcmp(tag, "ul") || !strcmp(tag, "ol"))
						child_counter = 0;
					generate_boxes(ctx, set, zip, base_uri, fz_xml_down(node), box, rule, &match, child_counter);
				}

				// TODO: remove empty flow boxes
			}
		}
		else
		{
			if (top->type != BOX_INLINE)
			{
				/* Create anonymous inline box, with the same style as the top block box. */
				box = new_box(ctx);
				insert_inline_box(ctx, box, top);
				box->style = top->style;
				/* Make sure not to recursively multiply font sizes. */
				box->style.font_size.value = 1;
				box->style.font_size.unit = N_SCALE;
				generate_text(ctx, box, fz_xml_text(node));
			}
			else
			{
				generate_text(ctx, top, fz_xml_text(node));
			}
		}

		node = fz_xml_next(node);
	}
}

static void measure_image(fz_context *ctx, fz_html_flow *node, float max_w, float max_h)
{
	float xs = 1, ys = 1, s = 1;
	node->x = 0;
	node->y = 0;
	if (node->image->w > max_w)
		xs = max_w / node->image->w;
	if (node->image->h > max_h)
		ys = max_h / node->image->h;
	s = fz_min(xs, ys);
	node->w = node->image->w * s;
	node->h = node->image->h * s;
}

static void measure_word(fz_context *ctx, fz_html_flow *node, float em)
{
	const char *s;
	int c, g;
	float w;

	em = fz_from_css_number(node->style->font_size, em, em);
	node->x = 0;
	node->y = 0;
	node->h = fz_from_css_number_scale(node->style->line_height, em, em, em);

	w = 0;
	s = node->text;
	while (*s)
	{
		s += fz_chartorune(&c, s);
		g = fz_encode_character(ctx, node->style->font, c);
		if (g)
		{
			w += fz_advance_glyph(ctx, node->style->font, g) * em;
		}
		else
		{
			g = fz_encode_character(ctx, node->style->fallback, c);
			w += fz_advance_glyph(ctx, node->style->fallback, g) * em;
		}
	}
	node->w = w;
	node->em = em;
}

static float measure_line(fz_html_flow *node, fz_html_flow *end, float *baseline, float *line_w)
{
	float max_a = 0, max_d = 0, h = node->h;
	while (node != end)
	{
		*line_w += node->w;
		if (node->type == FLOW_IMAGE)
		{
			if (node->h > max_a)
				max_a = node->h;
		}
		else
		{
			float a = node->em * 0.8;
			float d = node->em * 0.2;
			if (a > max_a) max_a = a;
			if (d > max_d) max_d = d;
		}
		if (node->h > h) h = node->h;
		if (max_a + max_d > h) h = max_a + max_d;
		node = node->next;
	}
	*baseline = max_a + (h - max_a - max_d) / 2;
	return h;
}

static void layout_line(fz_context *ctx, float indent, float page_w, float line_w, int align, fz_html_flow *node, fz_html_flow *end, fz_html *box, float baseline)
{
	float x = box->x + indent;
	float y = box->y + box->h;
	float slop = page_w - line_w;
	float justify = 0;
	float va;
	int n = 0;

	if (align == TA_JUSTIFY)
	{
		fz_html_flow *it;
		for (it = node; it != end; it = it->next)
			if (it->type == FLOW_GLUE && it->expand)
				++n;
		justify = slop / n;
	}
	else if (align == TA_RIGHT)
		x += slop;
	else if (align == TA_CENTER)
		x += slop / 2;

	while (node != end)
	{
		switch (node->style->vertical_align)
		{
		default:
		case VA_BASELINE:
			va = 0;
			break;
		case VA_SUB:
			va = node->em * 0.2f;
			break;
		case VA_SUPER:
			va = node->em * -0.3f;
			break;
		}
		node->x = x;
		if (node->type == FLOW_IMAGE)
			node->y = y + baseline - node->h;
		else
			node->y = y + baseline + va;
		x += node->w;
		if (node->type == FLOW_GLUE && node->expand)
			x += justify;
		node = node->next;
	}
}

static void find_accumulated_margins(fz_context *ctx, fz_html *box, float *w, float *h)
{
	while (box)
	{
		/* TODO: take into account collapsed margins */
		*h += box->margin[T] + box->padding[T] + box->border[T];
		*h += box->margin[B] + box->padding[B] + box->border[B];
		*w += box->margin[L] + box->padding[L] + box->border[L];
		*w += box->margin[R] + box->padding[R] + box->border[R];
		box = box->up;
	}
}

static void flush_line(fz_context *ctx, fz_html *box, float page_h, float page_w, int align, float indent, fz_html_flow *a, fz_html_flow *b)
{
	float avail, line_h, line_w, baseline;
	line_w = indent;
	avail = page_h - fmodf(box->y + box->h, page_h);
	line_h = measure_line(a, b, &baseline, &line_w);
	if (line_h > avail)
		box->h += avail;
	layout_line(ctx, indent, page_w, line_w, align, a, b, box, baseline);
	box->h += line_h;
}

static void layout_flow(fz_context *ctx, fz_html *box, fz_html *top, float em, float page_h)
{
	fz_html_flow *node, *line, *mark;
	float line_w;
	float indent;
	int align;
	int line_align;

	em = fz_from_css_number(box->style.font_size, em, em);
	indent = box->is_first_flow ? fz_from_css_number(top->style.text_indent, em, top->w) : 0;
	align = top->style.text_align;

	box->x = top->x;
	box->y = top->y + top->h;
	box->w = top->w;
	box->h = 0;

	if (!box->flow_head)
		return;

	for (node = box->flow_head; node; node = node->next)
	{
		if (node->type == FLOW_IMAGE)
		{
			float w = 0, h = 0;
			find_accumulated_margins(ctx, box, &w, &h);
			measure_image(ctx, node, top->w - w, page_h - h);
		}
		else
		{
			measure_word(ctx, node, em);
		}
	}

	/* start by skipping whitespace (and newline) at the beginning of tags */
	node = box->flow_head;
	if (node->type == FLOW_BREAK)
		node = node->next;
	while (node && node->type == FLOW_GLUE)
		node = node->next;

	mark = NULL;
	line = node;
	line_w = indent;

	while (node)
	{
		switch (node->type)
		{
		case FLOW_WORD:
			break;
		case FLOW_IMAGE:
			/* TODO: break before/after image */
			mark = node;
			break;
		case FLOW_GLUE:
			mark = node;
			break;
		case FLOW_BREAK:
			line_align = align == TA_JUSTIFY ? TA_LEFT : align;
			flush_line(ctx, box, page_h, top->w, line_align, indent, line, node);
			indent = 0;
			line = node->next;
			line_w = 0;
			mark = NULL;
			break;
		}

		if (mark && line_w + node->w > top->w)
		{
			flush_line(ctx, box, page_h, top->w, align, indent, line, mark);
			indent = 0;
			node = mark;
			while (node && node->type == FLOW_GLUE)
				node = node->next;
			line = node;
			line_w = 0;
			mark = NULL;
		}

		if (node)
		{
			line_w += node->w;
			node = node->next;
		}
	}

	if (line)
	{
		line_align = align == TA_JUSTIFY ? TA_LEFT : align;
		flush_line(ctx, box, page_h, top->w, line_align, indent, line, NULL);
	}
}

static float layout_block(fz_context *ctx, fz_html *box, fz_html *top, float em, float page_h, float vertical)
{
	fz_html *child;
	int first;

	fz_css_style *style = &box->style;
	float *margin = box->margin;
	float *border = box->border;
	float *padding = box->padding;

	em = box->em = fz_from_css_number(style->font_size, em, em);

	margin[0] = fz_from_css_number(style->margin[0], em, top->w);
	margin[1] = fz_from_css_number(style->margin[1], em, top->w);
	margin[2] = fz_from_css_number(style->margin[2], em, top->w);
	margin[3] = fz_from_css_number(style->margin[3], em, top->w);

	padding[0] = fz_from_css_number(style->padding[0], em, top->w);
	padding[1] = fz_from_css_number(style->padding[1], em, top->w);
	padding[2] = fz_from_css_number(style->padding[2], em, top->w);
	padding[3] = fz_from_css_number(style->padding[3], em, top->w);

	border[0] = style->border_style[0] ? fz_from_css_number(style->border_width[0], em, top->w) : 0;
	border[1] = style->border_style[1] ? fz_from_css_number(style->border_width[1], em, top->w) : 0;
	border[2] = style->border_style[2] ? fz_from_css_number(style->border_width[2], em, top->w) : 0;
	border[3] = style->border_style[3] ? fz_from_css_number(style->border_width[3], em, top->w) : 0;

	box->x = top->x + margin[L] + border[L] + padding[L];
	box->w = top->w - (margin[L] + margin[R] + border[L] + border[R] + padding[L] + padding[R]);

	if (margin[T] > vertical)
		margin[T] -= vertical;
	else
		margin[T] = 0;

	if (padding[T] == 0 && border[T] == 0)
		vertical += margin[T];
	else
		vertical = 0;

	box->y = top->y + top->h + margin[T] + border[T] + padding[T];
	box->h = 0;

	first = 1;
	for (child = box->down; child; child = child->next)
	{
		if (child->type == BOX_BLOCK)
		{
			vertical = layout_block(ctx, child, box, em, page_h, vertical);
			if (first)
			{
				/* move collapsed parent/child top margins to parent */
				margin[T] += child->margin[T];
				box->y += child->margin[T];
				child->margin[T] = 0;
				first = 0;
			}
			box->h += child->h +
				child->padding[T] + child->padding[B] +
				child->border[T] + child->border[B] +
				child->margin[T] + child->margin[B];
		}
		else if (child->type == BOX_BREAK)
		{
			box->h += fz_from_css_number_scale(style->line_height, em, em, em);
			vertical = 0;
			first = 0;
		}
		else if (child->type == BOX_FLOW)
		{
			layout_flow(ctx, child, box, em, page_h);
			if (child->h > 0)
			{
				box->h += child->h;
				vertical = 0;
				first = 0;
			}
		}
	}

	/* reserve space for the list mark */
	if (box->list_item && box->h == 0)
	{
		box->h += fz_from_css_number_scale(style->line_height, em, em, em);
		vertical = 0;
	}

	if (box->h == 0)
	{
		if (margin[B] > vertical)
			margin[B] -= vertical;
		else
			margin[B] = 0;
	}
	else
	{
		box->h -= vertical;
		vertical = fz_max(margin[B], vertical);
		margin[B] = vertical;
	}

	return vertical;
}

static void draw_flow_box(fz_context *ctx, fz_html *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *ctm)
{
	fz_html_flow *node;
	fz_text *text;
	fz_text *falltext;
	fz_matrix trm;
	const char *s;
	float color[3];
	float x, y;
	int c, g;

	for (node = box->flow_head; node; node = node->next)
	{
		if (node->type == FLOW_IMAGE)
		{
			if (node->y >= page_bot || node->y + node->h <= page_top)
				continue;
		}
		else
		{
			if (node->y > page_bot || node->y < page_top)
				continue;
		}

		if (node->type == FLOW_WORD)
		{
			fz_scale(&trm, node->em, -node->em);

			color[0] = node->style->color.r / 255.0f;
			color[1] = node->style->color.g / 255.0f;
			color[2] = node->style->color.b / 255.0f;

			text = NULL;
			falltext = NULL;

			x = node->x;
			y = node->y;
			s = node->text;
			while (*s)
			{
				s += fz_chartorune(&c, s);
				g = fz_encode_character(ctx, node->style->font, c);
				if (g)
				{
					if (node->style->visibility == V_VISIBLE)
					{
						if (!text)
							text = fz_new_text(ctx, node->style->font, &trm, 0);
						fz_add_text(ctx, text, g, c, x, y);
					}
					x += fz_advance_glyph(ctx, node->style->font, g) * node->em;
				}
				else
				{
					g = fz_encode_character(ctx, node->style->fallback, c);
					if (g)
					{
						if (node->style->visibility == V_VISIBLE)
						{
							if (!falltext)
								falltext = fz_new_text(ctx, node->style->fallback, &trm, 0);
							fz_add_text(ctx, falltext, g, c, x, y);
						}
					}
					x += fz_advance_glyph(ctx, node->style->fallback, g) * node->em;
				}
			}

			if (text)
			{
				fz_fill_text(ctx, dev, text, ctm, fz_device_rgb(ctx), color, 1);
				fz_drop_text(ctx, text);
			}
			if (falltext)
			{
				fz_fill_text(ctx, dev, falltext, ctm, fz_device_rgb(ctx), color, 1);
				fz_drop_text(ctx, falltext);
			}
		}
		else if (node->type == FLOW_IMAGE)
		{
			if (node->style->visibility == V_VISIBLE)
			{
				fz_matrix local_ctm = *ctm;
				fz_pre_translate(&local_ctm, node->x, node->y);
				fz_pre_scale(&local_ctm, node->w, node->h);
				fz_fill_image(ctx, dev, node->image, &local_ctm, 1);
			}
		}
	}
}

static void draw_rect(fz_context *ctx, fz_device *dev, const fz_matrix *ctm, fz_css_color color, float x0, float y0, float x1, float y1)
{
	if (color.a > 0)
	{
		float rgb[3];

		fz_path *path = fz_new_path(ctx);

		fz_moveto(ctx, path, x0, y0);
		fz_lineto(ctx, path, x1, y0);
		fz_lineto(ctx, path, x1, y1);
		fz_lineto(ctx, path, x0, y1);
		fz_closepath(ctx, path);

		rgb[0] = color.r / 255.0f;
		rgb[1] = color.g / 255.0f;
		rgb[2] = color.b / 255.0f;

		fz_fill_path(ctx, dev, path, 0, ctm, fz_device_rgb(ctx), rgb, color.a / 255.0f);

		fz_drop_path(ctx, path);
	}
}

static const char *roman_uc[3][10] = {
	{ "", "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX" },
	{ "", "X", "XX", "XXX", "XL", "L", "LX", "LXX", "LXXX", "XC" },
	{ "", "C", "CC", "CCC", "CD", "D", "DC", "DCC", "DCCC", "CM" },
};

static const char *roman_lc[3][10] = {
	{ "", "i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix" },
	{ "", "x", "xx", "xxx", "xl", "l", "lx", "lxx", "lxxx", "xc" },
	{ "", "c", "cc", "ccc", "cd", "d", "dc", "dcc", "dccc", "cm" },
};

static void format_roman_number(fz_context *ctx, char *buf, int size, int n, const char *sym[3][10], const char *sym_m)
{
	int I = n % 10;
	int X = (n / 10) % 10;
	int C = (n / 100) % 10;
	int M = (n / 1000);

	fz_strlcpy(buf, "", size);
	while (M--)
		fz_strlcat(buf, sym_m, size);
	fz_strlcat(buf, sym[2][C], size);
	fz_strlcat(buf, sym[1][X], size);
	fz_strlcat(buf, sym[0][I], size);
	fz_strlcat(buf, ". ", size);
}

static void format_alpha_number(fz_context *ctx, char *buf, int size, int n, int alpha, int omega)
{
	int base = omega - alpha + 1;
	int tmp[40];
	int i, c;

	if (alpha > 256) /* to skip final-s for greek */
		--base;

	/* Bijective base-26 (base-24 for greek) numeration */
	i = 0;
	while (n > 0)
	{
		--n;
		c = n % base + alpha;
		if (alpha > 256 && c > alpha + 16) /* skip final-s for greek */
			++c;
		tmp[i++] = c;
		n /= base;
	}

	while (i > 0)
		buf += fz_runetochar(buf, tmp[--i]);
	*buf++ = '.';
	*buf++ = ' ';
	*buf = 0;
}

static void format_list_number(fz_context *ctx, int type, int x, char *buf, int size)
{
	switch (type)
	{
	case LST_NONE: fz_strlcpy(buf, "", size); break;
	case LST_DISC: fz_strlcpy(buf, "\342\227\217  ", size); break; /* U+25CF BLACK CIRCLE */
	case LST_CIRCLE: fz_strlcpy(buf, "\342\227\213  ", size); break; /* U+25CB WHITE CIRCLE */
	case LST_SQUARE: fz_strlcpy(buf, "\342\226\240  ", size); break; /* U+25A0 BLACK SQUARE */
	default:
	case LST_DECIMAL: fz_snprintf(buf, size, "%d. ", x); break;
	case LST_DECIMAL_ZERO: fz_snprintf(buf, size, "%02d. ", x); break;
	case LST_LC_ROMAN: format_roman_number(ctx, buf, size, x, roman_lc, "m"); break;
	case LST_UC_ROMAN: format_roman_number(ctx, buf, size, x, roman_uc, "M"); break;
	case LST_LC_ALPHA: format_alpha_number(ctx, buf, size, x, 'a', 'z'); break;
	case LST_UC_ALPHA: format_alpha_number(ctx, buf, size, x, 'A', 'Z'); break;
	case LST_LC_LATIN: format_alpha_number(ctx, buf, size, x, 'a', 'z'); break;
	case LST_UC_LATIN: format_alpha_number(ctx, buf, size, x, 'A', 'Z'); break;
	case LST_LC_GREEK: format_alpha_number(ctx, buf, size, x, 0x03B1, 0x03C9); break;
	case LST_UC_GREEK: format_alpha_number(ctx, buf, size, x, 0x0391, 0x03A9); break;
	}
}

static fz_html_flow *find_list_mark_anchor(fz_context *ctx, fz_html *box)
{
	/* find first flow node in <li> tag */
	while (box)
	{
		if (box->type == BOX_FLOW)
		{
			fz_html_flow *flow = box->flow_head;
			if (flow && flow->type == FLOW_BREAK)
				flow = flow->next;
			while (flow && flow->type == FLOW_GLUE)
				flow = flow->next;
			return flow;
		}
		box = box->down;
	}
	return NULL;
}

static void draw_list_mark(fz_context *ctx, fz_html *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *ctm, int n)
{
	fz_text *text;
	fz_matrix trm;
	fz_html_flow *line;
	float x, y, w;
	float color[3];
	const char *s;
	char buf[40];
	int c, g;

	fz_scale(&trm, box->em, -box->em);
	text = fz_new_text(ctx, box->style.font, &trm, 0);

	line = find_list_mark_anchor(ctx, box);
	if (line)
	{
		y = line->y;
	}
	else
	{
		float h = fz_from_css_number_scale(box->style.line_height, box->em, box->em, box->em);
		float a = box->em * 0.8;
		float d = box->em * 0.2;
		if (a + d > h)
			h = a + d;
		y = box->y + a + (h - a - d) / 2;
	}

	if (y > page_bot || y < page_top)
		return;

	format_list_number(ctx, box->style.list_style_type, n, buf, sizeof buf);

	s = buf;
	w = 0;
	while (*s)
	{
		s += fz_chartorune(&c, s);
		g = fz_encode_character(ctx, box->style.font, c);
		w += fz_advance_glyph(ctx, box->style.font, g) * box->em;
	}

	s = buf;
	x = box->x - w;
	while (*s)
	{
		s += fz_chartorune(&c, s);
		g = fz_encode_character(ctx, box->style.font, c);
		fz_add_text(ctx, text, g, c, x, y);
		x += fz_advance_glyph(ctx, box->style.font, g) * box->em;
	}

	color[0] = box->style.color.r / 255.0f;
	color[1] = box->style.color.g / 255.0f;
	color[2] = box->style.color.b / 255.0f;

	fz_fill_text(ctx, dev, text, ctm, fz_device_rgb(ctx), color, 1);

	fz_drop_text(ctx, text);
}

static void draw_block_box(fz_context *ctx, fz_html *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *ctm)
{
	float x0, y0, x1, y1;

	float *border = box->border;
	float *padding = box->padding;

	x0 = box->x - padding[L];
	y0 = box->y - padding[T];
	x1 = box->x + box->w + padding[R];
	y1 = box->y + box->h + padding[B];

	if (y0 > page_bot || y1 < page_top)
		return;

	if (box->style.visibility == V_VISIBLE)
	{
		draw_rect(ctx, dev, ctm, box->style.background_color, x0, y0, x1, y1);

		if (border[T] > 0)
			draw_rect(ctx, dev, ctm, box->style.border_color[T], x0 - border[L], y0 - border[T], x1 + border[R], y0);
		if (border[B] > 0)
			draw_rect(ctx, dev, ctm, box->style.border_color[B], x0 - border[L], y1, x1 + border[R], y1 + border[B]);
		if (border[L] > 0)
			draw_rect(ctx, dev, ctm, box->style.border_color[L], x0 - border[L], y0 - border[T], x0, y1 + border[B]);
		if (border[R] > 0)
			draw_rect(ctx, dev, ctm, box->style.border_color[R], x1, y0 - border[T], x1 + border[R], y1 + border[B]);

		if (box->list_item)
			draw_list_mark(ctx, box, page_top, page_bot, dev, ctm, box->list_item);
	}

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
fz_draw_html(fz_context *ctx, fz_html *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *inctm)
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

static fz_css_rule *
html_load_css(fz_context *ctx, fz_archive *zip, const char *base_uri, fz_css_rule *css, fz_xml *root)
{
	fz_xml *node;
	fz_buffer *buf;
	char path[2048];

	fz_var(buf);

	for (node = root; node; node = fz_xml_next(node))
	{
		const char *tag = fz_xml_tag(node);
		if (tag && !strcmp(tag, "link"))
		{
			char *rel = fz_xml_att(node, "rel");
			if (rel && !fz_strcasecmp(rel, "stylesheet"))
			{
				char *type = fz_xml_att(node, "type");
				if ((type && !strcmp(type, "text/css")) || !type)
				{
					char *href = fz_xml_att(node, "href");
					if (href)
					{
						fz_strlcpy(path, base_uri, sizeof path);
						fz_strlcat(path, "/", sizeof path);
						fz_strlcat(path, href, sizeof path);
						fz_urldecode(path);
						fz_cleanname(path);

						buf = NULL;
						fz_try(ctx)
						{
							buf = fz_read_archive_entry(ctx, zip, path);
							fz_write_buffer_byte(ctx, buf, 0);
							css = fz_parse_css(ctx, css, (char*)buf->data, path);
						}
						fz_always(ctx)
							fz_drop_buffer(ctx, buf);
						fz_catch(ctx)
							fz_warn(ctx, "ignoring stylesheet %s", path);
					}
				}
			}
		}
		if (tag && !strcmp(tag, "style"))
		{
			char *s = concat_text(ctx, node);
			fz_try(ctx)
				css = fz_parse_css(ctx, css, s, "<style>");
			fz_catch(ctx)
				fz_warn(ctx, "ignoring inline stylesheet");
			fz_free(ctx, s);
		}
		if (fz_xml_down(node))
			css = html_load_css(ctx, zip, base_uri, css, fz_xml_down(node));
	}
	return css;
}

static void indent(int n)
{
	while (n-- > 0)
		putchar('\t');
}

void
fz_print_css_style(fz_context *ctx, fz_css_style *style, int boxtype, int n)
{
	indent(n); printf("font_size %g%c\n", style->font_size.value, style->font_size.unit);
	indent(n); printf("font %s\n", style->font ? style->font->name : "NULL");
	indent(n); printf("width = %g%c;\n", style->width.value, style->width.unit);
	indent(n); printf("height = %g%c;\n", style->height.value, style->height.unit);
	if (boxtype == BOX_BLOCK)
	{
		indent(n); printf("margin %g%c ", style->margin[0].value, style->margin[0].unit);
		printf("%g%c ", style->margin[1].value, style->margin[1].unit);
		printf("%g%c ", style->margin[2].value, style->margin[2].unit);
		printf("%g%c\n", style->margin[3].value, style->margin[3].unit);
		indent(n); printf("padding %g%c ", style->padding[0].value, style->padding[0].unit);
		printf("%g%c ", style->padding[1].value, style->padding[1].unit);
		printf("%g%c ", style->padding[2].value, style->padding[2].unit);
		printf("%g%c\n", style->padding[3].value, style->padding[3].unit);
		indent(n); printf("border_width %g%c ", style->border_width[0].value, style->border_width[0].unit);
		printf("%g%c ", style->border_width[1].value, style->border_width[1].unit);
		printf("%g%c ", style->border_width[2].value, style->border_width[2].unit);
		printf("%g%c\n", style->border_width[3].value, style->border_width[3].unit);
		indent(n); printf("border_style %d %d %d %d\n",
				style->border_style[0], style->border_style[1],
				style->border_style[2], style->border_style[3]);
		indent(n); printf("text_indent %g%c\n", style->text_indent.value, style->text_indent.unit);
		indent(n); printf("white_space %d\n", style->white_space);
		indent(n); printf("text_align %d\n", style->text_align);
		indent(n); printf("list_style_type %d\n", style->list_style_type);
	}
	indent(n); printf("line_height %g%c\n", style->line_height.value, style->line_height.unit);
	indent(n); printf("vertical_align %d\n", style->vertical_align);
}

void
fz_print_html_flow(fz_context *ctx, fz_html_flow *flow)
{
	while (flow)
	{
		switch (flow->type)
		{
		case FLOW_WORD: printf("%s", flow->text); break;
		case FLOW_GLUE: printf(" "); break;
		case FLOW_BREAK: printf("\\n"); break;
		case FLOW_IMAGE: printf("[image]"); break;
		}
		flow = flow->next;
	}
}

void
fz_print_html(fz_context *ctx, fz_html *box, int pstyle, int level)
{
	while (box)
	{
		indent(level);
		switch (box->type)
		{
		case BOX_BLOCK: printf("block"); break;
		case BOX_BREAK: printf("break"); break;
		case BOX_FLOW: printf("flow"); break;
		case BOX_INLINE: printf("inline"); break;
		}

		if (box->down || box->flow_head)
			printf(" {\n");
		else
			printf("\n");

		if (pstyle && !box->flow_head)
			fz_print_css_style(ctx, &box->style, box->type, level+1);

		fz_print_html(ctx, box->down, pstyle, level+1);

		if (box->flow_head)
		{
			indent(level+1);
			printf("\"");
			fz_print_html_flow(ctx, box->flow_head);
			printf("\"\n");
		}

		if (box->down || box->flow_head)
		{
			indent(level);
			printf("}\n");
		}

		box = box->next;
	}
}

void
fz_layout_html(fz_context *ctx, fz_html *box, float w, float h, float em)
{
	fz_html page_box;

	init_box(ctx, &page_box);
	page_box.w = w;
	page_box.h = 0;

	layout_block(ctx, box, &page_box, em, h, 0);
}

fz_html *
fz_parse_html(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_buffer *buf, const char *user_css)
{
	fz_xml *xml;
	fz_css_rule *css;
	fz_css_match match;
	fz_html *box;

	xml = fz_parse_xml(ctx, buf->data, buf->len, 1);

	css = fz_parse_css(ctx, NULL, default_css, "<default>");
	css = html_load_css(ctx, zip, base_uri, css, xml);
	if (user_css)
		css = fz_parse_css(ctx, css, user_css, "<user>");

	// print_rules(css);

	box = new_box(ctx);

	match.up = NULL;
	match.count = 0;
	fz_match_css_at_page(ctx, &match, css);
	fz_apply_css_style(ctx, set, &box->style, &match);

	generate_boxes(ctx, set, zip, base_uri, xml, box, css, &match, 0);

	fz_drop_css(ctx, css);
	fz_drop_xml(ctx, xml);

	return box;
}
