#include "mupdf/html.h"

#include "hb.h"
#include "hb-ft.h"
#include <ft2build.h>

#undef DEBUG_HARFBUZZ

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

static int is_all_white(const char *s)
{
	while (*s)
	{
		if (!iswhite(*s))
			return 0;
		++s;
	}
	return 1;
}

/* TODO: pool allocator for flow nodes */
/* TODO: store text by pointing to a giant buffer */

static void fz_drop_html_flow(fz_context *ctx, fz_html_flow *flow)
{
	while (flow)
	{
		fz_html_flow *next = flow->next;
		if (flow->type == FLOW_IMAGE)
			fz_drop_image(ctx, flow->content.image);
		flow = next;
	}
}

static fz_html_flow *add_flow(fz_context *ctx, fz_pool *pool, fz_html *top, fz_css_style *style, int type)
{
	fz_html_flow *flow = fz_pool_alloc(ctx, pool, sizeof *flow);
	flow->type = type;
	flow->expand = 0;
	flow->char_r2l = BIDI_LEFT_TO_RIGHT;
	flow->block_r2l = BIDI_LEFT_TO_RIGHT;
	flow->markup_r2l = BIDI_NEUTRAL;
	flow->breaks_line = 0;
	flow->style = style;
	*top->flow_tail = flow;
	top->flow_tail = &flow->next;
	return flow;
}

static void add_flow_space(fz_context *ctx, fz_pool *pool, fz_html *top, fz_css_style *style)
{
	fz_html_flow *flow = add_flow(ctx, pool, top, style, FLOW_SPACE);
	flow->expand = 1;
}

static void add_flow_break(fz_context *ctx, fz_pool *pool, fz_html *top, fz_css_style *style)
{
	(void)add_flow(ctx, pool, top, style, FLOW_BREAK);
}

static void add_flow_sbreak(fz_context *ctx, fz_pool *pool, fz_html *top, fz_css_style *style)
{
	(void)add_flow(ctx, pool, top, style, FLOW_SBREAK);
}

static void add_flow_shyphen(fz_context *ctx, fz_pool *pool, fz_html *top, fz_css_style *style)
{
	(void)add_flow(ctx, pool, top, style, FLOW_SHYPHEN);
}

static void add_flow_word(fz_context *ctx, fz_pool *pool, fz_html *top, fz_css_style *style, const char *a, const char *b)
{
	fz_html_flow *flow = add_flow(ctx, pool, top, style, FLOW_WORD);
	flow->content.text = fz_pool_alloc(ctx, pool, b - a + 1);
	memcpy(flow->content.text, a, b - a);
	flow->content.text[b - a] = 0;
}

static void add_flow_image(fz_context *ctx, fz_pool *pool, fz_html *top, fz_css_style *style, fz_image *img)
{
	fz_html_flow *flow = add_flow(ctx, pool, top, style, FLOW_IMAGE);
	flow->content.image = fz_keep_image(ctx, img);
}

static fz_html_flow *split_flow(fz_context *ctx, fz_pool *pool, fz_html_flow *flow, size_t offset)
{
	fz_html_flow *new_flow;
	char *text;
	size_t len;

	if (offset == 0)
		return flow;
	new_flow = fz_pool_alloc(ctx, pool, sizeof *flow);
	*new_flow = *flow;
	new_flow->next = flow->next;
	flow->next = new_flow;

	text = flow->content.text;
	while (*text && offset)
	{
		int rune;
		text += fz_chartorune(&rune, text);
		offset--;
	}
	len = strlen(text);
	new_flow->content.text = fz_pool_alloc(ctx, pool, len+1);
	strcpy(new_flow->content.text, text);
	*text = 0;
	return new_flow;
}

static int iscjk(int c)
{
	if (c >= 0x3000 && c <= 0x303F) return 1; /* CJK Symbols and Punctuation */
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
	if (c == ',' || c == 0xFF0C || c == 0x3001) return 1;
	if (c == '.' || c == 0xFF0E || c == 0x3002) return 1;
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

static void flush_space(fz_context *ctx, fz_pool *pool, fz_html *flow, fz_css_style *style, int *emit_white, int *at_bol)
{
	static const char *space = " ";
	int bsp = style->white_space & WS_ALLOW_BREAK_SPACE;
	if (*emit_white)
	{
		if (!*at_bol)
		{
			if (bsp)
				add_flow_space(ctx, pool, flow, style);
			else
				add_flow_word(ctx, pool, flow, style, space, space+1);
		}
		*emit_white = 0;
	}
}

static void generate_text(fz_context *ctx, fz_pool *pool, fz_html *box, const char *text, int *emit_white, int *at_bol)
{
	fz_html *flow;

	int collapse = box->style.white_space & WS_COLLAPSE;
	int bsp = box->style.white_space & WS_ALLOW_BREAK_SPACE;
	int bnl = box->style.white_space & WS_FORCE_BREAK_NEWLINE;

	static const char *space = " ";

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
			add_flow_break(ctx, pool, flow, &box->style);
			*at_bol = 1;
		}
		else if (iswhite(*text))
		{
			if (collapse)
			{
				if (bnl)
					while (*text == ' ' || *text == '\t')
						++text;
				else
					while (iswhite(*text))
						++text;
				*emit_white = 1;
			}
			else
			{
				// TODO: tabs
				if (bsp)
					add_flow_space(ctx, pool, flow, &box->style);
				else
					add_flow_word(ctx, pool, flow, &box->style, space, space+1);
				++text;
			}
		}
		else
		{
			const char *prev, *mark = text;
			int c, addsbreak = 0;

			flush_space(ctx, pool, flow, &box->style, emit_white, at_bol);

			while (*text && !iswhite(*text))
			{
				/* TODO: Unicode Line Breaking Algorithm (UAX #14) */
				prev = text;
				text += fz_chartorune(&c, text);
				if (c == 0xAD) /* soft hyphen */
				{
					if (mark != prev)
						add_flow_word(ctx, pool, flow, &box->style, mark, prev);
					add_flow_shyphen(ctx, pool, flow, &box->style);
					mark = text;
				}
				else if (iscjk(c))
				{
					int cat = ucdn_get_general_category(c);
					if (addsbreak && !not_at_bol(cat, c))
						add_flow_sbreak(ctx, pool, flow, &box->style);
					add_flow_word(ctx, pool, flow, &box->style, mark, text);
					if (!not_at_eol(cat, c))
						addsbreak = 1;
					mark = text;
				}
				else
				{
					addsbreak = 0;
				}
			}
			if (mark != text)
				add_flow_word(ctx, pool, flow, &box->style, mark, text);

			*at_bol = 0;
		}
	}
}

static void generate_image(fz_context *ctx, fz_pool *pool, fz_archive *zip, const char *base_uri, fz_html *box, const char *src, int *emit_white, int *at_bol)
{
	fz_image *img = NULL;
	fz_buffer *buf = NULL;
	char path[2048];

	fz_html *flow = box;
	while (flow->type != BOX_FLOW)
		flow = flow->up;

	fz_strlcpy(path, base_uri, sizeof path);
	fz_strlcat(path, "/", sizeof path);
	fz_strlcat(path, src, sizeof path);
	fz_urldecode(path);
	fz_cleanname(path);

	fz_var(buf);
	fz_var(img);

	flush_space(ctx, pool, flow, &box->style, emit_white, at_bol);

	fz_try(ctx)
	{
		buf = fz_read_archive_entry(ctx, zip, path);
		img = fz_new_image_from_buffer(ctx, buf);
		add_flow_sbreak(ctx, pool, flow, &box->style);
		add_flow_image(ctx, pool, flow, &box->style, img);
		add_flow_sbreak(ctx, pool, flow, &box->style);
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, buf);
		fz_drop_image(ctx, img);
	}
	fz_catch(ctx)
	{
		const char *alt = "[image]";
		fz_warn(ctx, "html: cannot add image src='%s'", src);
		add_flow_word(ctx, pool, flow, &box->style, alt, alt + 7);
	}

	*at_bol = 0;
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
	box->flow_dir = BIDI_NEUTRAL;

	fz_default_css_style(ctx, &box->style);
}

static void fz_drop_html_box(fz_context *ctx, fz_html *box)
{
	while (box)
	{
		fz_html *next = box->next;
		fz_drop_html_flow(ctx, box->flow_head);
		fz_drop_html_box(ctx, box->down);
		box = next;
	}
}

void fz_drop_html(fz_context *ctx, fz_html *box)
{
	fz_drop_html_box(ctx, box);
	fz_drop_pool(ctx, box->pool);
}

static fz_html *new_box(fz_context *ctx, fz_pool *pool)
{
	fz_html *box = fz_pool_alloc(ctx, pool, sizeof *box);
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

static void insert_inline_box(fz_context *ctx, fz_pool *pool, fz_html *box, fz_html *top, int *at_bol)
{
	if (top->type == BOX_BLOCK)
	{
		if (top->last && top->last->type == BOX_FLOW)
		{
			insert_box(ctx, box, BOX_INLINE, top->last);
		}
		else
		{
			fz_html *flow = new_box(ctx, pool);
			flow->is_first_flow = !top->last;
			insert_box(ctx, flow, BOX_FLOW, top);
			insert_box(ctx, box, BOX_INLINE, flow);
			*at_bol = 1;
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

static void generate_boxes(fz_context *ctx, fz_pool *pool,
	fz_html_font_set *set, fz_archive *zip, const char *base_uri,
	fz_xml *node, fz_html *top, fz_css_rule *rule, fz_css_match *up_match, int list_counter,
	int *emit_white, int *at_bol)
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
					add_flow_break(ctx, pool, flow, &top->style);
				}
				else
				{
					box = new_box(ctx, pool);
					fz_apply_css_style(ctx, set, &box->style, &match);
					top = insert_break_box(ctx, box, top);
				}
				*at_bol = 1;
			}

			else if (!strcmp(tag, "img"))
			{
				const char *src = fz_xml_att(node, "src");
				if (src)
				{
					box = new_box(ctx, pool);
					fz_apply_css_style(ctx, set, &box->style, &match);
					insert_inline_box(ctx, pool, box, top, at_bol);
					generate_image(ctx, pool, zip, base_uri, box, src, emit_white, at_bol);
				}
			}

			else if (display != DIS_NONE)
			{
				box = new_box(ctx, pool);
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
					insert_inline_box(ctx, pool, box, top, at_bol);
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
					generate_boxes(ctx, pool, set, zip, base_uri, fz_xml_down(node), box, rule, &match, child_counter, emit_white, at_bol);
				}
			}
		}
		else
		{
			const char *text = fz_xml_text(node);
			int collapse = top->style.white_space & WS_COLLAPSE;
			if (collapse && is_all_white(text))
			{
				*emit_white = 1;
			}
			else
			{
				if (top->type != BOX_INLINE)
				{
					/* Create anonymous inline box, with the same style as the top block box. */
					box = new_box(ctx, pool);
					insert_inline_box(ctx, pool, box, top, at_bol);
					box->style = top->style;
					/* Make sure not to recursively multiply font sizes. */
					box->style.font_size.value = 1;
					box->style.font_size.unit = N_SCALE;
					generate_text(ctx, pool, box, text, emit_white, at_bol);
				}
				else
				{
					generate_text(ctx, pool, top, text, emit_white, at_bol);
				}
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
	if (node->content.image->w > max_w)
		xs = max_w / node->content.image->w;
	if (node->content.image->h > max_h)
		ys = max_h / node->content.image->h;
	s = fz_min(xs, ys);
	node->w = node->content.image->w * s;
	node->h = node->content.image->h * s;
}

typedef struct string_walker
{
	fz_context *ctx;
	hb_buffer_t *hb_buf;
	int r2l;
	const char *start;
	const char *end;
	const char *s;
	fz_font *base_font;
	int script;
	fz_font *font;
	fz_font *next_font;
	hb_glyph_position_t *glyph_pos;
	unsigned int glyph_count;
	int scale;
} string_walker;

static void init_string_walker(fz_context *ctx, string_walker *walker, hb_buffer_t *hb_buf, int r2l, fz_font *font, int script, const char *text)
{
	walker->ctx = ctx;
	walker->hb_buf = hb_buf;
	walker->r2l = r2l;
	walker->start = text;
	walker->end = text;
	walker->s = text;
	walker->base_font = font;
	walker->script = script;
	walker->font = NULL;
	walker->next_font = NULL;
}

static int walk_string(string_walker *walker)
{
	fz_context *ctx = walker->ctx;
	FT_Face face;
	int fterr;

	walker->start = walker->end;
	walker->end = walker->s;
	walker->font = walker->next_font;

	if (*walker->start == 0)
		return 0;

	/* Run through the string, encoding chars until we find one
	 * that requires a different fallback font. */
	while (*walker->s)
	{
		int c;

		walker->s += fz_chartorune(&c, walker->s);
		(void)fz_encode_character_with_fallback(ctx, walker->base_font, c, walker->script, &walker->next_font);
		if (walker->next_font != walker->font)
		{
			if (walker->font != NULL)
				break;
			walker->font = walker->next_font;
		}
		walker->end = walker->s;
	}

	fz_try(ctx)
	{
		hb_lock(ctx);

		/* So, shape from start to end in font */
		face = walker->font->ft_face;
		walker->scale = face->units_per_EM;
		fterr = FT_Set_Char_Size(face, walker->scale, walker->scale, 72, 72);
		if (fterr)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failure sizing font (%d)", fterr);

		if (walker->font->shaper == NULL)
			walker->font->shaper = (void *)hb_ft_font_create(face, NULL);

		hb_buffer_clear_contents(walker->hb_buf);
		hb_buffer_set_direction(walker->hb_buf, walker->r2l ? HB_DIRECTION_RTL : HB_DIRECTION_LTR);
		/* We don't know script or language, so leave them blank */
		/* hb_buffer_set_script(hb_buf, HB_SCRIPT_LATIN); */
		/* hb_buffer_set_language(hb_buf, hb_language_from_string("en", strlen("en"))); */

		/* First put the text content into a harfbuzz buffer
		 * labelled with the position within the word. */
		hb_buffer_add_utf8(walker->hb_buf, walker->start, walker->end - walker->start, 0, -1);
		hb_buffer_guess_segment_properties(walker->hb_buf);

		/* Now shape that buffer */
		hb_shape(walker->font->shaper, walker->hb_buf, NULL, 0);

		walker->glyph_pos = hb_buffer_get_glyph_positions(walker->hb_buf, &walker->glyph_count);
	}
	fz_always(ctx)
	{
		hb_unlock(ctx);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return 1;
}

static char *get_node_text(fz_context *ctx, fz_html_flow *node)
{
	if (node->type == FLOW_WORD)
		return node->content.text;
	else if (node->type == FLOW_SPACE)
		return " ";
	else if (node->type == FLOW_SHYPHEN)
		return "-";
	else
		return "";
}

static void measure_string(fz_context *ctx, fz_html_flow *node, float em, hb_buffer_t *hb_buf)
{
	unsigned int i;
	int max_x, x;
	string_walker walker;
	char *s;

	em = fz_from_css_number(node->style->font_size, em, em);
	node->x = 0;
	node->y = 0;
	node->w = 0;
	node->h = fz_from_css_number_scale(node->style->line_height, em, em, em);

	s = get_node_text(ctx, node);
	init_string_walker(ctx, &walker, hb_buf, node->char_r2l, node->style->font, node->script, s);
	while (walk_string(&walker))
	{
		max_x = 0;
		x = 0;
		for (i = 0; i < walker.glyph_count; i++)
		{
			int lx;

			x += walker.glyph_pos[i].x_advance;
			lx = x + walker.glyph_pos[i].x_offset;
			if (lx > max_x)
				max_x = lx;
		}

		node->w += max_x * em / walker.scale;
	}

	node->em = em;
}

static float measure_line(fz_html_flow *node, fz_html_flow *end, float *baseline)
{
	float max_a = 0, max_d = 0, h = node->h;
	while (node != end)
	{
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

static void layout_line(fz_context *ctx, float indent, float page_w, float line_w, int align, fz_html_flow *start, fz_html_flow *end, fz_html *box, float baseline, float line_h)
{
	float x = box->x + indent;
	float y = box->y + box->h;
	float slop = page_w - line_w;
	float justify = 0;
	float va;
	int n = 0;
	fz_html_flow *node = start;
	fz_html_flow *mid;

	if (align == TA_JUSTIFY)
	{
		fz_html_flow *it;
		for (it = node; it != end; it = it->next)
			if (it->type == FLOW_SPACE && it->expand && !it->breaks_line)
				++n;
		justify = slop / n;
	}
	else if (align == TA_RIGHT)
		x += slop;
	else if (align == TA_CENTER)
		x += slop / 2;

	/* The line data as supplied is start...end. */
	/* We have the invariants that 1) start...mid are always laid out
	 * correctly and 2) mid..node are the most recent set of right to left
	 * blocks. */
	mid = start;
	while (node != end)
	{
		float w = node->w;

		if (node->type == FLOW_SPACE && node->breaks_line)
			w = 0;
		else if (node->type == FLOW_SPACE && !node->breaks_line)
			w += node->expand ? justify : 0;
		else if (node->type == FLOW_SHYPHEN && !node->breaks_line)
			w = 0;
		else if (node->type == FLOW_SHYPHEN && node->breaks_line)
			w = node->w;

		if (node->block_r2l)
		{
			float old_x = x;
			if (mid != node)
			{
				/* We have met a r2l block, and have just had at least
				 * one other r2l block. Move all the r2l blocks that
				 * we've just had further right, and position this one
				 * on the left. */
				fz_html_flow *temp = mid;
				while (temp != node)
				{
					old_x = temp->x;
					temp->x += w;
					temp = temp->next;
				}
			}
			node->x = old_x;
		}
		else
		{
			node->x = x;
			mid = node->next;
		}
		x += w;

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
		case VA_TEXT_TOP:
			va = -baseline + node->h;
			break;
		case VA_TEXT_BOTTOM:
			va = -baseline + line_h;
			break;
		}

		if (node->type == FLOW_IMAGE)
			node->y = y + baseline - node->h;
		else
			node->y = y + baseline + va;
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

static void flush_line(fz_context *ctx, fz_html *box, float page_h, float page_w, float line_w, int align, float indent, fz_html_flow *a, fz_html_flow *b)
{
	float avail, line_h, baseline;
	avail = page_h - fmodf(box->y + box->h, page_h);
	line_h = measure_line(a, b, &baseline);
	if (line_h > avail)
		box->h += avail;
	layout_line(ctx, indent, page_w, line_w, align, a, b, box, baseline, line_h);
	box->h += line_h;
}

static void layout_flow(fz_context *ctx, fz_html *box, fz_html *top, float em, float page_h, hb_buffer_t *hb_buf)
{
	fz_html_flow *node, *line, *candidate;
	float line_w, candidate_w, indent, break_w, nonbreak_w;
	int line_align, align;

	em = fz_from_css_number(box->style.font_size, em, em);
	indent = box->is_first_flow ? fz_from_css_number(top->style.text_indent, em, top->w) : 0;
	align = top->style.text_align;

	if (box->flow_dir == BIDI_RIGHT_TO_LEFT)
	{
		if (align == TA_LEFT)
			align = TA_RIGHT;
		else if (align == TA_RIGHT)
			align = TA_LEFT;
	}

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
			measure_string(ctx, node, em, hb_buf);
		}
	}

	node = box->flow_head;

	candidate = NULL;
	candidate_w = 0;
	line = node;
	line_w = indent;

	while (node)
	{
		switch (node->type)
		{
		default:
		case FLOW_WORD:
		case FLOW_IMAGE:
			nonbreak_w = break_w = node->w;
			break;

		case FLOW_SHYPHEN:
		case FLOW_SBREAK:
		case FLOW_SPACE:
			nonbreak_w = break_w = 0;

			/* Determine broken and unbroken widths of this node. */
			if (node->type == FLOW_SPACE)
				nonbreak_w = node->w;
			else if (node->type == FLOW_SHYPHEN)
				break_w = node->w;

			/* If the broken node fits, remember it. */
			/* Also remember it if we have no other candidate and need to break in desperation. */
			if (line_w + break_w <= box->w || !candidate) {
				candidate = node;
				candidate_w = line_w + break_w;
			}
			break;

		case FLOW_BREAK:
			nonbreak_w = break_w = 0;
			candidate = node;
			candidate_w = line_w;
			break;
		}

		/* The current node either does not fit or we saw a hard break. */
		/* Break the line if we have a candidate break point. */
		if (node->type == FLOW_BREAK || (line_w + nonbreak_w > box->w && candidate))
		{
			candidate->breaks_line = 1;
			if (candidate->type == FLOW_BREAK)
				line_align = (align == TA_JUSTIFY) ? TA_LEFT : align;
			else
				line_align = align;
			flush_line(ctx, box, page_h, box->w, candidate_w, line_align, indent, line, candidate->next);

			line = candidate->next;
			node = candidate->next;
			candidate = NULL;
			candidate_w = 0;
			indent = 0;
			line_w = 0;
		}
		else
		{
			line_w += nonbreak_w;
			node = node->next;
		}
	}

	if (line)
	{
		line_align = (align == TA_JUSTIFY) ? TA_LEFT : align;
		flush_line(ctx, box, page_h, box->w, line_w, line_align, indent, line, NULL);
	}
}

static float layout_block(fz_context *ctx, fz_html *box, fz_html *top, float em, float page_h, float vertical, hb_buffer_t *hb_buf)
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
			vertical = layout_block(ctx, child, box, em, page_h, vertical, hb_buf);
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
			layout_flow(ctx, child, box, em, page_h, hb_buf);
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

static void draw_flow_box(fz_context *ctx, fz_html *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *ctm, hb_buffer_t *hb_buf)
{
	fz_html_flow *node;
	fz_text *text;
	fz_matrix trm;
	float color[3];
	int c;
	float node_scale;
	float w, lx, ly;

	/* FIXME: HB_DIRECTION_TTB? */

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

		if (node->type == FLOW_WORD || node->type == FLOW_SPACE || node->type == FLOW_SHYPHEN)
		{
			int idx;
			unsigned int gp;
			hb_glyph_info_t *glyph_info;
			float x, y;
			string_walker walker;
			char *s;

			if (node->type == FLOW_WORD && node->content.text == NULL)
				continue;
			if (node->type == FLOW_SPACE && node->breaks_line)
				continue;
			if (node->type == FLOW_SHYPHEN && !node->breaks_line)
				continue;

			fz_scale(&trm, node->em, -node->em);

			color[0] = node->style->color.r / 255.0f;
			color[1] = node->style->color.g / 255.0f;
			color[2] = node->style->color.b / 255.0f;

			/* TODO: reuse text object if color is unchanged */
			text = fz_new_text(ctx);

			x = node->x;
			y = node->y;
			w = node->w;

			s = get_node_text(ctx, node);
			init_string_walker(ctx, &walker, hb_buf, node->char_r2l, node->style->font, node->script, s);
			while (walk_string(&walker))
			{
				const char *t;
#ifdef DEBUG_HARFBUZZ
				int c;

				printf("fragment: ");
				t = walker.start;
				while (t != walker.end)
				{
					t += fz_chartorune(&c, t);
					if (c >= 127)
						printf("<%x>", c);
					else
						printf("%c", c);
				}
				printf("\n");
#endif /* DEBUG_HARFBUZZ */
				glyph_info = hb_buffer_get_glyph_infos(hb_buf, &walker.glyph_count);

				/* Now offset the glyph_info with the correct positions.
				 * Harfbuzz always gives us the shaped glyphs for plotting in l2r
				 * order. We however still want to send glyphs r2l rather than l2r
				 * for r2l blocks so that text extraction works. So, regardless
				 * of ordering we resolve the positions here. The nasty thing is
				 * that we right the resolved positions back into the Harfbuzz
				 * buffer with a change of type. */
				node_scale = node->em / walker.scale;

				lx = 0;
				ly = 0;
				for (gp = 0; gp < walker.glyph_count; gp++)
				{
					hb_glyph_position_t *p = &walker.glyph_pos[gp];
#ifdef DEBUG_HARFBUZZ
					hb_glyph_info_t *g = &walker.glyph_info[gp];

					printf("glyph: %x(%d) @ %d %d + %d %d",
						g->codepoint, g->cluster, p->x_offset, p->y_offset,
						p->x_advance, p->y_advance);
#endif /* DEBUG_HARFBUZZ */
					*(float *)(&p->x_offset) = x + (lx + p->x_offset) * node_scale;
					*(float *)(&p->y_offset) = y + (ly + p->y_offset) * node_scale;
#ifdef DEBUG_HARFBUZZ
					printf(" => %g %g\n", *(float *)(&p->x_offset), *(float *)(&p->y_offset));
#endif /* DEBUG_HARFBUZZ */
					lx += p->x_advance;
					ly += p->y_advance;
				}

				if (node->char_r2l)
				{
					w -= lx * node_scale;
					for (gp = 0; gp < walker.glyph_count; gp++)
					{
						hb_glyph_position_t *p = &walker.glyph_pos[gp];
						*(float *)(&p->x_offset) += w;
					}
				}
				else
				{
					x += node_scale * lx;
					y += node_scale * ly;
				}

				/* Now read the data back out again, and turn it into
				 * glyph/ucs pairs to go to fz_text */
				idx = 0;
				t = walker.start;
				if (node->style->visibility == V_VISIBLE)
				{
					while (*t)
					{
						int l = fz_chartorune(&c, t);
						t += l;

						for (gp = 0; gp < walker.glyph_count; gp++)
						{
							hb_glyph_info_t *g = &glyph_info[gp];
							hb_glyph_position_t *p = &walker.glyph_pos[gp];
							if (g->cluster != idx)
								continue;
							trm.e = *(float *)&p->x_offset;
							trm.f = *(float *)&p->y_offset;
							fz_show_glyph(ctx, text, walker.font, &trm, g->codepoint, c, 0);
							break;
						}
						if (gp == walker.glyph_count)
						{
							/* We failed to find a glyph for this codepoint, presumably
							 * because we've been shaped away into another. We can't afford
							 * to just drop the codepoint as this will upset text extraction.
							 */
							fz_show_glyph(ctx, text, walker.font, &trm, -1, c, 0);
						}
						else
						{
							/* We've send the codepoint and glyph. Make sure there aren't
							 * more glyphs to come from the same codepoint. */
							for (gp++ ;gp < walker.glyph_count; gp++)
							{
								hb_glyph_info_t *g = &glyph_info[gp];
								hb_glyph_position_t *p = &walker.glyph_pos[gp];
								if (g->cluster != idx)
									continue;
								trm.e = *(float *)&p->x_offset;
								trm.f = *(float *)&p->y_offset;
								fz_show_glyph(ctx, text, walker.font, &trm, g->codepoint, -1, 0);
							}
						}
						idx += l;
					}
				}
			}
			fz_fill_text(ctx, dev, text, ctm, fz_device_rgb(ctx), color, 1);
			fz_drop_text(ctx, text);
		}
		else if (node->type == FLOW_IMAGE)
		{
			if (node->style->visibility == V_VISIBLE)
			{
				fz_matrix local_ctm = *ctm;
				fz_pre_translate(&local_ctm, node->x, node->y);
				fz_pre_scale(&local_ctm, node->w, node->h);
				fz_fill_image(ctx, dev, node->content.image, &local_ctm, 1);
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
			return box->flow_head;
		box = box->down;
	}
	return NULL;
}

static void draw_list_mark(fz_context *ctx, fz_html *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *ctm, int n)
{
	fz_font *font;
	fz_text *text;
	fz_matrix trm;
	fz_html_flow *line;
	float y, w;
	float color[3];
	const char *s;
	char buf[40];
	int c, g;

	fz_scale(&trm, box->em, -box->em);

	text = fz_new_text(ctx);

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
		g = fz_encode_character_with_fallback(ctx, box->style.font, c, UCDN_SCRIPT_LATIN, &font);
		w += fz_advance_glyph(ctx, font, g, 0) * box->em;
	}

	s = buf;
	trm.e = box->x - w;
	trm.f = y;
	while (*s)
	{
		s += fz_chartorune(&c, s);
		g = fz_encode_character_with_fallback(ctx, box->style.font, c, UCDN_SCRIPT_LATIN, &font);
		fz_show_glyph(ctx, text, font, &trm, g, c, 0);
		trm.e += fz_advance_glyph(ctx, font, g, 0) * box->em;
	}

	color[0] = box->style.color.r / 255.0f;
	color[1] = box->style.color.g / 255.0f;
	color[2] = box->style.color.b / 255.0f;

	fz_fill_text(ctx, dev, text, ctm, fz_device_rgb(ctx), color, 1);

	fz_drop_text(ctx, text);
}

static void draw_block_box(fz_context *ctx, fz_html *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *ctm, hb_buffer_t *hb_buf)
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
		case BOX_BLOCK: draw_block_box(ctx, box, page_top, page_bot, dev, ctm, hb_buf); break;
		case BOX_FLOW: draw_flow_box(ctx, box, page_top, page_bot, dev, ctm, hb_buf); break;
		}
	}
}

void
fz_draw_html(fz_context *ctx, fz_html *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *inctm)
{
	fz_matrix ctm = *inctm;
	hb_buffer_t *hb_buf = NULL;
	int unlocked = 0;

	fz_var(hb_buf);
	fz_var(unlocked);

	hb_lock(ctx);

	fz_try(ctx)
	{
		hb_buf = hb_buffer_create();
		hb_unlock(ctx);
		unlocked = 1;
		fz_pre_translate(&ctm, 0, -page_top);
		draw_block_box(ctx, box, page_top, page_bot, dev, &ctm, hb_buf);
	}
	fz_always(ctx)
	{
		if (unlocked)
			hb_lock(ctx);
		hb_buffer_destroy(hb_buf);
		hb_unlock(ctx);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static char *concat_text(fz_context *ctx, fz_xml *root)
{
	fz_xml *node;
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
	fz_xml *html, *head, *node;
	fz_buffer *buf;
	char path[2048];

	fz_var(buf);

	html = fz_xml_find(root, "html");
	head = fz_xml_find_down(html, "head");
	for (node = fz_xml_down(head); node; node = fz_xml_next(node))
	{
		if (fz_xml_is_tag(node, "link"))
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
		else if (fz_xml_is_tag(node, "style"))
		{
			char *s = concat_text(ctx, node);
			fz_try(ctx)
				css = fz_parse_css(ctx, css, s, "<style>");
			fz_catch(ctx)
				fz_warn(ctx, "ignoring inline stylesheet");
			fz_free(ctx, s);
		}
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
fz_print_html_flow(fz_context *ctx, fz_html_flow *flow, fz_html_flow *end)
{
	while (flow != end)
	{
		switch (flow->type)
		{
		case FLOW_WORD: printf("%s", flow->content.text); break;
		case FLOW_SPACE: printf("_"); break;
		case FLOW_SBREAK: printf("%%"); break;
		case FLOW_BREAK: printf("!"); break;
		case FLOW_IMAGE: printf("<img>"); break;
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

		if (box->list_item)
			printf(" list=%d", box->list_item);

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
			fz_print_html_flow(ctx, box->flow_head, NULL);
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
	hb_buffer_t *hb_buf = NULL;
	int unlocked = 0;

	fz_var(hb_buf);
	fz_var(unlocked);

	hb_lock(ctx);

	fz_try(ctx)
	{
		hb_buf = hb_buffer_create();
		unlocked = 1;
		hb_unlock(ctx);
		init_box(ctx, &page_box);
		page_box.w = w;
		page_box.h = 0;

		layout_block(ctx, box, &page_box, em, h, 0, hb_buf);
	}
	fz_always(ctx)
	{
		if (unlocked)
			hb_lock(ctx);
		hb_buffer_destroy(hb_buf);
		hb_unlock(ctx);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

typedef struct
{
	uint32_t *data;
	size_t cap;
	size_t len;
} uni_buf;

typedef struct
{
	fz_context *ctx;
	fz_pool *pool;
	fz_html_flow *flow;
	uni_buf *buffer;
} bidi_data;

static size_t utf8len(const char *text)
{
	size_t len = 0;

	while (*text)
	{
		int rune;
		text += fz_chartorune(&rune, text);
		len++;
	}
	return len;
}

static void newFragCb(const uint32_t *fragment,
			size_t fragment_len,
			int block_r2l,
			int char_r2l,
			int script,
			void *arg)
{
	bidi_data *data = (bidi_data *)arg;
	size_t fragment_offset = fragment - data->buffer->data;

	/* The Picsel code used to (effectively) do:
	 * if (fragment_offset == 0) char_r2l = block_r2l;
	 * but that makes no sense to me. All that could do is stop
	 * a european number being treated as l2r because it was the
	 * first thing on a line. */

	/* We are guaranteed that fragmentOffset will be at the beginning
	 * of flow. */
	while (fragment_len > 0)
	{
		size_t len;

		if (data->flow->type == FLOW_SPACE)
		{
			len = 1;

		}
		else if (data->flow->type == FLOW_BREAK || data->flow->type == FLOW_SBREAK || data->flow->type == FLOW_SHYPHEN)
		{
			len = 0;
		}
		else
		{
			/* Must be text */
			len = utf8len(data->flow->content.text);
			if (len > fragment_len)
			{
				/* We need to split this flow box */
				(void)split_flow(data->ctx, data->pool, data->flow, fragment_len);
				len = utf8len(data->flow->content.text);
			}
		}

		/* This flow box is entirely contained within this fragment. */
		data->flow->block_r2l = block_r2l;
		data->flow->char_r2l = char_r2l;
		data->flow->script = script;
		data->flow = data->flow->next;
		fragment_offset += len;
		fragment_len -= len;
	}
}

static int
dirn_matches(int dirn, int dirn2)
{
	return (dirn == BIDI_NEUTRAL || dirn2 == BIDI_NEUTRAL || dirn == dirn2);
}

static void
detect_flow_directionality(fz_context *ctx, fz_pool *pool, uni_buf *buffer, fz_bidi_direction *baseDir, fz_html_flow *flow)
{
	fz_html_flow *end = flow;
	const char *text;
	bidi_data data;
	fz_bidi_direction dirn;

	while (end)
	{
		dirn = BIDI_NEUTRAL;

		/* Gather the text from the flow up into a single buffer (at
		 * least, as much of it as has the same direction markup). */
		buffer->len = 0;
		while (end && dirn_matches(dirn, end->markup_r2l))
		{
			size_t len;
			int broken = 0;

			dirn = end->markup_r2l;

			switch (end->type)
			{
			case FLOW_WORD:
				len = utf8len(end->content.text);
				text = end->content.text;
				break;
			case FLOW_SPACE:
				len = 1;
				text = " ";
				break;
			case FLOW_SHYPHEN:
			case FLOW_SBREAK:
				len = 0;
				text = "";
				break;
			case FLOW_BREAK:
			case FLOW_IMAGE:
				broken = 1;
				break;
			}

			end = end->next;

			if (broken)
				break;

			/* Make sure the buffer is large enough */
			if (buffer->len + len > buffer->cap)
			{
				size_t newcap = buffer->cap * 2;
				if (newcap == 0)
					newcap = 128; /* Sensible small default */
				buffer->data = fz_resize_array(ctx, buffer->data, newcap, sizeof(uint32_t));
				buffer->cap = newcap;
			}

			/* Expand the utf8 text into Unicode and store it in the buffer */
			while (*text)
			{
				int rune;
				text += fz_chartorune(&rune, text);
				buffer->data[buffer->len++] = rune;
			}
		}

		/* Detect directionality for the buffer */
		data.ctx = ctx;
		data.pool = pool;
		data.flow = flow;
		data.buffer = buffer;
		fz_bidi_fragment_text(ctx, buffer->data, buffer->len, &dirn, &newFragCb, &data, 0 /* Flags */);

		/* Set the default flow of the box to be the first non NEUTRAL thing we find */
		if (*baseDir == BIDI_NEUTRAL)
		{
			*baseDir = dirn;
		}
	}
}

static void
detect_box_directionality(fz_context *ctx, fz_pool *pool, uni_buf *buffer, fz_html *box)
{
	while (box)
	{
		if (box->flow_head)
			detect_flow_directionality(ctx, pool, buffer, &box->flow_dir, box->flow_head);
		detect_box_directionality(ctx, pool, buffer, box->down);
		box = box->next;
	}
}

static void
detect_directionality(fz_context *ctx, fz_pool *pool, fz_html *box)
{
	uni_buf buffer = { NULL };

	fz_try(ctx)
		detect_box_directionality(ctx, pool, &buffer, box);
	fz_always(ctx)
		fz_free(ctx, buffer.data);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

fz_html *
fz_parse_html(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_buffer *buf, const char *user_css)
{
	fz_pool *pool;
	fz_xml *xml;
	fz_css_rule *css;
	fz_css_match match;
	fz_html *box;
	int emit_white = 0;
	int at_bol = 1;

	xml = fz_parse_xml(ctx, buf->data, buf->len, 1);

	css = fz_parse_css(ctx, NULL, default_css, "<default>");
	css = html_load_css(ctx, zip, base_uri, css, xml);
	if (user_css)
		css = fz_parse_css(ctx, css, user_css, "<user>");

	// print_rules(css);

	fz_add_css_font_faces(ctx, set, zip, base_uri, css); /* load @font-face fonts into font set */

	pool = fz_new_pool(ctx);

	box = new_box(ctx, pool);
	box->pool = pool;

	match.up = NULL;
	match.count = 0;
	fz_match_css_at_page(ctx, &match, css);
	fz_apply_css_style(ctx, set, &box->style, &match);

	generate_boxes(ctx, pool, set, zip, base_uri, xml, box, css, &match, 0, &emit_white, &at_bol);

	fz_drop_css(ctx, css);
	fz_drop_xml(ctx, xml);

	detect_directionality(ctx, pool, box);

	return box;
}
