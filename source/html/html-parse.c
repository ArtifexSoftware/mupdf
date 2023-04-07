// Copyright (C) 2004-2023 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 1305 Grant Avenue - Suite 200, Novato,
// CA 94945, U.S.A., +1(415)492-9861, for further information.

#include "mupdf/fitz.h"
#include "mupdf/ucdn.h"
#include "html-imp.h"

#include <string.h>
#include <stdio.h>
#include <assert.h>

enum { T, R, B, L };

#define DEFAULT_DIR FZ_BIDI_LTR

static const char *html_default_css =
"@page{margin:3em 2em}"
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
"table{display:table;border-spacing:2px}"
"tbody{display:table-row-group}"
"td{display:table-cell;padding:1px;background-color:inherit}"
"tfoot{display:table-footer-group}"
"th{display:table-cell;font-weight:bold;padding:1px;text-align:center;background-color:inherit}"
"thead{display:table-header-group}"
"tr{display:table-row}"
"ul{display:block;list-style-type:disc;margin:1em 0;padding:0 0 0 30pt}"
"ul ul{list-style-type:circle}"
"ul ul ul{list-style-type:square}"
"var{font-style:italic}"
"colgroup{display:table-column-group}"
"col{display:table-column}"
"caption{display:block;text-align:center}"
;

static const char *mobi_default_css =
"pagebreak{display:block;page-break-before:always}"
"dl,ol,ul{margin:0}"
"p{margin:0}"
"blockquote{margin:0 40px}"
"center{display:block;text-align:center}"
"big{font-size:1.17em}"
"strike{text-decoration:line-through}"
;

static const char *fb2_default_css =
"@page{margin:3em 2em}"
"FictionBook{display:block;margin:1em}"
"stylesheet,binary{display:none}"
"description>*{display:none}"
"description>title-info{display:block}"
"description>title-info>*{display:none}"
"description>title-info>coverpage{display:block;page-break-before:always;page-break-after:always}"
"body,section,title,subtitle,p,cite,epigraph,text-author,date,poem,stanza,v,empty-line{display:block}"
"image{display:block}"
"p>image{display:inline}"
"table{display:table}"
"tr{display:table-row}"
"th,td{display:table-cell}"
"a{color:#06C;text-decoration:underline}"
"a[type=note]{font-size:small;vertical-align:super}"
"code{white-space:pre;font-family:monospace}"
"emphasis{font-style:italic}"
"strikethrough{text-decoration:line-through}"
"strong{font-weight:bold}"
"sub{font-size:small;vertical-align:sub}"
"sup{font-size:small;vertical-align:super}"
"image{margin:1em 0;text-align:center}"
"cite,poem{margin:1em 2em}"
"subtitle,epigraph,stanza{margin:1em 0}"
"title>p{text-align:center;font-size:x-large}"
"subtitle{text-align:center;font-size:large}"
"p{margin-top:1em;text-align:justify}"
"empty-line{padding-top:1em}"
"p+p{margin-top:0;text-indent:1.5em}"
"empty-line+p{margin-top:0}"
"section>title{page-break-before:always}"
;

struct genstate
{
	fz_pool *pool;
	fz_html_font_set *set;
	fz_archive *zip;
	fz_tree *images;
	fz_xml_doc *xml;
	int is_fb2;
	const char *base_uri;
	fz_css *css;
	int at_bol;
	fz_html_box *emit_white;
	int last_brk_cls;

	int list_counter;
	int section_depth;
	fz_bidi_direction markup_dir;
	fz_text_language markup_lang;
	char *href;

	fz_css_style_splay *styles;
};

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

static fz_html_flow *add_flow(fz_context *ctx, fz_pool *pool, fz_html_box *top, fz_html_box *inline_box, int type, int extras)
{
	size_t size = (type == FLOW_IMAGE ? sizeof(fz_html_flow) : offsetof(fz_html_flow, content) + extras);
	fz_html_flow *flow;

	/* Shouldn't happen, but bug 705324. */
	if (top == NULL || top->type != BOX_FLOW)
		return NULL;

	flow = fz_pool_alloc(ctx, pool, size);
	flow->type = type;
	flow->expand = 0;
	flow->bidi_level = 0;
	flow->markup_lang = 0;
	flow->breaks_line = 0;
	flow->box = inline_box;
	(*top->s.build.flow_tail) = flow;
	top->s.build.flow_tail = &flow->next;
	return flow;
}

static void add_flow_space(fz_context *ctx, fz_pool *pool, fz_html_box *top, fz_html_box *inline_box)
{
	fz_html_flow *flow = add_flow(ctx, pool, top, inline_box, FLOW_SPACE, 0);
	if (flow)
		flow->expand = 1;
}

static void add_flow_break(fz_context *ctx, fz_pool *pool, fz_html_box *top, fz_html_box *inline_box)
{
	(void)add_flow(ctx, pool, top, inline_box, FLOW_BREAK, 0);
}

static void add_flow_sbreak(fz_context *ctx, fz_pool *pool, fz_html_box *top, fz_html_box *inline_box)
{
	(void)add_flow(ctx, pool, top, inline_box, FLOW_SBREAK, 0);
}

static void add_flow_shyphen(fz_context *ctx, fz_pool *pool, fz_html_box *top, fz_html_box *inline_box)
{
	(void)add_flow(ctx, pool, top, inline_box, FLOW_SHYPHEN, 0);
}

static void add_flow_word(fz_context *ctx, fz_pool *pool, fz_html_box *top, fz_html_box *inline_box, const char *a, const char *b, int lang)
{
	fz_html_flow *flow = add_flow(ctx, pool, top, inline_box, FLOW_WORD, b - a + 1);
	if (flow == NULL)
		return;
	memcpy(flow->content.text, a, b - a);
	flow->content.text[b - a] = 0;
	flow->markup_lang = lang;
}

static void add_flow_image(fz_context *ctx, fz_pool *pool, fz_html_box *top, fz_html_box *inline_box, fz_image *img)
{
	fz_html_flow *flow = add_flow(ctx, pool, top, inline_box, FLOW_IMAGE, 0);
	if (flow)
		flow->content.image = fz_keep_image(ctx, img);
}

static void add_flow_anchor(fz_context *ctx, fz_pool *pool, fz_html_box *top, fz_html_box *inline_box)
{
	(void)add_flow(ctx, pool, top, inline_box, FLOW_ANCHOR, 0);
}

fz_html_flow *fz_html_split_flow(fz_context *ctx, fz_pool *pool, fz_html_flow *flow, size_t offset)
{
	fz_html_flow *new_flow;
	char *text;
	size_t len;

	assert(flow->type == FLOW_WORD);

	if (offset == 0)
		return flow;
	text = flow->content.text;
	while (*text && offset)
	{
		int rune;
		text += fz_chartorune(&rune, text);
		offset--;
	}
	len = strlen(text);
	new_flow = fz_pool_alloc(ctx, pool, offsetof(fz_html_flow, content) + len+1);
	memcpy(new_flow, flow, offsetof(fz_html_flow, content));
	new_flow->next = flow->next;
	flow->next = new_flow;
	strcpy(new_flow->content.text, text);
	*text = 0;
	return new_flow;
}

static void flush_space(fz_context *ctx, fz_html_box *flow, int lang, struct genstate *g)
{
	static const char *space = " ";
	fz_pool *pool = g->pool;
	if (g->emit_white)
	{
		int bsp = g->emit_white->style->white_space & WS_ALLOW_BREAK_SPACE;
		if (!g->at_bol)
		{
			if (bsp)
				add_flow_space(ctx, pool, flow, g->emit_white);
			else
				add_flow_word(ctx, pool, flow, g->emit_white, space, space+1, lang);
		}
		g->emit_white = 0;
	}
}

/* pair-wise lookup table for UAX#14 linebreaks */
static const char *pairbrk[29] =
{
/*	-OCCQGNESIPPNAHIIHBBBZCWHHJJJR- */
/*	-PLPULSXYSROULLDNYAB2WMJ23LVTI- */
	"^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", /* OP open punctuation */
	"_^^%%^^^^%%_____%%__^^^______", /* CL close punctuation */
	"_^^%%^^^^%%%%%__%%__^^^______", /* CP close parenthesis */
	"^^^%%%^^^%%%%%%%%%%%^^^%%%%%%", /* QU quotation */
	"%^^%%%^^^%%%%%%%%%%%^^^%%%%%%", /* GL non-breaking glue */
	"_^^%%%^^^_______%%__^^^______", /* NS nonstarters */
	"_^^%%%^^^______%%%__^^^______", /* EX exclamation/interrogation */
	"_^^%%%^^^__%_%__%%__^^^______", /* SY symbols allowing break after */
	"_^^%%%^^^__%%%__%%__^^^______", /* IS infix numeric separator */
	"%^^%%%^^^__%%%%_%%__^^^%%%%%_", /* PR prefix numeric */
	"%^^%%%^^^__%%%__%%__^^^______", /* PO postfix numeric */
	"%^^%%%^^^%%%%%_%%%__^^^______", /* NU numeric */
	"%^^%%%^^^__%%%_%%%__^^^______", /* AL ordinary alphabetic and symbol characters */
	"%^^%%%^^^__%%%_%%%__^^^______", /* HL hebrew letter */
	"_^^%%%^^^_%____%%%__^^^______", /* ID ideographic */
	"_^^%%%^^^______%%%__^^^______", /* IN inseparable characters */
	"_^^%_%^^^__%____%%__^^^______", /* HY hyphens */
	"_^^%_%^^^_______%%__^^^______", /* BA break after */
	"%^^%%%^^^%%%%%%%%%%%^^^%%%%%%", /* BB break before */
	"_^^%%%^^^_______%%_^^^^______", /* B2 break opportunity before and after */
	"____________________^________", /* ZW zero width space */
	"%^^%%%^^^__%%%_%%%__^^^______", /* CM combining mark */
	"%^^%%%^^^%%%%%%%%%%%^^^%%%%%%", /* WJ word joiner */
	"_^^%%%^^^_%____%%%__^^^___%%_", /* H2 hangul leading/vowel syllable */
	"_^^%%%^^^_%____%%%__^^^____%_", /* H3 hangul leading/vowel/trailing syllable */
	"_^^%%%^^^_%____%%%__^^^%%%%__", /* JL hangul leading jamo */
	"_^^%%%^^^_%____%%%__^^^___%%_", /* JV hangul vowel jamo */
	"_^^%%%^^^_%____%%%__^^^____%_", /* JT hangul trailing jamo */
	"_^^%%%^^^_______%%__^^^_____%", /* RI regional indicator */
};

static fz_html_box *
find_flow_encloser(fz_context *ctx, fz_html_box *flow)
{
	/* This code was written to assume that there will always be a
	 * flow box enclosing callers of this. Bug 705324 shows that
	 * this isn't always the case. In the absence of a reproducer
	 * file, all I can do is try to patch around the issue so that
	 * we won't crash. */
	while (flow->type != BOX_FLOW)
	{
		if (flow->up == NULL)
		{
			fz_warn(ctx, "Flow encloser not found. Please report this file!");
			break;
		}
		flow = flow->up;
	}
	return flow;
}

static void generate_text(fz_context *ctx, fz_html_box *box, const char *text, int lang, struct genstate *g)
{
	fz_html_box *flow;
	fz_pool *pool = g->pool;
	int collapse = box->style->white_space & WS_COLLAPSE;
	int bsp = box->style->white_space & WS_ALLOW_BREAK_SPACE;
	int bnl = box->style->white_space & WS_FORCE_BREAK_NEWLINE;

	static const char *space = " ";

	flow = find_flow_encloser(ctx, box);
	if (flow == NULL)
		return;

	while (*text)
	{
		if (bnl && (*text == '\n' || *text == '\r'))
		{
			if (text[0] == '\r' && text[1] == '\n')
				text += 2;
			else
				text += 1;
			add_flow_break(ctx, pool, flow, box);
			g->at_bol = 1;
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
				g->emit_white = box;
			}
			else
			{
				// TODO: tabs
				if (bsp)
					add_flow_space(ctx, pool, flow, box);
				else
					add_flow_word(ctx, pool, flow, box, space, space+1, lang);
				++text;
			}
			g->last_brk_cls = UCDN_LINEBREAK_CLASS_WJ; /* don't add sbreaks after a space */
		}
		else
		{
			const char *prev, *mark = text;
			int c;

			flush_space(ctx, flow, lang, g);

			if (g->at_bol)
				g->last_brk_cls = UCDN_LINEBREAK_CLASS_WJ;

			while (*text && !iswhite(*text))
			{
				prev = text;
				text += fz_chartorune(&c, text);
				if (c == 0xAD) /* soft hyphen */
				{
					if (mark != prev)
						add_flow_word(ctx, pool, flow, box, mark, prev, lang);
					add_flow_shyphen(ctx, pool, flow, box);
					mark = text;
					g->last_brk_cls = UCDN_LINEBREAK_CLASS_WJ; /* don't add sbreaks after a soft hyphen */
				}
				else if (bsp) /* allow soft breaks */
				{
					int this_brk_cls = ucdn_get_resolved_linebreak_class(c);
					if (this_brk_cls < UCDN_LINEBREAK_CLASS_RI)
					{
						int brk = pairbrk[g->last_brk_cls][this_brk_cls];

						/* we handle spaces elsewhere, so ignore these classes */
						if (brk == '@') brk = '^';
						if (brk == '#') brk = '^';
						if (brk == '%') brk = '^';

						if (brk == '_')
						{
							if (mark != prev)
								add_flow_word(ctx, pool, flow, box, mark, prev, lang);
							add_flow_sbreak(ctx, pool, flow, box);
							mark = prev;
						}

						g->last_brk_cls = this_brk_cls;
					}
				}
			}
			if (mark != text)
				add_flow_word(ctx, pool, flow, box, mark, text, lang);

			g->at_bol = 0;
		}
	}
}

static fz_image *load_html_image(fz_context *ctx, fz_archive *zip, const char *base_uri, const char *src)
{
	char path[2048];
	fz_image *img = NULL;
	fz_buffer *buf = NULL;

	fz_var(img);
	fz_var(buf);

	fz_try(ctx)
	{
		if (!strncmp(src, "data:image/jpeg;base64,", 23))
			buf = fz_new_buffer_from_base64(ctx, src+23, 0);
		else if (!strncmp(src, "data:image/png;base64,", 22))
			buf = fz_new_buffer_from_base64(ctx, src+22, 0);
		else if (!strncmp(src, "data:image/gif;base64,", 22))
			buf = fz_new_buffer_from_base64(ctx, src+22, 0);
		else
		{
			fz_strlcpy(path, base_uri, sizeof path);
			fz_strlcat(path, "/", sizeof path);
			fz_strlcat(path, src, sizeof path);
			fz_urldecode(path);
			buf = fz_read_archive_entry(ctx, zip, path);
		}
#if FZ_ENABLE_SVG
		if (strstr(src, ".svg"))
			img = fz_new_image_from_svg(ctx, buf, base_uri, zip);
		else
#endif
			img = fz_new_image_from_buffer(ctx, buf);
	}
	fz_always(ctx)
		fz_drop_buffer(ctx, buf);
	fz_catch(ctx)
		fz_warn(ctx, "html: cannot load image src='%s'", src);

	return img;
}

static fz_image *load_svg_image(fz_context *ctx, fz_archive *zip, const char *base_uri,
	fz_xml_doc *xmldoc, fz_xml *node)
{
	fz_image *img = NULL;
#if FZ_ENABLE_SVG
	fz_try(ctx)
		img = fz_new_image_from_svg_xml(ctx, xmldoc, node, base_uri, zip);
	fz_catch(ctx)
		fz_warn(ctx, "html: cannot load embedded svg document");
#endif
	return img;
}

static void generate_image(fz_context *ctx, fz_html_box *box, fz_image *img, struct genstate *g)
{
	fz_html_box *flow;
	fz_pool *pool = g->pool;

	flow = find_flow_encloser(ctx, box);

	flush_space(ctx, flow, 0, g);

	if (!img)
	{
		const char *alt = "[image]";
		add_flow_word(ctx, pool, flow, box, alt, alt + 7, 0);
	}
	else
	{
		fz_try(ctx)
		{
			add_flow_sbreak(ctx, pool, flow, box);
			add_flow_image(ctx, pool, flow, box, img);
			add_flow_sbreak(ctx, pool, flow, box);
		}
		fz_always(ctx)
		{
			fz_drop_image(ctx, img);
		}
		fz_catch(ctx)
			fz_rethrow(ctx);
	}

	g->at_bol = 0;
}

static void fz_drop_html_box(fz_context *ctx, fz_html_box *box)
{
	while (box)
	{
		fz_html_box *next = box->next;
		if (box->type == BOX_FLOW)
			fz_drop_html_flow(ctx, box->u.flow.head);
		fz_drop_html_box(ctx, box->down);
		box = next;
	}
}

static void fz_drop_html_imp(fz_context *ctx, fz_storable *stor)
{
	fz_html *html = (fz_html *)stor;
	fz_drop_html_box(ctx, html->tree.root);
	fz_drop_pool(ctx, html->tree.pool);
}

static void fz_drop_story_imp(fz_context *ctx, fz_storable *stor)
{
	fz_story *story = (fz_story *)stor;
	fz_free(ctx, story->user_css);
	fz_drop_html_font_set(ctx, story->font_set);
	fz_drop_xml(ctx, story->dom);
	fz_drop_html_box(ctx, story->tree.root);
	fz_drop_buffer(ctx, story->warnings);
	fz_drop_archive(ctx, story->zip);
	/* The pool must be the last thing dropped. */
	fz_drop_pool(ctx, story->tree.pool);
}

/* Drop a structure derived from an html_tree. The exact things
 * freed here will depend upon the drop function with which it
 * was created. */
static void
fz_drop_html_tree(fz_context *ctx, fz_html_tree *tree)
{
	fz_defer_reap_start(ctx);
	fz_drop_storable(ctx, &tree->storable);
	fz_defer_reap_end(ctx);
}

void fz_drop_html(fz_context *ctx, fz_html *html)
{
	fz_drop_html_tree(ctx, &html->tree);
}

void fz_drop_story(fz_context *ctx, fz_story *story)
{
	if (!story)
		return;

	fz_drop_html_tree(ctx, &story->tree);
}

fz_html *fz_keep_html(fz_context *ctx, fz_html *html)
{
	return fz_keep_storable(ctx, &html->tree.storable);
}

static fz_html_box *new_box(fz_context *ctx, struct genstate *g, fz_xml *node, int type, fz_css_style *style)
{
	fz_html_box *box;
	const char *tag = fz_xml_tag(node);
	const char *id = fz_xml_att(node, "id");
	const char *href;

	if (type == BOX_INLINE)
		box = fz_pool_alloc(ctx, g->pool, offsetof(fz_html_box, u));
	else if (type == BOX_FLOW)
		box = fz_pool_alloc(ctx, g->pool, offsetof(fz_html_box, u) + sizeof(box->u.flow));
	else
		box = fz_pool_alloc(ctx, g->pool, offsetof(fz_html_box, u) + sizeof(box->u.block));

	box->type = type;
	box->is_first_flow = 0;
	box->markup_dir = g->markup_dir;
	box->structure = 0;
	box->list_item = 0;

	box->style = fz_css_enlist(ctx, style, &g->styles, g->pool);

#ifndef NDEBUG
	if (tag)
		box->tag = fz_pool_strdup(ctx, g->pool, tag);
	else
		box->tag = "#anon";
#endif

	if (id)
		box->id = fz_pool_strdup(ctx, g->pool, id);

	if (tag && tag[0]=='a' && tag[1]==0)
	{
		// Support deprecated anchor syntax with id in "name" instead of "id" attribute.
		if (!id)
		{
			const char *name = fz_xml_att(node, "name");
			if (name)
				box->id = fz_pool_strdup(ctx, g->pool, name);
		}

		if (g->is_fb2)
		{
			href = fz_xml_att(node, "l:href");
			if (!href)
				href = fz_xml_att(node, "xlink:href");
		}
		else
		{
			href = fz_xml_att(node, "href");
		}
		if (href)
			g->href = fz_pool_strdup(ctx, g->pool, href);
	}

	if (g->href)
		box->href = g->href;

	if (type == BOX_FLOW)
	{
		box->u.flow.head = NULL;
		box->s.build.flow_tail = &box->u.flow.head;
	}

	return box;
}

static void append_box(fz_context *ctx, fz_html_box *parent, fz_html_box *child)
{
	child->up = parent;
	if (!parent->down)
		parent->down = child;
	if (parent->s.build.last_child)
		parent->s.build.last_child->next = child;
	parent->s.build.last_child = child;
}

static fz_html_box *find_block_context(fz_context *ctx, fz_html_box *box)
{
	while (box->type != BOX_BLOCK && box->type != BOX_TABLE_CELL)
		box = box->up;
	return box;
}

static fz_html_box *find_table_row_context(fz_context *ctx, fz_html_box *box)
{
	fz_html_box *look = box;
	while (look && look->type != BOX_TABLE)
		look = look->up;
	if (look)
		return look;
	fz_warn(ctx, "table-row not inside table element");
	return box;
}

static fz_html_box *find_table_cell_context(fz_context *ctx, fz_html_box *box)
{
	fz_html_box *look = box;
	while (look && look->type != BOX_TABLE_ROW)
		look = look->up;
	if (look)
		return look;
	fz_warn(ctx, "table-cell not inside table-row element");
	return box;
}

static fz_html_box *find_inline_context(fz_context *ctx, struct genstate *g, fz_html_box *box)
{
	fz_css_style style;
	fz_html_box *flow_box;

	if (box->type == BOX_FLOW || box->type == BOX_INLINE)
		return box;

	// We have an inline element that is not in an existing flow/inline context.

	// Find the closest block level box to insert content into.
	while (box->type != BOX_BLOCK && box->type != BOX_TABLE_CELL)
		box = box->up;

	// Concatenate onto the last open flow box if we have one.
	if (box->s.build.last_child && box->s.build.last_child->type == BOX_FLOW)
		return box->s.build.last_child;

	// No flow box found, create and insert one!

	// TODO: null style instead of default for flow box?
	fz_default_css_style(ctx, &style);
	flow_box = new_box(ctx, g, NULL, BOX_FLOW, &style);
	flow_box->is_first_flow = !box->down;
	g->at_bol = 1;

	append_box(ctx, box, flow_box);

	return flow_box;
}

static void gen2_children(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *root_node, fz_css_match *root_match);

static void gen2_text(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node)
{
	fz_html_box *anon_box;
	fz_css_style style;
	const char *text;
	int collapse;

	text = fz_xml_text(node);
	collapse = root_box->style->white_space & WS_COLLAPSE;
	if (collapse && is_all_white(text))
	{
		g->emit_white = root_box;
	}
	else
	{
		if (root_box->type != BOX_INLINE)
		{
			/* Create anonymous inline box, with the same style as the top block box. */
			style = *root_box->style;

			// Make sure not to recursively multiply font sizes
			style.font_size.value = 1;
			style.font_size.unit = N_SCALE;

			root_box = find_inline_context(ctx, g, root_box);
			anon_box = new_box(ctx, g, NULL, BOX_INLINE, &style);
			append_box(ctx, root_box, anon_box);
			root_box = anon_box;
		}

		generate_text(ctx, root_box, text, g->markup_lang, g);
	}
}

static fz_html_box *gen2_inline(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node, fz_css_style *style)
{
	fz_html_box *this_box;
	fz_html_box *flow_box;
	root_box = find_inline_context(ctx, g, root_box);
	this_box = new_box(ctx, g, node, BOX_INLINE, style);
	append_box(ctx, root_box, this_box);
	if (this_box->id)
	{
		flow_box = find_flow_encloser(ctx, this_box);
		add_flow_anchor(ctx, g->pool, flow_box, this_box);
	}
	return this_box;
}

static void gen2_break(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node)
{
	fz_html_box *this_box;
	fz_html_box *flow_box;

	if (root_box->type != BOX_INLINE)
	{
		/* Create inline box to hold the <br> tag, with the same style as containing block. */
		/* Make sure not to recursively multiply font sizes. */
		fz_css_style style = *root_box->style;
		style.font_size.value = 1;
		style.font_size.unit = N_SCALE;
		this_box = new_box(ctx, g, node, BOX_INLINE, &style);
		append_box(ctx, find_inline_context(ctx, g, root_box), this_box);
	}
	else
	{
		this_box = root_box;
	}

	flow_box = find_flow_encloser(ctx, this_box);
	add_flow_break(ctx, g->pool, flow_box, this_box);
	g->at_bol = 1;
}

static fz_html_box *gen2_block(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node, fz_css_style *style)
{
	fz_html_box *this_box;
	root_box = find_block_context(ctx, root_box);
	this_box = new_box(ctx, g, node, BOX_BLOCK, style);
	append_box(ctx, root_box, this_box);
	return this_box;
}

static fz_html_box *gen2_table(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node, fz_css_style *style)
{
	fz_html_box *this_box;
	root_box = find_block_context(ctx, root_box);
	this_box = new_box(ctx, g, node, BOX_TABLE, style);
	append_box(ctx, root_box, this_box);
	return this_box;
}

static fz_html_box *gen2_table_row(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node, fz_css_style *style)
{
	fz_html_box *this_box;
	root_box = find_table_row_context(ctx, root_box);
	this_box = new_box(ctx, g, node, BOX_TABLE_ROW, style);
	append_box(ctx, root_box, this_box);
	return this_box;
}

static fz_html_box *gen2_table_cell(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node, fz_css_style *style)
{
	fz_html_box *this_box;
	root_box = find_table_cell_context(ctx, root_box);
	this_box = new_box(ctx, g, node, BOX_TABLE_CELL, style);
	append_box(ctx, root_box, this_box);
	return this_box;
}

static void gen2_image_common(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node, fz_image *img, int display, fz_css_style *style)
{
	fz_html_box *img_block_box;
	fz_html_box *img_inline_box;

	if (display == DIS_INLINE || display == DIS_INLINE_BLOCK)
	{
		root_box = find_inline_context(ctx, g, root_box);
		img_inline_box = new_box(ctx, g, node, BOX_INLINE, style);
		append_box(ctx, root_box, img_inline_box);
		generate_image(ctx, img_inline_box, img, g);
	}
	else
	{
		root_box = find_block_context(ctx, root_box);
		img_block_box = new_box(ctx, g, node, BOX_BLOCK, style);
		append_box(ctx, root_box, img_block_box);

		root_box = find_inline_context(ctx, g, img_block_box);
		img_inline_box = new_box(ctx, g, NULL, BOX_INLINE, style);
		append_box(ctx, root_box, img_inline_box);
		generate_image(ctx, img_inline_box, img, g);
	}
}

static void gen2_image_html(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node, int display, fz_css_style *style)
{
	const char *src = fz_xml_att(node, "src");
	if (src)
	{
		fz_css_style local_style = *style;
		fz_image *img;
		int w, h;
		const char *w_att = fz_xml_att(node, "width");
		const char *h_att = fz_xml_att(node, "height");

		if (w_att && (w = fz_atoi(w_att)) > 0)
		{
			local_style.width.value = w;
			local_style.width.unit = strchr(w_att, '%') ? N_PERCENT : N_LENGTH;
		}
		if (h_att && (h = fz_atoi(h_att)) > 0)
		{
			local_style.height.value = h;
			local_style.height.unit = strchr(h_att, '%') ? N_PERCENT : N_LENGTH;
		}

		img = load_html_image(ctx, g->zip, g->base_uri, src);
		gen2_image_common(ctx, g, root_box, node, img, display, &local_style);
	}
}

static void gen2_image_fb2(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node, int display, fz_css_style *style)
{
	const char *src = fz_xml_att(node, "l:href");
	if (!src)
		src = fz_xml_att(node, "xlink:href");
	if (src && src[0] == '#')
	{
		fz_image *img = fz_tree_lookup(ctx, g->images, src+1);
		gen2_image_common(ctx, g, root_box, node, fz_keep_image(ctx, img), display, style);
	}
}

static void gen2_image_svg(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node, int display, fz_css_style *style)
{
	fz_image *img = load_svg_image(ctx, g->zip, g->base_uri, g->xml, node);
	gen2_image_common(ctx, g, root_box, node, img, display, style);
}

static int
structure_from_tag(const char *tag, struct genstate *g)
{
	if (tag == NULL)
		return FZ_HTML_STRUCT_UNKNOWN;
	if (!strcmp(tag, "title") || !strcmp(tag, "subtitle"))
	{
		if (!g->is_fb2)
			return FZ_HTML_STRUCT_UNKNOWN;
		return g->section_depth ? (FZ_HTML_STRUCT_H1 - 1 + fz_mini(g->section_depth, 6)) : FZ_HTML_STRUCT_UNKNOWN;
	}
	else if (!strcmp(tag, "body"))
		return FZ_HTML_STRUCT_BODY;
	else if (!strcmp(tag, "div"))
		return FZ_HTML_STRUCT_DIV;
	else if (!strcmp(tag, "span"))
		return FZ_HTML_STRUCT_SPAN;
	else if (!strcmp(tag, "blockquote"))
		return FZ_HTML_STRUCT_BLOCKQUOTE;
	else if (!strcmp(tag, "p"))
		return FZ_HTML_STRUCT_P;
	else if (!strcmp(tag, "h1"))
		return FZ_HTML_STRUCT_H1;
	else if (!strcmp(tag, "h2"))
		return FZ_HTML_STRUCT_H2;
	else if (!strcmp(tag, "h3"))
		return FZ_HTML_STRUCT_H3;
	else if (!strcmp(tag, "h4"))
		return FZ_HTML_STRUCT_H4;
	else if (!strcmp(tag, "h5"))
		return FZ_HTML_STRUCT_H5;
	else if (!strcmp(tag, "h6"))
		return FZ_HTML_STRUCT_H6;
	else if (!strcmp(tag, "dl") || !strcmp(tag, "ul") || !strcmp(tag, "ol"))
		return FZ_HTML_STRUCT_L;
	else if (!strcmp(tag, "li") || !strcmp(tag, "dd") || !strcmp(tag, "dt"))
		return FZ_HTML_STRUCT_LI;
	else if (!strcmp(tag, "table"))
		return FZ_HTML_STRUCT_TABLE;
	else if (!strcmp(tag, "tr"))
		return FZ_HTML_STRUCT_TR;
	else if (!strcmp(tag, "th"))
		return FZ_HTML_STRUCT_TH;
	else if (!strcmp(tag, "td"))
		return FZ_HTML_STRUCT_TD;
	else if (!strcmp(tag, "thead"))
		return FZ_HTML_STRUCT_THEAD;
	else if (!strcmp(tag, "tbody"))
		return FZ_HTML_STRUCT_TBODY;
	else if (!strcmp(tag, "tfoot"))
		return FZ_HTML_STRUCT_TFOOT;

	return FZ_HTML_STRUCT_UNKNOWN;
}

static void gen2_tag(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *node,
	fz_css_match *match, int display, fz_css_style *style)
{
	fz_html_box *this_box;
	const char *tag;
	const char *lang_att;
	const char *dir_att;

	int save_markup_dir = g->markup_dir;
	int save_markup_lang = g->markup_lang;
	char *save_href = g->href;

	if (display == DIS_NONE)
		return;

	tag = fz_xml_tag(node);

	dir_att = fz_xml_att(node, "dir");
	if (dir_att)
	{
		if (!strcmp(dir_att, "auto"))
			g->markup_dir = FZ_BIDI_NEUTRAL;
		else if (!strcmp(dir_att, "rtl"))
			g->markup_dir = FZ_BIDI_RTL;
		else if (!strcmp(dir_att, "ltr"))
			g->markup_dir = FZ_BIDI_LTR;
		else
			g->markup_dir = DEFAULT_DIR;
	}

	lang_att = fz_xml_att(node, "lang");
	if (lang_att)
		g->markup_lang = fz_text_language_from_string(lang_att);

	switch (display)
	{
	case DIS_INLINE_BLOCK:
		// TODO handle inline block as a flow node
		this_box = gen2_block(ctx, g, root_box, node, style);
		break;

	case DIS_BLOCK:
		this_box = gen2_block(ctx, g, root_box, node, style);
		this_box->structure = structure_from_tag(tag, g);
		break;

	case DIS_LIST_ITEM:
		this_box = gen2_block(ctx, g, root_box, node, style);
		this_box->list_item = ++g->list_counter;
		break;

	case DIS_TABLE:
		this_box = gen2_table(ctx, g, root_box, node, style);
		break;
	case DIS_TABLE_GROUP:
		// no box for table-row-group elements
		this_box = root_box;
		break;
	case DIS_TABLE_ROW:
		this_box = gen2_table_row(ctx, g, root_box, node, style);
		break;
	case DIS_TABLE_CELL:
		this_box = gen2_table_cell(ctx, g, root_box, node, style);
		break;

	case DIS_INLINE:
	default:
		this_box = gen2_inline(ctx, g, root_box, node, style);
		break;
	}

	if (!strcmp(tag, "ol"))
	{
		int save_list_counter = g->list_counter;
		g->list_counter = 0;
		gen2_children(ctx, g, this_box, node, match);
		g->list_counter = save_list_counter;
	}
	else if (!strcmp(tag, "section"))
	{
		int save_section_depth = g->section_depth;
		g->section_depth++;
		gen2_children(ctx, g, this_box, node, match);
		g->section_depth = save_section_depth;
	}
	else
	{
		gen2_children(ctx, g, this_box, node, match);
	}

	g->markup_dir = save_markup_dir;
	g->markup_lang = save_markup_lang;
	g->href = save_href;
}

static void gen2_children(fz_context *ctx, struct genstate *g, fz_html_box *root_box, fz_xml *root_node, fz_css_match *root_match)
{
	fz_xml *node;
	const char *tag;
	fz_css_match match;
	fz_css_style style;
	int display;

	for (node = fz_xml_down(root_node); node; node = fz_xml_next(node))
	{
		tag = fz_xml_tag(node);
		if (tag)
		{
			fz_match_css(ctx, &match, root_match, g->css, node);
			fz_apply_css_style(ctx, g->set, &style, &match);
			display = fz_get_css_match_display(&match);
			if (tag[0]=='b' && tag[1]=='r' && tag[2]==0)
			{
				gen2_break(ctx, g, root_box, node);
			}
			else if (tag[0]=='i' && tag[1]=='m' && tag[2]=='g' && tag[3]==0)
			{
				gen2_image_html(ctx, g, root_box, node, display, &style);
			}
			else if (g->is_fb2 && tag[0]=='i' && tag[1]=='m' && tag[2]=='a' && tag[3]=='g' && tag[4]=='e' && tag[5]==0)
			{
				gen2_image_fb2(ctx, g, root_box, node, display, &style);
			}
			else if (tag[0]=='s' && tag[1]=='v' && tag[2]=='g' && tag[3]==0)
			{
				gen2_image_svg(ctx, g, root_box, node, display, &style);
			}
			else
			{
				gen2_tag(ctx, g, root_box, node, &match, display, &style);
			}
		}
		else
		{
			gen2_text(ctx, g, root_box, node);
		}
	}
}

static char *concat_text(fz_context *ctx, fz_xml *root)
{
	fz_xml *node;
	size_t i = 0, n = 1;
	char *s;
	for (node = fz_xml_down(root); node; node = fz_xml_next(node))
	{
		const char *text = fz_xml_text(node);
		n += text ? strlen(text) : 0;
	}
	s = Memento_label(fz_malloc(ctx, n), "concat_html");
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

static void
html_load_css_link(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_css *css, fz_xml *root, const char *href)
{
	char path[2048];
	char css_base_uri[2048];
	fz_buffer *buf;

	fz_var(buf);

	fz_strlcpy(path, base_uri, sizeof path);
	fz_strlcat(path, "/", sizeof path);
	fz_strlcat(path, href, sizeof path);
	fz_urldecode(path);
	fz_cleanname(path);

	fz_dirname(css_base_uri, path, sizeof css_base_uri);

	buf = NULL;
	fz_try(ctx)
	{
		buf = fz_read_archive_entry(ctx, zip, path);
		fz_parse_css(ctx, css, fz_string_from_buffer(ctx, buf), path);
		fz_add_css_font_faces(ctx, set, zip, css_base_uri, css);
	}
	fz_always(ctx)
		fz_drop_buffer(ctx, buf);
	fz_catch(ctx)
		fz_warn(ctx, "ignoring stylesheet %s", path);
}

static void
html_load_css(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_css *css, fz_xml *root)
{
	fz_xml *html, *head, *node;

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
						html_load_css_link(ctx, set, zip, base_uri, css, root, href);
					}
				}
			}
		}
		else if (fz_xml_is_tag(node, "style"))
		{
			char *s = concat_text(ctx, node);
			fz_try(ctx)
			{
				fz_parse_css(ctx, css, s, "<style>");
				fz_add_css_font_faces(ctx, set, zip, base_uri, css);
			}
			fz_catch(ctx)
				fz_warn(ctx, "ignoring inline stylesheet");
			fz_free(ctx, s);
		}
	}
}

static void
fb2_load_css(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_css *css, fz_xml *root)
{
	fz_xml *fictionbook, *stylesheet;

	fictionbook = fz_xml_find(root, "FictionBook");
	stylesheet = fz_xml_find_down(fictionbook, "stylesheet");
	if (stylesheet)
	{
		char *s = concat_text(ctx, stylesheet);
		fz_try(ctx)
		{
			fz_parse_css(ctx, css, s, "<stylesheet>");
			fz_add_css_font_faces(ctx, set, zip, base_uri, css);
		}
		fz_catch(ctx)
			fz_warn(ctx, "ignoring inline stylesheet");
		fz_free(ctx, s);
	}
}

static fz_tree *
load_fb2_images(fz_context *ctx, fz_xml *root)
{
	fz_xml *fictionbook, *binary;
	fz_tree *images = NULL;

	fictionbook = fz_xml_find(root, "FictionBook");
	for (binary = fz_xml_find_down(fictionbook, "binary"); binary; binary = fz_xml_find_next(binary, "binary"))
	{
		const char *id = fz_xml_att(binary, "id");
		char *b64 = NULL;
		fz_buffer *buf = NULL;
		fz_image *img = NULL;

		fz_var(b64);
		fz_var(buf);

		if (id == NULL)
		{
			fz_warn(ctx, "Skipping image with no id");
			continue;
		}

		fz_try(ctx)
		{
			b64 = concat_text(ctx, binary);
			buf = fz_new_buffer_from_base64(ctx, b64, strlen(b64));
			img = fz_new_image_from_buffer(ctx, buf);
		}
		fz_always(ctx)
		{
			fz_drop_buffer(ctx, buf);
			fz_free(ctx, b64);
		}
		fz_catch(ctx)
			fz_rethrow(ctx);

		images = fz_tree_insert(ctx, images, id, img);
	}

	return images;
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

static void fragment_cb(const uint32_t *fragment,
			size_t fragment_len,
			int bidi_level,
			int script,
			void *arg)
{
	bidi_data *data = (bidi_data *)arg;

	/* We are guaranteed that fragmentOffset will be at the beginning
	 * of flow. */
	while (fragment_len > 0)
	{
		size_t len;

		if (data->flow->type == FLOW_SPACE)
		{
			len = 1;
		}
		else if (data->flow->type == FLOW_BREAK || data->flow->type == FLOW_SBREAK ||
				data->flow->type == FLOW_SHYPHEN || data->flow->type == FLOW_ANCHOR)
		{
			len = 0;
		}
		else
		{
			/* Must be text */
			len = fz_utflen(data->flow->content.text);
			if (len > fragment_len)
			{
				/* We need to split this flow box */
				(void)fz_html_split_flow(data->ctx, data->pool, data->flow, fragment_len);
				len = fz_utflen(data->flow->content.text);
			}
		}

		/* This flow box is entirely contained within this fragment. */
		data->flow->bidi_level = bidi_level;
		data->flow->script = script;
		data->flow = data->flow->next;
		fragment_len -= len;
	}
}

static fz_bidi_direction
detect_flow_directionality(fz_context *ctx, fz_pool *pool, uni_buf *buffer, fz_bidi_direction bidi_dir, fz_html_flow *flow)
{
	fz_html_flow *end = flow;
	bidi_data data;

	while (end)
	{
		int level = end->bidi_level;

		/* Gather the text from the flow up into a single buffer (at
		 * least, as much of it as has the same direction markup). */
		buffer->len = 0;
		while (end && (level & 1) == (end->bidi_level & 1))
		{
			size_t len = 0;
			const char *text = "";
			int broken = 0;

			switch (end->type)
			{
			case FLOW_WORD:
				len = fz_utflen(end->content.text);
				text = end->content.text;
				break;
			case FLOW_SPACE:
				len = 1;
				text = " ";
				break;
			case FLOW_SHYPHEN:
			case FLOW_SBREAK:
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
				size_t newcap = buffer->cap;
				if (newcap < 128)
					newcap = 128; /* Sensible small default */

				while (newcap < buffer->len + len)
					newcap = (newcap * 3) / 2;

				buffer->data = fz_realloc_array(ctx, buffer->data, newcap, uint32_t);
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
		fz_bidi_fragment_text(ctx, buffer->data, buffer->len, &bidi_dir, fragment_cb, &data, 0 /* Flags */);
		flow = end;
	}
	return bidi_dir;
}

static void
detect_box_directionality(fz_context *ctx, fz_pool *pool, uni_buf *buffer, fz_html_box *box)
{
	while (box)
	{
		if (box->type == BOX_FLOW)
			box->markup_dir = detect_flow_directionality(ctx, pool, buffer, box->markup_dir, box->u.flow.head);
		detect_box_directionality(ctx, pool, buffer, box->down);
		box = box->next;
	}
}

static void
detect_directionality(fz_context *ctx, fz_pool *pool, fz_html_box *box)
{
	uni_buf buffer = { NULL };

	fz_try(ctx)
		detect_box_directionality(ctx, pool, &buffer, box);
	fz_always(ctx)
		fz_free(ctx, buffer.data);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static fz_xml_doc *
parse_to_xml(fz_context *ctx, fz_buffer *buf, int try_xml, int try_html5)
{
	fz_xml_doc *xml;

	if (try_xml && try_html5)
	{
		fz_try(ctx)
			xml = fz_parse_xml(ctx, buf, 1);
		fz_catch(ctx)
		{
			if (fz_caught(ctx) == FZ_ERROR_SYNTAX)
			{
				fz_warn(ctx, "syntax error in XHTML; retrying using HTML5 parser");
				xml = fz_parse_xml_from_html5(ctx, buf);
			}
			else
				fz_rethrow(ctx);
		}
	}
	else if (try_xml)
		xml = fz_parse_xml(ctx, buf, 1);
	else
	{
		assert(try_html5);
		xml = fz_parse_xml_from_html5(ctx, buf);
	}

	return xml;
}

static void
xml_to_boxes(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, const char *user_css,
	fz_xml_doc *xml, fz_html_tree *tree, char **rtitle, int try_fictionbook, int is_mobi)
{
	fz_xml *root, *node;
	char *title;

	fz_css_match match;
	struct genstate g = {0};

	g.pool = NULL;
	g.set = set;
	g.zip = zip;
	g.images = NULL;
	g.xml = xml;
	g.is_fb2 = 0;
	g.base_uri = base_uri;
	g.css = NULL;
	g.at_bol = 0;
	g.emit_white = 0;
	g.last_brk_cls = UCDN_LINEBREAK_CLASS_OP;
	g.list_counter = 0;
	g.section_depth = 0;
	g.markup_dir = FZ_BIDI_LTR;
	g.markup_lang = FZ_LANG_UNSET;
	g.href = NULL;
	g.styles = NULL;

	if (rtitle)
		*rtitle = NULL;

	root = fz_xml_root(g.xml);

	fz_try(ctx)
		g.css = fz_new_css(ctx);
	fz_catch(ctx)
	{
		fz_drop_xml(ctx, g.xml);
		fz_rethrow(ctx);
	}

#ifndef NDEBUG
	if (fz_atoi(getenv("FZ_DEBUG_XML")))
		fz_debug_xml(root, 0);
#endif

	fz_try(ctx)
	{
		if (try_fictionbook && fz_xml_find(root, "FictionBook"))
		{
			g.is_fb2 = 1;
			fz_parse_css(ctx, g.css, fb2_default_css, "<default:fb2>");
			if (fz_use_document_css(ctx))
				fb2_load_css(ctx, g.set, g.zip, g.base_uri, g.css, root);
			g.images = load_fb2_images(ctx, root);
		}
		else if (is_mobi)
		{
			g.is_fb2 = 0;
			fz_parse_css(ctx, g.css, html_default_css, "<default:html>");
			fz_parse_css(ctx, g.css, mobi_default_css, "<default:mobi>");
			if (fz_use_document_css(ctx))
				html_load_css(ctx, g.set, g.zip, g.base_uri, g.css, root);
		}
		else
		{
			g.is_fb2 = 0;
			fz_parse_css(ctx, g.css, html_default_css, "<default:html>");
			if (fz_use_document_css(ctx))
				html_load_css(ctx, g.set, g.zip, g.base_uri, g.css, root);
		}

		if (user_css)
		{
			fz_parse_css(ctx, g.css, user_css, "<user>");
			fz_add_css_font_faces(ctx, g.set, g.zip, ".", g.css);
		}
	}
	fz_catch(ctx)
	{
		fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
		fz_warn(ctx, "ignoring styles due to errors: %s", fz_caught_message(ctx));
	}

#ifndef NDEBUG
	if (fz_atoi(getenv("FZ_DEBUG_CSS")))
		fz_debug_css(ctx, g.css);
#endif

	fz_try(ctx)
	{
		fz_css_style style;

		fz_match_css_at_page(ctx, &match, g.css);
		fz_apply_css_style(ctx, g.set, &style, &match);

		g.pool = tree->pool;
		g.markup_dir = DEFAULT_DIR;
		g.markup_lang = FZ_LANG_UNSET;

		tree->root = new_box(ctx, &g, NULL, BOX_BLOCK, &style);
		// TODO: transfer page margins out of this hacky box

		gen2_children(ctx, &g, tree->root, root, &match);

		tree->root->s.layout.em = 0;
		tree->root->s.layout.x = 0;
		tree->root->s.layout.y = 0;
		tree->root->s.layout.w = 0;
		tree->root->s.layout.b = 0;

		detect_directionality(ctx, g.pool, tree->root);

		if (g.is_fb2)
		{
			node = fz_xml_find(root, "FictionBook");
			node = fz_xml_find_down(node, "description");
			node = fz_xml_find_down(node, "title-info");
			node = fz_xml_find_down(node, "book-title");
			if (rtitle)
			{
				title = fz_xml_text(fz_xml_down(node));
				if (title)
					*rtitle = fz_pool_strdup(ctx, g.pool, title);
			}
		}
		else
		{
			node = fz_xml_find(root, "html");
			node = fz_xml_find_down(node, "head");
			node = fz_xml_find_down(node, "title");
			if (rtitle)
			{
				title = fz_xml_text(fz_xml_down(node));
				if (title)
					*rtitle = fz_pool_strdup(ctx, g.pool, title);
			}
		}
	}
	fz_always(ctx)
	{
		fz_drop_tree(ctx, g.images, (void(*)(fz_context*,void*))fz_drop_image);
		fz_drop_css(ctx, g.css);
	}
	fz_catch(ctx)
	{
		if (rtitle)
		{
			fz_free(ctx, *rtitle);
			*rtitle = NULL;
		}
		/* Dropping the tree works regardless of whether the tree is part of an fz_html or not. */
		fz_drop_html_tree(ctx, tree);
		fz_rethrow(ctx);
	}
}

static const char *mobi_font_size[7] = {
	"8pt",
	"10pt",
	"12pt",
	"14pt",
	"16pt",
	"18pt",
	"20pt",
};

static void
patch_mobi_html(fz_context *ctx, fz_pool *pool, fz_xml *node)
{
	fz_xml *down;
	char buf[500];
	while (node)
	{
		char *tag = fz_xml_tag(node);
		if (tag)
		{
			// Read MOBI attributes, convert to inline CSS style
			if (!strcmp(tag, "font"))
			{
				const char *size = fz_xml_att(node, "size");
				if (size)
				{
					if (!strcmp(size, "1")) size = mobi_font_size[0];
					else if (!strcmp(size, "2")) size = mobi_font_size[1];
					else if (!strcmp(size, "3")) size = mobi_font_size[2];
					else if (!strcmp(size, "4")) size = mobi_font_size[3];
					else if (!strcmp(size, "5")) size = mobi_font_size[4];
					else if (!strcmp(size, "6")) size = mobi_font_size[5];
					else if (!strcmp(size, "7")) size = mobi_font_size[6];
					else if (!strcmp(size, "+1")) size = mobi_font_size[3];
					else if (!strcmp(size, "+2")) size = mobi_font_size[4];
					else if (!strcmp(size, "+3")) size = mobi_font_size[5];
					else if (!strcmp(size, "+4")) size = mobi_font_size[6];
					else if (!strcmp(size, "+5")) size = mobi_font_size[6];
					else if (!strcmp(size, "+6")) size = mobi_font_size[6];
					else if (!strcmp(size, "-1")) size = mobi_font_size[1];
					else if (!strcmp(size, "-2")) size = mobi_font_size[0];
					else if (!strcmp(size, "-3")) size = mobi_font_size[0];
					else if (!strcmp(size, "-4")) size = mobi_font_size[0];
					else if (!strcmp(size, "-5")) size = mobi_font_size[0];
					else if (!strcmp(size, "-6")) size = mobi_font_size[0];
					fz_snprintf(buf, sizeof buf, "font-size:%s", size);
					fz_xml_add_att(ctx, pool, node, "style", buf);
				}
			}
			else
			{
				char *height = fz_xml_att(node, "height");
				char *width = fz_xml_att(node, "width");
				char *align = fz_xml_att(node, "align");
				if (height || width || align)
				{
					buf[0] = 0;
					if (height)
					{
						fz_strlcat(buf, "margin-top:", sizeof buf);
						fz_strlcat(buf, height, sizeof buf);
						fz_strlcat(buf, ";", sizeof buf);
					}
					if (width)
					{
						fz_strlcat(buf, "text-indent:", sizeof buf);
						fz_strlcat(buf, width, sizeof buf);
						fz_strlcat(buf, ";", sizeof buf);
					}
					if (align)
					{
						fz_strlcat(buf, "text-align:", sizeof buf);
						fz_strlcat(buf, align, sizeof buf);
						fz_strlcat(buf, ";", sizeof buf);
					}
					fz_xml_add_att(ctx, pool, node, "style", buf);
				}
				if (!strcmp(tag, "img"))
				{
					char *recindex = fz_xml_att(node, "recindex");
					if (recindex)
						fz_xml_add_att(ctx, pool, node, "src", recindex);
				}
			}
		}

		down = fz_xml_down(node);
		if (down)
			patch_mobi_html(ctx, pool, down);

		node = fz_xml_next(node);
	}
}

static void
fz_parse_html_tree(fz_context *ctx,
	fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_buffer *buf, const char *user_css,
	int try_xml, int try_html5, fz_html_tree *tree, char **rtitle, int try_fictionbook, int patch_mobi)
{
	fz_xml_doc *xml;

	if (rtitle)
		*rtitle = NULL;

	xml = parse_to_xml(ctx, buf, try_xml, try_html5);

	if (patch_mobi)
		patch_mobi_html(ctx, xml->u.doc.pool, xml);

	fz_try(ctx)
		xml_to_boxes(ctx, set, zip, base_uri, user_css, xml, tree, rtitle, try_fictionbook, patch_mobi);
	fz_always(ctx)
		fz_drop_xml(ctx, xml);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

#define fz_new_derived_html_tree(CTX, TYPE, DROP) \
 ((TYPE *)Memento_label(fz_new_html_tree_of_size(CTX, sizeof(TYPE), DROP), #TYPE))

static fz_html_tree *
fz_new_html_tree_of_size(fz_context *ctx, size_t size, fz_store_drop_fn *drop)
{
	fz_pool *pool = fz_new_pool(ctx);
	fz_html_tree *tree;

	fz_try(ctx)
	{
		tree = fz_pool_alloc(ctx, pool, size);
		FZ_INIT_STORABLE(tree, 1, drop);
		tree->pool = pool;
	}
	fz_catch(ctx)
	{
		fz_drop_pool(ctx, pool);
		fz_rethrow(ctx);
	}

	return tree;
}

static fz_html *
fz_parse_html_imp(fz_context *ctx,
	fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_buffer *buf, const char *user_css,
	int try_xml, int try_html5, int patch_mobi)
{
	fz_html *html = fz_new_derived_html_tree(ctx, fz_html, fz_drop_html_imp);

	html->layout_w = 0;
	html->layout_h = 0;
	html->layout_em = 0;

	fz_parse_html_tree(ctx, set, zip, base_uri, buf, user_css, try_xml, try_html5, &html->tree, &html->title, 1, patch_mobi);

	return html;
}

typedef struct
{
	int saved;
	fz_warning_cb *old;
	void *arg;
	fz_buffer *buffer;
	fz_context *ctx;
} warning_save;

static void
warn_to_buffer(void *user, const char *message)
{
	warning_save *save = (warning_save *)user;
	fz_context *ctx = save->ctx;

	fz_try(ctx)
	{
		fz_append_string(ctx, save->buffer, message);
		fz_append_byte(ctx, save->buffer, '\n');
	}
	fz_catch(ctx)
	{
		/* Silently swallow the error. */
	}
}

static void
redirect_warnings_to_buffer(fz_context *ctx, fz_buffer *buf, warning_save *save)
{
	save->saved = 1;
	save->old = fz_warning_callback(ctx, &save->arg);
	save->buffer = buf;
	save->ctx = ctx;

	fz_flush_warnings(ctx);
	fz_set_warning_callback(ctx, warn_to_buffer, save);
}

static void
restore_warnings(fz_context *ctx, warning_save *save)
{
	if (!save->saved)
		return;

	fz_flush_warnings(ctx);
	fz_set_warning_callback(ctx, save->old, save->arg);
}

fz_story *
fz_new_story(fz_context *ctx, fz_buffer *buf, const char *user_css, float em, fz_archive *zip)
{
	fz_story *story = fz_new_derived_html_tree(ctx, fz_story, fz_drop_story_imp);
	warning_save saved = { 0 };
	fz_buffer *local_buffer = NULL;

	if (buf == NULL)
	{
		local_buffer = fz_new_buffer(ctx, 0);
		buf = local_buffer;
	}

	fz_var(local_buffer);
	fz_var(saved);

	fz_try(ctx)
	{
		story->zip = fz_keep_archive(ctx, zip);
		story->font_set = fz_new_html_font_set(ctx);
		story->em = em;
		story->user_css = user_css ? fz_strdup(ctx, user_css) : NULL;
		story->warnings = fz_new_buffer(ctx, 128);
		redirect_warnings_to_buffer(ctx, story->warnings, &saved);
		story->dom = parse_to_xml(ctx, buf, 0, 1);
	}
	fz_always(ctx)
	{
		restore_warnings(ctx, &saved);
		fz_drop_buffer(ctx, local_buffer);
	}
	fz_catch(ctx)
	{
		fz_drop_html_tree(ctx, &story->tree);
		fz_rethrow(ctx);
	}

	return story;
}

fz_html *
fz_parse_fb2(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_buffer *buf, const char *user_css)
{
	/* parse only as XML */
	return fz_parse_html_imp(ctx, set, zip, base_uri, buf, user_css, 1, 0, 0);
}

fz_html *
fz_parse_html5(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_buffer *buf, const char *user_css)
{
	/* parse only as HTML5 */
	return fz_parse_html_imp(ctx, set, zip, base_uri, buf, user_css, 0, 1, 0);
}

fz_html *
fz_parse_xhtml(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_buffer *buf, const char *user_css)
{
	/* try as XML first, fall back to HTML5 */
	return fz_parse_html_imp(ctx, set, zip, base_uri, buf, user_css, 1, 1, 0);
}

fz_html *
fz_parse_mobi(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_buffer *buf, const char *user_css)
{
	/* try as XML first, fall back to HTML5 */
	return fz_parse_html_imp(ctx, set, zip, base_uri, buf, user_css, 1, 1, 1);
}

static void indent(int level)
{
	while (level-- > 0)
		putchar('\t');
}

static void
fz_debug_html_flow(fz_context *ctx, fz_html_flow *flow, int level)
{
	fz_html_box *sbox = NULL;
	while (flow)
	{
		if (flow->box != sbox) {
			sbox = flow->box;
			indent(level);
#ifndef NDEBUG
			printf("@style <%s> em=%g font='%s'", sbox->tag, sbox->s.layout.em, fz_font_name(ctx, sbox->style->font));
#else
			printf("@style em=%g font='%s'", sbox->s.layout.em, fz_font_name(ctx, sbox->style->font));
#endif
			if (fz_font_is_serif(ctx, sbox->style->font))
				printf(" serif");
			else
				printf(" sans");
			if (fz_font_is_monospaced(ctx, sbox->style->font))
				printf(" monospaced");
			if (fz_font_is_bold(ctx, sbox->style->font))
				printf(" bold");
			if (fz_font_is_italic(ctx, sbox->style->font))
				printf(" italic");
			if (sbox->style->small_caps)
				printf(" small-caps");
			printf("\n");
		}

		indent(level);
		switch (flow->type) {
		case FLOW_WORD: printf("word "); break;
		case FLOW_SPACE: printf("space"); break;
		case FLOW_SBREAK: printf("sbrk "); break;
		case FLOW_SHYPHEN: printf("shy  "); break;
		case FLOW_BREAK: printf("break"); break;
		case FLOW_IMAGE: printf("image"); break;
		case FLOW_ANCHOR: printf("anchor"); break;
		}
		// printf(" y=%g x=%g w=%g", flow->y, flow->x, flow->w);
		if (flow->type == FLOW_IMAGE)
			printf(" h=%g", flow->h);
		if (flow->type == FLOW_WORD)
			printf(" text='%s'", flow->content.text);
		printf("\n");
		if (flow->breaks_line) {
			indent(level);
			printf("*\n");
		}

		flow = flow->next;
	}
}

const char *
fz_html_structure_to_string(int structure)
{
	switch (structure)
	{
	case FZ_HTML_STRUCT_UNKNOWN:
		return "unknown";
	case FZ_HTML_STRUCT_BODY:
		return "body";
	case FZ_HTML_STRUCT_DIV:
		return "div";
	case FZ_HTML_STRUCT_SPAN:
		return "span";
	case FZ_HTML_STRUCT_BLOCKQUOTE:
		return "blockquote";
	case FZ_HTML_STRUCT_P:
		return "p";
	case FZ_HTML_STRUCT_H1:
		return "h1";
	case FZ_HTML_STRUCT_H2:
		return "h2";
	case FZ_HTML_STRUCT_H3:
		return "h3";
	case FZ_HTML_STRUCT_H4:
		return "h4";
	case FZ_HTML_STRUCT_H5:
		return "h5";
	case FZ_HTML_STRUCT_H6:
		return "h6";
	case FZ_HTML_STRUCT_L:
		return "l";
	case FZ_HTML_STRUCT_LI:
		return "li";
	case FZ_HTML_STRUCT_TABLE:
		return "table";
	case FZ_HTML_STRUCT_TR:
		return "tr";
	case FZ_HTML_STRUCT_TH:
		return "th";
	case FZ_HTML_STRUCT_TD:
		return "td";
	case FZ_HTML_STRUCT_THEAD:
		return "thead";
	case FZ_HTML_STRUCT_TBODY:
		return "tbody";
	case FZ_HTML_STRUCT_TFOOT:
		return "tfoot";
	default:
		return "????";
	}

}

fz_structure fz_html_structure_to_structure(int s)
{
	switch (s)
	{
	case FZ_HTML_STRUCT_BODY:
		return FZ_STRUCTURE_DOCUMENT;
	case FZ_HTML_STRUCT_DIV:
		return FZ_STRUCTURE_DIV;
	case FZ_HTML_STRUCT_SPAN:
		return FZ_STRUCTURE_SPAN;
	case FZ_HTML_STRUCT_BLOCKQUOTE:
		return FZ_STRUCTURE_BLOCKQUOTE;
	case FZ_HTML_STRUCT_P:
		return FZ_STRUCTURE_P;
	case FZ_HTML_STRUCT_H1:
		return FZ_STRUCTURE_H1;
	case FZ_HTML_STRUCT_H2:
		return FZ_STRUCTURE_H2;
	case FZ_HTML_STRUCT_H3:
		return FZ_STRUCTURE_H3;
	case FZ_HTML_STRUCT_H4:
		return FZ_STRUCTURE_H4;
	case FZ_HTML_STRUCT_H5:
		return FZ_STRUCTURE_H5;
	case FZ_HTML_STRUCT_H6:
		return FZ_STRUCTURE_H6;
	case FZ_HTML_STRUCT_L:
		return FZ_STRUCTURE_LIST;
	case FZ_HTML_STRUCT_LI:
		return FZ_STRUCTURE_LISTITEM;
	case FZ_HTML_STRUCT_TABLE:
		return FZ_STRUCTURE_TABLE;
	case FZ_HTML_STRUCT_TR:
		return FZ_STRUCTURE_TR;
	case FZ_HTML_STRUCT_TH:
		return FZ_STRUCTURE_TH;
	case FZ_HTML_STRUCT_TD:
		return FZ_STRUCTURE_TD;
	case FZ_HTML_STRUCT_THEAD:
		return FZ_STRUCTURE_THEAD;
	case FZ_HTML_STRUCT_TBODY:
		return FZ_STRUCTURE_TBODY;
	case FZ_HTML_STRUCT_TFOOT:
		return FZ_STRUCTURE_TFOOT;
	default:
		return FZ_STRUCTURE_INVALID;
	}
}

static void
fz_debug_html_box(fz_context *ctx, fz_html_box *box, int level)
{
	while (box)
	{
		indent(level);
		printf("box ");
		switch (box->type) {
		case BOX_BLOCK: printf("block"); break;
		case BOX_FLOW: printf("flow"); break;
		case BOX_INLINE: printf("inline"); break;
		case BOX_TABLE: printf("table"); break;
		case BOX_TABLE_ROW: printf("table-row"); break;
		case BOX_TABLE_CELL: printf("table-cell"); break;
		}

#ifndef NDEBUG
		printf(" <%s>", box->tag);
#endif
		// printf(" em=%g", box->em);
		// printf(" x=%g y=%g w=%g b=%g", box->x, box->y, box->w, box->b);
		if (box->structure != FZ_HTML_STRUCT_UNKNOWN)
			printf(" struct=(%s)", fz_html_structure_to_string(box->structure));

		if (box->is_first_flow)
			printf(" is-first-flow");
		if (box->list_item)
			printf(" list=%d", box->list_item);
		if (box->id)
			printf(" id=(%s)", box->id);
		if (box->href)
			printf(" href=(%s)", box->href);
		printf("\n");

		if (box->type == BOX_BLOCK || box->type == BOX_TABLE) {
			indent(level+1);
			printf(">margin=(%g %g %g %g)\n", box->u.block.margin[0], box->u.block.margin[1], box->u.block.margin[2], box->u.block.margin[3]);
			//indent(level+1);
			//printf(">padding=(%g %g %g %g)\n", box->u.block.padding[0], box->u.block.padding[1], box->u.block.padding[2], box->u.block.padding[3]);
			//indent(level+1);
			//printf(">border=(%g %g %g %g)\n", box->u.block.border[0], box->u.block.border[1], box->u.block.border[2], box->u.block.border[3]);
		}

		if (box->down)
			fz_debug_html_box(ctx, box->down, level + 1);
		if (box->type == BOX_FLOW) {
			indent(level+1);
			printf("flow\n");
			fz_debug_html_flow(ctx, box->u.flow.head, level + 2);
		}

		box = box->next;
	}
}

void
fz_debug_html(fz_context *ctx, fz_html_box *box)
{
	fz_debug_html_box(ctx, box, 0);
}

static size_t
fz_html_size(fz_context *ctx, fz_html *html)
{
	return html ? fz_pool_size(ctx, html->tree.pool) : 0;
}

/* Magic to make html storable. */
typedef struct {
	int refs;
	void *doc;
	int chapter_num;
} fz_html_key;

static int
fz_make_hash_html_key(fz_context *ctx, fz_store_hash *hash, void *key_)
{
	fz_html_key *key = (fz_html_key *)key_;
	hash->u.pi.ptr = key->doc;
	hash->u.pi.i = key->chapter_num;
	return 1;
}

static void *
fz_keep_html_key(fz_context *ctx, void *key_)
{
	fz_html_key *key = (fz_html_key *)key_;
	return fz_keep_imp(ctx, key, &key->refs);
}

static void
fz_drop_html_key(fz_context *ctx, void *key_)
{
	fz_html_key *key = (fz_html_key *)key_;
	if (fz_drop_imp(ctx, key, &key->refs))
	{
		fz_free(ctx, key);
	}
}

static int
fz_cmp_html_key(fz_context *ctx, void *k0_, void *k1_)
{
	fz_html_key *k0 = (fz_html_key *)k0_;
	fz_html_key *k1 = (fz_html_key *)k1_;
	return k0->doc == k1->doc && k0->chapter_num == k1->chapter_num;
}

static void
fz_format_html_key(fz_context *ctx, char *s, size_t n, void *key_)
{
	fz_html_key *key = (fz_html_key *)key_;
	fz_snprintf(s, n, "(html doc=%p, ch=%d)", key->doc, key->chapter_num);
}

static const fz_store_type fz_html_store_type =
{
	"fz_html",
	fz_make_hash_html_key,
	fz_keep_html_key,
	fz_drop_html_key,
	fz_cmp_html_key,
	fz_format_html_key,
	NULL
};

fz_html *fz_store_html(fz_context *ctx, fz_html *html, void *doc, int chapter)
{
	fz_html_key *key = NULL;
	fz_html *other_html;

	/* Stick the parsed html in the store */
	fz_var(key);

	fz_try(ctx)
	{
		key = fz_malloc_struct(ctx, fz_html_key);
		key->refs = 1;
		key->doc = doc;
		key->chapter_num = chapter;
		other_html = fz_store_item(ctx, key, html, fz_html_size(ctx, html), &fz_html_store_type);
		if (other_html)
		{
			fz_drop_html(ctx, html);
			html = other_html;
		}
	}
	fz_always(ctx)
		fz_drop_html_key(ctx, key);
	fz_catch(ctx)
	{
		/* Do nothing */
	}

	return html;
}

fz_html *fz_find_html(fz_context *ctx, void *doc, int chapter)
{
	fz_html_key key;

	key.refs = 1;
	key.doc = doc;
	key.chapter_num = chapter;
	return fz_find_item(ctx, &fz_drop_html_imp, &key, &fz_html_store_type);
}

static int
html_filter_store(fz_context *ctx, void *doc, void *key_)
{
	fz_html_key *key = (fz_html_key *)key_;

	return (doc == key->doc);
}

void fz_purge_stored_html(fz_context *ctx, void *doc)
{
	fz_filter_store(ctx, html_filter_store, doc, &fz_html_store_type);
}

static void
convert_to_boxes(fz_context *ctx, fz_story *story)
{
	warning_save saved = { 0 };

	if (story->dom == NULL)
		return;

	fz_var(saved);

	fz_try(ctx)
	{
		redirect_warnings_to_buffer(ctx, story->warnings, &saved);
		xml_to_boxes(ctx, story->font_set, story->zip, ".", story->user_css, story->dom, &story->tree, NULL, 0, 0);
		fz_drop_xml(ctx, story->dom);
		story->dom = NULL;
	}
	fz_always(ctx)
	{
		restore_warnings(ctx, &saved);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);
}

int fz_place_story(fz_context *ctx, fz_story *story, fz_rect where, fz_rect *filled)
{
	float w, h;

	if (filled)
		*filled = fz_empty_rect;

	if (story == NULL || story->complete)
		return 0;

	/* Convert from XML to box model on the first attempt to place.
	 * The DOM is unusable from here on in. */
	convert_to_boxes(ctx, story);

	w = where.x1 - where.x0;
	h = where.y1 - where.y0;
	/* Confusingly, we call the layout using restart_draw, not restart_place,
	 * because we don't want to destroy the current values in restart_place
	 * in case we have to retry later. This means the values are left in
	 * the correct struct though! */
	story->restart_draw.start = story->restart_place.start;
	story->restart_draw.start_flow = story->restart_place.start_flow;
	story->restart_draw.end = NULL;
	story->restart_draw.end_flow = NULL;
	story->bbox = where;
	fz_restartable_layout_html(ctx, &story->tree, where.x0, where.y0, w, h, story->em, &story->restart_draw);
	story->restart_draw.start = story->restart_place.start;
	story->restart_draw.start_flow = story->restart_place.start_flow;

	if (filled)
	{
		fz_html_box *b = story->tree.root;
		filled->x0 = b->s.layout.x - b->u.block.margin[L] - b->u.block.border[L] - b->u.block.padding[L];
		filled->x1 = b->s.layout.w + b->u.block.margin[R] + b->u.block.border[R] + b->u.block.padding[R] + b->s.layout.x;
		filled->y0 = b->s.layout.y - b->u.block.margin[T] - b->u.block.border[T] - b->u.block.padding[T];
		filled->y1 = b->s.layout.b + b->u.block.margin[B] + b->u.block.border[B] + b->u.block.padding[B];
	}

#ifndef NDEBUG
	if (fz_atoi(getenv("FZ_DEBUG_HTML")))
		fz_debug_html(ctx, story->tree.root);
#endif

	return story->restart_draw.end != NULL;
}

const char *
fz_story_warnings(fz_context *ctx, fz_story *story)
{
	unsigned char *data;

	if (!story)
		return NULL;

	convert_to_boxes(ctx, story);

	fz_terminate_buffer(ctx, story->warnings);

	if (fz_buffer_storage(ctx, story->warnings, &data) == 0)
		return NULL;

	return (const char *)data;
}
