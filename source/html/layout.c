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
	float padding[4];
	float border[4];
	float margin[4];

	fz_xml *node;
	const char *text;

	struct box *up, *down, *last, *next;
};

struct box *new_box(fz_context *ctx, struct box *root, int type, struct computed_style *cstyle, fz_xml *node)
{
	struct box *box;
	int i;

	box = fz_malloc_struct(ctx, struct box);
	box->type = type;
	box->x = box->y = 0;
	box->w = box->h = 0;
	for (i = 0; i < 4; ++i)
	{
		box->padding[i] = cstyle->padding[i];
		box->margin[i] = cstyle->margin[i];
		box->border[i] = cstyle->border_width[i];
	}

	box->node = node;

	box->up = root;
	box->last = NULL;
	box->down = NULL;
	box->next = NULL;

	if (root)
	{
		if (!root->last)
		{
			root->down = root->last = box;
		}
		else
		{
			root->last->next = box;
			root->last = box;
		}
	}

	return box;
}

static struct box *new_block_box(fz_context *ctx, struct box *box, struct computed_style *cstyle, fz_xml *node)
{
	if (box->type == BOX_BLOCK)
	{
		box = new_box(ctx, box, BOX_BLOCK, cstyle, node);
	}
	else if (box->type == BOX_ANONYMOUS)
	{
		fz_warn(ctx, "block-level box inside anonymous box");
		while (box->type != BOX_BLOCK)
			box = box->up;
		box = new_box(ctx, box, BOX_BLOCK, cstyle, node);
	}
	else if (box->type == BOX_INLINE)
	{
		fz_warn(ctx, "block-level box inside inline box");
		while (box->type != BOX_BLOCK)
			box = box->up;
		box = new_box(ctx, box, BOX_BLOCK, cstyle, node);
	}
	return box;
}

static struct box *new_inline_box(fz_context *ctx, struct box *box, struct computed_style *cstyle, fz_xml *node)
{
	if (box->type == BOX_BLOCK)
	{
		if (box->last && box->last->type == BOX_ANONYMOUS)
			box = box->last;
		else
			box = new_box(ctx, box, BOX_ANONYMOUS, cstyle, NULL);
		box = new_box(ctx, box, BOX_INLINE, cstyle, node);
	}
	else if (box->type == BOX_ANONYMOUS)
	{
		box = new_box(ctx, box, BOX_INLINE, cstyle, node);
	}
	else if (box->type == BOX_INLINE)
	{
		box = new_box(ctx, box, BOX_INLINE, cstyle, node);
	}
	return box;
}

static void layout_tree(fz_context *ctx, fz_xml *node, struct box *box, struct style *up_style, struct rule *rule)
{
	struct style style;
	struct computed_style cstyle;
	struct box *save_box;

	while (node)
	{
		style.up = up_style;
		style.count = 0;

		if (fz_xml_tag(node))
		{
			apply_styles(ctx, &style, rule, node);
			compute_style(&cstyle, &style);
			// print_style(&cstyle);

			// TOOD: <br>
			// TODO: <img>

			if (cstyle.display != NONE)
			{
				save_box = box;

				if (cstyle.display == BLOCK)
				{
					box = new_block_box(ctx, box, &cstyle, node);
				}
				else if (cstyle.display == INLINE)
				{
					box = new_inline_box(ctx, box, &cstyle, node);
				}
				else
				{
					fz_warn(ctx, "unknown box display type");
					box = new_box(ctx, box, BOX_BLOCK, &cstyle, node);
				}

				if (fz_xml_down(node))
					layout_tree(ctx, fz_xml_down(node), box, &style, rule);

				box = save_box;
			}
		}
		else
		{
			compute_style(&cstyle, &style);
			new_inline_box(ctx, box, &cstyle, node);
		}

		node = fz_xml_next(node);
	}
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
		if (box->node) {
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
		if (text) {
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
	for (node = root; node; node = fz_xml_next(node)) {
		const char *tag = fz_xml_tag(node);
#if 0
		if (tag && !strcmp(tag, "link")) {
			char *rel = fz_xml_att(node, "rel");
			if (rel && !strcasecmp(rel, "stylesheet")) {
				char *type = fz_xml_att(node, "type");
				if ((type && !strcmp(type, "text/css")) || !type) {
					char *href = fz_xml_att(node, "href");
					strcpy(filename, dirname);
					strcat(filename, href);
					css = css_parse_file(css, filename);
				}
			}
		}
#endif
		if (tag && !strcmp(tag, "style")) {
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
	struct style style;
	struct computed_style cstyle;

#if 0
	strcpy(dirname, argv[i]);
	s = strrchr(dirname, '/');
	if (!s) s = strrchr(dirname, '\\');
	if (s) s[1] = 0;
	else strcpy(dirname, "./");
#endif

	css = fz_parse_css(doc->ctx, NULL, default_css);
	css = load_css(doc->ctx, css, doc->root);

	print_rules(css);

	style.up = NULL;
	style.count = 0;
	compute_style(&cstyle, &style);
	root_box = new_box(doc->ctx, NULL, BOX_BLOCK, &cstyle, NULL);

	layout_tree(doc->ctx, doc->root, root_box, NULL, css);
	print_box(doc->ctx, root_box, 0);
}
