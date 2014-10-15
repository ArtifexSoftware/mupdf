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

char dirname[2048];
char filename[2048];

static char *concat_text(fz_xml *root)
{
	fz_xml  *node;
	int i = 0, n = 1;
	char *s;
	for (node = fz_xml_down(root); node; node = fz_xml_next(node))
	{
		const char *text = fz_xml_text(node);
		n += text ? strlen(text) : 0;
	}
	s = malloc(n);
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
printf("found inline style sheet!\n");
			char *s = concat_text(node);
printf("'%s'\n", s);
			css = fz_parse_css(ctx, css, s);
		}
		if (fz_xml_down(node))
			css = load_css(ctx, css, fz_xml_down(node));
	}
	return css;
}

static void layout_text(struct rule *rule, struct style *style, fz_xml *node)
{
	printf("%s\n", fz_xml_text(node));
}

static void layout_tree(fz_context *ctx, struct rule *rule, struct style *up, fz_xml *node)
{
	while (node)
	{
		struct style style;
		style.up = up;
		style.count = 0;

		if (fz_xml_tag(node))
		{
			struct computed_style cstyle;
			const char *s;

			printf("open '%s'\n", fz_xml_tag(node));
			apply_styles(&style, rule, node);

			s = fz_xml_att(node, "style");
			if (s)
			{
				struct property *props = fz_parse_css_properties(ctx, s);
				apply_inline_style(&style, props);
				// free props
			}

			compute_style(&cstyle, &style);
			print_style(&cstyle);
		}
		else
			layout_text(rule, &style, node);

		// TOOD: <br>
		// TODO: <img>

		if (fz_xml_down(node))
			layout_tree(ctx, rule, &style, fz_xml_down(node));

		printf("end\n");
		node = fz_xml_next(node);
	}
}

void
html_layout_document(html_document *doc, float w, float h)
{
	struct rule *css = NULL;

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

	layout_tree(doc->ctx, css, NULL, doc->root);
}
