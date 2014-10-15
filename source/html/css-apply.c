#include "mupdf/html.h"

static void add_property(struct style *style, const char *name, struct value *value, int spec);

struct rule *
new_rule(struct selector *selector, struct property *declaration)
{
	struct rule *rule;

	rule = malloc(sizeof(struct rule));
	rule->selector = selector;
	rule->declaration = declaration;
	rule->next = NULL;

	return rule;
}

struct selector *
new_selector(const char *name)
{
	struct selector *sel;

	sel = malloc(sizeof(struct selector));
	sel->name = name ? strdup(name) : NULL;
	sel->combine = 0;
	sel->cond = NULL;
	sel->left = NULL;
	sel->right = NULL;
	sel->next = NULL;

	return sel;
}

struct condition *
new_condition(int type, const char *key, const char *val)
{
	struct condition *cond;

	cond = malloc(sizeof(struct condition));
	cond->type = type;
	cond->key = key ? strdup(key) : NULL;
	cond->val = val ? strdup(val) : NULL;
	cond->next = NULL;

	return cond;
}

struct property *
new_property(const char *name, struct value *value, int spec)
{
	struct property *prop;

	prop = malloc(sizeof(struct property));
	prop->name = strdup(name);
	prop->value = value;
	prop->spec = spec;
	prop->next = NULL;

	return prop;
}

struct value *
new_value(int type, const char *data)
{
	struct value *val;

	val = malloc(sizeof(struct value));
	val->type = type;
	val->data = strdup(data);
	val->args = NULL;
	val->next = NULL;

	return val;
}

/*
 * Compute specificity
 */

static int
count_condition_ids(struct condition *cond)
{
	int n = 0;
	while (cond)
	{
		if (cond->type == '#')
			n ++;
		cond = cond->next;
	}
	return n;
}

static int
count_selector_ids(struct selector *sel)
{
	int n = count_condition_ids(sel->cond);
	if (sel->left && sel->right)
	{
		n += count_selector_ids(sel->left);
		n += count_selector_ids(sel->right);
	}
	return n;
}

static int
count_condition_atts(struct condition *cond)
{
	int n = 0;
	while (cond)
	{
		if (cond->type != '#' && cond->type != ':')
			n ++;
		cond = cond->next;
	}
	return n;
}

static int
count_selector_atts(struct selector *sel)
{
	int n = count_condition_atts(sel->cond);
	if (sel->left && sel->right)
	{
		n += count_selector_atts(sel->left);
		n += count_selector_atts(sel->right);
	}
	return n;
}

static int
count_condition_names(struct condition *cond)
{
	int n = 0;
	while (cond)
	{
		if (cond->type == ':')
			n ++;
		cond = cond->next;
	}
	return n;
}

static int
count_selector_names(struct selector *sel)
{
	int n = count_condition_names(sel->cond);
	if (sel->left && sel->right)
	{
		n += count_selector_names(sel->left);
		n += count_selector_names(sel->right);
	}
	else if (sel->name)
	{
		n ++;
	}
	return n;
}

#define INLINE_SPECIFICITY 1000

int
selector_specificity(struct selector *sel)
{
	int b = count_selector_ids(sel);
	int c = count_selector_atts(sel);
	int d = count_selector_names(sel);
	return b * 100 + c * 10 + d;
}

/*
 * Pretty printing
 */

void
print_value(struct value *val)
{
	printf("%s", val->data);
	if (val->args)
	{
		printf("(");
		print_value(val->args);
		printf(")");
	}
	if (val->next)
	{
		printf(" ");
		print_value(val->next);
	}
}

void
print_property(struct property *prop)
{
	printf("\t%s: ", prop->name);
	print_value(prop->value);
	printf(" !%d;\n", prop->spec);
}

void
print_condition(struct condition *cond)
{
	if (cond->type == '=')
		printf("[%s=%s]", cond->key, cond->val);
	else if (cond->type == '[')
		printf("[%s]", cond->key);
	else
		printf("%c%s", cond->type, cond->val);
	if (cond->next)
		print_condition(cond->next);
}

void
print_selector(struct selector *sel)
{
	if (sel->combine)
	{
putchar('(');
		print_selector(sel->left);
		if (sel->combine == ' ')
			printf(" ");
		else
			printf(" %c ", sel->combine);
		print_selector(sel->right);
putchar(')');
	}
	else if (sel->name)
		printf("%s", sel->name);
	else
		printf("*");
	if (sel->cond)
	{
		print_condition(sel->cond);
	}
}

void
print_rule(struct rule *rule)
{
	struct selector *sel;
	struct property *prop;

	for (sel = rule->selector; sel; sel = sel->next)
	{
		print_selector(sel);
		printf(" !%d", selector_specificity(sel));
		if (sel->next)
			printf(", ");
	}

	printf("\n{\n");
	for (prop = rule->declaration; prop; prop = prop->next)
	{
		print_property(prop);
	}
	printf("}\n");
}

void
print_rules(struct rule *rule)
{
	while (rule)
	{
		print_rule(rule);
		rule = rule->next;
	}
}

/*
 * Selector matching
 */

int
match_id_condition(fz_xml *node, const char *p)
{
	const char *s = fz_xml_att(node, "id");
	if (s && !strcmp(s, p))
		return 1;
	return 0;
}

int
match_class_condition(fz_xml *node, const char *p)
{
	const char *s = fz_xml_att(node, "class");
	char buf[1024];
	if (s) {
		strcpy(buf, s);
		s = strtok(buf, " ");
		while (s) {
			if (!strcmp(s, p))
				return 1;
			s = strtok(NULL, " ");
		}
	}
	return 0;
}

int
match_condition(struct condition *cond, fz_xml *node)
{
	if (!cond)
		return 1;

	switch (cond->type) {
	default: return 0;
	case ':': return 0; /* don't support pseudo-classes */
	case '#': if (!match_id_condition(node, cond->val)) return 0; break;
	case '.': if (!match_class_condition(node, cond->val)) return 0; break;
	}

	return match_condition(cond->next, node);
}

int
match_selector(struct selector *sel, fz_xml *node)
{
	if (!node)
		return 0;

	if (sel->combine)
	{
		/* descendant */
		if (sel->combine == ' ')
		{
			fz_xml *parent = fz_xml_up(node);
			while (parent)
			{
				if (match_selector(sel->left, parent))
					if (match_selector(sel->right, node))
						return 1;
				parent = fz_xml_up(parent);
			}
			return 0;
		}

		/* child */
		if (sel->combine == '>')
		{
			fz_xml *parent = fz_xml_up(node);
			if (!parent)
				return 0;
			if (!match_selector(sel->left, parent))
				return 0;
			if (!match_selector(sel->right, node))
				return 0;
		}

		/* adjacent */
		if (sel->combine == '+')
		{
			fz_xml *prev = fz_xml_prev(node);
			while (prev && !fz_xml_tag(prev) && fz_xml_prev(prev))
				prev = fz_xml_prev(prev);
			if (!prev)
				return 0;
			if (!fz_xml_tag(prev))
				return 0;
			if (!match_selector(sel->left, prev))
				return 0;
			if (!match_selector(sel->right, node))
				return 0;
		}
	}

	if (sel->name)
	{
		if (strcmp(sel->name, fz_xml_tag(node)))
			return 0;
	}

	if (sel->cond)
	{
		if (!match_condition(sel->cond, node))
			return 0;
	}

	return 1;
}

/*
 * Annotating nodes with properties and expanding shorthand forms.
 */

static int
count_values(struct value *value)
{
	int n = 0;
	while (value)
	{
		n++;
		value = value->next;
	}
	return n;
}

static void
add_shorthand_margin(struct style *style, struct value *value, int spec)
{
	int n = count_values(value);

	if (n == 1)
	{
		add_property(style, "margin-top", value, spec);
		add_property(style, "margin-right", value, spec);
		add_property(style, "margin-bottom", value, spec);
		add_property(style, "margin-left", value, spec);
	}

	if (n == 2)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);

		add_property(style, "margin-top", a, spec);
		add_property(style, "margin-right", b, spec);
		add_property(style, "margin-bottom", a, spec);
		add_property(style, "margin-left", b, spec);
	}

	if (n == 3)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);
		struct value *c = new_value(value->next->next->type, value->next->next->data);

		add_property(style, "margin-top", a, spec);
		add_property(style, "margin-right", b, spec);
		add_property(style, "margin-bottom", c, spec);
		add_property(style, "margin-left", b, spec);
	}

	if (n == 4)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);
		struct value *c = new_value(value->next->next->type, value->next->next->data);
		struct value *d = new_value(value->next->next->next->type, value->next->next->next->data);

		add_property(style, "margin-top", a, spec);
		add_property(style, "margin-right", b, spec);
		add_property(style, "margin-bottom", c, spec);
		add_property(style, "margin-left", d, spec);
	}
}

static void
add_shorthand_padding(struct style *style, struct value *value, int spec)
{
	int n = count_values(value);

	if (n == 1)
	{
		add_property(style, "padding-top", value, spec);
		add_property(style, "padding-right", value, spec);
		add_property(style, "padding-bottom", value, spec);
		add_property(style, "padding-left", value, spec);
	}

	if (n == 2)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);

		add_property(style, "padding-top", a, spec);
		add_property(style, "padding-right", b, spec);
		add_property(style, "padding-bottom", a, spec);
		add_property(style, "padding-left", b, spec);
	}

	if (n == 3)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);
		struct value *c = new_value(value->next->next->type, value->next->next->data);

		add_property(style, "padding-top", a, spec);
		add_property(style, "padding-right", b, spec);
		add_property(style, "padding-bottom", c, spec);
		add_property(style, "padding-left", b, spec);
	}

	if (n == 4)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);
		struct value *c = new_value(value->next->next->type, value->next->next->data);
		struct value *d = new_value(value->next->next->next->type, value->next->next->next->data);

		add_property(style, "padding-top", a, spec);
		add_property(style, "padding-right", b, spec);
		add_property(style, "padding-bottom", c, spec);
		add_property(style, "padding-left", d, spec);
	}
}

static void
add_shorthand_border_width(struct style *style, struct value *value, int spec)
{
	int n = count_values(value);

	if (n == 1)
	{
		add_property(style, "border-top-width", value, spec);
		add_property(style, "border-right-width", value, spec);
		add_property(style, "border-bottom-width", value, spec);
		add_property(style, "border-left-width", value, spec);
	}

	if (n == 2)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);

		add_property(style, "border-top-width", a, spec);
		add_property(style, "border-right-width", b, spec);
		add_property(style, "border-bottom-width", a, spec);
		add_property(style, "border-left-width", b, spec);
	}

	if (n == 3)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);
		struct value *c = new_value(value->next->next->type, value->next->next->data);

		add_property(style, "border-top-width", a, spec);
		add_property(style, "border-right-width", b, spec);
		add_property(style, "border-bottom-width", c, spec);
		add_property(style, "border-left-width", b, spec);
	}

	if (n == 4)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);
		struct value *c = new_value(value->next->next->type, value->next->next->data);
		struct value *d = new_value(value->next->next->next->type, value->next->next->next->data);

		add_property(style, "border-top-width", a, spec);
		add_property(style, "border-right-width", b, spec);
		add_property(style, "border-bottom-width", c, spec);
		add_property(style, "border-left-width", d, spec);
	}
}

static void
add_property(struct style *style, const char *name, struct value *value, int spec)
{
	int i;

	if (!strcmp(name, "margin"))
	{
		add_shorthand_margin(style, value, spec);
		return;
	}
	if (!strcmp(name, "padding"))
	{
		add_shorthand_padding(style, value, spec);
		return;
	}
	if (!strcmp(name, "border-width"))
	{
		add_shorthand_border_width(style, value, spec);
		return;
	}

	/* TODO: border-color */
	/* TODO: border-style */
	/* TODO: border */
	/* TODO: font */
	/* TODO: list-style */
	/* TODO: background */

	for (i = 0; i < style->count; ++i)
	{
		if (!strcmp(style->prop[i].name, name))
		{
			if (style->prop[i].spec <= spec)
			{
				style->prop[i].value = value;
				style->prop[i].spec = spec;
			}
			return;
		}
	}

	if (style->count + 1 >= nelem(style->prop))
	{
		// fz_warn(ctx, "too many css properties");
		return;
	}

	style->prop[style->count].name = name;
	style->prop[style->count].value = value;
	style->prop[style->count].spec = spec;
	++style->count;
}

void
apply_styles(struct style *style, struct rule *rule, fz_xml *node)
{
	struct selector *sel;
	struct property *prop;

	while (rule)
	{
		sel = rule->selector;
		while (sel)
		{
			if (match_selector(sel, node))
			{
				for (prop = rule->declaration; prop; prop = prop->next)
					add_property(style, prop->name, prop->value, selector_specificity(sel));
				break;
			}
			sel = sel->next;
		}
		rule = rule->next;
	}
}

void
apply_inline_style(struct style *style, struct property *prop)
{
	while (prop)
	{
		add_property(style, prop->name, prop->value, INLINE_SPECIFICITY);
		prop = prop->next;
	}
}

static const char *inherit_list[] = {
	"color", "direction",
	"font-family", "font-size", "font-style", "font-variant", "font-weight",
	"letter-spacing", "line-height",
	"list-style-image", "list-style-position", "list-style-type",
	"orphans", "quotes", "text-align", "text-indent", "text-transform",
	"visibility", "white-space", "widows", "word-spacing",

	/* this is not supposed to be inherited: */
	"vertical-align",
};

static struct value *
get_raw_property(struct style *node, const char *name)
{
	int i;
	for (i = 0; i < node->count; ++i)
		if (!strcmp(node->prop[i].name, name))
			return node->prop[i].value;
	return NULL;
}

static int
should_inherit_property(const char *name)
{
	int l = 0;
	int r = nelem(inherit_list) - 1;
	while (l <= r)
	{
		int m = (l + r) >> 1;
		int c = strcmp(name, inherit_list[m]);
		if (c < 0)
			r = m - 1;
		else if (c > 0)
			l = m + 1;
		else
			return 1;
	}
	return 0;
}

static struct value *
get_style_property(struct style *node, const char *name)
{
	struct value *value;

	value = get_raw_property(node, name);
	if (node->up)
	{
		if (value && !strcmp(value->data, "inherit"))
			return get_style_property(node->up, name);
		if (!value && should_inherit_property(name))
			return get_style_property(node->up, name);
	}
	return value;
}

static const char *
get_style_property_string(struct style *node, const char *name, const char *initial)
{
	struct value *value;
	value = get_style_property(node, name);
	if (!value)
		return initial;
	return value->data;
}

static float
compute_number(struct value *value, float em, float hundred, float scale, float initial)
{
	char *p;

	if (!value)
		return initial;

	if (value->type == CSS_PERCENT)
		return strtof(value->data, &p) * hundred / 100;

	if (value->type == CSS_NUMBER)
		return strtof(value->data, &p) * scale;

	if (value->type == CSS_LENGTH)
	{
		float x = strtof(value->data, &p);

		if (p[0] == 'e' && p[1] == 'm')
			return x * em;
		if (p[0] == 'e' && p[1] == 'x')
			return x * em / 2;

		if (p[0] == 'i' && p[1] == 'n')
			return x * 72;
		if (p[0] == 'c' && p[1] == 'm')
			return x * 7200 / 254;
		if (p[0] == 'm' && p[1] == 'm')
			return x * 720 / 254;
		if (p[0] == 'p' && p[1] == 'c')
			return x * 12;

		if (p[0] == 'p' && p[1] == 't')
			return x;
		if (p[0] == 'p' && p[1] == 'x')
			return x;

		return x;
	}

	return initial;
}

void
compute_style(struct computed_style *style, struct style *node)
{
	struct value *value;
	float em = 12;
	float hundred = 100;

	memset(style, 0, sizeof *style);

	style->display = INLINE;
	style->position = STATIC;
	style->text_align = LEFT;
	style->font_size = 12;

	value = get_style_property(node, "display");
	if (value)
	{
		if (!strcmp(value->data, "none"))
			style->display = NONE;
		if (!strcmp(value->data, "inline"))
			style->display = INLINE;
		if (!strcmp(value->data, "block"))
			style->display = BLOCK;
		if (!strcmp(value->data, "list-item"))
			style->display = LIST_ITEM;
	}

	value = get_style_property(node, "position");
	if (value)
	{
		if (!strcmp(value->data, "static"))
			style->position = STATIC;
		if (!strcmp(value->data, "relative"))
			style->position = RELATIVE;
		if (!strcmp(value->data, "absolute"))
			style->position = ABSOLUTE;
		if (!strcmp(value->data, "fixed"))
			style->position = FIXED;
	}

	value = get_style_property(node, "text-align");
	if (value)
	{
		if (!strcmp(value->data, "left"))
			style->text_align = LEFT;
		if (!strcmp(value->data, "right"))
			style->text_align = RIGHT;
		if (!strcmp(value->data, "center"))
			style->text_align = CENTER;
		if (!strcmp(value->data, "justify"))
			style->text_align = JUSTIFY;
	}

	value = get_style_property(node, "vertical-align");
	if (value)
	{
		if (!strcmp(value->data, "super"))
			style->vertical_align = 1;
		if (!strcmp(value->data, "sub"))
			style->vertical_align = -1;
	}

	value = get_style_property(node, "font-size");
	if (value) {
		if (!strcmp(value->data, "xx-large")) style->font_size = 20;
		else if (!strcmp(value->data, "x-large")) style->font_size = 16;
		else if (!strcmp(value->data, "large")) style->font_size = 14;
		else if (!strcmp(value->data, "medium")) style->font_size = 12;
		else if (!strcmp(value->data, "small")) style->font_size = 10;
		else if (!strcmp(value->data, "x-small")) style->font_size = 8;
		else if (!strcmp(value->data, "xx-small")) style->font_size = 6;
		else if (!strcmp(value->data, "larger")) style->font_size = em + 2;
		else if (!strcmp(value->data, "smaller")) style->font_size = em - 2;
		else style->font_size = compute_number(value, em, em, 1, 12);
	} else {
		style->font_size = 12;
	}
	em = style->font_size;

	value = get_style_property(node, "line-height");
	style->line_height = compute_number(value, em, em, em, 1.2 * em);

	value = get_style_property(node, "text-indent");
	style->text_indent = compute_number(value, em, hundred, 1, 0);

	value = get_style_property(node, "margin-top");
	style->margin[0] = compute_number(value, em, hundred, 1, 0);
	value = get_style_property(node, "margin-right");
	style->margin[1] = compute_number(value, em, hundred, 1, 0);
	value = get_style_property(node, "margin-bottom");
	style->margin[2] = compute_number(value, em, hundred, 1, 0);
	value = get_style_property(node, "margin-left");
	style->margin[3] = compute_number(value, em, hundred, 1, 0);

	value = get_style_property(node, "padding-top");
	style->padding[0] = compute_number(value, em, hundred, 1, 0);
	value = get_style_property(node, "padding-right");
	style->padding[1] = compute_number(value, em, hundred, 1, 0);
	value = get_style_property(node, "padding-bottom");
	style->padding[2] = compute_number(value, em, hundred, 1, 0);
	value = get_style_property(node, "padding-left");
	style->padding[3] = compute_number(value, em, hundred, 1, 0);

	{
		const char *font_family = get_style_property_string(node, "font-family", "serif");
		const char *font_variant = get_style_property_string(node, "font-variant", "normal");
		const char *font_style = get_style_property_string(node, "font-style", "normal");
		const char *font_weight = get_style_property_string(node, "font-weight", "normal");

		style->font_family = font_family;

		style->smallcaps = 0;
		if (!strcmp(font_variant, "small-caps"))
			style->smallcaps = 1;

		style->italic = 0;
		if (!strcmp(font_style, "italic") || !strcmp(font_style, "oblique"))
			style->italic = 1;

		style->bold = 0;
		if (!strcmp(font_weight, "bold") || !strcmp(font_weight, "bolder") || atoi(font_weight) > 400)
			style->bold = 1;
	}
}

void
print_style(struct computed_style *style)
{
	printf("style {\n");
	printf("\tdisplay = %d;\n", style->display);
	printf("\tposition = %d;\n", style->position);
	printf("\ttext-align = %d;\n", style->text_align);
	printf("\tfont-family = %s;\n", style->font_family);
	printf("\tfont-weight = %s;\n", style->bold ? "bold" : "normal");
	printf("\tfont-style = %s;\n", style->italic ? "italic" : "normal");
	printf("\tfont-variant = %s;\n", style->smallcaps ? "small-caps" : "normal");
	printf("\tfont-size = %g;\n", style->font_size);
	printf("\tline-height = %g;\n", style->line_height);
	printf("\ttext-indent = %g;\n", style->text_indent);
	printf("\tvertical-align = %d;\n", style->vertical_align);
	printf("\tmargin = %g %g %g %g;\n",
		style->margin[0], style->margin[1], style->margin[2], style->margin[3]);
	printf("\tpadding = %g %g %g %g;\n",
		style->padding[0], style->padding[1], style->padding[2], style->padding[3]);
	printf("}\n");
}
