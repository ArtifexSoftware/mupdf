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
			while (prev && !fz_xml_tag(prev))
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

static const char *border_width_kw[] = {
	"thin", "medium", "thick",
};

static const char *border_style_kw[] = {
	"none", "hidden", "dotted", "dashed", "solid", "double", "groove", "ridge", "inset", "outset",
};

static const char *color_kw[] = {
	"transparent", "maroon", "red", "orange", "yellow", "olive", "purple", "fuchsia", "white",
	"lime", "green", "navy", "blue", "aqua", "teal", "black", "silver", "gray",
};

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
		add_property(style, "border-width-top", value, spec);
		add_property(style, "border-width-right", value, spec);
		add_property(style, "border-width-bottom", value, spec);
		add_property(style, "border-width-left", value, spec);
	}

	if (n == 2)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);

		add_property(style, "border-width-top", a, spec);
		add_property(style, "border-width-right", b, spec);
		add_property(style, "border-width-bottom", a, spec);
		add_property(style, "border-width-left", b, spec);
	}

	if (n == 3)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);
		struct value *c = new_value(value->next->next->type, value->next->next->data);

		add_property(style, "border-width-top", a, spec);
		add_property(style, "border-width-right", b, spec);
		add_property(style, "border-width-bottom", c, spec);
		add_property(style, "border-width-left", b, spec);
	}

	if (n == 4)
	{
		struct value *a = new_value(value->type, value->data);
		struct value *b = new_value(value->next->type, value->next->data);
		struct value *c = new_value(value->next->next->type, value->next->next->data);
		struct value *d = new_value(value->next->next->next->type, value->next->next->next->data);

		add_property(style, "border-width-top", a, spec);
		add_property(style, "border-width-right", b, spec);
		add_property(style, "border-width-bottom", c, spec);
		add_property(style, "border-width-left", d, spec);
	}
}

static void
add_shorthand_border(struct style *style, struct value *value, int spec)
{
	int i;

	while (value)
	{
		if (value->type == CSS_COLOR)
		{
			add_property(style, "border-color", value, spec);
		}
		else if (value->type == CSS_KEYWORD)
		{
			for (i = 0; i < nelem(border_width_kw); ++i)
			{
				if (!strcmp(value->data, border_width_kw[i]))
				{
					add_property(style, "border-width-top", value, spec);
					add_property(style, "border-width-right", value, spec);
					add_property(style, "border-width-bottom", value, spec);
					add_property(style, "border-width-left", value, spec);
					goto next;
				}
			}
			for (i = 0; i < nelem(border_style_kw); ++i)
			{
				if (!strcmp(value->data, border_style_kw[i]))
				{
					add_property(style, "border-style", value, spec);
					goto next;
				}
			}
			for (i = 0; i < nelem(color_kw); ++i)
			{
				if (!strcmp(value->data, color_kw[i]))
				{
					add_property(style, "border-color", value, spec);
					goto next;
				}
			}
		}
		else
		{
			add_property(style, "border-width-top", value, spec);
			add_property(style, "border-width-right", value, spec);
			add_property(style, "border-width-bottom", value, spec);
			add_property(style, "border-width-left", value, spec);
		}
next:
		value = value->next;
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
	if (!strcmp(name, "border"))
	{
		add_shorthand_border(style, value, spec);
		return;
	}

	/* shorthand expansions: */
	/* TODO: border-color */
	/* TODO: border-style */
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
apply_styles(fz_context *ctx, struct style *style, struct rule *rule, fz_xml *node)
{
	struct selector *sel;
	struct property *prop;
	const char *s;

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

	s = fz_xml_att(node, "style");
	if (s)
	{
		prop = fz_parse_css_properties(ctx, s);
		while (prop)
		{
			add_property(style, prop->name, prop->value, INLINE_SPECIFICITY);
			prop = prop->next;
		}
		// TODO: free props
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

static struct number
make_number(float v, int u)
{
	struct number n;
	n.value = v;
	n.unit = u;
	return n;
}

static struct number
number_from_value(struct value *value, float initial, int initial_unit)
{
	char *p;

	if (!value)
		return make_number(initial, initial_unit);

	if (value->type == CSS_PERCENT)
		return make_number(strtof(value->data, NULL), N_PERCENT);

	if (value->type == CSS_NUMBER)
		return make_number(strtof(value->data, NULL), N_NUMBER);

	if (value->type == CSS_LENGTH)
	{
		float x = strtof(value->data, &p);

		if (p[0] == 'e' && p[1] == 'm')
			return make_number(x, N_SCALE);
		if (p[0] == 'e' && p[1] == 'x')
			return make_number(x / 2, N_SCALE);

		if (p[0] == 'i' && p[1] == 'n')
			return make_number(x * 72, N_NUMBER);
		if (p[0] == 'c' && p[1] == 'm')
			return make_number(x * 7200 / 254, N_NUMBER);
		if (p[0] == 'm' && p[1] == 'm')
			return make_number(x * 720 / 254, N_NUMBER);
		if (p[0] == 'p' && p[1] == 'c')
			return make_number(x * 12, N_NUMBER);

		if (p[0] == 'p' && p[1] == 't')
			return make_number(x, N_NUMBER);
		if (p[0] == 'p' && p[1] == 'x')
			return make_number(x, N_NUMBER);

		return make_number(x, N_NUMBER);
	}

	return make_number(initial, initial_unit);
}

static struct number
number_from_property(struct style *node, const char *property, float initial, int initial_unit)
{
	return number_from_value(get_style_property(node, property), initial, initial_unit);
}

static struct number
border_width_from_property(struct style *node, const char *property)
{
	struct value *value = get_style_property(node, property);
	if (value)
	{
		if (!strcmp(value->data, "thin"))
			return make_number(1, N_NUMBER);
		if (!strcmp(value->data, "medium"))
			return make_number(2, N_NUMBER);
		if (!strcmp(value->data, "thick"))
			return make_number(4, N_NUMBER);
		return number_from_value(value, 0, N_NUMBER);
	}
	return make_number(2, N_NUMBER); /* initial: 'medium' */
}

float
from_number(struct number number, float em, float width)
{
	switch (number.unit) {
	default:
	case N_NUMBER: return number.value;
	case N_SCALE: return number.value * em;
	case N_PERCENT: return number.value * 0.01 * width;
	}
}

float
from_number_scale(struct number number, float scale, float em, float width)
{
	switch (number.unit) {
	default:
	case N_NUMBER: return number.value * scale;
	case N_SCALE: return number.value * em;
	case N_PERCENT: return number.value * 0.01 * width;
	}
}

static struct color
make_color(int r, int g, int b, int a)
{
	struct color c;
	c.r = r;
	c.g = g;
	c.b = b;
	c.a = a;
	return c;
}

static int tohex(int c)
{
	if (c - '0' < 10)
		return c - '0';
	return (c | 32) - 'a' + 10;
}

static struct color
color_from_value(struct value *value, struct color initial)
{
	if (!value)
		return initial;
	if (value->type == CSS_COLOR)
	{
		int r = tohex(value->data[0]) * 16 + tohex(value->data[1]);
		int g = tohex(value->data[2]) * 16 + tohex(value->data[3]);
		int b = tohex(value->data[4]) * 16 + tohex(value->data[5]);
		return make_color(r, g, b, 255);
	}
	if (value->type == CSS_KEYWORD)
	{
		if (!strcmp(value->data, "transparent"))
			return make_color(0, 0, 0, 0);
		if (!strcmp(value->data, "maroon"))
			return make_color(0x80, 0x00, 0x00, 255);
		if (!strcmp(value->data, "red"))
			return make_color(0xFF, 0x00, 0x00, 255);
		if (!strcmp(value->data, "orange"))
			return make_color(0xFF, 0xA5, 0x00, 255);
		if (!strcmp(value->data, "yellow"))
			return make_color(0xFF, 0xFF, 0x00, 255);
		if (!strcmp(value->data, "olive"))
			return make_color(0x80, 0x80, 0x00, 255);
		if (!strcmp(value->data, "purple"))
			return make_color(0x80, 0x00, 0x80, 255);
		if (!strcmp(value->data, "fuchsia"))
			return make_color(0xFF, 0x00, 0xFF, 255);
		if (!strcmp(value->data, "white"))
			return make_color(0xFF, 0xFF, 0xFF, 255);
		if (!strcmp(value->data, "lime"))
			return make_color(0x00, 0xFF, 0x00, 255);
		if (!strcmp(value->data, "green"))
			return make_color(0x00, 0x80, 0x00, 255);
		if (!strcmp(value->data, "navy"))
			return make_color(0x00, 0x00, 0x80, 255);
		if (!strcmp(value->data, "blue"))
			return make_color(0x00, 0x00, 0xFF, 255);
		if (!strcmp(value->data, "aqua"))
			return make_color(0x00, 0xFF, 0xFF, 255);
		if (!strcmp(value->data, "teal"))
			return make_color(0x00, 0x80, 0x80, 255);
		if (!strcmp(value->data, "black"))
			return make_color(0x00, 0x00, 0x00, 255);
		if (!strcmp(value->data, "silver"))
			return make_color(0xC0, 0xC0, 0xC0, 255);
		if (!strcmp(value->data, "gray"))
			return make_color(0x80, 0x80, 0x80, 255);
		return make_color(0, 0, 0, 255);
	}
	return initial;
}

static struct color
color_from_property(struct style *node, const char *property, struct color initial)
{
	return color_from_value(get_style_property(node, property), initial);
}

int
get_style_property_display(struct style *node)
{
	struct value *value = get_style_property(node, "display");
	if (value)
	{
		if (!strcmp(value->data, "none"))
			return DIS_NONE;
		if (!strcmp(value->data, "inline"))
			return DIS_INLINE;
		if (!strcmp(value->data, "block"))
			return DIS_BLOCK;
		if (!strcmp(value->data, "list-item"))
			return DIS_LIST_ITEM;
	}
	return DIS_INLINE;
}

int
get_style_property_white_space(struct style *node)
{
	struct value *value = get_style_property(node, "white-space");
	if (value)
	{
		if (!strcmp(value->data, "normal")) return WS_NORMAL;
		if (!strcmp(value->data, "pre")) return WS_PRE;
		if (!strcmp(value->data, "nowrap")) return WS_NOWRAP;
		if (!strcmp(value->data, "pre-wrap")) return WS_PRE_WRAP;
		if (!strcmp(value->data, "pre-line")) return WS_PRE_LINE;
	}
	return WS_NORMAL;
}

void
default_computed_style(struct computed_style *style)
{
	memset(style, 0, sizeof *style);
	style->text_align = TA_LEFT;
	style->vertical_align = 0;
	style->white_space = WS_NORMAL;
	style->font_size = make_number(1, N_SCALE);
}

void
compute_style(html_document *doc, struct computed_style *style, struct style *node)
{
	struct value *value;

	struct color black = { 0, 0, 0, 255 };
	struct color transparent = { 0, 0, 0, 0 };

	default_computed_style(style);

	style->white_space = get_style_property_white_space(node);

	value = get_style_property(node, "text-align");
	if (value)
	{
		if (!strcmp(value->data, "left"))
			style->text_align = TA_LEFT;
		if (!strcmp(value->data, "right"))
			style->text_align = TA_RIGHT;
		if (!strcmp(value->data, "center"))
			style->text_align = TA_CENTER;
		if (!strcmp(value->data, "justify"))
			style->text_align = TA_JUSTIFY;
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
	if (value)
	{
		if (!strcmp(value->data, "xx-large")) style->font_size = make_number(20, N_NUMBER);
		else if (!strcmp(value->data, "x-large")) style->font_size = make_number(16, N_NUMBER);
		else if (!strcmp(value->data, "large")) style->font_size = make_number(14, N_NUMBER);
		else if (!strcmp(value->data, "medium")) style->font_size = make_number(12, N_NUMBER);
		else if (!strcmp(value->data, "small")) style->font_size = make_number(10, N_NUMBER);
		else if (!strcmp(value->data, "x-small")) style->font_size = make_number(8, N_NUMBER);
		else if (!strcmp(value->data, "xx-small")) style->font_size = make_number(6, N_NUMBER);
		else if (!strcmp(value->data, "larger")) style->font_size = make_number(1.25f, N_SCALE);
		else if (!strcmp(value->data, "smaller")) style->font_size = make_number(0.8f, N_SCALE);
		else style->font_size = number_from_value(value, 12, N_NUMBER);
	}
	else
	{
		style->font_size = make_number(1, N_SCALE);
	}

	style->line_height = number_from_property(node, "line-height", 1.2, N_SCALE);

	style->text_indent = number_from_property(node, "text-indent", 0, N_NUMBER);

	style->margin[0] = number_from_property(node, "margin-top", 0, N_NUMBER);
	style->margin[1] = number_from_property(node, "margin-right", 0, N_NUMBER);
	style->margin[2] = number_from_property(node, "margin-bottom", 0, N_NUMBER);
	style->margin[3] = number_from_property(node, "margin-left", 0, N_NUMBER);

	style->padding[0] = number_from_property(node, "padding-top", 0, N_NUMBER);
	style->padding[1] = number_from_property(node, "padding-right", 0, N_NUMBER);
	style->padding[2] = number_from_property(node, "padding-bottom", 0, N_NUMBER);
	style->padding[3] = number_from_property(node, "padding-left", 0, N_NUMBER);

	style->border_width[0] = border_width_from_property(node, "border-width-top");
	style->border_width[1] = border_width_from_property(node, "border-width-right");
	style->border_width[2] = border_width_from_property(node, "border-width-bottom");
	style->border_width[3] = border_width_from_property(node, "border-width-left");

	style->color = color_from_property(node, "color", black);
	style->background_color = color_from_property(node, "background-color", transparent);
	style->border_color = color_from_property(node, "border-color", style->color);

	style->border_style = !strcmp(get_style_property_string(node, "border-style", "none"), "solid");

	{
		const char *font_family = get_style_property_string(node, "font-family", "serif");
		const char *font_variant = get_style_property_string(node, "font-variant", "normal");
		const char *font_style = get_style_property_string(node, "font-style", "normal");
		const char *font_weight = get_style_property_string(node, "font-weight", "normal");
		style->font = html_load_font(doc, font_family, font_variant, font_style, font_weight);
	}
}

void
print_style(struct computed_style *style)
{
	printf("style {\n");
	printf("\tfont-size = %g%c;\n", style->font_size.value, style->font_size.unit);
	printf("\tfont = %s;\n", style->font->name);
	printf("\tline-height = %g%c;\n", style->line_height.value, style->line_height.unit);
	printf("\ttext-indent = %g%c;\n", style->text_indent.value, style->text_indent.unit);
	printf("\ttext-align = %d;\n", style->text_align);
	printf("\tvertical-align = %d;\n", style->vertical_align);
	printf("\tmargin = %g%c %g%c %g%c %g%c;\n",
		style->margin[0].value, style->margin[0].unit,
		style->margin[1].value, style->margin[1].unit,
		style->margin[2].value, style->margin[2].unit,
		style->margin[3].value, style->margin[3].unit);
	printf("\tpadding = %g%c %g%c %g%c %g%c;\n",
		style->padding[0].value, style->padding[0].unit,
		style->padding[1].value, style->padding[1].unit,
		style->padding[2].value, style->padding[2].unit,
		style->padding[3].value, style->padding[3].unit);
	printf("}\n");
}
