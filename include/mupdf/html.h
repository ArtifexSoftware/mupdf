#ifndef MUPDF_HTML_H
#define MUPDF_HTML_H

#include "mupdf/fitz.h"

typedef struct html_document_s html_document;
typedef struct html_page_s html_page;

struct html_document_s
{
	fz_document super;
	fz_context *ctx;
	fz_xml *root;
};

html_document *html_open_document(fz_context *ctx, const char *filename);
html_document *html_open_document_with_stream(fz_context *ctx, fz_stream *file);

void html_layout_document(html_document *doc, float w, float h);

enum
{
	CSS_KEYWORD = 256,
	CSS_STRING,
	CSS_NUMBER,
	CSS_LENGTH,
	CSS_PERCENT,
	CSS_COLOR,
	CSS_URI,
};

struct rule
{
	struct selector *selector;
	struct property *declaration;
	struct rule *next;
};

struct selector
{
	const char *name;
	int combine;
	struct condition *cond;
	struct selector *left;
	struct selector *right;
	struct selector *next;
};

struct condition
{
	int type;
	const char *key;
	const char *val;
	struct condition *next;
};

struct property
{
	const char *name;
	struct value *value;
	int spec;
	struct property *next;
};

struct style
{
	struct style *up;
	struct {
		const char *name;
		struct value *value;
		int spec;
	} prop[64];
	int count;
};

struct value
{
	int type;
	const char *data;
	struct value *args; /* function arguments */
	struct value *next;
};

struct rule *new_rule(struct selector *selector, struct property *declaration);
struct selector *new_selector(const char *name);
struct condition *new_condition(int type, const char *key, const char *val);
struct property *new_property(const char *name, struct value *value, int spec);
struct value *new_value(int type, const char *value);

struct rule *fz_parse_css(fz_context *ctx, struct rule *old, const char *source);
struct property *fz_parse_css_properties(fz_context *ctx, const char *source);

enum { NONE, BLOCK, INLINE, LIST_ITEM };
enum { STATIC, RELATIVE, ABSOLUTE, FIXED };
enum { LEFT, RIGHT, CENTER, JUSTIFY };

struct color
{
	unsigned char r, g, b;
};

struct computed_style
{
	int display;
	int position;
	float top, right, bottom, left;
	float margin[4];
	float padding[4];
	float border_width[4];
	int border_style;
	struct color border_color;
	struct color color;
	struct color background_color;
	const char *font_family;
	int bold, italic, smallcaps;
	float font_size;
	float line_height;
	int vertical_align;
	int text_align;
	float text_indent;
};

void apply_styles(struct style *style, struct rule *rule, fz_xml *node);
void apply_inline_style(struct style *style, struct property *prop);
void compute_style(struct computed_style *cstyle, struct style *style);

#endif
