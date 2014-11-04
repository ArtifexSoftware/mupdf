#ifndef MUPDF_HTML_H
#define MUPDF_HTML_H

#include "mupdf/fitz.h"

typedef struct html_document_s html_document;
typedef struct box html_page;

struct html_document_s
{
	fz_document super;
	fz_context *ctx;
	fz_xml *xml;
	struct box *box;
};

html_document *html_open_document(fz_context *ctx, const char *filename);
html_document *html_open_document_with_stream(fz_context *ctx, fz_stream *file);

void html_layout_document(html_document *doc, float w, float h);
void html_run_box(fz_context *ctx, struct box *page, fz_device *dev, const fz_matrix *ctm);

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
	int count;
	struct {
		const char *name;
		struct value *value;
		int spec;
	} prop[64];
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

int get_style_property_display(struct style *node);
struct rule *fz_parse_css(fz_context *ctx, struct rule *old, const char *source);
struct property *fz_parse_css_properties(fz_context *ctx, const char *source);

enum { DIS_NONE, DIS_BLOCK, DIS_INLINE, DIS_LIST_ITEM };
enum { POS_STATIC, POS_RELATIVE, POS_ABSOLUTE, POS_FIXED };
enum { TA_LEFT, TA_RIGHT, TA_CENTER, TA_JUSTIFY };
enum { WS_NORMAL, WS_PRE, WS_NOWRAP, WS_PRE_WRAP, WS_PRE_LINE };

enum { TOP, RIGHT, BOTTOM, LEFT };

enum { N_NUMBER='p', N_SCALE='m', N_PERCENT='%' };

struct number
{
	float value;
	int unit;
};

struct color
{
	unsigned char r, g, b;
};

struct computed_style
{
	struct number font_size;
	struct number margin[4];
	struct number padding[4];
	struct number text_indent;
	int white_space;
	int text_align;
	int vertical_align;
	struct number line_height;
	const char *font_family;
	int bold, italic, smallcaps;
};

void apply_styles(fz_context *ctx, struct style *style, struct rule *rule, fz_xml *node);
void compute_style(struct computed_style *cstyle, struct style *style);
float from_number(struct number, float em, float width);

#endif
