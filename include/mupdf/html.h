#ifndef MUPDF_HTML_H
#define MUPDF_HTML_H

#include "mupdf/fitz.h"

typedef struct html_document_s html_document;
typedef struct box html_page;

struct html_document_s
{
	fz_document super;
	fz_context *ctx;
	char *dirname;
	fz_xml *xml;
	fz_font *fonts[16];
	float page_w, page_h;
	struct box *box;
};

html_document *html_open_document(fz_context *ctx, const char *filename);
html_document *html_open_document_with_stream(fz_context *ctx, fz_stream *file);

void html_layout_document(html_document *doc, float w, float h);
void html_run_box(fz_context *ctx, struct box *box, float offset, fz_device *dev, const fz_matrix *ctm);

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
struct rule *fz_parse_css_file(fz_context *ctx, struct rule *chain, const char *filename);
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
	fz_font *font;
};

void apply_styles(fz_context *ctx, struct style *style, struct rule *rule, fz_xml *node);
void default_computed_style(struct computed_style *cstyle);
void compute_style(html_document *doc, struct computed_style *cstyle, struct style *style);
float from_number(struct number, float em, float width);
float from_number_scale(struct number number, float scale, float em, float width);

fz_font *html_load_font(html_document *doc,
	const char *family, const char *variant, const char *style, const char *weight);

enum
{
	BOX_BLOCK,	/* block-level: contains block and flow boxes */
	BOX_FLOW,	/* block-level: contains only inline boxes */
	BOX_INLINE,	/* inline-level: contains only inline boxes */
};

struct box
{
	int type;
	float x, y, w, h; /* content */
	float padding[4];
	float margin[4];
	struct box *up, *down, *last, *next;
	fz_xml *node;
	struct flow *flow_head, **flow_tail;
	struct computed_style style;
};

enum
{
	FLOW_WORD,
	FLOW_GLUE,
};

struct flow
{
	int type;
	float x, y, w, h, em;
	struct computed_style *style;
	char *text, *broken_text;
	struct flow *next;
};

#endif
