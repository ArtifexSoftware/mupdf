#ifndef MUPDF_HTML_H
#define MUPDF_HTML_H

#include "mupdf/fitz.h"

typedef struct fz_html_font_set_s fz_html_font_set;
typedef struct fz_css_rule_s fz_css_rule;
typedef struct fz_css_match_s fz_css_match;

struct fz_html_font_set_s
{
	fz_font *fonts[16];
};

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

struct fz_css_rule_s
{
	struct selector *selector;
	struct property *declaration;
	fz_css_rule *next;
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

struct value
{
	int type;
	const char *data;
	struct value *args; /* function arguments */
	struct value *next;
};

struct fz_css_match_s
{
	fz_css_match *up;
	int count;
	struct {
		const char *name;
		struct value *value;
		int spec;
	} prop[64];
};

enum { DIS_NONE, DIS_BLOCK, DIS_INLINE, DIS_LIST_ITEM };
enum { POS_STATIC, POS_RELATIVE, POS_ABSOLUTE, POS_FIXED };
enum { WS_NORMAL, WS_PRE, WS_NOWRAP, WS_PRE_WRAP, WS_PRE_LINE };
enum { TA_LEFT, TA_RIGHT, TA_CENTER, TA_JUSTIFY };
enum { VA_BASELINE, VA_SUB, VA_SUPER, VA_TOP, VA_BOTTOM };
enum { BS_NONE, BS_SOLID };

enum { N_NUMBER='p', N_SCALE='m', N_PERCENT='%' };

struct number
{
	float value;
	int unit;
};

struct color
{
	unsigned char r, g, b, a;
};

struct computed_style
{
	struct number font_size;
	struct number margin[4];
	struct number padding[4];
	struct number border_width[4];
	struct number text_indent;
	int white_space;
	int text_align;
	int vertical_align;
	int border_style;
	struct number line_height;
	struct color background_color;
	struct color border_color;
	struct color color;
	fz_font *font;
};

enum
{
	BOX_BLOCK,	/* block-level: contains block, break, and flow boxes */
	BOX_BREAK,	/* block-level: empty <br> tag boxes */
	BOX_FLOW,	/* block-level: contains only inline boxes */
	BOX_INLINE,	/* inline-level: contains only inline boxes */
};

struct box
{
	int type;
	float x, y, w, h; /* content */
	float padding[4];
	float margin[4];
	float border[4];
	struct box *up, *down, *last, *next;
	fz_xml *node;
	struct flow *flow_head, **flow_tail;
	struct computed_style style;
	int is_first_flow; /* for text-indent */
};

enum
{
	FLOW_WORD,
	FLOW_GLUE,
	FLOW_IMAGE,
};

struct flow
{
	int type;
	float x, y, w, h, em;
	struct computed_style *style;
	char *text, *broken_text;
	fz_image *image;
	struct flow *next;
};

fz_css_rule *fz_parse_css(fz_context *ctx, fz_css_rule *old, const char *source);
struct property *fz_parse_css_properties(fz_context *ctx, const char *source);

void fz_match_css(fz_context *ctx, fz_css_match *match, fz_css_rule *rule, fz_xml *node);

int fz_get_css_match_display(fz_css_match *node);
void fz_default_css_style(fz_context *ctx, struct computed_style *style);
void fz_apply_css_style(fz_context *ctx, fz_html_font_set *set, struct computed_style *style, fz_css_match *match);

float fz_from_css_number(struct number, float em, float width);
float fz_from_css_number_scale(struct number number, float scale, float em, float width);

fz_html_font_set *fz_new_html_font_set(fz_context *ctx);
fz_font *fz_load_html_font(fz_context *ctx, fz_html_font_set *set,
	const char *family, const char *variant, const char *style, const char *weight);
void fz_free_html_font_set(fz_context *ctx, fz_html_font_set *htx);

struct box *fz_generate_html(fz_context *ctx, fz_html_font_set *htx, fz_archive *zip, const char *base_uri, fz_buffer *buf);
void fz_layout_html(fz_context *ctx, struct box *box, float w, float h, float em);
void fz_draw_html(fz_context *ctx, struct box *box, float page_top, float page_bot, fz_device *dev, const fz_matrix *ctm);

#endif
