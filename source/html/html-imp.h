#ifndef SOURCE_HTML_IMP_H
#define SOURCE_HTML_IMP_H

typedef struct fz_html_font_face_s fz_html_font_face;
typedef struct fz_html_font_set_s fz_html_font_set;
typedef struct fz_html_s fz_html;
typedef struct fz_html_box_s fz_html_box;
typedef struct fz_html_flow_s fz_html_flow;

typedef struct fz_css_s fz_css;
typedef struct fz_css_rule_s fz_css_rule;
typedef struct fz_css_match_prop_s fz_css_match_prop;
typedef struct fz_css_match_s fz_css_match;
typedef struct fz_css_style_s fz_css_style;

typedef struct fz_css_selector_s fz_css_selector;
typedef struct fz_css_condition_s fz_css_condition;
typedef struct fz_css_property_s fz_css_property;
typedef struct fz_css_value_s fz_css_value;
typedef struct fz_css_number_s fz_css_number;
typedef struct fz_css_color_s fz_css_color;

struct fz_html_font_face_s
{
	char *family;
	int is_bold;
	int is_italic;
	fz_font *font;
	char *src;
	fz_html_font_face *next;
};

struct fz_html_font_set_s
{
	fz_font *fonts[12]; /* Times, Helvetica, Courier in R,I,B,BI */
	fz_html_font_face *custom;
};

enum
{
	CSS_KEYWORD = 256,
	CSS_HASH,
	CSS_STRING,
	CSS_NUMBER,
	CSS_LENGTH,
	CSS_PERCENT,
	CSS_URI,
};

struct fz_css_s
{
	fz_pool *pool;
	fz_css_rule *rule;
};

struct fz_css_rule_s
{
	fz_css_selector *selector;
	fz_css_property *declaration;
	fz_css_rule *next;
};

struct fz_css_selector_s
{
	char *name;
	int combine;
	fz_css_condition *cond;
	fz_css_selector *left;
	fz_css_selector *right;
	fz_css_selector *next;
};

struct fz_css_condition_s
{
	int type;
	char *key;
	char *val;
	fz_css_condition *next;
};

struct fz_css_property_s
{
	char *name;
	fz_css_value *value;
	short spec;
	short important;
	fz_css_property *next;
};

struct fz_css_value_s
{
	int type;
	char *data;
	fz_css_value *args; /* function arguments */
	fz_css_value *next;
};

struct fz_css_match_prop_s
{
	const char *name; /* not owned */
	fz_css_value *value; /* not owned */
	int spec;
};

struct fz_css_match_s
{
	fz_css_match *up;
	int count;
	fz_css_match_prop prop[64];
};

enum { DIS_NONE, DIS_BLOCK, DIS_INLINE, DIS_LIST_ITEM, DIS_INLINE_BLOCK };
enum { POS_STATIC, POS_RELATIVE, POS_ABSOLUTE, POS_FIXED };
enum { TA_LEFT, TA_RIGHT, TA_CENTER, TA_JUSTIFY };
enum { VA_BASELINE, VA_SUB, VA_SUPER, VA_TOP, VA_BOTTOM, VA_TEXT_TOP, VA_TEXT_BOTTOM };
enum { BS_NONE, BS_SOLID };
enum { V_VISIBLE, V_HIDDEN, V_COLLAPSE };
enum { PB_AUTO, PB_ALWAYS, PB_AVOID, PB_LEFT, PB_RIGHT };

enum {
	WS_COLLAPSE = 1,
	WS_ALLOW_BREAK_SPACE = 2,
	WS_FORCE_BREAK_NEWLINE = 4,
	WS_NORMAL = WS_COLLAPSE | WS_ALLOW_BREAK_SPACE,
	WS_PRE = WS_FORCE_BREAK_NEWLINE,
	WS_NOWRAP = WS_COLLAPSE,
	WS_PRE_WRAP = WS_ALLOW_BREAK_SPACE | WS_FORCE_BREAK_NEWLINE,
	WS_PRE_LINE = WS_COLLAPSE | WS_ALLOW_BREAK_SPACE | WS_FORCE_BREAK_NEWLINE
};

enum {
	LST_NONE,
	LST_DISC, LST_CIRCLE, LST_SQUARE,
	LST_DECIMAL, LST_DECIMAL_ZERO,
	LST_LC_ROMAN, LST_UC_ROMAN,
	LST_LC_GREEK, LST_UC_GREEK,
	LST_LC_LATIN, LST_UC_LATIN,
	LST_LC_ALPHA, LST_UC_ALPHA,
	LST_ARMENIAN, LST_GEORGIAN,
};

enum { N_NUMBER='u', N_LENGTH='p', N_SCALE='m', N_PERCENT='%', N_AUTO='a' };

struct fz_css_number_s
{
	float value;
	int unit;
};

struct fz_css_color_s
{
	unsigned char r, g, b, a;
};

struct fz_css_style_s
{
	fz_css_number font_size;
	fz_css_number width, height;
	fz_css_number margin[4];
	fz_css_number padding[4];
	fz_css_number border_width[4];
	fz_css_number text_indent;
	unsigned int visibility : 2;
	unsigned int white_space : 3;
	unsigned int text_align : 2;
	unsigned int vertical_align : 3;
	unsigned int list_style_type : 4;
	unsigned int page_break_before : 3;
	unsigned int page_break_after : 3;
	unsigned int border_style_0 : 1;
	unsigned int border_style_1 : 1;
	unsigned int border_style_2 : 1;
	unsigned int border_style_3 : 1;
	fz_css_number line_height;
	fz_css_color background_color;
	fz_css_color border_color[4];
	fz_css_color color;
	fz_font *font;
};

enum
{
	BOX_BLOCK,	/* block-level: contains block, break, and flow boxes */
	BOX_BREAK,	/* block-level: empty <br> tag boxes */
	BOX_FLOW,	/* block-level: contains only inline boxes */
	BOX_INLINE,	/* inline-level: contains only inline boxes */
};

struct fz_html_s
{
	fz_pool *pool; /* pool allocator for this html tree */
	float page_w, page_h;
	float page_margin[4];
	fz_html_box *root;
};

struct fz_html_box_s
{
	unsigned int type : 2;
	unsigned int is_first_flow : 1; /* for text-indent */
	unsigned int markup_dir : 2;
	unsigned int list_item : 27;
	float x, y, w, h; /* content */
	float padding[4];
	float margin[4];
	float border[4];
	float em;
	fz_html_box *up, *down, *last, *next;
	fz_html_flow *flow_head, **flow_tail;
	char *id, *href;
	fz_css_style style;
};

enum
{
	FLOW_WORD = 0,
	FLOW_SPACE = 1,
	FLOW_BREAK = 2,
	FLOW_IMAGE = 3,
	FLOW_SBREAK = 4,
	FLOW_SHYPHEN = 5,
	FLOW_ANCHOR = 6
};

struct fz_html_flow_s
{
	/* What type of node */
	unsigned int type : 3;

	/* Whether this should expand during justification */
	unsigned int expand : 1;

	/* Whether this node is currently taken as a line break */
	unsigned int breaks_line : 1;

	/* Direction setting for text - UAX#9 says 125 is the max */
	unsigned int bidi_level : 7;

	/* The script detected by the bidi code. */
	unsigned int script : 8;

	/* Whether the markup specifies a given language. */
	unsigned int markup_lang : 15;

	float x, y, w, h;
	fz_html_box *box; /* for style and em */
	union {
		char *text;
		fz_image *image;
	} content;
	fz_html_flow *next;
};

fz_css *fz_new_css(fz_context *ctx);
void fz_parse_css(fz_context *ctx, fz_css *css, const char *source, const char *file);
fz_css_property *fz_parse_css_properties(fz_context *ctx, fz_pool *pool, const char *source);
void fz_drop_css(fz_context *ctx, fz_css *css);
void fz_debug_css(fz_context *ctx, fz_css *css);

void fz_match_css(fz_context *ctx, fz_css_match *match, fz_css *css, fz_xml *node);
void fz_match_css_at_page(fz_context *ctx, fz_css_match *match, fz_css *css);

int fz_get_css_match_display(fz_css_match *node);
void fz_default_css_style(fz_context *ctx, fz_css_style *style);
void fz_apply_css_style(fz_context *ctx, fz_html_font_set *set, fz_css_style *style, fz_css_match *match);

float fz_from_css_number(fz_css_number, float em, float width);
float fz_from_css_number_scale(fz_css_number number, float scale, float em, float width);

fz_html_font_set *fz_new_html_font_set(fz_context *ctx);
void fz_add_html_font_face(fz_context *ctx, fz_html_font_set *set,
	const char *family, int is_bold, int is_italic, const char *src, fz_font *font);
fz_font *fz_load_html_font(fz_context *ctx, fz_html_font_set *set, const char *family, int is_bold, int is_italic);
void fz_drop_html_font_set(fz_context *ctx, fz_html_font_set *htx);

void fz_add_css_font_faces(fz_context *ctx, fz_html_font_set *set, fz_archive *zip, const char *base_uri, fz_css *css);

fz_html *fz_parse_html(fz_context *ctx, fz_html_font_set *htx, fz_archive *zip, const char *base_uri, fz_buffer *buf, const char *user_css);
void fz_layout_html(fz_context *ctx, fz_html *html, float w, float h, float em);
void fz_draw_html(fz_context *ctx, fz_device *dev, const fz_matrix *ctm, fz_html *html, int page);

float fz_find_html_target(fz_context *ctx, fz_html *html, const char *id);
fz_link *fz_load_html_links(fz_context *ctx, fz_html *html, int page, const char *base_uri, void *doc);
void fz_drop_html(fz_context *ctx, fz_html *html);
fz_bookmark fz_make_html_bookmark(fz_context *ctx, fz_html *html, int page);
int fz_lookup_html_bookmark(fz_context *ctx, fz_html *html, fz_bookmark mark);

#endif
