#ifndef _MUXPS_H_
#define _MUXPS_H_

#ifndef _FITZ_H_
#error "fitz.h must be included before muxps.h"
#endif

typedef unsigned char byte;

/*
 * XPS and ZIP constants.
 */

typedef struct xps_context_s xps_context;

#define REL_START_PART \
	"http://schemas.microsoft.com/xps/2005/06/fixedrepresentation"
#define REL_REQUIRED_RESOURCE \
	"http://schemas.microsoft.com/xps/2005/06/required-resource"
#define REL_REQUIRED_RESOURCE_RECURSIVE \
	"http://schemas.microsoft.com/xps/2005/06/required-resource#recursive"

#define ZIP_LOCAL_FILE_SIG 0x04034b50
#define ZIP_DATA_DESC_SIG 0x08074b50
#define ZIP_CENTRAL_DIRECTORY_SIG 0x02014b50
#define ZIP_END_OF_CENTRAL_DIRECTORY_SIG 0x06054b50

/*
 * Memory, and string functions.
 */

int xps_strcasecmp(char *a, char *b);
void xps_absolute_path(char *output, char *base_uri, char *path, int output_size);

int xps_utf8_to_ucs(int *p, const char *s, int n);

/*
 * Generic hashtable.
 */

typedef struct xps_hash_table_s xps_hash_table;

xps_hash_table *xps_hash_new(xps_context *ctx);
void *xps_hash_lookup(xps_hash_table *table, char *key);
int xps_hash_insert(xps_context *ctx, xps_hash_table *table, char *key, void *value);
void xps_hash_free(xps_context *ctx, xps_hash_table *table,
	void (*free_key)(xps_context *ctx, void *),
	void (*free_value)(xps_context *ctx, void *));
void xps_hash_debug(xps_hash_table *table);

/*
 * Container parts.
 */

typedef struct xps_part_s xps_part;

struct xps_part_s
{
	char *name;
	int size;
	int cap;
	byte *data;
};

xps_part *xps_new_part(xps_context *ctx, char *name, int size);
xps_part *xps_read_part(xps_context *ctx, char *partname);
void xps_free_part(xps_context *ctx, xps_part *part);

/*
 * Document structure.
 */

typedef struct xps_document_s xps_document;
typedef struct xps_page_s xps_page;

struct xps_document_s
{
	char *name;
	xps_document *next;
};

struct xps_page_s
{
	char *name;
	int width;
	int height;
	struct xps_item_s *root;
	xps_page *next;
};

int xps_parse_metadata(xps_context *ctx, xps_part *part);
void xps_free_fixed_pages(xps_context *ctx);
void xps_free_fixed_documents(xps_context *ctx);
void xps_debug_fixdocseq(xps_context *ctx);

/*
 * Images.
 */

typedef struct xps_image xps_image;

/* type for the information derived directly from the raster file format */

struct xps_image
{
	fz_pixmap *pixmap;
	int xres;
	int yres;
};

int xps_decode_jpeg(xps_image **imagep, xps_context *ctx, byte *rbuf, int rlen);
int xps_decode_png(xps_image **imagep, xps_context *ctx, byte *rbuf, int rlen);
int xps_decode_tiff(xps_image **imagep, xps_context *ctx, byte *rbuf, int rlen);
int xps_decode_jpegxr(xps_image **imagep, xps_context *ctx, byte *rbuf, int rlen);

void xps_free_image(xps_context *ctx, xps_image *image);

/*
 * Fonts.
 */

typedef struct xps_glyph_metrics_s xps_glyph_metrics;

struct xps_glyph_metrics_s
{
	float hadv, vadv, vorg;
};

int xps_count_font_encodings(fz_font *font);
void xps_identify_font_encoding(fz_font *font, int idx, int *pid, int *eid);
void xps_select_font_encoding(fz_font *font, int idx);
int xps_encode_font_char(fz_font *font, int key);

void xps_measure_font_glyph(xps_context *ctx, fz_font *font, int gid, xps_glyph_metrics *mtx);

void xps_debug_path(xps_context *ctx);

/*
 * Colorspaces and colors.
 */

fz_colorspace *xps_read_icc_colorspace(xps_context *ctx, char *base_uri, char *profile);
void xps_parse_color(xps_context *ctx, char *base_uri, char *hexstring, fz_colorspace **csp, float *samples);
void xps_set_color(xps_context *ctx, fz_colorspace *colorspace, float *samples);

/*
 * XML document model
 */

typedef struct xps_item_s xps_item;

xps_item * xps_parse_xml(xps_context *ctx, byte *buf, int len);
xps_item * xps_next(xps_item *item);
xps_item * xps_down(xps_item *item);
char * xps_tag(xps_item *item);
char * xps_att(xps_item *item, const char *att);
void xps_free_item(xps_context *ctx, xps_item *item);
void xps_debug_item(xps_item *item, int level);

/*
 * Resource dictionaries.
 */

typedef struct xps_resource_s xps_resource;

struct xps_resource_s
{
	char *name;
	char *base_uri; /* only used in the head nodes */
	xps_item *base_xml; /* only used in the head nodes, to free the xml document */
	xps_item *data;
	xps_resource *next;
	xps_resource *parent; /* up to the previous dict in the stack */
};

int xps_parse_resource_dictionary(xps_context *ctx, xps_resource **dictp, char *base_uri, xps_item *root);
void xps_free_resource_dictionary(xps_context *ctx, xps_resource *dict);
void xps_resolve_resource_reference(xps_context *ctx, xps_resource *dict, char **attp, xps_item **tagp, char **urip);

void xps_debug_resource_dictionary(xps_resource *dict);

/*
 * Fixed page/graphics parsing.
 */

int xps_load_fixed_page(xps_context *ctx, xps_page *page);
void xps_parse_fixed_page(xps_context *ctx, fz_matrix ctm, xps_page *page);
void xps_parse_canvas(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node);
void xps_parse_path(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node);
void xps_parse_glyphs(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node);
void xps_parse_solid_color_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node);
void xps_parse_image_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node);
void xps_parse_visual_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node);
void xps_parse_linear_gradient_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node);
void xps_parse_radial_gradient_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node);

void xps_parse_tiling_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *root, void(*func)(xps_context*, fz_matrix, char*, xps_resource*, xps_item*, void*), void *user);

void xps_parse_matrix_transform(xps_context *ctx, xps_item *root, fz_matrix *matrix);
void xps_parse_render_transform(xps_context *ctx, char *text, fz_matrix *matrix);
void xps_parse_rectangle(xps_context *ctx, char *text, fz_rect *rect);
void xps_parse_abbreviated_geometry(xps_context *ctx, char *geom);
void xps_parse_path_geometry(xps_context *ctx, xps_resource *dict, xps_item *root, int stroking);

void xps_begin_opacity(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, char *opacity_att, xps_item *opacity_mask_tag);
void xps_end_opacity(xps_context *ctx, char *base_uri, xps_resource *dict, char *opacity_att, xps_item *opacity_mask_tag);

void xps_parse_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node);
void xps_parse_element(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node);

void xps_fill(xps_context *ctx, fz_matrix ctm);
void xps_clip(xps_context *ctx, fz_matrix ctm);
void xps_bounds_in_user_space(xps_context *ctx, fz_rect *user);

int xps_element_has_transparency(xps_context *ctx, char *base_uri, xps_item *node);
int xps_resource_dictionary_has_transparency(xps_context *ctx, char *base_uri, xps_item *node);
int xps_image_brush_has_transparency(xps_context *ctx, char *base_uri, xps_item *root);

/*
 * The interpreter context.
 */

typedef struct xps_entry_s xps_entry;

struct xps_entry_s
{
	char *name;
	int offset;
	int csize;
	int usize;
};

struct xps_context_s
{
	char *directory;
	FILE *file;
	int zip_count;
	xps_entry *zip_table;

	char *start_part; /* fixed document sequence */
	xps_document *first_fixdoc; /* first fixed document */
	xps_document *last_fixdoc; /* last fixed document */
	xps_page *first_page; /* first page of document */
	xps_page *last_page; /* last page of document */

	char *base_uri; /* base uri for parsing XML and resolving relative paths */
	char *part_uri; /* part uri for parsing metadata relations */

	/* We cache font and colorspace resources */
	xps_hash_table *font_table;
	xps_hash_table *colorspace_table;

	/* The fill_rule is set by path parsing.
	 * It is used by clip/fill functions.
	 * 1=nonzero, 0=evenodd
	 */
	int fill_rule;

	/* Current path being accumulated */
	fz_path *path;
	fz_text *text; /* ... or text, for clipping brushes */

	/* Current color */
	fz_colorspace *colorspace;
	float color[8];
	float alpha;

	/* Current device */
	fz_device *dev;
};

int xps_read_and_process_page_part(xps_context *ctx, fz_matrix ctm, char *name);
int xps_open_file(xps_context *ctx, char *filename);
int xps_count_pages(xps_context *ctx);
xps_page *xps_load_page(xps_context *ctx, int number);
xps_context *xps_new_context(void);
int xps_free_context(xps_context *ctx);

#endif
