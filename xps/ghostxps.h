/* Copyright (C) 2006-2010 Artifex Software, Inc.
   All Rights Reserved.

   This software is provided AS-IS with no warranty, either express or
   implied.

   This software is distributed under license and may not be copied, modified
   or distributed except as expressly authorized under the terms of that
   license.  Refer to licensing information at http://www.artifex.com/
   or contact Artifex Software, Inc.,  7 Mt. Lassen  Drive - Suite A-134,
   San Rafael, CA  94903, U.S.A., +1(415)492-9861, for further information.
*/

/* combined internal header for the XPS interpreter */

#include "memory_.h"
#include "math_.h"

#include <stdlib.h>
#include <ctype.h> /* for toupper() */

#include "gp.h"

#include "gsgc.h"
#include "gstypes.h"
#include "gsstate.h"
#include "gsmatrix.h"
#include "gscoord.h"
#include "gsmemory.h"
#include "gsparam.h"
#include "gsdevice.h"
#include "scommon.h"
#include "gdebug.h"
#include "gserror.h"
#include "gserrors.h"
#include "gspaint.h"
#include "gspath.h"
#include "gsimage.h"
#include "gscspace.h"
#include "gsptype1.h"
#include "gscolor2.h"
#include "gscolor3.h"
#include "gsutil.h"
#include "gsicc.h"

#include "gstrans.h"

#include "gxpath.h"		/* gsshade.h depends on it */
#include "gxfixed.h"	/* gsshade.h depends on it */
#include "gxmatrix.h"	/* gxtype1.h depends on it */
#include "gsshade.h"
#include "gsfunc.h"
#include "gsfunc3.h"	/* we use stitching and exponential interp */

#include "gxfont.h"
#include "gxchar.h"
#include "gxcolor2.h" /* Required for definition of gs_pattern1_instance_t */
#include "gxtype1.h"
#include "gxfont1.h"
#include "gxfont42.h"
#include "gxfcache.h"
#include "gxistate.h"

#include "gzstate.h"
#include "gzpath.h"
#include "gzcpath.h"

#include "gsicc_manage.h"
#include "gscms.h"
#include "gsicc_cache.h"

#include "zlib.h"

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a,b) ((a) < (b) ? (b) : (a))
#endif
#ifndef ABS
#define ABS(a) ((a) < 0 ? -(a) : (a))
#endif

/*
 * XPS and ZIP contants.
 */

typedef struct xps_context_s xps_context_t;

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

void * xps_realloc_imp(xps_context_t *ctx, void *ptr, int size, const char *func);

#define xps_alloc(ctx, size) \
	((void*)gs_alloc_bytes(ctx->memory, size, __func__))
#define xps_realloc(ctx, ptr, size) \
	xps_realloc_imp(ctx, ptr, size, __func__)
#define xps_strdup(ctx, str) \
	xps_strdup_imp(ctx, str, __func__)
#define xps_free(ctx, ptr) \
	gs_free_object(ctx->memory, ptr, __func__)

size_t xps_strlcpy(char *destination, const char *source, size_t size);
size_t xps_strlcat(char *destination, const char *source, size_t size);
int xps_strcasecmp(char *a, char *b);
char *xps_strdup_imp(xps_context_t *ctx, const char *str, const char *function);
void xps_absolute_path(char *output, char *base_uri, char *path, int output_size);

int xps_utf8_to_ucs(int *p, const char *s, int n);

/*
 * Generic hashtable.
 */

typedef struct xps_hash_table_s xps_hash_table_t;

xps_hash_table_t *xps_hash_new(xps_context_t *ctx);
void *xps_hash_lookup(xps_hash_table_t *table, char *key);
int xps_hash_insert(xps_context_t *ctx, xps_hash_table_t *table, char *key, void *value);
void xps_hash_free(xps_context_t *ctx, xps_hash_table_t *table,
	void (*free_key)(xps_context_t *ctx, void *),
	void (*free_value)(xps_context_t *ctx, void *));
void xps_hash_debug(xps_hash_table_t *table);

/*
 * Container parts.
 */

typedef struct xps_part_s xps_part_t;

struct xps_part_s
{
	char *name;
	int size;
	int cap;
	byte *data;
};

xps_part_t *xps_new_part(xps_context_t *ctx, char *name, int size);
xps_part_t *xps_read_part(xps_context_t *ctx, char *partname);
void xps_free_part(xps_context_t *ctx, xps_part_t *part);

/*
 * Document structure.
 */

typedef struct xps_document_s xps_document_t;
typedef struct xps_page_s xps_page_t;

struct xps_document_s
{
	char *name;
	xps_document_t *next;
};

struct xps_page_s
{
	char *name;
	int width;
	int height;
	xps_page_t *next;
};

int xps_parse_metadata(xps_context_t *ctx, xps_part_t *part);
void xps_free_fixed_pages(xps_context_t *ctx);
void xps_free_fixed_documents(xps_context_t *ctx);
void xps_debug_fixdocseq(xps_context_t *ctx);

/*
 * Images.
 */

typedef struct xps_image_s xps_image_t;

/* type for the information derived directly from the raster file format */

struct xps_image_s
{
	int width;
	int height;
	int stride;
	gs_color_space *colorspace;
	int comps;
	int hasalpha; /* chunky alpha */
	int bits;
	int xres;
	int yres;
	byte *samples;
	byte *alpha; /* isolated alpha plane */
	byte *profile;
	int profilesize;
};

int xps_decode_jpeg(xps_context_t *ctx, byte *rbuf, int rlen, xps_image_t *image);
int xps_decode_png(xps_context_t *ctx, byte *rbuf, int rlen, xps_image_t *image);
int xps_decode_tiff(xps_context_t *ctx, byte *rbuf, int rlen, xps_image_t *image);
int xps_decode_jpegxr(xps_context_t *ctx, byte *buf, int len, xps_image_t *image);

int xps_png_has_alpha(xps_context_t *ctx, byte *rbuf, int rlen);
int xps_tiff_has_alpha(xps_context_t *ctx, byte *rbuf, int rlen);
int xps_jpegxr_has_alpha(xps_context_t *ctx, byte *buf, int len);

void xps_free_image(xps_context_t *ctx, xps_image_t *image);

/*
 * Fonts.
 */

typedef struct xps_font_s xps_font_t;
typedef struct xps_glyph_metrics_s xps_glyph_metrics_t;

struct xps_font_s
{
	byte *data;
	int length;
	gs_font *font;

	int subfontid;
	int cmaptable;
	int cmapsubcount;
	int cmapsubtable;
	int usepua;

	/* these are for CFF opentypes only */
	byte *cffdata;
	byte *cffend;
	byte *gsubrs;
	byte *subrs;
	byte *charstrings;
};

struct xps_glyph_metrics_s
{
	float hadv, vadv, vorg;
};

xps_font_t *xps_new_font(xps_context_t *ctx, byte *buf, int buflen, int index);
void xps_free_font(xps_context_t *ctx, xps_font_t *font);

int xps_count_font_encodings(xps_font_t *font);
void xps_identify_font_encoding(xps_font_t *font, int idx, int *pid, int *eid);
void xps_select_font_encoding(xps_font_t *font, int idx);
int xps_encode_font_char(xps_font_t *font, int key);

void xps_measure_font_glyph(xps_context_t *ctx, xps_font_t *font, int gid, xps_glyph_metrics_t *mtx);

int xps_find_sfnt_table(xps_font_t *font, const char *name, int *lengthp);
void xps_load_sfnt_name(xps_font_t *font, char *namep);
int xps_init_truetype_font(xps_context_t *ctx, xps_font_t *font);
int xps_init_postscript_font(xps_context_t *ctx, xps_font_t *font);

void xps_debug_path(xps_context_t *ctx);

/*
 * Colorspaces and colors.
 */

gs_color_space *xps_read_icc_colorspace(xps_context_t *ctx, char *base_uri, char *profile);
void xps_parse_color(xps_context_t *ctx, char *base_uri, char *hexstring, gs_color_space **csp, float *samples);
void xps_set_color(xps_context_t *ctx, gs_color_space *colorspace, float *samples);

/*
 * XML document model
 */

typedef struct xps_item_s xps_item_t;

xps_item_t * xps_parse_xml(xps_context_t *ctx, byte *buf, int len);
xps_item_t * xps_next(xps_item_t *item);
xps_item_t * xps_down(xps_item_t *item);
char * xps_tag(xps_item_t *item);
char * xps_att(xps_item_t *item, const char *att);
void xps_free_item(xps_context_t *ctx, xps_item_t *item);
void xps_debug_item(xps_item_t *item, int level);

/*
 * Resource dictionaries.
 */

typedef struct xps_resource_s xps_resource_t;

struct xps_resource_s
{
	char *name;
	char *base_uri; /* only used in the head nodes */
	xps_item_t *base_xml; /* only used in the head nodes, to free the xml document */
	xps_item_t *data;
	xps_resource_t *next;
	xps_resource_t *parent; /* up to the previous dict in the stack */
};

int xps_parse_resource_dictionary(xps_context_t *ctx, xps_resource_t **dictp, char *base_uri, xps_item_t *root);
void xps_free_resource_dictionary(xps_context_t *ctx, xps_resource_t *dict);
void xps_resolve_resource_reference(xps_context_t *ctx, xps_resource_t *dict, char **attp, xps_item_t **tagp, char **urip);

void xps_debug_resource_dictionary(xps_resource_t *dict);

/*
 * Fixed page/graphics parsing.
 */

int xps_parse_fixed_page(xps_context_t *ctx, xps_part_t *part);
int xps_parse_canvas(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node);
int xps_parse_path(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node);
int xps_parse_glyphs(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node);
int xps_parse_solid_color_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node);
int xps_parse_image_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node);
int xps_parse_visual_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node);
int xps_parse_linear_gradient_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node);
int xps_parse_radial_gradient_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node);

int xps_parse_tiling_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root, int (*func)(xps_context_t*, char*, xps_resource_t*, xps_item_t*, void*), void *user);

void xps_parse_matrix_transform(xps_context_t *ctx, xps_item_t *root, gs_matrix *matrix);
void xps_parse_render_transform(xps_context_t *ctx, char *text, gs_matrix *matrix);
void xps_parse_rectangle(xps_context_t *ctx, char *text, gs_rect *rect);
void xps_parse_abbreviated_geometry(xps_context_t *ctx, char *geom);
void xps_parse_path_geometry(xps_context_t *ctx, xps_resource_t *dict, xps_item_t *root, int stroking);

int xps_begin_opacity(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, char *opacity_att, xps_item_t *opacity_mask_tag);
void xps_end_opacity(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, char *opacity_att, xps_item_t *opacity_mask_tag);

int xps_parse_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node);
int xps_parse_element(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node);

void xps_clip(xps_context_t *ctx);
void xps_fill(xps_context_t *ctx);
void xps_bounds_in_user_space(xps_context_t *ctx, gs_rect *user);

int xps_element_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *node);
int xps_resource_dictionary_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *node);
int xps_image_brush_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *root);

/*
 * The interpreter context.
 */

typedef struct xps_entry_s xps_entry_t;

struct xps_entry_s
{
	char *name;
	int offset;
	int csize;
	int usize;
};

struct xps_context_s
{
	void *instance;
	gs_memory_t *memory;
	gs_state *pgs;
	gs_font_dir *fontdir;

	gs_color_space *gray;
	gs_color_space *srgb;
	gs_color_space *scrgb;
	gs_color_space *cmyk;

	char *directory;
	FILE *file;
	int zip_count;
	xps_entry_t *zip_table;

	char *start_part; /* fixed document sequence */
	xps_document_t *first_fixdoc; /* first fixed document */
	xps_document_t *last_fixdoc; /* last fixed document */
	xps_page_t *first_page; /* first page of document */
	xps_page_t *last_page; /* last page of document */

	char *base_uri; /* base uri for parsing XML and resolving relative paths */
	char *part_uri; /* part uri for parsing metadata relations */

	/* We cache font and colorspace resources */
	xps_hash_table_t *font_table;
	xps_hash_table_t *colorspace_table;

	/* Global toggle for transparency */
	int use_transparency;

	/* Hack to workaround ghostscript's lack of understanding
	 * the pdf 1.4 specification of Alpha only transparency groups.
	 * We have to force all colors to be grayscale whenever we are computing
	 * opacity masks.
	 */
	int opacity_only;

	/* The fill_rule is set by path parsing.
	 * It is used by clip/fill functions.
	 * 1=nonzero, 0=evenodd
	 */
	int fill_rule;
};

int xps_process_file(xps_context_t *ctx, char *filename);

/* end of page device callback foo */
int xps_show_page(xps_context_t *ctx, int num_copies, int flush);
