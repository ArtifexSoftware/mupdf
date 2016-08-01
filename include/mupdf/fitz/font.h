#ifndef MUPDF_FITZ_FONT_H
#define MUPDF_FITZ_FONT_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/math.h"
#include "mupdf/fitz/buffer.h"

/*
	An abstract font handle. Currently there are no public API functions
	for handling these.
*/
typedef struct fz_font_s fz_font;

/*
 * Fonts come in two variants:
 *	Regular fonts are handled by FreeType.
 *	Type 3 fonts have callbacks to the interpreter.
 */

char *ft_error_string(int err);

/* forward declaration for circular dependency */
struct fz_device_s;
struct fz_display_list_s;

struct fz_font_s
{
	int refs;
	char name[32];
	fz_buffer *buffer;

	unsigned int is_mono : 1;
	unsigned int is_serif : 1;
	unsigned int is_bold : 1;
	unsigned int is_italic : 1;
	unsigned int ft_substitute : 1; /* use substitute metrics */
	unsigned int ft_stretch : 1; /* stretch to match PDF metrics */

	unsigned int fake_bold : 1; /* synthesize bold */
	unsigned int fake_italic : 1; /* synthesize italic */
	unsigned int force_hinting : 1; /* force hinting for DynaLab fonts */
	unsigned int has_opentype : 1; /* has opentype shaping tables */
	unsigned int invalid_bbox : 1;
	unsigned int use_glyph_bbox : 1;

	void *ft_face; /* has an FT_Face if used */
	void *hb_font; /* hb_font for shaping */
	void (*hb_destroy)(void *); /* Destructor for hb_font */

	fz_matrix t3matrix;
	void *t3resources;
	fz_buffer **t3procs; /* has 256 entries if used */
	struct fz_display_list_s **t3lists; /* has 256 entries if used */
	float *t3widths; /* has 256 entries if used */
	unsigned short *t3flags; /* has 256 entries if used */
	void *t3doc; /* a pdf_document for the callback */
	void (*t3run)(fz_context *ctx, void *doc, void *resources, fz_buffer *contents, struct fz_device_s *dev, const fz_matrix *ctm, void *gstate, int nestedDepth);
	void (*t3freeres)(fz_context *ctx, void *doc, void *resources);

	fz_rect bbox;	/* font bbox is used only for t3 fonts */

	int glyph_count;

	/* per glyph bounding box cache */
	fz_rect *bbox_table;

	/* substitute metrics */
	int width_count;
	short width_default; /* in 1000 units */
	short *width_table; /* in 1000 units */

	/* cached glyph metrics */
	float *advance_cache;

	/* cached encoding lookup */
	uint16_t *encoding_cache[256];
};

/* common CJK font collections */
enum { FZ_ADOBE_CNS_1, FZ_ADOBE_GB_1, FZ_ADOBE_JAPAN_1, FZ_ADOBE_KOREA_1 };

void fz_new_font_context(fz_context *ctx);
fz_font_context *fz_keep_font_context(fz_context *ctx);
void fz_drop_font_context(fz_context *ctx);

typedef fz_font *(*fz_load_system_font_func)(fz_context *ctx, const char *name, int bold, int italic, int needs_exact_metrics);
typedef fz_font *(*fz_load_system_cjk_font_func)(fz_context *ctx, const char *name, int ros, int serif);
void fz_install_load_system_font_funcs(fz_context *ctx, fz_load_system_font_func f, fz_load_system_cjk_font_func f_cjk);
/* fz_load_*_font returns NULL if no font could be loaded (also on error) */
fz_font *fz_load_system_font(fz_context *ctx, const char *name, int bold, int italic, int needs_exact_metrics);
fz_font *fz_load_system_cjk_font(fz_context *ctx, const char *name, int ros, int serif);

const char *fz_lookup_builtin_font(fz_context *ctx, const char *name, int is_bold, int is_italic, int *size);
const char *fz_lookup_base14_font(fz_context *ctx, const char *name, int *len);
const char *fz_lookup_cjk_font(fz_context *ctx, int registry, int serif, int wmode, int *len, int *index);
const char *fz_lookup_noto_font(fz_context *ctx, int script, int lang, int serif, int *len);
const char *fz_lookup_noto_symbol_font(fz_context *ctx, int *len);
const char *fz_lookup_noto_emoji_font(fz_context *ctx, int *len);

fz_font *fz_load_fallback_font(fz_context *ctx, int script, int language, int serif, int bold, int italic);
fz_font *fz_load_fallback_symbol_font(fz_context *ctx);
fz_font *fz_load_fallback_emoji_font(fz_context *ctx);

fz_font *fz_new_type3_font(fz_context *ctx, const char *name, const fz_matrix *matrix);

fz_font *fz_new_font_from_memory(fz_context *ctx, const char *name, const char *data, int len, int index, int use_glyph_bbox);
fz_font *fz_new_font_from_buffer(fz_context *ctx, const char *name, fz_buffer *buffer, int index, int use_glyph_bbox);
fz_font *fz_new_font_from_file(fz_context *ctx, const char *name, const char *path, int index, int use_glyph_bbox);

fz_font *fz_keep_font(fz_context *ctx, fz_font *font);
void fz_drop_font(fz_context *ctx, fz_font *font);

void fz_set_font_bbox(fz_context *ctx, fz_font *font, float xmin, float ymin, float xmax, float ymax);
fz_rect *fz_bound_glyph(fz_context *ctx, fz_font *font, int gid, const fz_matrix *trm, fz_rect *r);
int fz_glyph_cacheable(fz_context *ctx, fz_font *font, int gid);

void fz_run_t3_glyph(fz_context *ctx, fz_font *font, int gid, const fz_matrix *trm, struct fz_device_s *dev);

void fz_decouple_type3_font(fz_context *ctx, fz_font *font, void *t3doc);

float fz_advance_glyph(fz_context *ctx, fz_font *font, int glyph, int wmode);
int fz_encode_character(fz_context *ctx, fz_font *font, int unicode);
int fz_encode_character_with_fallback(fz_context *ctx, fz_font *font, int unicode, int script, int language, fz_font **out_font);
void fz_get_glyph_name(fz_context *ctx, fz_font *font, int glyph, char *buf, int size);

void fz_print_font(fz_context *ctx, fz_output *out, fz_font *font);

void hb_lock(fz_context *ctx);
void hb_unlock(fz_context *ctx);

#endif
