/*
 * A very simple font cache and rasterizer that uses FreeType
 * to draw fonts from a single OpenGL texture. The code uses
 * a linear-probe hashtable, and writes new glyphs into
 * the texture using glTexSubImage2D. When the texture fills
 * up, or the hash table gets too crowded, the cache is emptied.
 *
 * This is designed to be used for horizontal text only,
 * and draws unhinted text with subpixel accurate metrics
 * and kerning. As such, you should always call the drawing
 * function with an orthogonal transform that maps units
 * to pixels accurately.
 */

#include "gl-app.h"

#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>

#define PADDING 1		/* set to 0 to save some space but disallow arbitrary transforms */

#define MAXGLYPHS 4093	/* prime number for hash table goodness */
#define CACHESIZE 1024
#define XPRECISION 4
#define YPRECISION 1

struct key
{
	fz_font *font;
	short gid;
	unsigned char subx;
	unsigned char suby;
};

struct glyph
{
	char lsb, top, w, h;
	short s, t;
};

struct table
{
	struct key key;
	struct glyph glyph;
};

static struct table g_table[MAXGLYPHS];
static int g_table_load = 0;
static unsigned int g_cache_tex = 0;
static int g_cache_w = CACHESIZE;
static int g_cache_h = CACHESIZE;
static int g_cache_row_y = 0;
static int g_cache_row_x = 0;
static int g_cache_row_h = 0;

static fz_font *g_font = NULL;
static float g_font_size = 16;

static void clear_font_cache(void)
{
#if PADDING > 0
	unsigned char *zero = malloc(g_cache_w * g_cache_h);
	memset(zero, 0, g_cache_w * g_cache_h);
	glBindTexture(GL_TEXTURE_2D, g_cache_tex);
	glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, g_cache_w, g_cache_h, GL_ALPHA, GL_UNSIGNED_BYTE, zero);
	free(zero);
#endif

	memset(g_table, 0, sizeof(g_table));
	g_table_load = 0;

	g_cache_row_y = PADDING;
	g_cache_row_x = PADDING;
	g_cache_row_h = 0;
}

void ui_init_fonts(fz_context *ctx, float pixelsize)
{
	const char *data;
	int size;

	glGenTextures(1, &g_cache_tex);
	glBindTexture(GL_TEXTURE_2D, g_cache_tex);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_ALPHA, g_cache_w, g_cache_h, 0, GL_ALPHA, GL_UNSIGNED_BYTE, NULL);

	clear_font_cache();

	data = fz_lookup_builtin_font(ctx, "Charis SIL", 0, 0, &size);
	if (!data)
		data = fz_lookup_builtin_font(ctx, "Times", 0, 0, &size);
	g_font = fz_new_font_from_memory(ctx, NULL, data, size, 0, 0);
	g_font_size = pixelsize;
}

void ui_finish_fonts(fz_context *ctx)
{
	clear_font_cache();
	fz_drop_font(ctx, g_font);
}

static unsigned int hashfunc(struct key *key)
{
	unsigned char *buf = (unsigned char *)key;
	unsigned int len = sizeof(struct key);
	unsigned int h = 0;
	while (len--)
		h = *buf++ + (h << 6) + (h << 16) - h;
	return h;
}

static unsigned int lookup_table(struct key *key)
{
	unsigned int pos = hashfunc(key) % MAXGLYPHS;
	while (1)
	{
		if (!g_table[pos].key.font) /* empty slot */
			return pos;
		if (!memcmp(key, &g_table[pos].key, sizeof(struct key))) /* matching slot */
			return pos;
		pos = (pos + 1) % MAXGLYPHS;
	}
}

static struct glyph *lookup_glyph(fz_font *font, int gid, float *xp, float *yp)
{
	fz_matrix trm, subpix_trm;
	unsigned char subx, suby;
	fz_pixmap *pixmap;
	struct key key;
	unsigned int pos;
	int w, h;

	/* match fitz's glyph cache quantization */
	fz_scale(&trm, g_font_size, -g_font_size);
	trm.e = *xp;
	trm.f = *yp;
	fz_subpixel_adjust(ctx, &trm, &subpix_trm, &subx, &suby);
	*xp = trm.e;
	*yp = trm.f;

	/*
	 * Look it up in the table
	 */

	memset(&key, 0, sizeof key);
	key.font = font;
	key.gid = gid;
	key.subx = subx;
	key.suby = suby;

	pos = lookup_table(&key);
	if (g_table[pos].key.font)
		return &g_table[pos].glyph;

	/*
	 * Render the bitmap
	 */

	glEnd();

	pixmap = fz_render_glyph_pixmap(ctx, font, gid, &subpix_trm, NULL);
	w = pixmap->w;
	h = pixmap->h;

	/*
	 * Find an empty slot in the texture
	 */

	if (g_table_load == (MAXGLYPHS * 3) / 4)
	{
		puts("font cache table full, clearing cache");
		clear_font_cache();
		pos = lookup_table(&key);
	}

	if (h + PADDING > g_cache_h || w + PADDING > g_cache_w)
		return NULL;

	if (g_cache_row_x + w + PADDING > g_cache_w)
	{
		g_cache_row_y += g_cache_row_h + PADDING;
		g_cache_row_x = PADDING;
		g_cache_row_h = 0;
	}
	if (g_cache_row_y + h + PADDING > g_cache_h)
	{
		puts("font cache texture full, clearing cache");
		clear_font_cache();
		pos = lookup_table(&key);
	}

	/*
	 * Copy bitmap into texture
	 */

	memcpy(&g_table[pos].key, &key, sizeof(struct key));
	g_table[pos].glyph.w = pixmap->w;
	g_table[pos].glyph.h = pixmap->h;
	g_table[pos].glyph.lsb = pixmap->x;
	g_table[pos].glyph.top = -pixmap->y;
	g_table[pos].glyph.s = g_cache_row_x;
	g_table[pos].glyph.t = g_cache_row_y;
	g_table_load ++;

	glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
	glPixelStorei(GL_UNPACK_ROW_LENGTH, pixmap->w);
	glTexSubImage2D(GL_TEXTURE_2D, 0, g_cache_row_x, g_cache_row_y, w, h,
			GL_ALPHA, GL_UNSIGNED_BYTE, pixmap->samples);
	glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);

	fz_drop_pixmap(ctx, pixmap);

	glBegin(GL_QUADS);

	g_cache_row_x += w + PADDING;
	if (g_cache_row_h < h + PADDING)
		g_cache_row_h = h + PADDING;

	return &g_table[pos].glyph;
}

static float ui_draw_glyph(fz_font *font, int gid, float x, float y)
{
	struct glyph *glyph;
	float s0, t0, s1, t1, xc, yc;

	glyph = lookup_glyph(font, gid, &x, &y);
	if (!glyph)
		return 0;

	s0 = (float) glyph->s / g_cache_w;
	t0 = (float) glyph->t / g_cache_h;
	s1 = (float) (glyph->s + glyph->w) / g_cache_w;
	t1 = (float) (glyph->t + glyph->h) / g_cache_h;
	xc = floorf(x) + glyph->lsb;
	yc = floorf(y) - glyph->top + glyph->h;

	glTexCoord2f(s0, t0); glVertex2f(xc, yc - glyph->h);
	glTexCoord2f(s1, t0); glVertex2f(xc + glyph->w, yc - glyph->h);
	glTexCoord2f(s1, t1); glVertex2f(xc + glyph->w, yc);
	glTexCoord2f(s0, t1); glVertex2f(xc, yc);

	return fz_advance_glyph(ctx, font, gid, 0) * g_font_size;
}

float ui_measure_character(fz_context *ctx, int ucs)
{
	fz_font *font;
	int gid = fz_encode_character_with_fallback(ctx, g_font, ucs, 0, 0, &font);
	return fz_advance_glyph(ctx, font, gid, 0) * g_font_size;
}

float ui_draw_character(fz_context *ctx, int ucs, float x, float y)
{
	fz_font *font;
	int gid = fz_encode_character_with_fallback(ctx, g_font, ucs, 0, 0, &font);
	return ui_draw_glyph(font, gid, x, y);
}

void ui_begin_text(fz_context *ctx)
{
	glBindTexture(GL_TEXTURE_2D, g_cache_tex);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_BLEND);
	glEnable(GL_TEXTURE_2D);
	glBegin(GL_QUADS);
}

void ui_end_text(fz_context *ctx)
{
	glEnd();
	glDisable(GL_TEXTURE_2D);
	glDisable(GL_BLEND);
}

float ui_draw_string(fz_context *ctx, float x, float y, const char *str)
{
	int ucs;

	ui_begin_text(ctx);

	while (*str)
	{
		str += fz_chartorune(&ucs, str);
		x += ui_draw_character(ctx, ucs, x, y);
	}

	ui_end_text(ctx);

	return x;
}

float ui_measure_string(fz_context *ctx, char *str)
{
	int ucs;
	float x = 0;

	ui_begin_text(ctx);

	while (*str)
	{
		str += fz_chartorune(&ucs, str);
		x += ui_measure_character(ctx, ucs);
	}

	ui_end_text(ctx);

	return x;
}
