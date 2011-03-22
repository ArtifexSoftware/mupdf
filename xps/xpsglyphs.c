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

/* XPS interpreter - text drawing support */

#include "ghostxps.h"

#include <ctype.h>

#define XPS_TEXT_BUFFER_SIZE 300

typedef struct xps_text_buffer_s xps_text_buffer_t;

struct xps_text_buffer_s
{
	int count;
	float x[XPS_TEXT_BUFFER_SIZE + 1];
	float y[XPS_TEXT_BUFFER_SIZE + 1];
	gs_glyph g[XPS_TEXT_BUFFER_SIZE];
};

static inline int unhex(int i)
{
	if (isdigit(i))
		return i - '0';
	return tolower(i) - 'a' + 10;
}

void
xps_debug_path(xps_context_t *ctx)
{
	segment *seg;
	curve_segment *cseg;

	seg = (segment*)ctx->pgs->path->first_subpath;
	while (seg)
	{
		switch (seg->type)
		{
		case s_start:
			dprintf2("%g %g moveto\n",
					fixed2float(seg->pt.x) * 0.001,
					fixed2float(seg->pt.y) * 0.001);
			break;
		case s_line:
			dprintf2("%g %g lineto\n",
					fixed2float(seg->pt.x) * 0.001,
					fixed2float(seg->pt.y) * 0.001);
			break;
		case s_line_close:
			dputs("closepath\n");
			break;
		case s_curve:
			cseg = (curve_segment*)seg;
			dprintf6("%g %g %g %g %g %g curveto\n",
					fixed2float(cseg->p1.x) * 0.001,
					fixed2float(cseg->p1.y) * 0.001,
					fixed2float(cseg->p2.x) * 0.001,
					fixed2float(cseg->p2.y) * 0.001,
					fixed2float(seg->pt.x) * 0.001,
					fixed2float(seg->pt.y) * 0.001);
			break;
		}
		seg = seg->next;
	}
}

/*
 * Some fonts in XPS are obfuscated by XOR:ing the first 32 bytes of the
 * data with the GUID in the fontname.
 */
static void
xps_deobfuscate_font_resource(xps_context_t *ctx, xps_part_t *part)
{
	byte buf[33];
	byte key[16];
	char *p;
	int i;

	p = strrchr(part->name, '/');
	if (!p)
		p = part->name;

	for (i = 0; i < 32 && *p; p++)
	{
		if (isxdigit(*p))
			buf[i++] = *p;
	}
	buf[i] = 0;

	if (i != 32)
	{
		gs_warn("cannot extract GUID from obfuscated font part name");
		return;
	}

	for (i = 0; i < 16; i++)
		key[i] = unhex(buf[i*2+0]) * 16 + unhex(buf[i*2+1]);

	for (i = 0; i < 16; i++)
	{
		part->data[i] ^= key[15-i];
		part->data[i+16] ^= key[15-i];
	}
}

static void
xps_select_best_font_encoding(xps_font_t *font)
{
	static struct { int pid, eid; } xps_cmap_list[] =
	{
		{ 3, 10 },		/* Unicode with surrogates */
		{ 3, 1 },		/* Unicode without surrogates */
		{ 3, 5 },		/* Wansung */
		{ 3, 4 },		/* Big5 */
		{ 3, 3 },		/* Prc */
		{ 3, 2 },		/* ShiftJis */
		{ 3, 0 },		/* Symbol */
		// { 0, * }, -- Unicode (deprecated)
		{ 1, 0 },
		{ -1, -1 },
	};

	int i, k, n, pid, eid;

	n = xps_count_font_encodings(font);
	for (k = 0; xps_cmap_list[k].pid != -1; k++)
	{
		for (i = 0; i < n; i++)
		{
			xps_identify_font_encoding(font, i, &pid, &eid);
			if (pid == xps_cmap_list[k].pid && eid == xps_cmap_list[k].eid)
			{
				xps_select_font_encoding(font, i);
				return;
			}
		}
	}

	gs_warn("could not find a suitable cmap");
}

/*
 * Call text drawing primitives.
 */

static int
xps_flush_text_buffer(xps_context_t *ctx, xps_font_t *font,
		xps_text_buffer_t *buf, int is_charpath)
{
	gs_text_params_t params;
	gs_text_enum_t *textenum;
	float x = buf->x[0];
	float y = buf->y[0];
	int code;
	int i;

	// dprintf1("flushing text buffer (%d glyphs)\n", buf->count);

	gs_moveto(ctx->pgs, x, y);

	params.operation = TEXT_FROM_GLYPHS | TEXT_REPLACE_WIDTHS;
	if (is_charpath)
		params.operation |= TEXT_DO_FALSE_CHARPATH;
	else
		params.operation |= TEXT_DO_DRAW;
	params.data.glyphs = buf->g;
	params.size = buf->count;
	params.x_widths = buf->x + 1;
	params.y_widths = buf->y + 1;
	params.widths_size = buf->count;

	for (i = 0; i < buf->count; i++)
	{
		buf->x[i] = buf->x[i] - x;
		buf->y[i] = buf->y[i] - y;
		x += buf->x[i];
		y += buf->y[i];
	}
	buf->x[buf->count] = 0;
	buf->y[buf->count] = 0;

	code = gs_text_begin(ctx->pgs, &params, ctx->memory, &textenum);
	if (code != 0)
		return gs_throw1(-1, "cannot gs_text_begin() (%d)", code);

	code = gs_text_process(textenum);

	if (code != 0)
		return gs_throw1(-1, "cannot gs_text_process() (%d)", code);

	gs_text_release(textenum, "gslt font render");

	buf->count = 0;

	return 0;
}

/*
 * Parse and draw an XPS <Glyphs> element.
 *
 * Indices syntax:

 GlyphIndices	= GlyphMapping ( ";" GlyphMapping )
 GlyphMapping	= ( [ClusterMapping] GlyphIndex ) [GlyphMetrics]
 ClusterMapping = "(" ClusterCodeUnitCount [":" ClusterGlyphCount] ")"
 ClusterCodeUnitCount	= * DIGIT
 ClusterGlyphCount		= * DIGIT
 GlyphIndex		= * DIGIT
 GlyphMetrics	= "," AdvanceWidth ["," uOffset ["," vOffset]]
 AdvanceWidth	= ["+"] RealNum
 uOffset		= ["+" | "-"] RealNum
 vOffset		= ["+" | "-"] RealNum
 RealNum		= ((DIGIT ["." DIGIT]) | ("." DIGIT)) [Exponent]
 Exponent		= ( ("E"|"e") ("+"|"-") DIGIT )

 */

static char *
xps_parse_digits(char *s, int *digit)
{
	*digit = 0;
	while (*s >= '0' && *s <= '9')
	{
		*digit = *digit * 10 + (*s - '0');
		s ++;
	}
	return s;
}

static inline int is_real_num_char(int c)
{
	return (c >= '0' && c <= '9') || c == 'e' || c == 'E' || c == '+' || c == '-' || c == '.';
}

static char *
xps_parse_real_num(char *s, float *number)
{
	char buf[64];
	char *p = buf;
	while (is_real_num_char(*s))
		*p++ = *s++;
	*p = 0;
	if (buf[0])
		*number = atof(buf);
	return s;
}

static char *
xps_parse_cluster_mapping(char *s, int *code_count, int *glyph_count)
{
	if (*s == '(')
		s = xps_parse_digits(s + 1, code_count);
	if (*s == ':')
		s = xps_parse_digits(s + 1, glyph_count);
	if (*s == ')')
		s ++;
	return s;
}

static char *
xps_parse_glyph_index(char *s, int *glyph_index)
{
	if (*s >= '0' && *s <= '9')
		s = xps_parse_digits(s, glyph_index);
	return s;
}

static char *
xps_parse_glyph_metrics(char *s, float *advance, float *uofs, float *vofs)
{
	if (*s == ',')
		s = xps_parse_real_num(s + 1, advance);
	if (*s == ',')
		s = xps_parse_real_num(s + 1, uofs);
	if (*s == ',')
		s = xps_parse_real_num(s + 1, vofs);
	return s;
}

/*
 * Parse unicode and indices strings and encode glyphs.
 * Calculate metrics for positioning.
 */
static int
xps_parse_glyphs_imp(xps_context_t *ctx, xps_font_t *font, float size,
		float originx, float originy, int is_sideways, int bidi_level,
		char *indices, char *unicode, int is_charpath)
{
	xps_text_buffer_t buf;
	xps_glyph_metrics_t mtx;
	float x = originx;
	float y = originy;
	char *us = unicode;
	char *is = indices;
	int un = 0;
	int code;

	buf.count = 0;

	if (!unicode && !indices)
		return gs_throw(-1, "no text in glyphs element");

	if (us)
	{
		if (us[0] == '{' && us[1] == '}')
			us = us + 2;
		un = strlen(us);
	}

	while ((us && un > 0) || (is && *is))
	{
		int code_count = 1;
		int glyph_count = 1;

		if (is && *is)
		{
			is = xps_parse_cluster_mapping(is, &code_count, &glyph_count);
		}

		if (code_count < 1)
			code_count = 1;
		if (glyph_count < 1)
			glyph_count = 1;

		while (code_count > 0 || glyph_count > 0)
		{
			int char_code = '?';
			int glyph_index = -1;
			float u_offset = 0.0;
			float v_offset = 0.0;
			float advance;

			if (glyph_count)
			{
				if (is && *is)
					is = xps_parse_glyph_index(is, &glyph_index);
				glyph_count --;
			}

			if (code_count)
			{
				if (us && un > 0)
				{
					int t = xps_utf8_to_ucs(&char_code, us, un);
					if (t < 0)
						return gs_rethrow(-1, "error decoding UTF-8 string");
					us += t; un -= t;
				}
				code_count --;
			}

			if (glyph_index == -1)
				glyph_index = xps_encode_font_char(font, char_code);

			xps_measure_font_glyph(ctx, font, glyph_index, &mtx);
			if (is_sideways)
				advance = mtx.vadv * 100.0;
			else if (bidi_level & 1)
				advance = -mtx.hadv * 100.0;
			else
				advance = mtx.hadv * 100.0;

			if (is && *is)
			{
				is = xps_parse_glyph_metrics(is, &advance, &u_offset, &v_offset);
				if (*is == ';')
					is ++;
			}

#if 0
			dprintf6("glyph mapping (%d:%d)%d,%g,%g,%g\n",
					code_count, glyph_count, glyph_index,
					advance, u_offset, v_offset);
#endif

			if (bidi_level & 1)
				u_offset = -mtx.hadv * 100 - u_offset;

			u_offset = u_offset * 0.01 * size;
			v_offset = v_offset * 0.01 * size;

			if (buf.count == XPS_TEXT_BUFFER_SIZE)
			{
				code = xps_flush_text_buffer(ctx, font, &buf, is_charpath);
				if (code)
					return gs_rethrow(code, "cannot flush buffered text");
			}

			if (is_sideways)
			{
				buf.x[buf.count] = x + u_offset + (mtx.vorg * size);
				buf.y[buf.count] = y - v_offset + (mtx.hadv * 0.5 * size);
			}
			else
			{
				buf.x[buf.count] = x + u_offset;
				buf.y[buf.count] = y - v_offset;
			}
			buf.g[buf.count] = glyph_index;
			buf.count ++;

			x += advance * 0.01 * size;
		}
	}

	if (buf.count > 0)
	{
		code = xps_flush_text_buffer(ctx, font, &buf, is_charpath);
		if (code)
			return gs_rethrow(code, "cannot flush buffered text");
	}

	return 0;
}

int
xps_parse_glyphs(xps_context_t *ctx,
		char *base_uri, xps_resource_t *dict, xps_item_t *root)
{
	xps_item_t *node;
	int code;

	char *fill_uri;
	char *opacity_mask_uri;

	char *bidi_level_att;
	char *caret_stops_att;
	char *fill_att;
	char *font_size_att;
	char *font_uri_att;
	char *origin_x_att;
	char *origin_y_att;
	char *is_sideways_att;
	char *indices_att;
	char *unicode_att;
	char *style_att;
	char *transform_att;
	char *clip_att;
	char *opacity_att;
	char *opacity_mask_att;

	xps_item_t *transform_tag = NULL;
	xps_item_t *clip_tag = NULL;
	xps_item_t *fill_tag = NULL;
	xps_item_t *opacity_mask_tag = NULL;

	char *fill_opacity_att = NULL;

	xps_part_t *part;
	xps_font_t *font;

	char partname[1024];
	char *subfont;

	gs_matrix matrix;
	float font_size = 10.0;
	int subfontid = 0;
	int is_sideways = 0;
	int bidi_level = 0;

	/*
	 * Extract attributes and extended attributes.
	 */

	bidi_level_att = xps_att(root, "BidiLevel");
	caret_stops_att = xps_att(root, "CaretStops");
	fill_att = xps_att(root, "Fill");
	font_size_att = xps_att(root, "FontRenderingEmSize");
	font_uri_att = xps_att(root, "FontUri");
	origin_x_att = xps_att(root, "OriginX");
	origin_y_att = xps_att(root, "OriginY");
	is_sideways_att = xps_att(root, "IsSideways");
	indices_att = xps_att(root, "Indices");
	unicode_att = xps_att(root, "UnicodeString");
	style_att = xps_att(root, "StyleSimulations");
	transform_att = xps_att(root, "RenderTransform");
	clip_att = xps_att(root, "Clip");
	opacity_att = xps_att(root, "Opacity");
	opacity_mask_att = xps_att(root, "OpacityMask");

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "Glyphs.RenderTransform"))
			transform_tag = xps_down(node);

		if (!strcmp(xps_tag(node), "Glyphs.OpacityMask"))
			opacity_mask_tag = xps_down(node);

		if (!strcmp(xps_tag(node), "Glyphs.Clip"))
			clip_tag = xps_down(node);

		if (!strcmp(xps_tag(node), "Glyphs.Fill"))
			fill_tag = xps_down(node);
	}

	fill_uri = base_uri;
	opacity_mask_uri = base_uri;

	xps_resolve_resource_reference(ctx, dict, &transform_att, &transform_tag, NULL);
	xps_resolve_resource_reference(ctx, dict, &clip_att, &clip_tag, NULL);
	xps_resolve_resource_reference(ctx, dict, &fill_att, &fill_tag, &fill_uri);
	xps_resolve_resource_reference(ctx, dict, &opacity_mask_att, &opacity_mask_tag, &opacity_mask_uri);

	/*
	 * Check that we have all the necessary information.
	 */

	if (!font_size_att || !font_uri_att || !origin_x_att || !origin_y_att)
		return gs_throw(-1, "missing attributes in glyphs element");

	if (!indices_att && !unicode_att)
		return 0; /* nothing to draw */

	if (is_sideways_att)
		is_sideways = !strcmp(is_sideways_att, "true");

	if (bidi_level_att)
		bidi_level = atoi(bidi_level_att);

	/*
	 * Find and load the font resource
	 */

	xps_absolute_path(partname, base_uri, font_uri_att, sizeof partname);
	subfont = strrchr(partname, '#');
	if (subfont)
	{
		subfontid = atoi(subfont + 1);
		*subfont = 0;
	}

	font = xps_hash_lookup(ctx->font_table, partname);
	if (!font)
	{
		part = xps_read_part(ctx, partname);
		if (!part)
			return gs_throw1(-1, "cannot find font resource part '%s'", partname);

		/* deobfuscate if necessary */
		if (strstr(part->name, ".odttf"))
			xps_deobfuscate_font_resource(ctx, part);
		if (strstr(part->name, ".ODTTF"))
			xps_deobfuscate_font_resource(ctx, part);

		font = xps_new_font(ctx, part->data, part->size, subfontid);
		if (!font)
			return gs_rethrow1(-1, "cannot load font resource '%s'", partname);

		xps_select_best_font_encoding(font);

		xps_hash_insert(ctx, ctx->font_table, part->name, font);

		/* NOTE: we kept part->name in the hashtable and part->data in the font */
		xps_free(ctx, part);
	}

	/*
	 * Set up graphics state.
	 */

	gs_gsave(ctx->pgs);

	if (transform_att || transform_tag)
	{
		gs_matrix transform;

		if (transform_att)
			xps_parse_render_transform(ctx, transform_att, &transform);
		if (transform_tag)
			xps_parse_matrix_transform(ctx, transform_tag, &transform);

		gs_concat(ctx->pgs, &transform);
	}

	if (clip_att || clip_tag)
	{
		if (clip_att)
			xps_parse_abbreviated_geometry(ctx, clip_att);
		if (clip_tag)
			xps_parse_path_geometry(ctx, dict, clip_tag, 0);
		xps_clip(ctx);
	}

	font_size = atof(font_size_att);

	gs_setfont(ctx->pgs, font->font);
	gs_make_scaling(font_size, -font_size, &matrix);
	if (is_sideways)
		gs_matrix_rotate(&matrix, 90.0, &matrix);

	gs_setcharmatrix(ctx->pgs, &matrix);

	gs_matrix_multiply(&matrix, &font->font->orig_FontMatrix, &font->font->FontMatrix);

	code = xps_begin_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);
	if (code)
	{
		gs_grestore(ctx->pgs);
		return gs_rethrow(code, "cannot create transparency group");
	}

	/*
	 * If it's a solid color brush fill/stroke do a simple fill
	 */

	if (fill_tag && !strcmp(xps_tag(fill_tag), "SolidColorBrush"))
	{
		fill_opacity_att = xps_att(fill_tag, "Opacity");
		fill_att = xps_att(fill_tag, "Color");
		fill_tag = NULL;
	}

	if (fill_att)
	{
		float samples[32];
		gs_color_space *colorspace;
		xps_parse_color(ctx, base_uri, fill_att, &colorspace, samples);
		if (fill_opacity_att)
			samples[0] = atof(fill_opacity_att);
		xps_set_color(ctx, colorspace, samples);
		code = xps_parse_glyphs_imp(ctx, font, font_size,
				atof(origin_x_att), atof(origin_y_att),
				is_sideways, bidi_level,
				indices_att, unicode_att, 0);
		if (code)
		{
			xps_end_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot parse glyphs data");
		}
	}

	/*
	 * If it's a visual brush or image, use the charpath as a clip mask to paint brush
	 */

	if (fill_tag)
	{
		ctx->fill_rule = 1; /* always use non-zero winding rule for char paths */
		code = xps_parse_glyphs_imp(ctx, font, font_size,
				atof(origin_x_att), atof(origin_y_att),
				is_sideways, bidi_level, indices_att, unicode_att, 1);
		if (code)
		{
			xps_end_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot parse glyphs data");
		}

		code = xps_parse_brush(ctx, fill_uri, dict, fill_tag);
		if (code)
		{
			xps_end_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot parse fill brush");
		}
	}

	xps_end_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);

	gs_grestore(ctx->pgs);

	return 0;
}
