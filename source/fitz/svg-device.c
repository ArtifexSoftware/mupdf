// Copyright (C) 2004-2024 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 39 Mesa Street, Suite 108A, San Francisco,
// CA 94129, USA, for further information.

#include "mupdf/fitz.h"

#include <string.h>
#include <float.h>
#include <math.h>

typedef struct
{
	int pattern;
	fz_matrix ctm;
	fz_rect view;
	fz_rect area;
	fz_point step;
} tile;

typedef struct
{
	int id;
	fz_font *font;
	int max_sentlist;
	char *sentlist;
} font;

typedef struct
{
	int id;
	fz_image *image;
} image;

typedef struct
{
	fz_device super;

	int text_as_text;
	int reuse_images;

	fz_output *real_out;
	int in_defs;
	fz_buffer *defs;
	fz_buffer *main;
	fz_buffer *out;

	int *save_id;
	int id;

	int blend_bitmask;

	int num_tiles;
	int max_tiles;
	tile *tiles;

	int num_fonts;
	int max_fonts;
	font *fonts;

	int num_images;
	int max_images;
	image *images;

	int layers;

	float page_width;
	float page_height;
} svg_device;

static fz_buffer *
start_def(fz_context *ctx, svg_device *sdev, int need_tag)
{
	if (sdev->in_defs > 0)
	{
		if (need_tag)
			fz_append_string(ctx, sdev->defs, "<defs>\n");
	}
	else
	{
		sdev->out = sdev->defs;
	}
	sdev->in_defs++;
	return sdev->out;
}

static fz_buffer *
end_def(fz_context *ctx, svg_device *sdev, int need_tag)
{
	sdev->in_defs--;
	if (sdev->in_defs > 0)
	{
		if (need_tag)
			fz_append_string(ctx, sdev->defs, "</defs>\n");
	}
	else
	{
		sdev->out = sdev->main;
	}
	return sdev->out;
}

/* Helper functions */

struct svg_path_walker_state {
	fz_buffer *out;
	int space; // needs space
	float x, y; // last location
	int cmd; // last command
};

static void
svg_path_emit_number(fz_context *ctx, struct svg_path_walker_state *pws, float a)
{
	if (pws->space && a >= 0)
		fz_append_byte(ctx, pws->out, ' ');
	fz_append_printf(ctx, pws->out, "%g", a);
	pws->space = 1;
}

static void
svg_path_emit_command(fz_context *ctx, struct svg_path_walker_state *pws, char cmd)
{
	if (pws->cmd != cmd) {
		fz_append_byte(ctx, pws->out, cmd);
		pws->space = 0;
		pws->cmd = cmd;
	}
}

static void
svg_path_moveto(fz_context *ctx, void *arg, float x, float y)
{
	struct svg_path_walker_state *pws = arg;
	svg_path_emit_command(ctx, pws, 'M');
	svg_path_emit_number(ctx, pws, x);
	svg_path_emit_number(ctx, pws, y);
	pws->cmd = 'L';
	pws->x = x;
	pws->y = y;
}

static void
svg_path_lineto(fz_context *ctx, void *arg, float x, float y)
{
	struct svg_path_walker_state *pws = arg;
	if (pws->x == x) {
		svg_path_emit_command(ctx, pws, 'V');
		svg_path_emit_number(ctx, pws, y);
	} else if (pws->y == y) {
		svg_path_emit_command(ctx, pws, 'H');
		svg_path_emit_number(ctx, pws, x);
	} else {
		svg_path_emit_command(ctx, pws, 'L');
		svg_path_emit_number(ctx, pws, x);
		svg_path_emit_number(ctx, pws, y);
	}
	pws->x = x;
	pws->y = y;
}

static void
svg_path_curveto(fz_context *ctx, void *arg, float x1, float y1, float x2, float y2, float x3, float y3)
{
	struct svg_path_walker_state *pws = arg;
	svg_path_emit_command(ctx, pws, 'C');
	svg_path_emit_number(ctx, pws, x1);
	svg_path_emit_number(ctx, pws, y1);
	svg_path_emit_number(ctx, pws, x2);
	svg_path_emit_number(ctx, pws, y2);
	svg_path_emit_number(ctx, pws, x3);
	svg_path_emit_number(ctx, pws, y3);
	pws->x = x3;
	pws->y = y3;
}

static void
svg_path_close(fz_context *ctx, void *arg)
{
	struct svg_path_walker_state *pws = arg;
	svg_path_emit_command(ctx, arg, 'Z');
	pws->x = NAN;
	pws->y = NAN;
}

static const fz_path_walker svg_path_walker =
{
	svg_path_moveto,
	svg_path_lineto,
	svg_path_curveto,
	svg_path_close
};

static void
svg_dev_path(fz_context *ctx, svg_device *sdev, const fz_path *path)
{
	struct svg_path_walker_state pws = { sdev->out, 0, NAN, NAN, 0 };
	fz_append_printf(ctx, sdev->out, " d=\"");
	fz_walk_path(ctx, path, &svg_path_walker, &pws);
	fz_append_printf(ctx, sdev->out, "\"");
}

static void
svg_dev_ctm(fz_context *ctx, svg_device *sdev, fz_matrix ctm)
{
	fz_buffer *out = sdev->out;

	if (ctm.a != 1.0f || ctm.b != 0 || ctm.c != 0 || ctm.d != 1.0f || ctm.e != 0 || ctm.f != 0)
	{
		fz_append_printf(ctx, out, " transform=\"matrix(%g,%g,%g,%g,%g,%g)\"",
			ctm.a, ctm.b, ctm.c, ctm.d, ctm.e, ctm.f);
	}
}

static void
svg_dev_stroke_state(fz_context *ctx, svg_device *sdev, const fz_stroke_state *stroke_state, fz_matrix ctm)
{
	fz_buffer *out = sdev->out;
	float exp;

	exp = fz_matrix_expansion(ctm);
	if (exp == 0)
		exp = 1;
	exp = stroke_state->linewidth/exp;

	fz_append_printf(ctx, out, " stroke-width=\"%g\"", exp);
	fz_append_printf(ctx, out, " stroke-linecap=\"%s\"",
		(stroke_state->start_cap == FZ_LINECAP_SQUARE ? "square" :
			(stroke_state->start_cap == FZ_LINECAP_ROUND ? "round" : "butt")));
	if (stroke_state->dash_len != 0)
	{
		int i;
		fz_append_printf(ctx, out, " stroke-dasharray=");
		for (i = 0; i < stroke_state->dash_len; i++)
			fz_append_printf(ctx, out, "%c%g", (i == 0 ? '\"' : ','), stroke_state->dash_list[i]);
		fz_append_printf(ctx, out, "\"");
		if (stroke_state->dash_phase != 0)
			fz_append_printf(ctx, out, " stroke-dashoffset=\"%g\"", stroke_state->dash_phase);
	}
	if (stroke_state->linejoin == FZ_LINEJOIN_MITER || stroke_state->linejoin == FZ_LINEJOIN_MITER_XPS)
		fz_append_printf(ctx, out, " stroke-miterlimit=\"%g\"", stroke_state->miterlimit);
	fz_append_printf(ctx, out, " stroke-linejoin=\"%s\"",
		(stroke_state->linejoin == FZ_LINEJOIN_BEVEL ? "bevel" :
			(stroke_state->linejoin == FZ_LINEJOIN_ROUND ? "round" : "miter")));
}

static unsigned int
svg_hex_color(fz_context *ctx, fz_colorspace *colorspace, const float *color, fz_color_params color_params)
{
	float rgb[3];
	int r, g, b;

	if (colorspace != fz_device_rgb(ctx))
	{
		fz_convert_color(ctx, colorspace, color, fz_device_rgb(ctx), rgb, NULL, color_params);
		color = rgb;
	}

	r = fz_clampi(255 * color[0] + 0.5f, 0, 255);
	g = fz_clampi(255 * color[1] + 0.5f, 0, 255);
	b = fz_clampi(255 * color[2] + 0.5f, 0, 255);

	return (r << 16) | (g << 8) | b;
}

static void
svg_dev_fill_color(fz_context *ctx, svg_device *sdev, fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_buffer *out = sdev->out;
	if (colorspace)
	{
		int rgb = svg_hex_color(ctx, colorspace, color, color_params);
		if (rgb != 0) /* black is the default value */
			fz_append_printf(ctx, out, " fill=\"#%06x\"", rgb);
	}
	else
		fz_append_printf(ctx, out, " fill=\"none\"");
	if (alpha != 1)
		fz_append_printf(ctx, out, " fill-opacity=\"%g\"", alpha);
}

static void
svg_dev_stroke_color(fz_context *ctx, svg_device *sdev, fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_buffer *out = sdev->out;
	if (colorspace)
		fz_append_printf(ctx, out, " fill=\"none\" stroke=\"#%06x\"", svg_hex_color(ctx, colorspace, color, color_params));
	else
		fz_append_printf(ctx, out, " fill=\"none\" stroke=\"none\"");
	if (alpha != 1)
		fz_append_printf(ctx, out, " stroke-opacity=\"%g\"", alpha);
}

static void
svg_font_family(fz_context *ctx, char buf[], int size, const char *name)
{
	/* Remove "ABCDEF+" prefix and "-Bold" suffix. */
	char *p = strchr(name, '+');
	if (p) fz_strlcpy(buf, p+1, size);
	else fz_strlcpy(buf, name, size);
	p = strrchr(buf, '-');
	if (p) *p = 0;
}

static int
find_first_char(fz_context *ctx, const fz_text_span *span, int i)
{
	for (; i < span->len; ++i)
		if (span->items[i].ucs >= 0)
			return i;
	return i;
}

static int
find_next_line_break(fz_context *ctx, const fz_text_span *span, fz_matrix inv_tm, int i)
{
	fz_point p, old_p;

	old_p.x = span->items[i].x;
	old_p.y = span->items[i].y;
	old_p = fz_transform_point(old_p, inv_tm);

	for (++i; i < span->len; ++i)
	{
		if (span->items[i].ucs >= 0)
		{
			p.x = span->items[i].x;
			p.y = span->items[i].y;
			p = fz_transform_point(p, inv_tm);
			if (span->wmode == 0)
			{
				if (p.y != old_p.y)
					return i;
			}
			else
			{
				if (p.x != old_p.x)
					return i;
			}
			old_p = p;
		}
	}

	return i;
}

static float
svg_cluster_advance(fz_context *ctx, const fz_text_span *span, int i, int end)
{
	int n = 1;
	while (i + n < end && span->items[i + n].gid == -1)
		++n;
	if (n > 1)
		return span->items[i].adv / n;
	return 0; /* this value is never used (since n==1) */
}

static void
svg_dev_text_span(fz_context *ctx, svg_device *sdev, fz_matrix ctm, const fz_text_span *span)
{
	fz_buffer *out = sdev->out;
	char font_family[100];
	int is_bold, is_italic;
	fz_matrix tm, inv_tm, final_tm;
	fz_point p;
	float font_size;
	fz_text_item *it;
	int start, end, i;
	float cluster_advance = 0;

	if (span->len == 0)
	{
		fz_append_printf(ctx, out, "/>\n");
		return;
	}

	tm = span->trm;
	font_size = fz_matrix_expansion(tm);
	final_tm.a = tm.a / font_size;
	final_tm.b = tm.b / font_size;
	final_tm.c = -tm.c / font_size;
	final_tm.d = -tm.d / font_size;
	final_tm.e = 0;
	final_tm.f = 0;
	inv_tm = fz_invert_matrix(final_tm);
	final_tm = fz_concat(final_tm, ctm);

	tm.e = span->items[0].x;
	tm.f = span->items[0].y;

	svg_font_family(ctx, font_family, sizeof font_family, fz_font_name(ctx, span->font));
	is_bold = fz_font_is_bold(ctx, span->font);
	is_italic = fz_font_is_italic(ctx, span->font);

	fz_append_printf(ctx, out, " xml:space=\"preserve\"");
	fz_append_printf(ctx, out, " transform=\"matrix(%M)\"", &final_tm);
	fz_append_printf(ctx, out, " font-size=\"%g\"", font_size);
	fz_append_printf(ctx, out, " font-family=\"%s\"", font_family);
	if (is_bold) fz_append_printf(ctx, out, " font-weight=\"bold\"");
	if (is_italic) fz_append_printf(ctx, out, " font-style=\"italic\"");
	if (span->wmode != 0) fz_append_printf(ctx, out, " writing-mode=\"tb\"");

	fz_append_byte(ctx, out, '>');

	start = find_first_char(ctx, span, 0);
	while (start < span->len)
	{
		end = find_next_line_break(ctx, span, inv_tm, start);

		p.x = span->items[start].x;
		p.y = span->items[start].y;
		p = fz_transform_point(p, inv_tm);
		if (span->items[start].gid >= 0)
			cluster_advance = svg_cluster_advance(ctx, span, start, end);
		if (span->wmode == 0)
			fz_append_printf(ctx, out, "<tspan y=\"%g\" x=\"%g", p.y, p.x);
		else
			fz_append_printf(ctx, out, "<tspan x=\"%g\" y=\"%g", p.x, p.y);
		for (i = start + 1; i < end; ++i)
		{
			it = &span->items[i];
			if (it->gid >= 0)
				cluster_advance = svg_cluster_advance(ctx, span, i, end);
			if (it->ucs >= 0)
			{
				if (it->gid >= 0)
				{
					p.x = it->x;
					p.y = it->y;
					p = fz_transform_point(p, inv_tm);
				}
				else
				{
					/* we have no glyph (such as in a ligature) -- advance a bit */
					if (span->wmode == 0)
						p.x += font_size * cluster_advance;
					else
						p.y += font_size * cluster_advance;
				}
				fz_append_printf(ctx, out, " %g", span->wmode == 0 ? p.x : p.y);
			}
		}
		fz_append_printf(ctx, out, "\">");
		for (i = start; i < end; ++i)
		{
			it = &span->items[i];
			if (it->ucs >= 0)
			{
				int c = it->ucs;
				if (c >= 32 && c <= 127 && c != '<' && c != '&' && c != '>')
					fz_append_byte(ctx, out, c);
				else
					fz_append_printf(ctx, out, "&#x%04x;", c);
			}
		}
		fz_append_printf(ctx, out, "</tspan>");

		start = find_first_char(ctx, span, end);
	}

	fz_append_printf(ctx, out, "</text>\n");
}

static font *
svg_dev_text_span_as_paths_defs(fz_context *ctx, fz_device *dev, fz_text_span *span, fz_matrix ctm)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;
	int i, font_idx;
	font *fnt;

	for (font_idx = 0; font_idx < sdev->num_fonts; font_idx++)
	{
		if (sdev->fonts[font_idx].font == span->font)
			break;
	}
	if (font_idx == sdev->num_fonts)
	{
		/* New font */
		if (font_idx == sdev->max_fonts)
		{
			int newmax = sdev->max_fonts * 2;
			if (newmax == 0)
				newmax = 4;
			sdev->fonts = fz_realloc_array(ctx, sdev->fonts, newmax, font);
			memset(&sdev->fonts[font_idx], 0, (newmax - font_idx) * sizeof(font));
			sdev->max_fonts = newmax;
		}
		sdev->fonts[font_idx].id = sdev->id++;
		sdev->fonts[font_idx].font = fz_keep_font(ctx, span->font);
		sdev->num_fonts++;
	}
	fnt = &sdev->fonts[font_idx];

	for (i=0; i < span->len; i++)
	{
		fz_text_item *it = &span->items[i];
		int gid = it->gid;

		if (gid < 0)
			continue;
		if (gid >= fnt->max_sentlist)
		{
			int j;
			fnt->sentlist = fz_realloc_array(ctx, fnt->sentlist, gid+1, char);
			for (j = fnt->max_sentlist; j <= gid; j++)
				fnt->sentlist[j] = 0;
			fnt->max_sentlist = gid+1;
		}
		if (!fnt->sentlist[gid])
		{
			/* Need to send this one */
			fz_path *path;
			out = start_def(ctx, sdev, 1);
			if (fz_font_ft_face(ctx, span->font))
			{
				path = fz_outline_glyph(ctx, span->font, gid, fz_identity);
				if (path)
				{
					fz_append_printf(ctx, out, "<path id=\"font_%d_%d\"", fnt->id, gid);
					svg_dev_path(ctx, sdev, path);
					fz_append_printf(ctx, out, "/>\n");
					fz_drop_path(ctx, path);
				}
				else
				{
					fz_append_printf(ctx, out, "<g id=\"font_%d_%d\"></g>\n", fnt->id, gid);
				}
			}
			else if (fz_font_t3_procs(ctx, span->font))
			{
				fz_append_printf(ctx, out, "<g id=\"font_%d_%d\">\n", fnt->id, gid);
				fz_run_t3_glyph(ctx, span->font, gid, fz_identity, dev);
				fnt = &sdev->fonts[font_idx]; /* recursion may realloc the font array! */
				fz_append_printf(ctx, out, "</g>\n");
			}
			out = end_def(ctx, sdev, 1);
			fnt->sentlist[gid] = 1;
		}
	}
	return fnt;
}

static void
svg_dev_data_text(fz_context *ctx, fz_buffer *out, int c)
{
	if (c > 0)
	{
		fz_append_string(ctx, out, " data-text=\"");
		if (c == '&')
			fz_append_string(ctx, out, "&amp;");
		else if (c == '"')
			fz_append_string(ctx, out, "&quot;");
		else if (c >= 32 && c < 127 && c != '<' && c != '>')
			fz_append_byte(ctx, out, c);
		else if (c >= 0xD800 && c <= 0xDFFF)
			/* no surrogate characters in SVG */
			fz_append_printf(ctx, out, "&#xFFFD;");
		else
			fz_append_printf(ctx, out, "&#x%04x;", c);
		fz_append_byte(ctx, out, '"');
	}
}

static void
svg_dev_text_span_as_paths_fill(fz_context *ctx, fz_device *dev, const fz_text_span *span, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, font *fnt, fz_color_params color_params)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;
	fz_matrix trm, mtx;
	int i;

	/* Rely on the fact that trm.{e,f} == 0 */
	trm.a = span->trm.a;
	trm.b = span->trm.b;
	trm.c = span->trm.c;
	trm.d = span->trm.d;
	trm.e = 0;
	trm.f = 0;

	for (i=0; i < span->len; i++)
	{
		fz_text_item *it = &span->items[i];
		int gid = it->gid;
		if (gid < 0)
			continue;

		trm.e = it->x;
		trm.f = it->y;
		mtx = fz_concat(trm, ctm);

		fz_append_string(ctx, out, "<use");
		svg_dev_data_text(ctx, out, it->ucs);
		fz_append_printf(ctx, out, " xlink:href=\"#font_%d_%d\"", fnt->id, gid);
		svg_dev_ctm(ctx, sdev, mtx);
		svg_dev_fill_color(ctx, sdev, colorspace, color, alpha, color_params);
		fz_append_printf(ctx, out, "/>\n");
	}
}

static void
svg_dev_text_span_as_paths_stroke(fz_context *ctx, fz_device *dev, const fz_text_span *span,
	const fz_stroke_state *stroke, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, font *fnt, fz_color_params color_params)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;
	fz_matrix trm, mtx;
	int i;

	/* Rely on the fact that trm.{e,f} == 0 */
	trm.a = span->trm.a;
	trm.b = span->trm.b;
	trm.c = span->trm.c;
	trm.d = span->trm.d;
	trm.e = 0;
	trm.f = 0;

	for (i=0; i < span->len; i++)
	{
		fz_text_item *it = &span->items[i];
		int gid = it->gid;
		if (gid < 0)
			continue;

		trm.e = it->x;
		trm.f = it->y;
		mtx = fz_concat(trm, ctm);

		fz_append_string(ctx, out, "<use");
		svg_dev_data_text(ctx, out, it->ucs);
		fz_append_printf(ctx, out, " xlink:href=\"#font_%d_%d\"", fnt->id, gid);
		svg_dev_stroke_state(ctx, sdev, stroke, mtx);
		svg_dev_ctm(ctx, sdev, mtx);
		svg_dev_stroke_color(ctx, sdev, colorspace, color, alpha, color_params);
		fz_append_printf(ctx, out, "/>\n");
	}
}

/* Entry points */

static void
svg_dev_fill_path(fz_context *ctx, fz_device *dev, const fz_path *path, int even_odd, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;

	fz_append_printf(ctx, out, "<path");
	svg_dev_ctm(ctx, sdev, ctm);
	svg_dev_path(ctx, sdev, path);
	svg_dev_fill_color(ctx, sdev, colorspace, color, alpha, color_params);
	if (even_odd)
		fz_append_printf(ctx, out, " fill-rule=\"evenodd\"");
	fz_append_printf(ctx, out, "/>\n");
}

static void
svg_dev_stroke_path(fz_context *ctx, fz_device *dev, const fz_path *path, const fz_stroke_state *stroke, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;

	fz_append_printf(ctx, out, "<path");
	svg_dev_ctm(ctx, sdev, ctm);
	svg_dev_stroke_state(ctx, sdev, stroke, fz_identity);
	svg_dev_stroke_color(ctx, sdev, colorspace, color, alpha, color_params);
	svg_dev_path(ctx, sdev, path);
	fz_append_printf(ctx, out, "/>\n");
}

static void
svg_dev_clip_path(fz_context *ctx, fz_device *dev, const fz_path *path, int even_odd, fz_matrix ctm, fz_rect scissor)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out;

	int num = sdev->id++;

	out = start_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<clipPath id=\"clip_%d\">\n", num);
	fz_append_printf(ctx, out, "<path");
	svg_dev_ctm(ctx, sdev, ctm);
	svg_dev_path(ctx, sdev, path);
	if (even_odd)
		fz_append_printf(ctx, out, " clip-rule=\"evenodd\"");
	fz_append_printf(ctx, out, "/>\n</clipPath>\n");
	out = end_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<g clip-path=\"url(#clip_%d)\">\n", num);
}

static void
svg_dev_clip_stroke_path(fz_context *ctx, fz_device *dev, const fz_path *path, const fz_stroke_state *stroke, fz_matrix ctm, fz_rect scissor)
{
	svg_device *sdev = (svg_device*)dev;

	fz_buffer *out;
	fz_rect bounds;
	int num = sdev->id++;
	float white[3] = { 1, 1, 1 };

	bounds = fz_bound_path(ctx, path, stroke, ctm);

	out = start_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<mask id=\"mask_%d\" x=\"%g\" y=\"%g\" width=\"%g\" height=\"%g\" maskUnits=\"userSpaceOnUse\" maskContentUnits=\"userSpaceOnUse\">\n",
		num, bounds.x0, bounds.y0, bounds.x1 - bounds.x0, bounds.y1 - bounds.y0);
	fz_append_printf(ctx, out, "<path");
	svg_dev_ctm(ctx, sdev, ctm);
	svg_dev_stroke_state(ctx, sdev, stroke, fz_identity);
	svg_dev_stroke_color(ctx, sdev, fz_device_rgb(ctx), white, 1, fz_default_color_params);
	svg_dev_path(ctx, sdev, path);
	fz_append_printf(ctx, out, "/>\n</mask>\n");
	out = end_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<g mask=\"url(#mask_%d)\">\n", num);
}

static void
svg_dev_fill_text(fz_context *ctx, fz_device *dev, const fz_text *text, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;
	font *fnt;
	fz_text_span *span;

	if (sdev->text_as_text)
	{
		for (span = text->head; span; span = span->next)
		{
			fz_append_printf(ctx, out, "<text");
			svg_dev_fill_color(ctx, sdev, colorspace, color, alpha, color_params);
			svg_dev_text_span(ctx, sdev, ctm, span);
		}
	}
	else
	{
		for (span = text->head; span; span = span->next)
		{
			fnt = svg_dev_text_span_as_paths_defs(ctx, dev, span, ctm);
			svg_dev_text_span_as_paths_fill(ctx, dev, span, ctm, colorspace, color, alpha, fnt, color_params);
		}
	}
}

static void
svg_dev_stroke_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_stroke_state *stroke, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;
	font *fnt;
	fz_text_span *span;

	if (sdev->text_as_text)
	{
		for (span = text->head; span; span = span->next)
		{
			fz_append_printf(ctx, out, "<text");
			svg_dev_fill_color(ctx, sdev, colorspace, color, alpha, color_params);
			svg_dev_text_span(ctx, sdev, ctm, span);
		}
	}
	else
	{
		for (span = text->head; span; span = span->next)
		{
			fnt = svg_dev_text_span_as_paths_defs(ctx, dev, span, ctm);
			svg_dev_text_span_as_paths_stroke(ctx, dev, span, stroke, ctm, colorspace, color, alpha, fnt, color_params);
		}
	}
}

static void
svg_dev_clip_text(fz_context *ctx, fz_device *dev, const fz_text *text, fz_matrix ctm, fz_rect scissor)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;

	fz_rect bounds;
	int num = sdev->id++;
	float white[3] = { 1, 1, 1 };
	font *fnt;
	fz_text_span *span;

	bounds = fz_bound_text(ctx, text, NULL, ctm);

	out = start_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<mask id=\"mask_%d\" x=\"%g\" y=\"%g\" width=\"%g\" height=\"%g\"",
			num, bounds.x0, bounds.y0, bounds.x1 - bounds.x0, bounds.y1 - bounds.y0);
	fz_append_printf(ctx, out, " maskUnits=\"userSpaceOnUse\" maskContentUnits=\"userSpaceOnUse\">\n");
	if (sdev->text_as_text)
	{
		for (span = text->head; span; span = span->next)
		{
			fz_append_printf(ctx, out, "<text");
			svg_dev_fill_color(ctx, sdev, fz_device_rgb(ctx), white, 1, fz_default_color_params);
			svg_dev_text_span(ctx, sdev, ctm, span);
		}
	}
	else
	{
		for (span = text->head; span; span = span->next)
		{
			fnt = svg_dev_text_span_as_paths_defs(ctx, dev, span, ctm);
			svg_dev_text_span_as_paths_fill(ctx, dev, span, ctm, fz_device_rgb(ctx), white, 1.0f, fnt, fz_default_color_params);
		}
	}
	fz_append_printf(ctx, out, "</mask>\n");
	out = end_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<g mask=\"url(#mask_%d)\">\n", num);
}

static void
svg_dev_clip_stroke_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_stroke_state *stroke, fz_matrix ctm, fz_rect scissor)
{
	svg_device *sdev = (svg_device*)dev;

	fz_buffer *out;
	fz_rect bounds;
	int num = sdev->id++;
	float white[3] = { 255, 255, 255 };
	font *fnt;
	fz_text_span *span;

	bounds = fz_bound_text(ctx, text, NULL, ctm);

	out = start_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<mask id=\"mask_%d\" x=\"%g\" y=\"%g\" width=\"%g\" height=\"%g\"",
		num, bounds.x0, bounds.y0, bounds.x1 - bounds.x0, bounds.y1 - bounds.y0);
	fz_append_printf(ctx, out, " maskUnits=\"userSpaceOnUse\" maskContentUnits=\"userSpaceOnUse\">\n");
	if (sdev->text_as_text)
	{
		for (span = text->head; span; span = span->next)
		{
			fz_append_printf(ctx, out, "<text");
			svg_dev_stroke_state(ctx, sdev, stroke, fz_identity);
			svg_dev_stroke_color(ctx, sdev, fz_device_rgb(ctx), white, 1, fz_default_color_params);
			svg_dev_text_span(ctx, sdev, ctm, span);
		}
	}
	else
	{
		for (span = text->head; span; span = span->next)
		{
			fnt = svg_dev_text_span_as_paths_defs(ctx, dev, span, ctm);
			svg_dev_text_span_as_paths_stroke(ctx, dev, span, stroke, ctm, fz_device_rgb(ctx), white, 1.0f, fnt, fz_default_color_params);
		}
	}
	fz_append_printf(ctx, out, "</mask>\n");
	out = end_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<g mask=\"url(#mask_%d)\">\n", num);
}

static void
svg_dev_ignore_text(fz_context *ctx, fz_device *dev, const fz_text *text, fz_matrix ctm)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;
	fz_text_span *span;

	float black[3] = { 0, 0, 0};

	if (sdev->text_as_text)
	{
		for (span = text->head; span; span = span->next)
		{
			fz_append_printf(ctx, out, "<text");
			svg_dev_fill_color(ctx, sdev, fz_device_rgb(ctx), black, 0.0f, fz_default_color_params);
			svg_dev_text_span(ctx, sdev, ctm, span);
		}
	}
}

/* We spot repeated images, and send them just once using
 * defs. Unfortunately, for pathological files, such
 * as the example in Bug695988, this can cause viewers to
 * have conniptions. We therefore have an option that is
 * made to avoid this (reuse-images=no). */
static void
svg_send_image(fz_context *ctx, svg_device *sdev, fz_image *img, fz_color_params color_params)
{
	fz_buffer *out = sdev->out;
	int i;
	int id;

	if (sdev->reuse_images)
	{
		for (i = sdev->num_images-1; i >= 0; i--)
			if (img == sdev->images[i].image)
				break;
		if (i >= 0)
		{
			fz_append_printf(ctx, out, "<use xlink:href=\"#image_%d\" x=\"0\" y=\"0\" width=\"%d\" height=\"%d\"/>\n",
					sdev->images[i].id, img->w, img->h);
			return;
		}

		/* We need to send this image for the first time */
		if (sdev->num_images == sdev->max_images)
		{
			int new_max = sdev->max_images * 2;
			if (new_max == 0)
				new_max = 32;
			sdev->images = fz_realloc_array(ctx, sdev->images, new_max, image);
			sdev->max_images = new_max;
		}

		id = sdev->id++;

		fz_append_printf(ctx, out, "<image id=\"image_%d\" width=\"%d\" height=\"%d\" xlink:href=\"", id, img->w, img->h);
		fz_append_image_as_data_uri(ctx, out, img);
		fz_append_printf(ctx, out, "\"/>\n");

		sdev->images[sdev->num_images].id = id;
		sdev->images[sdev->num_images].image = fz_keep_image(ctx, img);
		sdev->num_images++;
	}
	else
	{
		fz_append_printf(ctx, out, "<image width=\"%d\" height=\"%d\" xlink:href=\"", img->w, img->h);
		fz_append_image_as_data_uri(ctx, out, img);
		fz_append_printf(ctx, out, "\"/>\n");
	}
}

static void
svg_dev_fill_image(fz_context *ctx, fz_device *dev, fz_image *image, fz_matrix ctm, float alpha, fz_color_params color_params)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;

	fz_matrix local_ctm = ctm;
	fz_matrix scale = { 0 };

	if (alpha == 0)
		return;

	scale.a = 1.0f / image->w;
	scale.d = 1.0f / image->h;

	local_ctm = fz_concat(scale, ctm);
	fz_append_printf(ctx, out, "<g");
	if (alpha != 1.0f)
		fz_append_printf(ctx, out, " opacity=\"%g\"", alpha);
	svg_dev_ctm(ctx, sdev, local_ctm);
	fz_append_printf(ctx, out, ">\n");
	svg_send_image(ctx, sdev, image, color_params);
	fz_append_printf(ctx, out, "</g>\n");
}

static void
svg_dev_fill_shade(fz_context *ctx, fz_device *dev, fz_shade *shade, fz_matrix ctm, float alpha, fz_color_params color_params)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;
	fz_irect bbox;
	fz_pixmap *pix;
	fz_rect scissor = fz_device_current_scissor(ctx, dev);

	if (alpha == 0)
		return;

	if (fz_is_infinite_rect(scissor))
	{
		scissor.x0 = 0;
		scissor.x1 = sdev->page_width;
		scissor.y0 = 0;
		scissor.y1 = sdev->page_height;
	}

	bbox = fz_round_rect(fz_intersect_rect(fz_bound_shade(ctx, shade, ctm), scissor));
	if (fz_is_empty_irect(bbox))
		return;
	pix = fz_new_pixmap_with_bbox(ctx, fz_device_rgb(ctx), bbox, NULL, 1);
	fz_clear_pixmap(ctx, pix);

	fz_try(ctx)
	{
		fz_paint_shade(ctx, shade, NULL, ctm, pix, color_params, bbox, NULL, NULL);
		if (alpha != 1.0f)
			fz_append_printf(ctx, out, "<g opacity=\"%g\">\n", alpha);
		fz_append_printf(ctx, out, "<image x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\" xlink:href=\"", pix->x, pix->y, pix->w, pix->h);
		fz_append_pixmap_as_data_uri(ctx, out, pix);
		fz_append_printf(ctx, out, "\"/>\n");
		if (alpha != 1.0f)
			fz_append_printf(ctx, out, "</g>\n");
	}
	fz_always(ctx)
	{
		fz_drop_pixmap(ctx, pix);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void
svg_dev_fill_image_mask(fz_context *ctx, fz_device *dev, fz_image *image, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out;
	fz_matrix local_ctm = ctm;
	fz_matrix scale = { 0 };
	int mask = sdev->id++;

	scale.a = 1.0f / image->w;
	scale.d = 1.0f / image->h;

	local_ctm = fz_concat(scale, ctm);
	out = start_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<mask id=\"mask_%d\">\n", mask);
	svg_send_image(ctx, sdev, image, color_params);
	fz_append_printf(ctx, out, "</mask>\n");
	out = end_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<rect x=\"0\" y=\"0\" width=\"%d\" height=\"%d\"", image->w, image->h);
	svg_dev_fill_color(ctx, sdev, colorspace, color, alpha, color_params);
	svg_dev_ctm(ctx, sdev, local_ctm);
	fz_append_printf(ctx, out, " mask=\"url(#mask_%d)\"/>\n", mask);
}

static void
svg_dev_clip_image_mask(fz_context *ctx, fz_device *dev, fz_image *image, fz_matrix ctm, fz_rect scissor)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out;
	fz_matrix local_ctm = ctm;
	fz_matrix scale = { 0 };
	int mask = sdev->id++;

	scale.a = 1.0f / image->w;
	scale.d = 1.0f / image->h;

	local_ctm = fz_concat(scale, ctm);
	out = start_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<mask id=\"mask_%d\">\n<g", mask);
	svg_dev_ctm(ctx, sdev, local_ctm);
	fz_append_printf(ctx, out, ">\n");
	svg_send_image(ctx, sdev, image, fz_default_color_params/* FIXME */);
	fz_append_printf(ctx, out, "</g>\n</mask>\n");
	out = end_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<g mask=\"url(#mask_%d)\">\n", mask);
}

static void
svg_dev_pop_clip(fz_context *ctx, fz_device *dev)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;

	/* FIXME */
	fz_append_printf(ctx, out, "</g>\n");
}

static void
svg_dev_begin_mask(fz_context *ctx, fz_device *dev, fz_rect bbox, int luminosity, fz_colorspace *colorspace, const float *color, fz_color_params color_params)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out;
	int mask = sdev->id++;

	out = start_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<mask id=\"mask_%d\">\n", mask);

	if (dev->container_len > 0)
		dev->container[dev->container_len-1].user = mask;
}

static void
svg_dev_end_mask(fz_context *ctx, fz_device *dev, fz_function *tr)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;
	int mask = 0;

	if (dev->container_len > 0)
		mask = dev->container[dev->container_len-1].user;

	if (tr)
		fz_warn(ctx, "Ignoring Transfer Function");

	fz_append_printf(ctx, out, "\"/>\n</mask>\n");
	out = end_def(ctx, sdev, 0);
	fz_append_printf(ctx, out, "<g mask=\"url(#mask_%d)\">\n", mask);
}

static void
svg_dev_begin_group(fz_context *ctx, fz_device *dev, fz_rect bbox, fz_colorspace *cs, int isolated, int knockout, int blendmode, float alpha)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;

	/* SVG only supports normal/multiply/screen/darken/lighten,
	 * but we'll send them all, as the spec says that unrecognised
	 * ones are treated as normal. */
	static char *blend_names[] = {
		"normal",	/* FZ_BLEND_NORMAL */
		"multiply",	/* FZ_BLEND_MULTIPLY */
		"screen",	/* FZ_BLEND_SCREEN */
		"overlay",	/* FZ_BLEND_OVERLAY */
		"darken",	/* FZ_BLEND_DARKEN */
		"lighten",	/* FZ_BLEND_LIGHTEN */
		"color-dodge",	/* FZ_BLEND_COLOR_DODGE */
		"color-burn",	/* FZ_BLEND_COLOR_BURN */
		"hard-light",	/* FZ_BLEND_HARD_LIGHT */
		"soft-light",	/* FZ_BLEND_SOFT_LIGHT */
		"difference",	/* FZ_BLEND_DIFFERENCE */
		"exclusion",	/* FZ_BLEND_EXCLUSION */
		"hue",		/* FZ_BLEND_HUE */
		"saturation",	/* FZ_BLEND_SATURATION */
		"color",	/* FZ_BLEND_COLOR */
		"luminosity",	/* FZ_BLEND_LUMINOSITY */
	};

	if (blendmode < FZ_BLEND_NORMAL || blendmode > FZ_BLEND_LUMINOSITY)
		blendmode = FZ_BLEND_NORMAL;
	if (blendmode != FZ_BLEND_NORMAL && (sdev->blend_bitmask & (1<<blendmode)) == 0)
		sdev->blend_bitmask |= (1<<blendmode);

	/* FIXME: Handle alpha == 0 somehow? */
	/* SVG 1.1 doesn't support adequate blendmodes/knockout etc, so just ignore it for now */
	if (alpha == 1)
		fz_append_printf(ctx, out, "<g");
	else
		fz_append_printf(ctx, out, "<g opacity=\"%g\"", alpha);
	if (blendmode != FZ_BLEND_NORMAL)
		fz_append_printf(ctx, out, " style=\"mix-blend-mode:%s\"", blend_names[blendmode]);
	fz_append_printf(ctx, out, ">\n");
}

static void
svg_dev_end_group(fz_context *ctx, fz_device *dev)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;

	fz_append_printf(ctx, out, "</g>\n");
}

static int
svg_dev_begin_tile(fz_context *ctx, fz_device *dev, fz_rect area, fz_rect view, float xstep, float ystep, fz_matrix ctm, int id, int doc_id)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out;
	int num;
	tile *t;

	if (sdev->num_tiles == sdev->max_tiles)
	{
		int n = (sdev->num_tiles == 0 ? 4 : sdev->num_tiles * 2);

		sdev->tiles = fz_realloc_array(ctx, sdev->tiles, n, tile);
		sdev->max_tiles = n;
	}
	num = sdev->num_tiles++;
	t = &sdev->tiles[num];
	t->area = area;
	t->view = view;
	t->ctm = ctm;
	t->pattern = sdev->id++;

	xstep = fabsf(xstep);
	ystep = fabsf(ystep);
	if (xstep == 0 || ystep == 0) {
		fz_warn(ctx, "Pattern cannot have x or ystep == 0.");
		if (xstep == 0)
			xstep = 1;
		if (ystep == 0)
			ystep = 1;
	}

	t->step.x = xstep;
	t->step.y = ystep;

	/* view = area of our reference tile in pattern space.
	 * area = area to tile into in pattern space.
	 * xstep/ystep = pattern repeat step in pattern space.
	 * All of these need to be transformed by ctm to get to device space.
	 * SVG only allows us to specify pattern tiles as axis aligned
	 * rectangles, so we send these through as is, and ensure that the
	 * correct matrix is used on the fill.
	 */

	/* The first thing we do is to capture the contents of the pattern
	 * as a def we can reuse. */
	out = start_def(ctx, sdev, 1);
	fz_append_printf(ctx, out, "<g id=\"pattern_tile_%d\">\n", t->pattern);

	return 0;
}

static void
svg_dev_end_tile(fz_context *ctx, fz_device *dev)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;
	int num, cp = -1;
	tile *t;
	fz_matrix inverse;
	float x, y, w, h;

	if (sdev->num_tiles == 0)
		return;
	num = --sdev->num_tiles;
	t = &sdev->tiles[num];

	fz_append_printf(ctx, out, "</g>\n");

	/* In svg, the reference tile is taken from (x,y) to (x+width,y+height)
	 * and is repeated at (x+n*width,y+m*height) for all integer n and m.
	 * This means that width and height generally correspond to xstep and
	 * ystep. There are exceptional cases where we have to break this
	 * though; when xstep/ystep are smaller than the width/height of the
	 * pattern tile, we need to render the pattern contents several times
	 * to ensure that the pattern tile contains everything. */

	fz_append_printf(ctx, out, "<pattern id=\"pattern_%d\" patternUnits=\"userSpaceOnUse\" patternContentUnits=\"userSpaceOnUse\"",
		t->pattern);
	fz_append_printf(ctx, out, " x=\"0\" y=\"0\" width=\"%g\" height=\"%g\">\n",
		t->step.x, t->step.y);

	if (t->view.x0 > 0 || t->step.x < t->view.x1 || t->view.y0 > 0 || t->step.y < t->view.y1)
	{
		cp = sdev->id++;
		fz_append_printf(ctx, out, "<clipPath id=\"clip_%d\">\n", cp);
		fz_append_printf(ctx, out, "<path d=\"M %g %g L %g %g L %g %g L %g %g Z\"/>\n",
			t->view.x0, t->view.y0,
			t->view.x1, t->view.y0,
			t->view.x1, t->view.y1,
			t->view.x0, t->view.y1);
		fz_append_printf(ctx, out, "</clipPath>\n");
		fz_append_printf(ctx, out, "<g clip-path=\"url(#clip_%d)\">\n", cp);
	}

	/* All the pattern contents will have their own ctm applied. Let's
	 * undo the current one to allow for this */
	inverse = fz_invert_matrix(t->ctm);
	fz_append_printf(ctx, out, "<g");
	svg_dev_ctm(ctx, sdev, inverse);
	fz_append_printf(ctx, out, ">\n");

	w = t->view.x1 - t->view.x0;
	h = t->view.y1 - t->view.y0;

	for (x = 0; x > -w; x -= t->step.x)
		for (y = 0; y > -h; y -= t->step.y)
			fz_append_printf(ctx, out, "<use x=\"%g\" y=\"%g\" xlink:href=\"#pattern_tile_%d\"/>\n", x, y, t->pattern);

	fz_append_printf(ctx, out, "</g>\n");
	if (cp != -1)
		fz_append_printf(ctx, out, "</g>\n");
	fz_append_printf(ctx, out, "</pattern>\n");
	out = end_def(ctx, sdev, 1);

	/* Finally, fill a rectangle with the pattern. */
	fz_append_printf(ctx, out, "<rect");
	svg_dev_ctm(ctx, sdev, t->ctm);
	fz_append_printf(ctx, out, " fill=\"url(#pattern_%d)\" x=\"%g\" y=\"%g\" width=\"%g\" height=\"%g\"/>\n",
		t->pattern, t->area.x0, t->area.y0, t->area.x1 - t->area.x0, t->area.y1 - t->area.y0);
}

static void
svg_dev_begin_layer(fz_context *ctx, fz_device *dev, const char *name)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;

	sdev->layers++;
	fz_append_printf(ctx, out, "<g inkscape:groupmode=\"layer\" inkscape:label=%<>\n", name ? name : "");
}

static void
svg_dev_end_layer(fz_context *ctx, fz_device *dev)
{
	svg_device *sdev = (svg_device*)dev;
	fz_buffer *out = sdev->out;

	if (sdev->layers == 0)
		return;

	sdev->layers--;
	fz_append_printf(ctx, out, "</g>\n");
}

static void
svg_dev_close_device(fz_context *ctx, fz_device *dev)
{
	svg_device *sdev = (svg_device*)dev;
	fz_output *out = sdev->real_out;

	while (sdev->layers > 0)
	{
		fz_append_string(ctx, sdev->main, "</g>\n");
		sdev->layers--;
	}

	if (sdev->save_id)
		*sdev->save_id = sdev->id;

	fz_write_string(ctx, out, "<svg");
	fz_write_string(ctx, out, " xmlns=\"http://www.w3.org/2000/svg\"");
	fz_write_string(ctx, out, " xmlns:xlink=\"http://www.w3.org/1999/xlink\"");
	fz_write_string(ctx, out, " xmlns:inkscape=\"http://www.inkscape.org/namespaces/inkscape\"");
	fz_write_string(ctx, out, " version=\"1.1\"");
	fz_write_printf(ctx, out, " width=\"%g\" height=\"%g\" viewBox=\"0 0 %g %g\">\n",
		sdev->page_width, sdev->page_height, sdev->page_width, sdev->page_height);

	if (sdev->defs->len > 0)
	{
		fz_write_printf(ctx, out, "<defs>\n");
		fz_write_buffer(ctx, out, sdev->defs);
		fz_write_printf(ctx, out, "</defs>\n");
	}

	fz_write_buffer(ctx, out, sdev->main);

	fz_write_printf(ctx, out, "</svg>\n");
}

static void
svg_dev_drop_device(fz_context *ctx, fz_device *dev)
{
	svg_device *sdev = (svg_device*)dev;
	int i;

	fz_free(ctx, sdev->tiles);
	fz_drop_buffer(ctx, sdev->defs);
	fz_drop_buffer(ctx, sdev->main);
	for (i = 0; i < sdev->num_fonts; i++)
	{
		fz_drop_font(ctx, sdev->fonts[i].font);
		fz_free(ctx, sdev->fonts[i].sentlist);
	}
	fz_free(ctx, sdev->fonts);
	for (i = 0; i < sdev->num_images; i++)
	{
		fz_drop_image(ctx, sdev->images[i].image);
	}
	fz_free(ctx, sdev->images);
}

fz_device *fz_new_svg_device_with_id(fz_context *ctx, fz_output *out, float page_width, float page_height, int text_format, int reuse_images, int *id)
{
	svg_device *dev = fz_new_derived_device(ctx, svg_device);

	dev->super.close_device = svg_dev_close_device;
	dev->super.drop_device = svg_dev_drop_device;

	dev->super.fill_path = svg_dev_fill_path;
	dev->super.stroke_path = svg_dev_stroke_path;
	dev->super.clip_path = svg_dev_clip_path;
	dev->super.clip_stroke_path = svg_dev_clip_stroke_path;

	dev->super.fill_text = svg_dev_fill_text;
	dev->super.stroke_text = svg_dev_stroke_text;
	dev->super.clip_text = svg_dev_clip_text;
	dev->super.clip_stroke_text = svg_dev_clip_stroke_text;
	dev->super.ignore_text = svg_dev_ignore_text;

	dev->super.fill_shade = svg_dev_fill_shade;
	dev->super.fill_image = svg_dev_fill_image;
	dev->super.fill_image_mask = svg_dev_fill_image_mask;
	dev->super.clip_image_mask = svg_dev_clip_image_mask;

	dev->super.pop_clip = svg_dev_pop_clip;

	dev->super.begin_mask = svg_dev_begin_mask;
	dev->super.end_mask = svg_dev_end_mask;
	dev->super.begin_group = svg_dev_begin_group;
	dev->super.end_group = svg_dev_end_group;

	dev->super.begin_tile = svg_dev_begin_tile;
	dev->super.end_tile = svg_dev_end_tile;

	dev->super.begin_layer = svg_dev_begin_layer;
	dev->super.end_layer = svg_dev_end_layer;

	dev->real_out = out;
	dev->in_defs = 0;
	dev->defs = fz_new_buffer(ctx, 4096);
	dev->main = fz_new_buffer(ctx, 4096);
	dev->out = dev->main;

	dev->save_id = id;
	dev->id = id ? *id : 1;
	dev->layers = 0;
	dev->text_as_text = (text_format == FZ_SVG_TEXT_AS_TEXT);
	dev->reuse_images = reuse_images;
	dev->page_width = page_width;
	dev->page_height = page_height;

	return (fz_device*)dev;
}

fz_device *fz_new_svg_device(fz_context *ctx, fz_output *out, float page_width, float page_height, int text_format, int reuse_images)
{
	return fz_new_svg_device_with_id(ctx, out, page_width, page_height, text_format, reuse_images, NULL);
}
