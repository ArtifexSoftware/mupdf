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

typedef struct
{
	fz_device super;
	fz_output *out;
	int depth;
} fz_trace_device;

static void fz_trace_indent(fz_context *ctx, fz_output *out, int depth)
{
	while (depth-- > 0)
		fz_write_string(ctx, out, "    ");
}

static void
fz_trace_matrix(fz_context *ctx, fz_output *out, fz_matrix ctm)
{
	fz_write_printf(ctx, out, " transform=\"%g %g %g %g %g %g\"", ctm.a, ctm.b, ctm.c, ctm.d, ctm.e, ctm.f);
}

static void
fz_trace_color(fz_context *ctx, fz_output *out, fz_colorspace *colorspace, const float *color, float alpha)
{
	int i, n;
	if (colorspace)
	{
		n = fz_colorspace_n(ctx, colorspace);
		fz_write_printf(ctx, out, " colorspace=\"%s\" color=\"", fz_colorspace_name(ctx, colorspace));
		for (i = 0; i < n; i++)
			fz_write_printf(ctx, out, "%s%g", i == 0 ? "" : " ", color[i]);
		fz_write_printf(ctx, out, "\"");
	}
	if (alpha < 1)
		fz_write_printf(ctx, out, " alpha=\"%g\"", alpha);
}

static void
fz_trace_color_params(fz_context *ctx, fz_output *out, fz_color_params color_params)
{
	fz_write_printf(ctx, out, " ri=\"%d\" bp=\"%d\" op=\"%d\" opm=\"%d\"",
		color_params.ri, color_params.bp, color_params.op, color_params.opm);
}

static void
fz_trace_text_span(fz_context *ctx, fz_output *out, fz_text_span *span, int depth)
{
	int i;
	fz_trace_indent(ctx, out, depth);
	fz_write_printf(ctx, out, "<span font=\"%s\" wmode=\"%d\" bidi=\"%d\"", fz_font_name(ctx, span->font), span->wmode, span->bidi_level);
	if (span->language != FZ_LANG_UNSET)
	{
		char text[8];
		fz_string_from_text_language(text, span->language);
		fz_write_printf(ctx, out, " lang=\"%s\"", text);
	}
	fz_write_printf(ctx, out, " trm=\"%g %g %g %g\">\n", span->trm.a, span->trm.b, span->trm.c, span->trm.d);
	for (i = 0; i < span->len; i++)
	{
		int ucs = span->items[i].ucs;

		fz_trace_indent(ctx, out, depth+1);
		fz_write_string(ctx, out, "<g");
		if (span->items[i].ucs >= 0)
		{
			fz_write_string(ctx, out, " unicode=\"");
			switch (ucs)
			{
			default:
				if (ucs < 32)
					fz_write_printf(ctx, out, "&#x%x;", ucs);
				else
					fz_write_rune(ctx, out, ucs);
				break;
			case '&': fz_write_string(ctx, out, "&amp;"); break;
			case '\'': fz_write_string(ctx, out, "&apos;"); break;
			case '"': fz_write_string(ctx, out, "&quot;"); break;
			case '<': fz_write_string(ctx, out, "&lt;"); break;
			case '>': fz_write_string(ctx, out, "&gt;"); break;
			}
			fz_write_string(ctx, out, "\"");
		}
		if (span->items[i].gid >= 0)
		{
			char name[32];
			fz_get_glyph_name(ctx, span->font, span->items[i].gid, name, sizeof name);
			fz_write_printf(ctx, out, " glyph=\"%s\"", name);
		}

		fz_write_printf(ctx, out, " x=\"%g\" y=\"%g\" adv=\"%g\"/>\n", span->items[i].x, span->items[i].y, span->items[i].adv);
	}
	fz_trace_indent(ctx, out, depth);
	fz_write_string(ctx, out, "</span>\n");
}

static void
fz_trace_text(fz_context *ctx, fz_output *out, const fz_text *text, int depth)
{
	fz_text_span *span;
	for (span = text->head; span; span = span->next)
		fz_trace_text_span(ctx, out, span, depth);
}

static void
trace_moveto(fz_context *ctx, void *dev_, float x, float y)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<moveto x=\"%g\" y=\"%g\"/>\n", x, y);
}

static void
trace_lineto(fz_context *ctx, void *dev_, float x, float y)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<lineto x=\"%g\" y=\"%g\"/>\n", x, y);
}

static void
trace_curveto(fz_context *ctx, void *dev_, float x1, float y1, float x2, float y2, float x3, float y3)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<curveto x1=\"%g\" y1=\"%g\" x2=\"%g\" y2=\"%g\" x3=\"%g\" y3=\"%g\"/>\n", x1, y1, x2, y2, x3, y3);
}

static void
trace_close(fz_context *ctx, void *dev_)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<closepath/>\n");
}

static const fz_path_walker trace_path_walker =
{
	trace_moveto,
	trace_lineto,
	trace_curveto,
	trace_close
};

static void
fz_trace_path(fz_context *ctx, fz_trace_device *dev, const fz_path *path)
{
	dev->depth++;
	fz_walk_path(ctx, path, &trace_path_walker, dev);
	dev->depth--;
}

static void
fz_trace_fill_path(fz_context *ctx, fz_device *dev_, const fz_path *path, int even_odd, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<fill_path");
	if (even_odd)
		fz_write_printf(ctx, out, " winding=\"eofill\"");
	else
		fz_write_printf(ctx, out, " winding=\"nonzero\"");
	fz_trace_color(ctx, out, colorspace, color, alpha);
	fz_trace_color_params(ctx, out, color_params);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_path(ctx, dev, path);
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</fill_path>\n");
}

static void
fz_trace_stroke_path(fz_context *ctx, fz_device *dev_, const fz_path *path, const fz_stroke_state *stroke, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	int i;

	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<stroke_path");
	fz_write_printf(ctx, out, " linewidth=\"%g\"", stroke->linewidth);
	fz_write_printf(ctx, out, " miterlimit=\"%g\"", stroke->miterlimit);
	fz_write_printf(ctx, out, " linecap=\"%d,%d,%d\"", stroke->start_cap, stroke->dash_cap, stroke->end_cap);
	fz_write_printf(ctx, out, " linejoin=\"%d\"", stroke->linejoin);

	if (stroke->dash_len)
	{
		fz_write_printf(ctx, out, " dash_phase=\"%g\" dash=\"", stroke->dash_phase);
		for (i = 0; i < stroke->dash_len; i++)
			fz_write_printf(ctx, out, "%s%g", i > 0 ? " " : "", stroke->dash_list[i]);
		fz_write_printf(ctx, out, "\"");
	}

	fz_trace_color(ctx, out, colorspace, color, alpha);
	fz_trace_color_params(ctx, out, color_params);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");

	fz_trace_path(ctx, dev, path);

	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</stroke_path>\n");
}

static void
fz_trace_clip_path(fz_context *ctx, fz_device *dev_, const fz_path *path, int even_odd, fz_matrix ctm, fz_rect scissor)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<clip_path");
	if (even_odd)
		fz_write_printf(ctx, out, " winding=\"eofill\"");
	else
		fz_write_printf(ctx, out, " winding=\"nonzero\"");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_path(ctx, dev, path);
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</clip_path>\n");
	dev->depth++;
}

static void
fz_trace_clip_stroke_path(fz_context *ctx, fz_device *dev_, const fz_path *path, const fz_stroke_state *stroke, fz_matrix ctm, fz_rect scissor)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<clip_stroke_path");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_path(ctx, dev, path);
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</clip_stroke_path>\n");
	dev->depth++;
}

static void
fz_trace_fill_text(fz_context *ctx, fz_device *dev_, const fz_text *text, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<fill_text");
	fz_trace_color(ctx, out, colorspace, color, alpha);
	fz_trace_color_params(ctx, out, color_params);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_text(ctx, out, text, dev->depth+1);
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</fill_text>\n");
}

static void
fz_trace_stroke_text(fz_context *ctx, fz_device *dev_, const fz_text *text, const fz_stroke_state *stroke, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<stroke_text");
	fz_trace_color(ctx, out, colorspace, color, alpha);
	fz_trace_color_params(ctx, out, color_params);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_text(ctx, out, text, dev->depth+1);
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</stroke_text>\n");
}

static void
fz_trace_clip_text(fz_context *ctx, fz_device *dev_, const fz_text *text, fz_matrix ctm, fz_rect scissor)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<clip_text");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_text(ctx, out, text, dev->depth+1);
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</clip_text>\n");
	dev->depth++;
}

static void
fz_trace_clip_stroke_text(fz_context *ctx, fz_device *dev_, const fz_text *text, const fz_stroke_state *stroke, fz_matrix ctm, fz_rect scissor)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<clip_stroke_text");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_text(ctx, out, text, dev->depth+1);
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</clip_stroke_text>\n");
	dev->depth++;
}

static void
fz_trace_ignore_text(fz_context *ctx, fz_device *dev_, const fz_text *text, fz_matrix ctm)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<ignore_text");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_text(ctx, out, text, dev->depth+1);
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</ignore_text>\n");
}

static void
fz_trace_fill_image(fz_context *ctx, fz_device *dev_, fz_image *image, fz_matrix ctm, float alpha, fz_color_params color_params)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<fill_image alpha=\"%g\"", alpha);
	if (image->colorspace)
		fz_write_printf(ctx, out, " colorspace=\"%s\"", fz_colorspace_name(ctx, image->colorspace));
	fz_trace_color_params(ctx, out, color_params);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, " width=\"%d\" height=\"%d\"", image->w, image->h);
	fz_write_printf(ctx, out, "/>\n");
}

static void
fz_trace_fill_shade(fz_context *ctx, fz_device *dev_, fz_shade *shade, fz_matrix ctm, float alpha, fz_color_params color_params)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<fill_shade alpha=\"%g\"", alpha);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, " pattern_matrix=\"%g %g %g %g %g %g\"",
		shade->matrix.a,
		shade->matrix.b,
		shade->matrix.c,
		shade->matrix.d,
		shade->matrix.e,
		shade->matrix.f);
	fz_write_printf(ctx, out, " colorspace=\"%s\"", fz_colorspace_name(ctx, shade->colorspace));
	fz_trace_color_params(ctx, out, color_params);
	// TODO: use_background and background
	// TODO: use_function and function
	switch (shade->type)
	{
	case FZ_FUNCTION_BASED:
		fz_write_printf(ctx, out, " type=\"function\"");
		fz_write_printf(ctx, out, " function_matrix=\"%g %g %g %g %g %g\"",
			shade->u.f.matrix.a,
			shade->u.f.matrix.b,
			shade->u.f.matrix.c,
			shade->u.f.matrix.d,
			shade->u.f.matrix.e,
			shade->u.f.matrix.f);
		fz_write_printf(ctx, out, " domain=\"%g %g %g %g\"",
			shade->u.f.domain[0][0],
			shade->u.f.domain[0][1],
			shade->u.f.domain[1][0],
			shade->u.f.domain[1][1]);
		fz_write_printf(ctx, out, " samples=\"%d %d\"",
			shade->u.f.xdivs,
			shade->u.f.ydivs);
		fz_write_printf(ctx, out, "/>\n");
		break;
	case FZ_LINEAR:
		fz_write_printf(ctx, out, " type=\"linear\"");
		fz_write_printf(ctx, out, " extend=\"%d %d\"",
			shade->u.l_or_r.extend[0],
			shade->u.l_or_r.extend[1]);
		fz_write_printf(ctx, out, " start=\"%g %g\"",
			shade->u.l_or_r.coords[0][0],
			shade->u.l_or_r.coords[0][1]);
		fz_write_printf(ctx, out, " end=\"%g %g\"",
			shade->u.l_or_r.coords[1][0],
			shade->u.l_or_r.coords[1][1]);
		fz_write_printf(ctx, out, "/>\n");
		break;
	case FZ_RADIAL:
		fz_write_printf(ctx, out, " type=\"radial\"");
		fz_write_printf(ctx, out, " extend=\"%d %d\"",
			shade->u.l_or_r.extend[0],
			shade->u.l_or_r.extend[1]);
		fz_write_printf(ctx, out, " inner=\"%g %g %g\"",
			shade->u.l_or_r.coords[0][0],
			shade->u.l_or_r.coords[0][1],
			shade->u.l_or_r.coords[0][2]);
		fz_write_printf(ctx, out, " outer=\"%g %g %g\"",
			shade->u.l_or_r.coords[1][0],
			shade->u.l_or_r.coords[1][1],
			shade->u.l_or_r.coords[1][2]);
		fz_write_printf(ctx, out, "/>\n");
		break;
	default:
		fz_write_printf(ctx, out, " type=\"mesh\"/>\n");
		break;
	}
}

static void
fz_trace_fill_image_mask(fz_context *ctx, fz_device *dev_, fz_image *image, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<fill_image_mask");
	fz_trace_matrix(ctx, out, ctm);
	fz_trace_color(ctx, out, colorspace, color, alpha);
	fz_trace_color_params(ctx, out, color_params);
	fz_write_printf(ctx, out, " width=\"%d\" height=\"%d\"", image->w, image->h);
	fz_write_printf(ctx, out, "/>\n");
}

static void
fz_trace_clip_image_mask(fz_context *ctx, fz_device *dev_, fz_image *image, fz_matrix ctm, fz_rect scissor)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<clip_image_mask");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, " width=\"%d\" height=\"%d\"", image->w, image->h);
	fz_write_printf(ctx, out, "/>\n");
	dev->depth++;
}

static void
fz_trace_pop_clip(fz_context *ctx, fz_device *dev_)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	dev->depth--;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<pop_clip/>\n");
}

static void
fz_trace_begin_mask(fz_context *ctx, fz_device *dev_, fz_rect bbox, int luminosity, fz_colorspace *colorspace, const float *color, fz_color_params color_params)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<clip_mask bbox=\"%g %g %g %g\" s=\"%s\"",
		bbox.x0, bbox.y0, bbox.x1, bbox.y1,
		luminosity ? "luminosity" : "alpha");
	fz_trace_color_params(ctx, out, color_params);
	fz_write_printf(ctx, out, ">\n");
	dev->depth++;
}

static void
fz_trace_end_mask(fz_context *ctx, fz_device *dev_, fz_function *tr)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	dev->depth--;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</clip_mask%s>\n", tr ? " (with TR)" : "");
	dev->depth++;
}

static void
fz_trace_begin_group(fz_context *ctx, fz_device *dev_, fz_rect bbox, fz_colorspace *cs, int isolated, int knockout, int blendmode, float alpha)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<group bbox=\"%g %g %g %g\" isolated=\"%d\" knockout=\"%d\" blendmode=\"%s\" alpha=\"%g\">\n",
		bbox.x0, bbox.y0, bbox.x1, bbox.y1,
		isolated, knockout, fz_blendmode_name(blendmode), alpha);
	dev->depth++;
}

static void
fz_trace_end_group(fz_context *ctx, fz_device *dev_)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	dev->depth--;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</group>\n");
}

static int
fz_trace_begin_tile(fz_context *ctx, fz_device *dev_, fz_rect area, fz_rect view, float xstep, float ystep, fz_matrix ctm, int id)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<tile id=\"%d\"", id);
	fz_write_printf(ctx, out, " area=\"%g %g %g %g\"", area.x0, area.y0, area.x1, area.y1);
	fz_write_printf(ctx, out, " view=\"%g %g %g %g\"", view.x0, view.y0, view.x1, view.y1);
	fz_write_printf(ctx, out, " xstep=\"%g\" ystep=\"%g\"", xstep, ystep);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	dev->depth++;
	return 0;
}

static void
fz_trace_end_tile(fz_context *ctx, fz_device *dev_)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	dev->depth--;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</tile>\n");
}

static void
fz_trace_begin_layer(fz_context *ctx, fz_device *dev_, const char *name)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<layer name=\"%s\">\n", name ? name : "");
	dev->depth++;
}

static void
fz_trace_end_layer(fz_context *ctx, fz_device *dev_)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	dev->depth--;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</layer>\n");
}

static void
fz_trace_begin_structure(fz_context *ctx, fz_device *dev_, fz_structure standard, const char *raw, int idx)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	const char *str = fz_structure_to_string(standard);
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<structure standard=\"%s\"", str);
	if (raw && strcmp(str, raw))
		fz_write_printf(ctx, out, " raw=\"%s\"", raw);
	if (idx != 0)
		fz_write_printf(ctx, out, " idx=\"%d\"", idx);
	fz_write_printf(ctx, out, ">\n");
	dev->depth++;
}

static void
fz_trace_end_structure(fz_context *ctx, fz_device *dev_)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	dev->depth--;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</structure>\n");
}

static const char *
metatext_type(fz_metatext meta)
{
	switch (meta)
	{
	case FZ_METATEXT_ABBREVIATION:
		return "abbreviation";
	case FZ_METATEXT_ACTUALTEXT:
		return "actualtext";
	case FZ_METATEXT_ALT:
		return "alt";
	case FZ_METATEXT_TITLE:
		return "title";
	}
	return "????";
}

static void
fz_trace_begin_metatext(fz_context *ctx, fz_device *dev_, fz_metatext meta, const char *txt)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	const char *type = metatext_type(meta);
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<metatext type=\"%s\" txt=\"%s\">\n", type, txt ? txt : "");
	dev->depth++;
}

static void
fz_trace_end_metatext(fz_context *ctx, fz_device *dev_)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	dev->depth--;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "</metatext>\n");
}

static void
fz_trace_render_flags(fz_context *ctx, fz_device *dev_, int set, int clear)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<render_flags set=\"0x%x\" clear=\"0x%x\"/>\n", set, clear);
}

static void
fz_trace_set_default_colorspaces(fz_context *ctx, fz_device *dev_, fz_default_colorspaces *dcs)
{
	fz_trace_device *dev = (fz_trace_device*)dev_;
	fz_output *out = dev->out;
	fz_trace_indent(ctx, out, dev->depth);
	fz_write_printf(ctx, out, "<set_default_colorspaces");
	fz_write_printf(ctx, out, " gray=\"%s\"", fz_colorspace_name(ctx, fz_default_gray(ctx, dcs)));
	fz_write_printf(ctx, out, " rgb=\"%s\"", fz_colorspace_name(ctx, fz_default_rgb(ctx, dcs)));
	fz_write_printf(ctx, out, " cmyk=\"%s\"", fz_colorspace_name(ctx, fz_default_cmyk(ctx, dcs)));
	fz_write_printf(ctx, out, " oi=\"%s\"/>\n",fz_colorspace_name(ctx, fz_default_output_intent(ctx, dcs)));
}

fz_device *fz_new_trace_device(fz_context *ctx, fz_output *out)
{
	fz_trace_device *dev = fz_new_derived_device(ctx, fz_trace_device);

	dev->super.fill_path = fz_trace_fill_path;
	dev->super.stroke_path = fz_trace_stroke_path;
	dev->super.clip_path = fz_trace_clip_path;
	dev->super.clip_stroke_path = fz_trace_clip_stroke_path;

	dev->super.fill_text = fz_trace_fill_text;
	dev->super.stroke_text = fz_trace_stroke_text;
	dev->super.clip_text = fz_trace_clip_text;
	dev->super.clip_stroke_text = fz_trace_clip_stroke_text;
	dev->super.ignore_text = fz_trace_ignore_text;

	dev->super.fill_shade = fz_trace_fill_shade;
	dev->super.fill_image = fz_trace_fill_image;
	dev->super.fill_image_mask = fz_trace_fill_image_mask;
	dev->super.clip_image_mask = fz_trace_clip_image_mask;

	dev->super.pop_clip = fz_trace_pop_clip;

	dev->super.begin_mask = fz_trace_begin_mask;
	dev->super.end_mask = fz_trace_end_mask;
	dev->super.begin_group = fz_trace_begin_group;
	dev->super.end_group = fz_trace_end_group;

	dev->super.begin_tile = fz_trace_begin_tile;
	dev->super.end_tile = fz_trace_end_tile;

	dev->super.begin_layer = fz_trace_begin_layer;
	dev->super.end_layer = fz_trace_end_layer;

	dev->super.begin_structure = fz_trace_begin_structure;
	dev->super.end_structure = fz_trace_end_structure;

	dev->super.begin_metatext = fz_trace_begin_metatext;
	dev->super.end_metatext = fz_trace_end_metatext;

	dev->super.render_flags = fz_trace_render_flags;
	dev->super.set_default_colorspaces = fz_trace_set_default_colorspaces;

	dev->out = out;

	return (fz_device*)dev;
}
