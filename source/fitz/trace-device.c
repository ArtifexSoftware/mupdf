#include "mupdf/fitz.h"

typedef struct fz_trace_device_s
{
	fz_device super;
	fz_output *out;
} fz_trace_device;

static void
fz_trace_matrix(fz_context *ctx, fz_output *out, const fz_matrix *ctm)
{
	fz_write_printf(ctx, out, " matrix=\"%g %g %g %g %g %g\"",
		ctm->a, ctm->b, ctm->c, ctm->d, ctm->e, ctm->f);
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

static int
isxmlmeta(int c)
{
	return c < 32 || c >= 128 || c == '&' || c == '<' || c == '>' || c == '\'' || c == '"';
}

static void
fz_trace_text_span(fz_context *ctx, fz_output *out, fz_text_span *span)
{
	int i;
	fz_write_printf(ctx, out, "<span font=\"%s\" wmode=\"%d\"", fz_font_name(ctx, span->font), span->wmode);
	fz_write_printf(ctx, out, " trm=\"%g %g %g %g\">\n", span->trm.a, span->trm.b, span->trm.c, span->trm.d);
	for (i = 0; i < span->len; i++)
	{
		char name[32];

		if (span->items[i].ucs == -1)
			fz_write_printf(ctx, out, "<g unicode=\"-1\"");
		else if (!isxmlmeta(span->items[i].ucs))
			fz_write_printf(ctx, out, "<g unicode=\"%c\"", span->items[i].ucs);
		else
			fz_write_printf(ctx, out, "<g unicode=\"U+%04x\"", span->items[i].ucs);

		if (span->items[i].gid >= 0)
		{
			fz_get_glyph_name(ctx, span->font, span->items[i].gid, name, sizeof name);
			fz_write_printf(ctx, out, " glyph=\"%s\"", name);
		}
		else
			fz_write_printf(ctx, out, " glyph=\"-1\"");

		fz_write_printf(ctx, out, " x=\"%g\" y=\"%g\" />\n", span->items[i].x, span->items[i].y);
	}
	fz_write_printf(ctx, out, "</span>\n");
}

static void
fz_trace_text(fz_context *ctx, fz_output *out, const fz_text *text)
{
	fz_text_span *span;
	for (span = text->head; span; span = span->next)
		fz_trace_text_span(ctx, out, span);
}

static void
trace_moveto(fz_context *ctx, void *arg, float x, float y)
{
	fz_output *out = arg;
	fz_write_printf(ctx, out, "<moveto x=\"%g\" y=\"%g\"/>\n", x, y);
}

static void
trace_lineto(fz_context *ctx, void *arg, float x, float y)
{
	fz_output *out = arg;
	fz_write_printf(ctx, out, "<lineto x=\"%g\" y=\"%g\"/>\n", x, y);
}

static void
trace_curveto(fz_context *ctx, void *arg, float x1, float y1, float x2, float y2, float x3, float y3)
{
	fz_output *out = arg;
	fz_write_printf(ctx, out, "<curveto x1=\"%g\" y1=\"%g\" x2=\"%g\" y2=\"%g\" x3=\"%g\" y3=\"%g\"/>\n", x1, y1, x2, y2, x3, y3);
}

static void
trace_close(fz_context *ctx, void *arg)
{
	fz_output *out = arg;
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
fz_trace_path(fz_context *ctx, fz_output *out, const fz_path *path)
{
	fz_walk_path(ctx, path, &trace_path_walker, out);
}

static void
fz_trace_fill_path(fz_context *ctx, fz_device *dev, const fz_path *path, int even_odd, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<fill_path");
	if (even_odd)
		fz_write_printf(ctx, out, " winding=\"eofill\"");
	else
		fz_write_printf(ctx, out, " winding=\"nonzero\"");
	fz_trace_color(ctx, out, colorspace, color, alpha);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_path(ctx, out, path);
	fz_write_printf(ctx, out, "</fill_path>\n");
}

static void
fz_trace_stroke_path(fz_context *ctx, fz_device *dev, const fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	int i;

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
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");

	fz_trace_path(ctx, out, path);

	fz_write_printf(ctx, out, "</stroke_path>\n");
}

static void
fz_trace_clip_path(fz_context *ctx, fz_device *dev, const fz_path *path, int even_odd, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<clip_path");
	if (even_odd)
		fz_write_printf(ctx, out, " winding=\"eofill\"");
	else
		fz_write_printf(ctx, out, " winding=\"nonzero\"");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_path(ctx, out, path);
	fz_write_printf(ctx, out, "</clip_path>\n");
}

static void
fz_trace_clip_stroke_path(fz_context *ctx, fz_device *dev, const fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<clip_stroke_path");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_path(ctx, out, path);
	fz_write_printf(ctx, out, "</clip_stroke_path>\n");
}

static void
fz_trace_fill_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<fill_text");
	fz_trace_color(ctx, out, colorspace, color, alpha);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_text(ctx, out, text);
	fz_write_printf(ctx, out, "</fill_text>\n");
}

static void
fz_trace_stroke_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_stroke_state *stroke, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<stroke_text");
	fz_trace_color(ctx, out, colorspace, color, alpha);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_text(ctx, out, text);
	fz_write_printf(ctx, out, "</stroke_text>\n");
}

static void
fz_trace_clip_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<clip_text");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_text(ctx, out, text);
	fz_write_printf(ctx, out, "</clip_text>\n");
}

static void
fz_trace_clip_stroke_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_stroke_state *stroke, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<clip_stroke_text");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_text(ctx, out, text);
	fz_write_printf(ctx, out, "</clip_stroke_text>\n");
}

static void
fz_trace_ignore_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<ignore_text");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	fz_trace_text(ctx, out, text);
	fz_write_printf(ctx, out, "</ignore_text>\n");
}

static void
fz_trace_fill_image(fz_context *ctx, fz_device *dev, fz_image *image, const fz_matrix *ctm, float alpha)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<fill_image alpha=\"%g\"", alpha);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, " width=\"%d\" height=\"%d\"", image->w, image->h);
	fz_write_printf(ctx, out, "/>\n");
}

static void
fz_trace_fill_shade(fz_context *ctx, fz_device *dev, fz_shade *shade, const fz_matrix *ctm, float alpha)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<fill_shade alpha=\"%g\"", alpha);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, "/>\n");
}

static void
fz_trace_fill_image_mask(fz_context *ctx, fz_device *dev, fz_image *image, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<fill_image_mask");
	fz_trace_matrix(ctx, out, ctm);
	fz_trace_color(ctx, out, colorspace, color, alpha);
	fz_write_printf(ctx, out, " width=\"%d\" height=\"%d\"", image->w, image->h);
	fz_write_printf(ctx, out, "/>\n");
}

static void
fz_trace_clip_image_mask(fz_context *ctx, fz_device *dev, fz_image *image, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<clip_image_mask");
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, " width=\"%d\" height=\"%d\"", image->w, image->h);
	fz_write_printf(ctx, out, "/>\n");
}

static void
fz_trace_pop_clip(fz_context *ctx, fz_device *dev)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<pop_clip/>\n");
}

static void
fz_trace_begin_mask(fz_context *ctx, fz_device *dev, const fz_rect *bbox, int luminosity, fz_colorspace *colorspace, const float *color)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<mask bbox=\"%g %g %g %g\" s=\"%s\"",
		bbox->x0, bbox->y0, bbox->x1, bbox->y1,
		luminosity ? "luminosity" : "alpha");
	fz_write_printf(ctx, out, ">\n");
}

static void
fz_trace_end_mask(fz_context *ctx, fz_device *dev)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "</mask>\n");
}

static void
fz_trace_begin_group(fz_context *ctx, fz_device *dev, const fz_rect *bbox, int isolated, int knockout, int blendmode, float alpha)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<group bbox=\"%g %g %g %g\" isolated=\"%d\" knockout=\"%d\" blendmode=\"%s\" alpha=\"%g\">\n",
		bbox->x0, bbox->y0, bbox->x1, bbox->y1,
		isolated, knockout, fz_blendmode_name(blendmode), alpha);
}

static void
fz_trace_end_group(fz_context *ctx, fz_device *dev)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "</group>\n");
}

static int
fz_trace_begin_tile(fz_context *ctx, fz_device *dev, const fz_rect *area, const fz_rect *view, float xstep, float ystep, const fz_matrix *ctm, int id)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "<tile");
	fz_write_printf(ctx, out, " area=\"%g %g %g %g\"", area->x0, area->y0, area->x1, area->y1);
	fz_write_printf(ctx, out, " view=\"%g %g %g %g\"", view->x0, view->y0, view->x1, view->y1);
	fz_write_printf(ctx, out, " xstep=\"%g\" ystep=\"%g\"", xstep, ystep);
	fz_trace_matrix(ctx, out, ctm);
	fz_write_printf(ctx, out, ">\n");
	return 0;
}

static void
fz_trace_end_tile(fz_context *ctx, fz_device *dev)
{
	fz_output *out = ((fz_trace_device*)dev)->out;
	fz_write_printf(ctx, out, "</tile>\n");
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

	dev->out = out;

	return (fz_device*)dev;
}
