// Copyright (C) 2026 Artifex Software, Inc.
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

#include "color-imp.h"

typedef struct
{
	fz_device super;
	fz_device *passthrough;
	fz_culling_options opts;
} fz_culling_device;

static void
fz_culling_fill_path(fz_context *ctx, fz_device *dev_, const fz_path *path, int even_odd, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_fill_path(ctx, dev->passthrough, path, even_odd, ctm, colorspace, color, alpha, color_params);
}

static void
fz_culling_stroke_path(fz_context *ctx, fz_device *dev_, const fz_path *path, const fz_stroke_state *stroke,
	fz_matrix ctm, fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_stroke_path(ctx, dev->passthrough, path, stroke, ctm, colorspace, color, alpha, color_params);
}

static fz_text *
fz_new_text_with_span_of_cap(fz_context *ctx, int cap)
{
	fz_text *text = fz_new_text(ctx);
	fz_text_span *ns;

	ns = text->head = fz_malloc_struct(ctx, fz_text_span);
	text->tail = ns;
	/* Now allocate and copy the items. */
	ns->items = fz_malloc_array(ctx, cap, fz_text_item);
	ns->cap = cap;

	return text;
}

/* Break an fz_text down into subspans. Consider each subspan for culling. If not culled,
 * pass them into the callback function. */
static void
text_as_spans(fz_context *ctx, fz_culling_device *dev, const fz_text *text, fz_matrix ctm, const fz_stroke_state *stroke,
		void (*callback)(fz_context *ctx, fz_device *thru_dev, fz_text *text, fz_matrix ctm, const fz_stroke_state *stroke, void *args), void *args)
{
	fz_text_span *span, *new_span;
	fz_matrix tm, trm;
	fz_rect bbox;
	int i, max;
	fz_text *new_text = NULL;

	fz_var(new_text);

	max = 0;
	for (span = text->head; span; span = span->next)
		if (span->len > max)
			max = span->len;

	fz_try(ctx)
	{
		new_text = fz_new_text_with_span_of_cap(ctx, max);

		for (span = text->head; span; span = span->next)
		{
			if (span->len <= 0)
				continue;

			new_span = new_text->head;
			new_span->len = 0;

			tm = span->trm;
			for (i = 0; i < span->len; i++)
			{
				if (span->items[i].gid < 0)
					continue;

				tm.e = span->items[i].x;
				tm.f = span->items[i].y;
				trm = fz_concat(tm, ctm);
				bbox = fz_bound_glyph(ctx, span->font, span->items[i].gid, trm);

				if (fz_is_empty_rect(bbox))
					continue;

				/* FIXME: SText bboxes do not allow for stroke sizes. Should they? */
#if 0
				if (stroke)
					bbox = fz_adjust_rect_for_stroke(ctx, bbox, stroke, ctm);
#endif

				if (dev->opts.cull_glyph(ctx, dev->opts.opaque, bbox))
					continue;

				/* We need to send that glyph through. */
				new_span->items[new_span->len++] = span->items[i];
			}
			if (new_span->len == 0)
				continue;

			new_span->bidi_level = span->bidi_level;
			new_span->language = span->language;
			new_span->markup_dir = span->markup_dir;
			new_span->trm = span->trm;
			new_span->wmode = span->wmode;
			new_span->font = fz_keep_font(ctx, span->font);
			callback(ctx, dev->passthrough, new_text, ctm, stroke, args);
			fz_drop_font(ctx, new_span->font);
			new_span->font = NULL;
		}
	}
	fz_always(ctx)
		fz_drop_text(ctx, new_text);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

typedef struct
{
	fz_colorspace *colorspace;
	const float *color;
	float alpha;
	fz_color_params params;
	fz_rect scissor;
} cb_args;

static void
fill_text_cb(fz_context *ctx, fz_device *dev, fz_text *text, fz_matrix ctm, const fz_stroke_state *stroke, void *args)
{
	cb_args *fa = (cb_args *)args;

	if (dev->fill_text)
		dev->fill_text(ctx, dev, text, ctm, fa->colorspace, fa->color, fa->alpha, fa->params);
}

static void
fz_culling_fill_text(fz_context *ctx, fz_device *dev_, const fz_text *text, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;
	cb_args fa = { colorspace, color, alpha, color_params };

	if (dev->passthrough)
		text_as_spans(ctx, dev, text, ctm, NULL, fill_text_cb, &fa);
}

static void
stroke_text_cb(fz_context *ctx, fz_device *dev, fz_text *text, fz_matrix ctm, const fz_stroke_state *stroke, void *args)
{
	cb_args *fa = (cb_args *)args;

	if (dev->stroke_text)
		dev->stroke_text(ctx, dev, text, stroke, ctm, fa->colorspace, fa->color, fa->alpha, fa->params);
}

static void
fz_culling_stroke_text(fz_context *ctx, fz_device *dev_, const fz_text *text, const fz_stroke_state *stroke,
	fz_matrix ctm, fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;
	cb_args fa = { colorspace, color, alpha, color_params };

	if (dev->passthrough)
		text_as_spans(ctx, dev, text, ctm, stroke, stroke_text_cb, &fa);
}

static void
clip_text_cb(fz_context *ctx, fz_device *dev, fz_text *text, fz_matrix ctm, const fz_stroke_state *stroke, void *args)
{
	cb_args *fa = (cb_args *)args;

	if (dev->clip_text)
		dev->clip_text(ctx, dev, text, ctm, fa->scissor);
}

static void
fz_culling_clip_text(fz_context *ctx, fz_device *dev_, const fz_text *text, fz_matrix ctm, fz_rect scissor)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;
	cb_args fa = { 0 };

	fa.scissor = scissor;

	if (dev->passthrough)
		text_as_spans(ctx, dev, text, ctm, NULL, clip_text_cb, &fa);
}

static void
clip_stroke_text_cb(fz_context *ctx, fz_device *dev, fz_text *text, fz_matrix ctm, const fz_stroke_state *stroke, void *args)
{
	cb_args *fa = (cb_args *)args;

	if (dev->clip_stroke_text)
		dev->clip_stroke_text(ctx, dev, text, stroke, ctm, fa->scissor);
}

static void
fz_culling_clip_stroke_text(fz_context *ctx, fz_device *dev_, const fz_text *text, const fz_stroke_state *stroke, fz_matrix ctm, fz_rect scissor)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;
	cb_args fa = { 0 };

	fa.scissor = scissor;

	if (dev->passthrough)
		text_as_spans(ctx, dev, text, ctm, NULL, clip_stroke_text_cb, &fa);
}

static void
fz_culling_ignore_text(fz_context *ctx, fz_device *dev_, const fz_text *text, fz_matrix ctm)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_ignore_text(ctx, dev->passthrough, text, ctm);
}

static void
fz_culling_fill_shade(fz_context *ctx, fz_device *dev_, fz_shade *shade, fz_matrix ctm, float alpha, fz_color_params color_params)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_fill_shade(ctx, dev->passthrough, shade, ctm, alpha, color_params);
}

static void
fz_culling_fill_image(fz_context *ctx, fz_device *dev_, fz_image *image, fz_matrix ctm, float alpha, fz_color_params color_params)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_fill_image(ctx, dev->passthrough, image, ctm, alpha, color_params);
}

static void
fz_culling_fill_image_mask(fz_context *ctx, fz_device *dev_, fz_image *image, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_fill_image_mask(ctx, dev->passthrough, image, ctm, colorspace, color, alpha, color_params);
}

static void
fz_culling_clip_path(fz_context *ctx, fz_device *dev_, const fz_path *path, int even_odd, fz_matrix ctm, fz_rect scissor)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_clip_path(ctx, dev->passthrough, path, even_odd, ctm, scissor);
}

static void
fz_culling_clip_stroke_path(fz_context *ctx, fz_device *dev_, const fz_path *path, const fz_stroke_state *stroke, fz_matrix ctm, fz_rect scissor)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_clip_stroke_path(ctx, dev->passthrough, path, stroke, ctm, scissor);
}

static void
fz_culling_clip_image_mask(fz_context *ctx, fz_device *dev_, fz_image *img, fz_matrix ctm, fz_rect scissor)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_clip_image_mask(ctx, dev->passthrough, img, ctm, scissor);
}

static void
fz_culling_pop_clip(fz_context *ctx, fz_device *dev_)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_pop_clip(ctx, dev->passthrough);
}

static void
fz_culling_begin_mask(fz_context *ctx, fz_device *dev_, fz_rect rect, int luminosity, fz_colorspace *cs, const float *bc, fz_color_params color_params)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_begin_mask(ctx, dev->passthrough, rect, luminosity, cs, bc, color_params);
}

static void
fz_culling_end_mask(fz_context *ctx, fz_device *dev_, fz_function *tr)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_end_mask_tr(ctx, dev->passthrough, tr);
}

static void
fz_culling_begin_group(fz_context *ctx, fz_device *dev_, fz_rect rect, fz_colorspace *cs, int isolated, int knockout, int blendmode, float alpha)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_begin_group(ctx, dev->passthrough, rect, cs, isolated, knockout, blendmode, alpha);
}

static void
fz_culling_end_group(fz_context *ctx, fz_device *dev_)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_end_group(ctx, dev->passthrough);
}

static int
fz_culling_begin_tile(fz_context *ctx, fz_device *dev_, fz_rect area, fz_rect view, float xstep, float ystep, fz_matrix ctm, int id, int doc_id)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		return fz_begin_tile_tid(ctx, dev->passthrough, area, view, xstep, ystep, ctm, id, doc_id);
	else
		return 0;
}

static void
fz_culling_end_tile(fz_context *ctx, fz_device *dev_)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_end_tile(ctx, dev->passthrough);
}

static void
fz_culling_render_flags(fz_context *ctx, fz_device *dev_, int set, int clear)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_render_flags(ctx, dev->passthrough, set, clear);
}

static void
fz_culling_set_default_colorspaces(fz_context *ctx, fz_device *dev_, fz_default_colorspaces *ds)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_set_default_colorspaces(ctx, dev->passthrough, ds);
}

static void
fz_culling_begin_layer(fz_context *ctx, fz_device *dev_, const char *layer_name)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_begin_layer(ctx, dev->passthrough, layer_name);
}

static void
fz_culling_end_layer(fz_context *ctx, fz_device *dev_)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_end_layer(ctx, dev->passthrough);
}

static void
fz_culling_begin_structure(fz_context *ctx, fz_device *dev_, fz_structure standard, const char *raw, int idx)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_begin_structure(ctx, dev->passthrough, standard, raw, idx);
}

static void
fz_culling_end_structure(fz_context *ctx, fz_device *dev_)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_end_structure(ctx, dev->passthrough);
}

static void
fz_culling_begin_metatext(fz_context *ctx, fz_device *dev_, fz_metatext meta, const char *text)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_begin_metatext(ctx, dev->passthrough, meta, text);
}

static void
fz_culling_end_metatext(fz_context *ctx, fz_device *dev_)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->passthrough)
		fz_end_metatext(ctx, dev->passthrough);
}

static void
fz_culling_close_device(fz_context *ctx, fz_device *dev_)
{
	/* Does not pass through */
}

static void
fz_culling_drop_device(fz_context *ctx, fz_device *dev_)
{
	fz_culling_device *dev = (fz_culling_device*)dev_;

	if (dev->opts.drop)
		dev->opts.drop(ctx, dev->opts.opaque);
	fz_drop_device(ctx, dev->passthrough); /* Drop my reference */
}

fz_device *
fz_new_culling_device(fz_context *ctx, fz_device *passthrough, fz_culling_options *opts)
{
	fz_culling_device *dev = fz_new_derived_device(ctx, fz_culling_device);

	dev->super.fill_path = fz_culling_fill_path;
	dev->super.stroke_path = fz_culling_stroke_path;
	dev->super.clip_path = fz_culling_clip_path;
	dev->super.clip_stroke_path = fz_culling_clip_stroke_path;
	dev->super.fill_text = fz_culling_fill_text;
	dev->super.stroke_text = fz_culling_stroke_text;
	dev->super.clip_text = fz_culling_clip_text;
	dev->super.clip_stroke_text = fz_culling_clip_stroke_text;
	dev->super.ignore_text = fz_culling_ignore_text;
	dev->super.fill_shade = fz_culling_fill_shade;
	dev->super.fill_image = fz_culling_fill_image;
	dev->super.fill_image_mask = fz_culling_fill_image_mask;
	dev->super.clip_image_mask = fz_culling_clip_image_mask;
	dev->super.pop_clip = fz_culling_pop_clip;
	dev->super.begin_mask = fz_culling_begin_mask;
	dev->super.end_mask = fz_culling_end_mask;
	dev->super.begin_group = fz_culling_begin_group;
	dev->super.end_group = fz_culling_end_group;
	dev->super.begin_tile = fz_culling_begin_tile;
	dev->super.end_tile = fz_culling_end_tile;
	dev->super.render_flags = fz_culling_render_flags;
	dev->super.set_default_colorspaces = fz_culling_set_default_colorspaces;
	dev->super.begin_layer = fz_culling_begin_layer;
	dev->super.end_layer = fz_culling_end_layer;
	dev->super.begin_structure = fz_culling_begin_structure;
	dev->super.end_structure = fz_culling_end_structure;
	dev->super.begin_metatext = fz_culling_begin_metatext;
	dev->super.end_metatext = fz_culling_end_metatext;

	dev->super.close_device = fz_culling_close_device;
	dev->super.drop_device = fz_culling_drop_device;

	dev->opts = *opts;

	dev->passthrough = fz_keep_device(ctx, passthrough);

	return (fz_device*)dev;
}

typedef struct
{
	int n;
	fz_rect rects[FZ_FLEXIBLE_ARRAY];
} cull_rects;

static void
drop_culling_rects(fz_context *ctx, void *opaque)
{
	cull_rects *er = (cull_rects *)opaque;

	fz_free(ctx, er);
}

static int
cull_rect(fz_context *ctx, void *opaque, fz_rect rect)
{
	int i;
	cull_rects *er = (cull_rects *)opaque;
	float area = fz_rect_area(rect)/2;
	float overlapped = 0;

	for (i = 0; i < er->n; i++)
	{
		fz_rect ov = fz_intersect_rect(rect, er->rects[i]);
		overlapped += fz_rect_area(ov);
		/* If more than half of the text box is overlapped, cull it. */
		if (overlapped > area)
			return 1;
	}

	return 0;
}

fz_device *
fz_new_culling_device_with_rects(fz_context *ctx, fz_device *passthrough, int n, const fz_rect *rects)
{
	cull_rects *er;
	fz_device *dev = NULL;
	fz_culling_options opts;

	er = fz_malloc_flexible(ctx, cull_rects, rects, n);
	er->n = n;
	if (n)
		memcpy(er->rects, rects, sizeof(rects[0])*n);

	opts.opaque = er;
	opts.drop = drop_culling_rects;
	opts.cull_glyph = cull_rect;

	fz_var(dev);

	fz_try(ctx)
	{
		dev = fz_new_culling_device(ctx, passthrough, &opts);
	}
	fz_catch(ctx)
	{
		drop_culling_rects(ctx, er);
		fz_rethrow(ctx);
	}

	return dev;
}

fz_pixmap *
fz_draw_page_culling_text(fz_context *ctx, fz_page *page, fz_matrix ctm, int n, const fz_rect *rects)
{
	fz_device *draw_dev = NULL;
	fz_device *cull_dev = NULL;
	fz_rect bounds = fz_bound_page(ctx, page);
	fz_rect tbounds = fz_transform_rect(bounds, ctm);
	fz_irect itbounds = fz_irect_from_rect(tbounds);
	fz_pixmap *pix = fz_new_pixmap_with_bbox(ctx, fz_device_gray(ctx), itbounds, NULL, 0);

	fz_var(draw_dev);
	fz_var(cull_dev);

	fz_try(ctx)
	{
		fz_clear_pixmap(ctx, pix);
		draw_dev = fz_new_draw_device(ctx, ctm, pix);
		cull_dev = fz_new_culling_device_with_rects(ctx, draw_dev, n, rects);

		fz_run_page(ctx, page, cull_dev, fz_identity, NULL);
		fz_close_device(ctx, cull_dev);
		fz_close_device(ctx, draw_dev);
	}
	fz_always(ctx)
	{
		fz_drop_device(ctx, cull_dev);
		fz_drop_device(ctx, draw_dev);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);

	return pix;
}
