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

#include "color-imp.h"

typedef struct
{
	fz_device super;
	fz_device *passthrough;
	fz_elide_options opts;
} fz_elide_device;

static void
fz_elide_fill_path(fz_context *ctx, fz_device *dev_, const fz_path *path, int even_odd, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_fill_path(ctx, dev->passthrough, path, even_odd, ctm, colorspace, color, alpha, color_params);
}

static void
fz_elide_stroke_path(fz_context *ctx, fz_device *dev_, const fz_path *path, const fz_stroke_state *stroke,
	fz_matrix ctm, fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_stroke_path(ctx, dev->passthrough, path, stroke, ctm, colorspace, color, alpha, color_params);
}

static void
fz_elide_fill_text(fz_context *ctx, fz_device *dev_, const fz_text *text, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;
	fz_rect bounds = fz_bound_text(ctx, text, NULL, ctm);

	if (dev->opts.elide_text(ctx, dev->opts.opaque, bounds))
		return;

	if (dev->passthrough)
		fz_fill_text(ctx, dev->passthrough, text, ctm, colorspace, color, alpha, color_params);
}

static void
fz_elide_stroke_text(fz_context *ctx, fz_device *dev_, const fz_text *text, const fz_stroke_state *stroke,
	fz_matrix ctm, fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;
	fz_rect bounds = fz_bound_text(ctx, text, stroke, ctm);

	if (dev->opts.elide_text(ctx, dev->opts.opaque, bounds))
		return;

	if (dev->passthrough)
		fz_stroke_text(ctx, dev->passthrough, text, stroke, ctm, colorspace, color, alpha, color_params);
}

static void
fz_elide_fill_shade(fz_context *ctx, fz_device *dev_, fz_shade *shade, fz_matrix ctm, float alpha, fz_color_params color_params)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_fill_shade(ctx, dev->passthrough, shade, ctm, alpha, color_params);
}

static void
fz_elide_fill_image(fz_context *ctx, fz_device *dev_, fz_image *image, fz_matrix ctm, float alpha, fz_color_params color_params)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_fill_image(ctx, dev->passthrough, image, ctm, alpha, color_params);
}

static void
fz_elide_fill_image_mask(fz_context *ctx, fz_device *dev_, fz_image *image, fz_matrix ctm,
	fz_colorspace *colorspace, const float *color, float alpha, fz_color_params color_params)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_fill_image_mask(ctx, dev->passthrough, image, ctm, colorspace, color, alpha, color_params);
}

static void
fz_elide_clip_path(fz_context *ctx, fz_device *dev_, const fz_path *path, int even_odd, fz_matrix ctm, fz_rect scissor)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_clip_path(ctx, dev->passthrough, path, even_odd, ctm, scissor);
}

static void
fz_elide_clip_stroke_path(fz_context *ctx, fz_device *dev_, const fz_path *path, const fz_stroke_state *stroke, fz_matrix ctm, fz_rect scissor)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_clip_stroke_path(ctx, dev->passthrough, path, stroke, ctm, scissor);
}

static void
fz_elide_clip_text(fz_context *ctx, fz_device *dev_, const fz_text *text, fz_matrix ctm, fz_rect scissor)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;
	fz_rect bounds = fz_bound_text(ctx, text, NULL, ctm);

	if (dev->opts.elide_text(ctx, dev->opts.opaque, bounds))
		return;

	if (dev->passthrough)
		fz_clip_text(ctx, dev->passthrough, text, ctm, scissor);
}

static void
fz_elide_clip_stroke_text(fz_context *ctx, fz_device *dev_, const fz_text *text, const fz_stroke_state *stroke, fz_matrix ctm, fz_rect scissor)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;
	fz_rect bounds = fz_bound_text(ctx, text, stroke, ctm);

	if (dev->opts.elide_text(ctx, dev->opts.opaque, bounds))
		return;

	if (dev->passthrough)
		fz_clip_stroke_text(ctx, dev->passthrough, text, stroke, ctm, scissor);
}

static void
fz_elide_ignore_text(fz_context *ctx, fz_device *dev_, const fz_text *text, fz_matrix ctm)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_ignore_text(ctx, dev->passthrough, text, ctm);
}

static void
fz_elide_clip_image_mask(fz_context *ctx, fz_device *dev_, fz_image *img, fz_matrix ctm, fz_rect scissor)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_clip_image_mask(ctx, dev->passthrough, img, ctm, scissor);
}

static void
fz_elide_pop_clip(fz_context *ctx, fz_device *dev_)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_pop_clip(ctx, dev->passthrough);
}

static void
fz_elide_begin_mask(fz_context *ctx, fz_device *dev_, fz_rect rect, int luminosity, fz_colorspace *cs, const float *bc, fz_color_params color_params)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_begin_mask(ctx, dev->passthrough, rect, luminosity, cs, bc, color_params);
}

static void
fz_elide_end_mask(fz_context *ctx, fz_device *dev_, fz_function *tr)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_end_mask_tr(ctx, dev->passthrough, tr);
}

static void
fz_elide_begin_group(fz_context *ctx, fz_device *dev_, fz_rect rect, fz_colorspace *cs, int isolated, int knockout, int blendmode, float alpha)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_begin_group(ctx, dev->passthrough, rect, cs, isolated, knockout, blendmode, alpha);
}

static void
fz_elide_end_group(fz_context *ctx, fz_device *dev_)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_end_group(ctx, dev->passthrough);
}

static int
fz_elide_begin_tile(fz_context *ctx, fz_device *dev_, fz_rect area, fz_rect view, float xstep, float ystep, fz_matrix ctm, int id, int doc_id)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		return fz_begin_tile_tid(ctx, dev->passthrough, area, view, xstep, ystep, ctm, id, doc_id);
	else
		return 0;
}

static void
fz_elide_end_tile(fz_context *ctx, fz_device *dev_)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_end_tile(ctx, dev->passthrough);
}

static void
fz_elide_render_flags(fz_context *ctx, fz_device *dev_, int set, int clear)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_render_flags(ctx, dev->passthrough, set, clear);
}

static void
fz_elide_set_default_colorspaces(fz_context *ctx, fz_device *dev_, fz_default_colorspaces *ds)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_set_default_colorspaces(ctx, dev->passthrough, ds);
}

static void
fz_elide_begin_layer(fz_context *ctx, fz_device *dev_, const char *layer_name)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_begin_layer(ctx, dev->passthrough, layer_name);
}

static void
fz_elide_end_layer(fz_context *ctx, fz_device *dev_)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_end_layer(ctx, dev->passthrough);
}

static void
fz_elide_begin_structure(fz_context *ctx, fz_device *dev_, fz_structure standard, const char *raw, int idx)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_begin_structure(ctx, dev->passthrough, standard, raw, idx);
}

static void
fz_elide_end_structure(fz_context *ctx, fz_device *dev_)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_end_structure(ctx, dev->passthrough);
}

static void
fz_elide_begin_metatext(fz_context *ctx, fz_device *dev_, fz_metatext meta, const char *text)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_begin_metatext(ctx, dev->passthrough, meta, text);
}

static void
fz_elide_end_metatext(fz_context *ctx, fz_device *dev_)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->passthrough)
		fz_end_metatext(ctx, dev->passthrough);
}

static void
fz_elide_close_device(fz_context *ctx, fz_device *dev_)
{
	/* Does not pass through */
}

static void
fz_elide_drop_device(fz_context *ctx, fz_device *dev_)
{
	fz_elide_device *dev = (fz_elide_device*)dev_;

	if (dev->opts.drop)
		dev->opts.drop(ctx, dev->opts.opaque);
	fz_drop_device(ctx, dev->passthrough); /* Drop my reference */
}

fz_device *
fz_new_elide_device(fz_context *ctx, fz_device *passthrough, fz_elide_options *opts)
{
	fz_elide_device *dev = fz_new_derived_device(ctx, fz_elide_device);

	dev->super.fill_path = fz_elide_fill_path;
	dev->super.stroke_path = fz_elide_stroke_path;
	dev->super.clip_path = fz_elide_clip_path;
	dev->super.clip_stroke_path = fz_elide_clip_stroke_path;
	dev->super.fill_text = fz_elide_fill_text;
	dev->super.stroke_text = fz_elide_stroke_text;
	dev->super.clip_text = fz_elide_clip_text;
	dev->super.clip_stroke_text = fz_elide_clip_stroke_text;
	dev->super.ignore_text = fz_elide_ignore_text;
	dev->super.fill_shade = fz_elide_fill_shade;
	dev->super.fill_image = fz_elide_fill_image;
	dev->super.fill_image_mask = fz_elide_fill_image_mask;
	dev->super.clip_image_mask = fz_elide_clip_image_mask;
	dev->super.pop_clip = fz_elide_pop_clip;
	dev->super.begin_mask = fz_elide_begin_mask;
	dev->super.end_mask = fz_elide_end_mask;
	dev->super.begin_group = fz_elide_begin_group;
	dev->super.end_group = fz_elide_end_group;
	dev->super.begin_tile = fz_elide_begin_tile;
	dev->super.end_tile = fz_elide_end_tile;

	dev->super.close_device = fz_elide_close_device;
	dev->super.drop_device = fz_elide_drop_device;

	dev->opts = *opts;

	dev->passthrough = fz_keep_device(ctx, passthrough);

	return (fz_device*)dev;
}

typedef struct
{
	int n;
	fz_rect rects[FZ_FLEXIBLE_ARRAY];
} elide_rects;

static void
drop_elide_rects(fz_context *ctx, void *opaque)
{
	elide_rects *er = (elide_rects *)opaque;

	fz_free(ctx, er);
}

static int
elide_rect(fz_context *ctx, void *opaque, fz_rect rect)
{
	int i;
	elide_rects *er = (elide_rects *)opaque;

	for (i = 0; i < er->n; i++)
	{
		fz_rect ov = fz_intersect_rect(rect, er->rects[i]);
		if (fz_is_empty_rect(ov))
			continue;
		return 1; /* FIXME: Maybe too harsh? */
	}

	return 0;
}

fz_device *
fz_new_elide_device_with_rects(fz_context *ctx, fz_device *passthrough, int n, const fz_rect *rects)
{
	elide_rects *er;
	fz_device *dev = NULL;
	fz_elide_options opts;

	er = fz_malloc_flexible(ctx, elide_rects, rects, n);
	er->n = n;
	memcpy(er->rects, rects, sizeof(rects[0])*n);

	opts.opaque = er;
	opts.drop = drop_elide_rects;
	opts.elide_text = elide_rect;

	fz_var(dev);

	fz_try(ctx)
	{
		dev = fz_new_elide_device(ctx, passthrough, &opts);
	}
	fz_catch(ctx)
	{
		drop_elide_rects(ctx, er);
		fz_rethrow(ctx);
	}

	return dev;
}

fz_pixmap *
fz_draw_page_eliding_text(fz_context *ctx, fz_page *page, fz_matrix ctm, int n, const fz_rect *rects)
{
	fz_device *draw_dev = NULL;
	fz_device *elide_dev = NULL;
	fz_rect bounds = fz_bound_page(ctx, page);
	fz_rect tbounds = fz_transform_rect(bounds, ctm);
	fz_irect itbounds = fz_irect_from_rect(tbounds);
	fz_pixmap *pix = fz_new_pixmap_with_bbox(ctx, fz_device_gray(ctx), itbounds, NULL, 0);

	fz_var(draw_dev);
	fz_var(elide_dev);

	fz_try(ctx)
	{
		fz_clear_pixmap(ctx, pix);
		draw_dev = fz_new_draw_device(ctx, ctm, pix);
		elide_dev = fz_new_elide_device_with_rects(ctx, draw_dev, n, rects);

		fz_run_page(ctx, page, elide_dev, fz_identity, NULL);
		fz_close_device(ctx, elide_dev);
		fz_close_device(ctx, draw_dev);
	}
	fz_always(ctx)
	{
		fz_drop_device(ctx, elide_dev);
		fz_drop_device(ctx, draw_dev);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);

	return pix;
}
