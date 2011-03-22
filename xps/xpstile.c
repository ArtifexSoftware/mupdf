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

/* XPS interpreter - tiles for pattern rendering */

#include "ghostxps.h"

/*
 * Parse a tiling brush (visual and image brushes at this time) common
 * properties. Use the callback to draw the individual tiles.
 */

enum { TILE_NONE, TILE_TILE, TILE_FLIP_X, TILE_FLIP_Y, TILE_FLIP_X_Y };

struct tile_closure_s
{
	xps_context_t *ctx;
	char *base_uri;
	xps_resource_t *dict;
	xps_item_t *tag;
	gs_rect viewbox;
	int tile_mode;
	void *user;
	int (*func)(xps_context_t*, char*, xps_resource_t*, xps_item_t*, void*);
};

static int
xps_paint_tiling_brush_clipped(struct tile_closure_s *c)
{
	xps_context_t *ctx = c->ctx;
	int code;

	gs_moveto(ctx->pgs, c->viewbox.p.x, c->viewbox.p.y);
	gs_lineto(ctx->pgs, c->viewbox.p.x, c->viewbox.q.y);
	gs_lineto(ctx->pgs, c->viewbox.q.x, c->viewbox.q.y);
	gs_lineto(ctx->pgs, c->viewbox.q.x, c->viewbox.p.y);
	gs_closepath(ctx->pgs);
	gs_clip(ctx->pgs);
	gs_newpath(ctx->pgs);

	code = c->func(c->ctx, c->base_uri, c->dict, c->tag, c->user);
	if (code < 0)
		return gs_rethrow(code, "cannot draw clipped tile");

	return 0;
}

static int
xps_paint_tiling_brush(const gs_client_color *pcc, gs_state *pgs)
{
	const gs_client_pattern *ppat = gs_getpattern(pcc);
	struct tile_closure_s *c = ppat->client_data;
	xps_context_t *ctx = c->ctx;
	gs_state *saved_pgs;
	int code;

	saved_pgs = ctx->pgs;
	ctx->pgs = pgs;

	gs_gsave(ctx->pgs);
	code = xps_paint_tiling_brush_clipped(c);
	if (code)
		goto cleanup;
	gs_grestore(ctx->pgs);

	if (c->tile_mode == TILE_FLIP_X || c->tile_mode == TILE_FLIP_X_Y)
	{
		gs_gsave(ctx->pgs);
		gs_translate(ctx->pgs, c->viewbox.q.x * 2, 0.0);
		gs_scale(ctx->pgs, -1.0, 1.0);
		code = xps_paint_tiling_brush_clipped(c);
		if (code)
			goto cleanup;
		gs_grestore(ctx->pgs);
	}

	if (c->tile_mode == TILE_FLIP_Y || c->tile_mode == TILE_FLIP_X_Y)
	{
		gs_gsave(ctx->pgs);
		gs_translate(ctx->pgs, 0.0, c->viewbox.q.y * 2);
		gs_scale(ctx->pgs, 1.0, -1.0);
		code = xps_paint_tiling_brush_clipped(c);
		if (code)
			goto cleanup;
		gs_grestore(ctx->pgs);
	}

	if (c->tile_mode == TILE_FLIP_X_Y)
	{
		gs_gsave(ctx->pgs);
		gs_translate(ctx->pgs, c->viewbox.q.x * 2, c->viewbox.q.y * 2);
		gs_scale(ctx->pgs, -1.0, -1.0);
		code = xps_paint_tiling_brush_clipped(c);
		if (code)
			goto cleanup;
		gs_grestore(ctx->pgs);
	}

	ctx->pgs = saved_pgs;

	return 0;

cleanup:
	gs_grestore(ctx->pgs);
	ctx->pgs = saved_pgs;
	return gs_rethrow(code, "cannot draw tile");
}

int
xps_high_level_pattern(xps_context_t *ctx)
{
	gs_matrix m;
	gs_rect bbox;
	gs_fixed_rect clip_box;
	int code;
	gx_device_color *pdc = gs_currentdevicecolor_inline(ctx->pgs);
	const gs_client_pattern *ppat = gs_getpattern(&pdc->ccolor);
	gs_pattern1_instance_t *pinst =
		(gs_pattern1_instance_t *)gs_currentcolor(ctx->pgs)->pattern;

	code = gx_pattern_cache_add_dummy_entry((gs_imager_state *)ctx->pgs,
		pinst, ctx->pgs->device->color_info.depth);
	if (code < 0)
		return code;

	code = gs_gsave(ctx->pgs);
	if (code < 0)
		return code;

	dev_proc(ctx->pgs->device, get_initial_matrix)(ctx->pgs->device, &m);
	gs_setmatrix(ctx->pgs, &m);
	code = gs_bbox_transform(&ppat->BBox, &ctm_only(ctx->pgs), &bbox);
	if (code < 0) {
		gs_grestore(ctx->pgs);
		return code;
	}
	clip_box.p.x = float2fixed(bbox.p.x);
	clip_box.p.y = float2fixed(bbox.p.y);
	clip_box.q.x = float2fixed(bbox.q.x);
	clip_box.q.y = float2fixed(bbox.q.y);
	code = gx_clip_to_rectangle(ctx->pgs, &clip_box);
	if (code < 0) {
		gs_grestore(ctx->pgs);
		return code;
	}
	code = dev_proc(ctx->pgs->device, pattern_manage)(ctx->pgs->device, pinst->id, pinst,
		pattern_manage__start_accum);
	if (code < 0) {
		gs_grestore(ctx->pgs);
		return code;
	}

	code = xps_paint_tiling_brush(&pdc->ccolor, ctx->pgs);
	if (code) {
		gs_grestore(ctx->pgs);
		return gs_rethrow(code, "high level pattern brush function failed");
	}

	code = gs_grestore(ctx->pgs);
	if (code < 0)
		return code;

	code = dev_proc(ctx->pgs->device, pattern_manage)(ctx->pgs->device, gx_no_bitmap_id, NULL,
		pattern_manage__finish_accum);

	return code;
}

static int
xps_remap_pattern(const gs_client_color *pcc, gs_state *pgs)
{
	const gs_client_pattern *ppat = gs_getpattern(pcc);
	struct tile_closure_s *c = ppat->client_data;
	xps_context_t *ctx = c->ctx;
	int code;

	/* pgs->device is the newly created pattern accumulator, but we want to test the device
	 * that is 'behind' that, the actual output device, so we use the one from
	 * the saved XPS graphics state.
	 */
	code = dev_proc(ctx->pgs->device, pattern_manage)(ctx->pgs->device, ppat->uid.id, ppat,
								pattern_manage__can_accum);

	if (code == 1) {
		/* Device handles high-level patterns, so return 'remap'.
		 * This closes the internal accumulator device, as we no longer need
		 * it, and the error trickles back up to the PDL client. The client
		 * must then take action to start the device's accumulator, draw the
		 * pattern, close the device's accumulator and generate a cache entry.
		 */
		return gs_error_Remap_Color;
	} else {
		code = xps_paint_tiling_brush(pcc, pgs);
		if (code)
			return gs_rethrow(code, "remap pattern brush function failed");
		return 0;
	}
}

int
xps_parse_tiling_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root,
	int (*func)(xps_context_t*, char*, xps_resource_t*, xps_item_t*, void*), void *user)
{
	xps_item_t *node;
	int code;

	char *opacity_att;
	char *transform_att;
	char *viewbox_att;
	char *viewport_att;
	char *tile_mode_att;
	char *viewbox_units_att;
	char *viewport_units_att;

	xps_item_t *transform_tag = NULL;

	gs_matrix transform;
	gs_rect viewbox;
	gs_rect viewport;
	float scalex, scaley;
	int tile_mode;

	opacity_att = xps_att(root, "Opacity");
	transform_att = xps_att(root, "Transform");
	viewbox_att = xps_att(root, "Viewbox");
	viewport_att = xps_att(root, "Viewport");
	tile_mode_att = xps_att(root, "TileMode");
	viewbox_units_att = xps_att(root, "ViewboxUnits");
	viewport_units_att = xps_att(root, "ViewportUnits");

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "ImageBrush.Transform"))
			transform_tag = xps_down(node);
		if (!strcmp(xps_tag(node), "VisualBrush.Transform"))
			transform_tag = xps_down(node);
	}

	xps_resolve_resource_reference(ctx, dict, &transform_att, &transform_tag, NULL);

	gs_make_identity(&transform);
	if (transform_att)
		xps_parse_render_transform(ctx, transform_att, &transform);
	if (transform_tag)
		xps_parse_matrix_transform(ctx, transform_tag, &transform);

	viewbox.p.x = 0.0; viewbox.p.y = 0.0;
	viewbox.q.x = 1.0; viewbox.q.y = 1.0;
	if (viewbox_att)
		xps_parse_rectangle(ctx, viewbox_att, &viewbox);

	viewport.p.x = 0.0; viewport.p.y = 0.0;
	viewport.q.x = 1.0; viewport.q.y = 1.0;
	if (viewport_att)
		xps_parse_rectangle(ctx, viewport_att, &viewport);

	/* some sanity checks on the viewport/viewbox size */
	if (fabs(viewport.q.x - viewport.p.x) < 0.01) return 0;
	if (fabs(viewport.q.y - viewport.p.y) < 0.01) return 0;
	if (fabs(viewbox.q.x - viewbox.p.x) < 0.01) return 0;
	if (fabs(viewbox.q.y - viewbox.p.y) < 0.01) return 0;

	scalex = (viewport.q.x - viewport.p.x) / (viewbox.q.x - viewbox.p.x);
	scaley = (viewport.q.y - viewport.p.y) / (viewbox.q.y - viewbox.p.y);

	tile_mode = TILE_NONE;
	if (tile_mode_att)
	{
		if (!strcmp(tile_mode_att, "None"))
			tile_mode = TILE_NONE;
		if (!strcmp(tile_mode_att, "Tile"))
			tile_mode = TILE_TILE;
		if (!strcmp(tile_mode_att, "FlipX"))
			tile_mode = TILE_FLIP_X;
		if (!strcmp(tile_mode_att, "FlipY"))
			tile_mode = TILE_FLIP_Y;
		if (!strcmp(tile_mode_att, "FlipXY"))
			tile_mode = TILE_FLIP_X_Y;
	}

	gs_gsave(ctx->pgs);

	code = xps_begin_opacity(ctx, base_uri, dict, opacity_att, NULL);
	if (code)
	{
		gs_grestore(ctx->pgs);
		return gs_rethrow(code, "cannot create transparency group");
	}

	/* TODO(tor): check viewport and tiling to see if we can set it to TILE_NONE */

	if (tile_mode != TILE_NONE)
	{
		struct tile_closure_s closure;

		gs_client_pattern gspat;
		gs_client_color gscolor;
		gs_color_space *cs;

		closure.ctx = ctx;
		closure.base_uri = base_uri;
		closure.dict = dict;
		closure.tag = root;
		closure.tile_mode = tile_mode;
		closure.user = user;
		closure.func = func;

		closure.viewbox.p.x = viewbox.p.x;
		closure.viewbox.p.y = viewbox.p.y;
		closure.viewbox.q.x = viewbox.q.x;
		closure.viewbox.q.y = viewbox.q.y;

		gs_pattern1_init(&gspat);
		uid_set_UniqueID(&gspat.uid, gs_next_ids(ctx->memory, 1));
		gspat.PaintType = 1;
		gspat.TilingType = 1;
		gspat.PaintProc = xps_remap_pattern;
		gspat.client_data = &closure;

		gspat.XStep = viewbox.q.x - viewbox.p.x;
		gspat.YStep = viewbox.q.y - viewbox.p.y;
		gspat.BBox.p.x = viewbox.p.x;
		gspat.BBox.p.y = viewbox.p.y;
		gspat.BBox.q.x = viewbox.q.x;
		gspat.BBox.q.y = viewbox.q.y;

		if (tile_mode == TILE_FLIP_X || tile_mode == TILE_FLIP_X_Y)
		{
			gspat.BBox.q.x += gspat.XStep;
			gspat.XStep *= 2;
		}

		if (tile_mode == TILE_FLIP_Y || tile_mode == TILE_FLIP_X_Y)
		{
			gspat.BBox.q.y += gspat.YStep;
			gspat.YStep *= 2;
		}

		gs_matrix_translate(&transform, viewport.p.x, viewport.p.y, &transform);
		gs_matrix_scale(&transform, scalex, scaley, &transform);
		gs_matrix_translate(&transform, -viewbox.p.x, -viewbox.p.y, &transform);

		cs = ctx->srgb;
		gs_setcolorspace(ctx->pgs, cs);
		gs_makepattern(&gscolor, &gspat, &transform, ctx->pgs, NULL);
		gs_setpattern(ctx->pgs, &gscolor);

		xps_fill(ctx);

		/* gs_makepattern increments the pattern count stored in the color
		 * structure. We will discard the color struct (its on the stack)
		 * so we need to decrement the reference before we throw away
		 * the structure.
		 */
		gs_pattern_reference(&gscolor, -1);
	}
	else
	{
		xps_clip(ctx);

		gs_concat(ctx->pgs, &transform);

		gs_translate(ctx->pgs, viewport.p.x, viewport.p.y);
		gs_scale(ctx->pgs, scalex, scaley);
		gs_translate(ctx->pgs, -viewbox.p.x, -viewbox.p.y);

		gs_moveto(ctx->pgs, viewbox.p.x, viewbox.p.y);
		gs_lineto(ctx->pgs, viewbox.p.x, viewbox.q.y);
		gs_lineto(ctx->pgs, viewbox.q.x, viewbox.q.y);
		gs_lineto(ctx->pgs, viewbox.q.x, viewbox.p.y);
		gs_closepath(ctx->pgs);
		gs_clip(ctx->pgs);
		gs_newpath(ctx->pgs);

		code = func(ctx, base_uri, dict, root, user);
		if (code < 0)
		{
			xps_end_opacity(ctx, base_uri, dict, opacity_att, NULL);
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot draw tile");
		}
	}

	xps_end_opacity(ctx, base_uri, dict, opacity_att, NULL);

	gs_grestore(ctx->pgs);

	return 0;
}
