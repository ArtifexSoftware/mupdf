#include "fitz.h"
#include "muxps.h"

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
	fz_rect viewbox;
	int tile_mode;
	void *user;
	int (*func)(xps_context_t*, char*, xps_resource_t*, xps_item_t*, void*);
};

static int
xps_paint_tiling_brush_clipped(struct tile_closure_s *c)
{
	xps_context_t *ctx = c->ctx;
	int code;

#if 0
	gs_moveto(ctx->pgs, c->viewbox.p.x, c->viewbox.p.y);
	gs_lineto(ctx->pgs, c->viewbox.p.x, c->viewbox.q.y);
	gs_lineto(ctx->pgs, c->viewbox.q.x, c->viewbox.q.y);
	gs_lineto(ctx->pgs, c->viewbox.q.x, c->viewbox.p.y);
	gs_closepath(ctx->pgs);
	gs_clip(ctx->pgs);
	gs_newpath(ctx->pgs);
#endif

	code = c->func(c->ctx, c->base_uri, c->dict, c->tag, c->user);
	if (code < 0)
		return fz_rethrow(code, "cannot draw clipped tile");

	return 0;
}

#if 0
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
	return fz_rethrow(code, "cannot draw tile");
}
#endif

int
xps_parse_tiling_brush(xps_context_t *ctx, fz_matrix ctm,
	char *base_uri, xps_resource_t *dict, xps_item_t *root,
	int (*func)(xps_context_t*, fz_matrix, char*, xps_resource_t*, xps_item_t*, void*), void *user)
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

	fz_matrix transform;
	fz_rect viewbox;
	fz_rect viewport;
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

	transform = fz_identity;
	if (transform_att)
		xps_parse_render_transform(ctx, transform_att, &transform);
	if (transform_tag)
		xps_parse_matrix_transform(ctx, transform_tag, &transform);

	viewbox = fz_unitrect;
	if (viewbox_att)
		xps_parse_rectangle(ctx, viewbox_att, &viewbox);

	viewport = fz_unitrect;
	if (viewport_att)
		xps_parse_rectangle(ctx, viewport_att, &viewport);

	/* some sanity checks on the viewport/viewbox size */
	if (fabs(viewport.x1 - viewport.x0) < 0.01) return 0;
	if (fabs(viewport.y1 - viewport.y0) < 0.01) return 0;
	if (fabs(viewbox.x1 - viewbox.x0) < 0.01) return 0;
	if (fabs(viewbox.y1 - viewbox.y0) < 0.01) return 0;

	scalex = (viewport.x1 - viewport.x0) / (viewbox.x1 - viewbox.x0);
	scaley = (viewport.y1 - viewport.y0) / (viewbox.y1 - viewbox.y0);

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

//	gs_gsave(ctx->pgs);

	code = xps_begin_opacity(ctx, ctm, base_uri, dict, opacity_att, NULL);
	if (code)
	{
//		gs_grestore(ctx->pgs);
		return fz_rethrow(code, "cannot create transparency group");
	}

	/* TODO(tor): check viewport and tiling to see if we can set it to TILE_NONE */

#if 0
	if (tile_mode != TILE_NONE)
	{
		struct tile_closure_s closure;

		gs_client_pattern gspat;
		gs_client_color gscolor;
		fz_colorspace *cs;

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

		fz_matrix_translate(&transform, viewport.p.x, viewport.p.y, &transform);
		fz_matrix_scale(&transform, scalex, scaley, &transform);
		fz_matrix_translate(&transform, -viewbox.p.x, -viewbox.p.y, &transform);

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
			return fz_rethrow(code, "cannot draw tile");
		}
	}
#endif

	xps_end_opacity(ctx, base_uri, dict, opacity_att, NULL);

//	gs_grestore(ctx->pgs);

	return 0;
}
