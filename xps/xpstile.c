#include "fitz.h"
#include "muxps.h"

/*
 * Parse a tiling brush (visual and image brushes at this time) common
 * properties. Use the callback to draw the individual tiles.
 */

enum { TILE_NONE, TILE_TILE, TILE_FLIP_X, TILE_FLIP_Y, TILE_FLIP_X_Y };

struct closure
{
	char *base_uri;
	xps_resource *dict;
	xps_item *root;
	void *user;
	void (*func)(xps_context*, fz_matrix, char*, xps_resource*, xps_item*, void*);
};

static void
xps_paint_tiling_brush_clipped(xps_context *ctx, fz_matrix ctm, fz_rect viewbox, struct closure *c)
{
	ctx->path = fz_newpath();
	fz_moveto(ctx->path, viewbox.x0, viewbox.y0);
	fz_lineto(ctx->path, viewbox.x0, viewbox.y1);
	fz_lineto(ctx->path, viewbox.x1, viewbox.y1);
	fz_lineto(ctx->path, viewbox.x1, viewbox.y0);
	fz_closepath(ctx->path);
	xps_clip(ctx, ctm);

	c->func(ctx, ctm, c->base_uri, c->dict, c->root, c->user);

	ctx->dev->popclip(ctx->dev->user);
}

static void
xps_paint_tiling_brush(xps_context *ctx, fz_matrix ctm, fz_rect viewbox, int tile_mode, struct closure *c)
{
	fz_matrix ttm;

	xps_paint_tiling_brush_clipped(ctx, ctm, viewbox, c);

	if (tile_mode == TILE_FLIP_X || tile_mode == TILE_FLIP_X_Y)
	{
		ttm = fz_concat(fz_translate(viewbox.x1 * 2, 0), ctm);
		ttm = fz_concat(fz_scale(-1, 1), ttm);
		xps_paint_tiling_brush_clipped(ctx, ttm, viewbox, c);
	}

	if (tile_mode == TILE_FLIP_Y || tile_mode == TILE_FLIP_X_Y)
	{
		ttm = fz_concat(fz_translate(0, viewbox.y1 * 2), ctm);
		ttm = fz_concat(fz_scale(1, -1), ttm);
		xps_paint_tiling_brush_clipped(ctx, ttm, viewbox, c);
	}

	if (tile_mode == TILE_FLIP_X_Y)
	{
		ttm = fz_concat(fz_translate(viewbox.x1 * 2, viewbox.y1 * 2), ctm);
		ttm = fz_concat(fz_scale(-1, -1), ttm);
		xps_paint_tiling_brush_clipped(ctx, ttm, viewbox, c);
	}
}

void
xps_parse_tiling_brush(xps_context *ctx, fz_matrix ctm, fz_rect area,
	char *base_uri, xps_resource *dict, xps_item *root,
	void (*func)(xps_context*, fz_matrix, char*, xps_resource*, xps_item*, void*), void *user)
{
	xps_item *node;
	struct closure c;

	char *opacity_att;
	char *transform_att;
	char *viewbox_att;
	char *viewport_att;
	char *tile_mode_att;
	char *viewbox_units_att;
	char *viewport_units_att;

	xps_item *transform_tag = NULL;

	fz_matrix transform;
	fz_rect viewbox;
	fz_rect viewport;
	float xstep, ystep;
	float xscale, yscale;
	int tile_mode;

	opacity_att = xps_att(root, "Opacity");
	transform_att = xps_att(root, "Transform");
	viewbox_att = xps_att(root, "Viewbox");
	viewport_att = xps_att(root, "Viewport");
	tile_mode_att = xps_att(root, "TileMode");
	viewbox_units_att = xps_att(root, "ViewboxUnits");
	viewport_units_att = xps_att(root, "ViewportUnits");

	c.base_uri = base_uri;
	c.dict = dict;
	c.root = root;
	c.user = user;
	c.func = func;

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
	if (fabs(viewport.x1 - viewport.x0) < 0.01) return;
	if (fabs(viewport.y1 - viewport.y0) < 0.01) return;
	if (fabs(viewbox.x1 - viewbox.x0) < 0.01) return;
	if (fabs(viewbox.y1 - viewbox.y0) < 0.01) return;

	xstep = viewbox.x1 - viewbox.x0;
	ystep = viewbox.y1 - viewbox.y0;

	xscale = (viewport.x1 - viewport.x0) / xstep;
	yscale = (viewport.y1 - viewport.y0) / ystep;

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

	if (tile_mode == TILE_FLIP_X || tile_mode == TILE_FLIP_X_Y)
		xstep *= 2;
	if (tile_mode == TILE_FLIP_Y || tile_mode == TILE_FLIP_X_Y)
		ystep *= 2;

	xps_begin_opacity(ctx, ctm, base_uri, dict, opacity_att, NULL);

	ctm = fz_concat(transform, ctm);
	ctm = fz_concat(fz_translate(viewport.x0, viewport.y0), ctm);
	ctm = fz_concat(fz_scale(xscale, yscale), ctm);
	ctm = fz_concat(fz_translate(-viewbox.x0, -viewbox.y0), ctm);

	if (tile_mode != TILE_NONE && !fz_isinfiniterect(area))
	{
		fz_matrix invctm = fz_invertmatrix(ctm);
		fz_rect bbox = fz_transformrect(invctm, area);
		int x0 = floorf(bbox.x0 / xstep);
		int y0 = floorf(bbox.y0 / ystep);
		int x1 = ceilf(bbox.x1 / xstep);
		int y1 = ceilf(bbox.y1 / ystep);
		int x, y;

		printf("repeating tile %d x %d times\n", x1-x0, y1-y0);

		for (y = y0; y < y1; y++)
		{
			for (x = x0; x < x1; x++)
			{
				fz_matrix ttm = fz_concat(fz_translate(xstep * x, ystep * y), ctm);
				xps_paint_tiling_brush(ctx, ttm, viewbox, tile_mode, &c);
			}
		}
	}
	else
	{
		xps_paint_tiling_brush(ctx, ctm, viewbox, tile_mode, &c);
	}

	xps_end_opacity(ctx, base_uri, dict, opacity_att, NULL);
}
