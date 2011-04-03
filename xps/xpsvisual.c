#include "fitz.h"
#include "muxps.h"

enum { TILE_NONE, TILE_TILE, TILE_FLIP_X, TILE_FLIP_Y, TILE_FLIP_X_Y };

static void
xps_paint_visual_brush(xps_context *ctx, fz_matrix ctm,
	char *base_uri, xps_resource *dict, xml_element *root, void *visual_tag)
{
	xps_parse_element(ctx, ctm, base_uri, dict, (xml_element *)visual_tag);
}

void
xps_parse_visual_brush(xps_context *ctx, fz_matrix ctm, fz_rect area,
	char *base_uri, xps_resource *dict, xml_element *root)
{
	xml_element *node;

	char *visual_uri;
	char *visual_att;
	xml_element *visual_tag = NULL;

	visual_att = xml_att(root, "Visual");

	for (node = xml_down(root); node; node = xml_next(node))
	{
		if (!strcmp(xml_tag(node), "VisualBrush.Visual"))
			visual_tag = xml_down(node);
	}

	visual_uri = base_uri;
	xps_resolve_resource_reference(ctx, dict, &visual_att, &visual_tag, &visual_uri);

	if (visual_tag)
	{
		xps_parse_tiling_brush(ctx, ctm, area,
			visual_uri, dict, root, xps_paint_visual_brush, visual_tag);
	}
}
