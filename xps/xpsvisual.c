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

/* XPS interpreter - visual brush functions */

#include "ghostxps.h"

enum { TILE_NONE, TILE_TILE, TILE_FLIP_X, TILE_FLIP_Y, TILE_FLIP_X_Y };

struct userdata
{
	xps_context_t *ctx;
	xps_resource_t *dict;
	xps_item_t *visual_tag;
};

static int
xps_paint_visual_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root, void *visual_tag)
{
	return xps_parse_element(ctx, base_uri, dict, (xps_item_t *)visual_tag);
}

int
xps_parse_visual_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root)
{
	xps_item_t *node;
	int code;

	char *visual_uri;
	char *visual_att;
	xps_item_t *visual_tag = NULL;

	visual_att = xps_att(root, "Visual");

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "VisualBrush.Visual"))
			visual_tag = xps_down(node);
	}

	visual_uri = base_uri;
	xps_resolve_resource_reference(ctx, dict, &visual_att, &visual_tag, &visual_uri);

	if (visual_tag)
	{
		code = xps_parse_tiling_brush(ctx, visual_uri, dict, root, xps_paint_visual_brush, visual_tag);
		if (code)
			return gs_rethrow(code, "cannot parse tiling brush");
	}

	return 0;
}
