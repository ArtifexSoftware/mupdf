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

/* XPS interpreter - common parse functions */

#include "ghostxps.h"

int
xps_parse_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node)
{
	if (!strcmp(xps_tag(node), "SolidColorBrush"))
		return xps_parse_solid_color_brush(ctx, base_uri, dict, node);
	if (!strcmp(xps_tag(node), "ImageBrush"))
	{
		int code = xps_parse_image_brush(ctx, base_uri, dict, node);
		if (code)
			gs_catch(code, "ignoring error in image brush");
		return gs_okay;
	}
	if (!strcmp(xps_tag(node), "VisualBrush"))
		return xps_parse_visual_brush(ctx, base_uri, dict, node);
	if (!strcmp(xps_tag(node), "LinearGradientBrush"))
		return xps_parse_linear_gradient_brush(ctx, base_uri, dict, node);
	if (!strcmp(xps_tag(node), "RadialGradientBrush"))
		return xps_parse_radial_gradient_brush(ctx, base_uri, dict, node);
	return gs_throw1(-1, "unknown brush tag: %s", xps_tag(node));
}

int
xps_parse_element(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *node)
{
	if (!strcmp(xps_tag(node), "Path"))
		return xps_parse_path(ctx, base_uri, dict, node);
	if (!strcmp(xps_tag(node), "Glyphs"))
		return xps_parse_glyphs(ctx, base_uri, dict, node);
	if (!strcmp(xps_tag(node), "Canvas"))
		return xps_parse_canvas(ctx, base_uri, dict, node);
	/* skip unknown tags (like Foo.Resources and similar) */
	return 0;
}

void
xps_parse_render_transform(xps_context_t *ctx, char *transform, gs_matrix *matrix)
{
	float args[6];
	char *s = transform;
	int i;

	args[0] = 1.0; args[1] = 0.0;
	args[2] = 0.0; args[3] = 1.0;
	args[4] = 0.0; args[5] = 0.0;

	for (i = 0; i < 6 && *s; i++)
	{
		args[i] = atof(s);
		while (*s && *s != ',')
			s++;
		if (*s == ',')
			s++;
	}

	matrix->xx = args[0]; matrix->xy = args[1];
	matrix->yx = args[2]; matrix->yy = args[3];
	matrix->tx = args[4]; matrix->ty = args[5];
}

void
xps_parse_matrix_transform(xps_context_t *ctx, xps_item_t *root, gs_matrix *matrix)
{
	char *transform;

	gs_make_identity(matrix);

	if (!strcmp(xps_tag(root), "MatrixTransform"))
	{
		transform = xps_att(root, "Matrix");
		if (transform)
			xps_parse_render_transform(ctx, transform, matrix);
	}
}

void
xps_parse_rectangle(xps_context_t *ctx, char *text, gs_rect *rect)
{
	float args[4];
	char *s = text;
	int i;

	args[0] = 0.0; args[1] = 0.0;
	args[2] = 1.0; args[3] = 1.0;

	for (i = 0; i < 4 && *s; i++)
	{
		args[i] = atof(s);
		while (*s && *s != ',')
			s++;
		if (*s == ',')
			s++;
	}

	rect->p.x = args[0];
	rect->p.y = args[1];
	rect->q.x = args[0] + args[2];
	rect->q.y = args[1] + args[3];
}
