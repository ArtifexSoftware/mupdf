/* XPS interpreter - analyze page checking for transparency.
 * This is a stripped down parser that looks for alpha values < 1.0 in
 * any part of the page.
 */

#include "fitz.h"
#include "muxps.h"

static int
xps_remote_resource_dictionary_has_transparency(xps_context_t *ctx, char *base_uri, char *source_att)
{
	//dputs("page has transparency: uses a remote resource; not parsed; being conservative\n");
	return 1;
}

int
xps_resource_dictionary_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *root)
{
	char *source;
	xps_item_t *node;

	source = xps_att(root, "Source");
	if (source)
		return xps_remote_resource_dictionary_has_transparency(ctx, base_uri, source);

	for (node = xps_down(root); node; node = xps_next(node))
	{
		// TODO: ... all kinds of stuff can be here, brushes, elements, whatnot
	}

	return 1;
}

static int
xps_gradient_stops_have_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *root)
{
	xps_item_t *node;
	fz_colorspace *colorspace;
	char *color_att;
	float samples[32];

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "GradientStop"))
		{
			color_att = xps_att(node, "Color");
			if (color_att)
			{
				xps_parse_color(ctx, base_uri, color_att, &colorspace, samples);
				if (samples[0] < 1.0)
				{
					//dputs("page has transparency: GradientStop has alpha\n");
					return 1;
				}
			}
		}
	}

	return 0;
}

static int
xps_gradient_brush_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *root)
{
	xps_item_t *node;
	char *opacity_att;

	opacity_att = xps_att(root, "Opacity");
	if (opacity_att)
	{
		if (atof(opacity_att) < 1.0)
		{
			//dputs("page has transparency: GradientBrush Opacity\n");
			return 1;
		}
	}

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "RadialGradientBrush.GradientStops"))
		{
			if (xps_gradient_stops_have_transparency(ctx, base_uri, node))
				return 1;
		}
		if (!strcmp(xps_tag(node), "LinearGradientBrush.GradientStops"))
		{
			if (xps_gradient_stops_have_transparency(ctx, base_uri, node))
				return 1;
		}
	}

	return 0;
}

static int
xps_brush_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *root)
{
	char *opacity_att;
	char *color_att;
	xps_item_t *node;

	fz_colorspace *colorspace;
	float samples[32];

	if (!strcmp(xps_tag(root), "SolidColorBrush"))
	{
		opacity_att = xps_att(root, "Opacity");
		if (opacity_att)
		{
			if (atof(opacity_att) < 1.0)
			{
				//dputs("page has transparency: SolidColorBrush Opacity\n");
				return 1;
			}
		}

		color_att = xps_att(root, "Color");
		if (color_att)
		{
			xps_parse_color(ctx, base_uri, color_att, &colorspace, samples);
			if (samples[0] < 1.0)
			{
				//dputs("page has transparency: SolidColorBrush Color has alpha\n");
				return 1;
			}
		}
	}

	if (!strcmp(xps_tag(root), "VisualBrush"))
	{
		char *opacity_att = xps_att(root, "Opacity");
		if (opacity_att)
		{
			if (atof(opacity_att) < 1.0)
			{
				//dputs("page has transparency: VisualBrush Opacity\n");
				return 1;
			}
		}

		for (node = xps_down(root); node; node = xps_next(node))
		{
			if (!strcmp(xps_tag(node), "VisualBrush.Visual"))
			{
				if (xps_element_has_transparency(ctx, base_uri, xps_down(node)))
					return 1;
			}
		}
	}

	if (!strcmp(xps_tag(root), "ImageBrush"))
	{
		if (xps_image_brush_has_transparency(ctx, base_uri, root))
			return 1;
	}

	if (!strcmp(xps_tag(root), "LinearGradientBrush"))
	{
		if (xps_gradient_brush_has_transparency(ctx, base_uri, root))
			return 1;
	}

	if (!strcmp(xps_tag(root), "RadialGradientBrush"))
	{
		if (xps_gradient_brush_has_transparency(ctx, base_uri, root))
			return 1;
	}

	return 0;
}

static int
xps_path_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *root)
{
	xps_item_t *node;

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "Path.OpacityMask"))
		{
			//dputs("page has transparency: Path.OpacityMask\n");
			return 1;
		}

		if (!strcmp(xps_tag(node), "Path.Stroke"))
		{
			if (xps_brush_has_transparency(ctx, base_uri, xps_down(node)))
				return 1;
		}

		if (!strcmp(xps_tag(node), "Path.Fill"))
		{
			if (xps_brush_has_transparency(ctx, base_uri, xps_down(node)))
				return 1;
		}
	}

	return 0;
}

static int
xps_glyphs_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *root)
{
	xps_item_t *node;

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "Glyphs.OpacityMask"))
		{
			//dputs("page has transparency: Glyphs.OpacityMask\n");
			return 1;
		}

		if (!strcmp(xps_tag(node), "Glyphs.Fill"))
		{
			if (xps_brush_has_transparency(ctx, base_uri, xps_down(node)))
				return 1;
		}
	}

	return 0;
}

static int
xps_canvas_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *root)
{
	xps_item_t *node;

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "Canvas.Resources"))
		{
			if (xps_resource_dictionary_has_transparency(ctx, base_uri, xps_down(node)))
				return 1;
		}

		if (!strcmp(xps_tag(node), "Canvas.OpacityMask"))
		{
			//dputs("page has transparency: Canvas.OpacityMask\n");
			return 1;
		}

		if (xps_element_has_transparency(ctx, base_uri, node))
			return 1;
	}

	return 0;
}

int
xps_element_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *node)
{
	char *opacity_att;
	char *stroke_att;
	char *fill_att;

	fz_colorspace *colorspace;
	float samples[32];

	stroke_att = xps_att(node, "Stroke");
	if (stroke_att)
	{
		xps_parse_color(ctx, base_uri, stroke_att, &colorspace, samples);
		if (samples[0] < 1.0)
		{
			//dprintf1("page has transparency: Stroke alpha=%g\n", samples[0]);
			return 1;
		}
	}

	fill_att = xps_att(node, "Fill");
	if (fill_att)
	{
		xps_parse_color(ctx, base_uri, fill_att, &colorspace, samples);
		if (samples[0] < 1.0)
		{
			//dprintf1("page has transparency: Fill alpha=%g\n", samples[0]);
			return 1;
		}
	}

	opacity_att = xps_att(node, "Opacity");
	if (opacity_att)
	{
		if (atof(opacity_att) < 1.0)
		{
			//dprintf1("page has transparency: Opacity=%g\n", atof(opacity_att));
			return 1;
		}
	}

	if (xps_att(node, "OpacityMask"))
	{
		//dputs("page has transparency: OpacityMask\n");
		return 1;
	}

	if (!strcmp(xps_tag(node), "Path"))
		if (xps_path_has_transparency(ctx, base_uri, node))
			return 1;
	if (!strcmp(xps_tag(node), "Glyphs"))
		if (xps_glyphs_has_transparency(ctx, base_uri, node))
			return 1;
	if (!strcmp(xps_tag(node), "Canvas"))
		if (xps_canvas_has_transparency(ctx, base_uri, node))
			return 1;

	return 0;
}
