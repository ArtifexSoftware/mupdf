#include "fitz.h"
#include "muxps.h"

void
xps_parse_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node)
{
	/* SolidColorBrushes are handled in a special case and will never show up here */
	if (!strcmp(xps_tag(node), "ImageBrush"))
		xps_parse_image_brush(ctx, ctm, base_uri, dict, node);
	else if (!strcmp(xps_tag(node), "VisualBrush"))
		xps_parse_visual_brush(ctx, ctm, base_uri, dict, node);
	else if (!strcmp(xps_tag(node), "LinearGradientBrush"))
		xps_parse_linear_gradient_brush(ctx, ctm, base_uri, dict, node);
	else if (!strcmp(xps_tag(node), "RadialGradientBrush"))
		xps_parse_radial_gradient_brush(ctx, ctm, base_uri, dict, node);
	else
		fz_warn("unknown brush tag: %s", xps_tag(node));
}

void
xps_parse_element(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *node)
{
	if (!strcmp(xps_tag(node), "Path"))
		xps_parse_path(ctx, ctm, base_uri, dict, node);
	if (!strcmp(xps_tag(node), "Glyphs"))
		xps_parse_glyphs(ctx, ctm, base_uri, dict, node);
	if (!strcmp(xps_tag(node), "Canvas"))
		xps_parse_canvas(ctx, ctm, base_uri, dict, node);
	/* skip unknown tags (like Foo.Resources and similar) */
}

void
xps_parse_render_transform(xps_context *ctx, char *transform, fz_matrix *matrix)
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

	matrix->a = args[0]; matrix->b = args[1];
	matrix->c = args[2]; matrix->d = args[3];
	matrix->e = args[4]; matrix->f = args[5];
}

void
xps_parse_matrix_transform(xps_context *ctx, xps_item *root, fz_matrix *matrix)
{
	char *transform;

	*matrix = fz_identity;

	if (!strcmp(xps_tag(root), "MatrixTransform"))
	{
		transform = xps_att(root, "Matrix");
		if (transform)
			xps_parse_render_transform(ctx, transform, matrix);
	}
}

void
xps_parse_rectangle(xps_context *ctx, char *text, fz_rect *rect)
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

	rect->x0 = args[0];
	rect->y0 = args[1];
	rect->x1 = args[0] + args[2];
	rect->y1 = args[1] + args[3];
}
