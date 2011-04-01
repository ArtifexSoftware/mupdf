#include "fitz.h"
#include "muxps.h"

#define MAX_STOPS 256

enum { SPREAD_PAD, SPREAD_REPEAT, SPREAD_REFLECT };

/*
 * Parse a list of GradientStop elements.
 * Fill the offset and color arrays, and
 * return the number of stops parsed.
 */

struct stop
{
	float offset;
	float r, g, b, a;
};

static int cmp_stop(const void *a, const void *b)
{
	const struct stop *astop = a;
	const struct stop *bstop = b;
	float diff = astop->offset - bstop->offset;
	if (diff < 0)
		return -1;
	if (diff > 0)
		return 1;
	return 0;
}

static inline float lerp(float a, float b, float x)
{
	return a + (b - a) * x;
}

static int
xps_parse_gradient_stops(xps_context *ctx, char *base_uri, xps_item *node,
	struct stop *stops, int maxcount)
{
	fz_colorspace *colorspace;
	float sample[8];
	float rgb[3];
	int before, after;
	int count;
	int i;

	/* We may have to insert 2 extra stops when postprocessing */
	maxcount -= 2;

	count = 0;
	while (node && count < maxcount)
	{
		if (!strcmp(xps_tag(node), "GradientStop"))
		{
			char *offset = xps_att(node, "Offset");
			char *color = xps_att(node, "Color");
			if (offset && color)
			{
				stops[count].offset = atof(offset);

				xps_parse_color(ctx, base_uri, color, &colorspace, sample);

				fz_convertcolor(colorspace, sample + 1, fz_devicergb, rgb);

				stops[count].r = rgb[0];
				stops[count].g = rgb[1];
				stops[count].b = rgb[2];
				stops[count].a = sample[0];

				count ++;
			}
		}
		node = xps_next(node);
	}

	if (count == 0)
	{
		fz_warn("gradient brush has no gradient stops");
		stops[0].offset = 0;
		stops[0].r = 0;
		stops[0].g = 0;
		stops[0].b = 0;
		stops[0].a = 1;
		stops[1].offset = 1;
		stops[1].r = 1;
		stops[1].g = 1;
		stops[1].b = 1;
		stops[1].a = 1;
		return 2;
	}

	if (count == maxcount)
		fz_warn("gradient brush exceeded maximum number of gradient stops");

	/* Postprocess to make sure the range of offsets is 0.0 to 1.0 */

	qsort(stops, count, sizeof(struct stop), cmp_stop);

	before = -1;
	after = -1;

	for (i = 0; i < count; i++)
	{
		if (stops[i].offset < 0)
			before = i;
		if (stops[i].offset > 1)
		{
			after = i;
			break;
		}
	}

	/* Remove all stops < 0 except the largest one */
	if (before > 0)
	{
		memmove(stops, stops + before, (count - before) * sizeof(struct stop));
		count -= before;
	}

	/* Remove all stops > 1 except the smallest one */
	if (after >= 0)
		count = after + 1;

	/* Expand single stop to 0 .. 1 */
	if (count == 1)
	{
		stops[1] = stops[0];
		stops[0].offset = 0;
		stops[1].offset = 1;
		return 2;
	}

	/* First stop < 0 -- interpolate value to 0 */
	if (stops[0].offset < 0)
	{
		float d = -stops[0].offset / (stops[1].offset - stops[0].offset);
		stops[0].offset = 0;
		stops[0].r = lerp(stops[0].r, stops[1].r, d);
		stops[0].g = lerp(stops[0].g, stops[1].g, d);
		stops[0].b = lerp(stops[0].b, stops[1].b, d);
		stops[0].a = lerp(stops[0].a, stops[1].a, d);
	}

	/* Last stop > 1 -- interpolate value to 1 */
	if (stops[count-1].offset > 1)
	{
		float d = (1 - stops[count-2].offset) / (stops[count-1].offset - stops[count-2].offset);
		stops[count-1].offset = 1;
		stops[0].r = lerp(stops[count-2].r, stops[count-1].r, d);
		stops[0].g = lerp(stops[count-2].g, stops[count-1].g, d);
		stops[0].b = lerp(stops[count-2].b, stops[count-1].b, d);
		stops[0].a = lerp(stops[count-2].a, stops[count-1].a, d);
	}

	/* First stop > 0 -- insert a duplicate at 0 */
	if (stops[0].offset > 0)
	{
		memmove(stops + 1, stops, count * sizeof(struct stop));
		stops[0] = stops[1];
		stops[0].offset = 0;
		count++;
	}

	/* Last stop < 1 -- insert a duplicate at 1 */
	if (stops[count-1].offset < 1)
	{
		stops[count] = stops[count-1];
		stops[count].offset = 1;
		count++;
	}

	return count;
}

static void
xps_sample_gradient_stops(fz_shade *shade, struct stop *stops, int count)
{
	float offset, d;
	int i, k;

	k = 0;
	for (i = 0; i < 256; i++)
	{
		offset = i / 255.0f;
		while (k + 1 < count && offset > stops[k+1].offset)
			k++;

		d = (offset - stops[k].offset) / (stops[k+1].offset - stops[k].offset);

		shade->function[i][0] = lerp(stops[k].r, stops[k+1].r, d);
		shade->function[i][1] = lerp(stops[k].g, stops[k+1].g, d);
		shade->function[i][2] = lerp(stops[k].b, stops[k+1].b, d);
		shade->function[i][3] = lerp(stops[k].a, stops[k+1].a, d);
	}
}

/*
 * Radial gradients map more or less to Radial shadings.
 * The inner circle is always a point.
 * The outer circle is actually an ellipse,
 * mess with the transform to squash the circle into the right aspect.
 */

static void
xps_draw_one_radial_gradient(xps_context *ctx, fz_matrix ctm,
	struct stop *stops, int count,
	int extend,
	float x0, float y0, float r0,
	float x1, float y1, float r1)
{
	fz_shade *shade;

	/* TODO: this (and the stuff in pdf_shade) should move to res_shade.c */
	shade = fz_malloc(sizeof(fz_shade));
	shade->refs = 1;
	shade->cs = fz_devicergb;
	shade->bbox = fz_infiniterect;
	shade->matrix = fz_identity;
	shade->usebackground = 0;
	shade->usefunction = 1;
	shade->type = FZ_RADIAL;
	shade->extend[0] = extend;
	shade->extend[1] = extend;

	xps_sample_gradient_stops(shade, stops, count);

	shade->meshlen = 6;
	shade->meshcap = 6;
	shade->mesh = fz_calloc(shade->meshcap, sizeof(float));
	shade->mesh[0] = x0;
	shade->mesh[1] = y0;
	shade->mesh[2] = r0;
	shade->mesh[3] = x1;
	shade->mesh[4] = y1;
	shade->mesh[5] = r1;

	ctx->dev->fillshade(ctx->dev->user, shade, ctm, 1);

	fz_dropshade(shade);
}

/*
 * Linear gradients map to Axial shadings.
 */

static void
xps_draw_one_linear_gradient(xps_context *ctx, fz_matrix ctm,
	struct stop *stops, int count,
	int extend,
	float x0, float y0, float x1, float y1)
{
	fz_shade *shade;

	/* TODO: this (and the stuff in pdf_shade) should move to res_shade.c */
	shade = fz_malloc(sizeof(fz_shade));
	shade->refs = 1;
	shade->cs = fz_devicergb;
	shade->bbox = fz_infiniterect;
	shade->matrix = fz_identity;
	shade->usebackground = 0;
	shade->usefunction = 1;
	shade->type = FZ_LINEAR;
	shade->extend[0] = extend;
	shade->extend[1] = extend;

	xps_sample_gradient_stops(shade, stops, count);

	shade->meshlen = 6;
	shade->meshcap = 6;
	shade->mesh = fz_calloc(shade->meshcap, sizeof(float));
	shade->mesh[0] = x0;
	shade->mesh[1] = y0;
	shade->mesh[2] = 0;
	shade->mesh[3] = x1;
	shade->mesh[4] = y1;
	shade->mesh[5] = 0;

	ctx->dev->fillshade(ctx->dev->user, shade, ctm, 1);

	fz_dropshade(shade);
}

/*
 * We need to loop and create many shading objects to account
 * for the Repeat and Reflect SpreadMethods.
 * I'm not smart enough to calculate this analytically
 * so we iterate and check each object until we
 * reach a reasonable limit for infinite cases.
 */

static inline float point_inside_circle(float px, float py, float x, float y, float r)
{
	float dx = px - x;
	float dy = py - y;
	return dx * dx + dy * dy <= r * r;
}

static void
xps_draw_radial_gradient(xps_context *ctx, fz_matrix ctm,
	struct stop *stops, int count,
	xps_item *root, int spread)
{
	fz_rect bbox;
	float x0, y0, r0;
	float x1, y1, r1;
	float xrad = 1;
	float yrad = 1;
	float invscale;
	float dx, dy;
	int i;
	int done;

	char *center_att = xps_att(root, "Center");
	char *origin_att = xps_att(root, "GradientOrigin");
	char *radius_x_att = xps_att(root, "RadiusX");
	char *radius_y_att = xps_att(root, "RadiusY");

	if (origin_att)
		sscanf(origin_att, "%g,%g", &x0, &y0);
	if (center_att)
		sscanf(center_att, "%g,%g", &x1, &y1);
	if (radius_x_att)
		xrad = atof(radius_x_att);
	if (radius_y_att)
		yrad = atof(radius_y_att);

	/* scale the ctm to make ellipses */
	ctm = fz_concat(fz_scale(1.0, yrad / xrad), ctm);

	invscale = xrad / yrad;
	y0 = y0 * invscale;
	y1 = y1 * invscale;

	r0 = 0.0;
	r1 = xrad;

	dx = x1 - x0;
	dy = y1 - y0;

	xps_draw_one_radial_gradient(ctx, ctm, stops, count, 1, x0, y0, r0, x1, y1, r1);

#if 0
	xps_bounds_in_user_space(ctx, &bbox);

	if (spread == SPREAD_PAD)
	{
		if (!point_inside_circle(x0, y0, x1, y1, r1))
		{
			float in[1];
			float out[4];
			float fary[10];
			void *vary[1];

			/* PDF shadings with extend doesn't work the same way as XPS
			 * gradients when the radial shading is a cone. In this case
			 * we fill the background ourselves.
			 */
			in[0] = 1.0;
			out[0] = 1.0;
			out[1] = 0.0;
			out[2] = 0.0;
			out[3] = 0.0;
			if (ctx->opacity_only)
				gs_function_evaluate(func, in, out);
			else
				gs_function_evaluate(func, in, out + 1);

			xps_set_color(ctx, ctx->srgb, out);

			gs_moveto(ctx->pgs, bbox.p.x, bbox.p.y);
			gs_lineto(ctx->pgs, bbox.q.x, bbox.p.y);
			gs_lineto(ctx->pgs, bbox.q.x, bbox.q.y);
			gs_lineto(ctx->pgs, bbox.p.x, bbox.q.y);
			gs_closepath(ctx->pgs);
			gs_fill(ctx->pgs);

			/* We also have to reverse the direction so the bigger circle
			 * comes first or the graphical results do not match. We also
			 * have to reverse the direction of the function to compensate.
			 */

//			reverse = xps_reverse_function(ctx, func, fary, vary);
//			xps_draw_one_radial_gradient(ctx, reverse, 1, x1, y1, r1, x0, y0, r0);
			xps_draw_one_radial_gradient(ctx, ctm, stops, count,
				1, x1, y1, r1, x0, y0, r0);
		}
		else
		{
			xps_draw_one_radial_gradient(ctx, ctm, stops, count,
				1, x0, y0, r0, x1, y1, r1);
		}
	}
	else
	{
		for (i = 0; i < 2; i++)
		{
			/* Draw current circle */

			if (!point_inside_circle(x0, y0, x1, y1, r1))
				printf("xps: we should reverse gradient here too\n");

			if (spread == SPREAD_REFLECT && (i & 1))
				xps_draw_one_radial_gradient(ctx, ctm, stops, count,
					0, x1, y1, r1, x0, y0, r0);
			else
				xps_draw_one_radial_gradient(ctx, ctm, stops, count,
					0, x0, y0, r0, x1, y1, r1);

			/* Check if circle encompassed the entire bounding box (break loop if we do) */
			done = 1;
			if (!point_inside_circle(bbox.x0, bbox.y0, x1, y1, r1)) done = 0;
			if (!point_inside_circle(bbox.x0, bbox.y1, x1, y1, r1)) done = 0;
			if (!point_inside_circle(bbox.x1, bbox.y1, x1, y1, r1)) done = 0;
			if (!point_inside_circle(bbox.x1, bbox.y0, x1, y1, r1)) done = 0;
			if (done)
				break;

			/* Prepare next circle */

			r0 = r1;
			r1 += xrad;

			x0 += dx;
			y0 += dy;
			x1 += dx;
			y1 += dy;
		}
	}
#endif
}

/*
 * Calculate how many iterations are needed to cover
 * the bounding box.
 */

static void
xps_draw_linear_gradient(xps_context *ctx, fz_matrix ctm,
	struct stop *stops, int count,
	xps_item *root, int spread)
{
	fz_rect bbox;
	float x0, y0, x1, y1;
	float dx, dy;
	int i;

	char *start_point_att = xps_att(root, "StartPoint");
	char *end_point_att = xps_att(root, "EndPoint");

	x0 = 0;
	y0 = 0;
	x1 = 0;
	y1 = 1;

	if (start_point_att)
		sscanf(start_point_att, "%g,%g", &x0, &y0);
	if (end_point_att)
		sscanf(end_point_att, "%g,%g", &x1, &y1);

	dx = x1 - x0;
	dy = y1 - y0;

	xps_draw_one_linear_gradient(ctx, ctm, stops, count, 1, x0, y0, x1, y1);

#if 0
	xps_bounds_in_user_space(ctx, &bbox);

	if (spread == SPREAD_PAD)
	{
		xps_draw_one_linear_gradient(ctx, ctm, stops, count, 1, x0, y0, x1, y1);
	}
	else
	{
		float len;
		float a, b;
		float dist[4];
		float d0, d1;
		int i0, i1;

		len = sqrt(dx * dx + dy * dy);
		a = dx / len;
		b = dy / len;

		dist[0] = a * (bbox.x0 - x0) + b * (bbox.y0 - y0);
		dist[1] = a * (bbox.x0 - x0) + b * (bbox.y1 - y0);
		dist[2] = a * (bbox.x1 - x0) + b * (bbox.y1 - y0);
		dist[3] = a * (bbox.x1 - x0) + b * (bbox.y0 - y0);

		d0 = dist[0];
		d1 = dist[0];
		for (i = 1; i < 4; i++)
		{
			if (dist[i] < d0) d0 = dist[i];
			if (dist[i] > d1) d1 = dist[i];
		}

		i0 = floor(d0 / len);
		i1 = ceil(d1 / len);

		for (i = i0; i < i1; i++)
		{
			if (spread == SPREAD_REFLECT && (i & 1))
				xps_draw_one_linear_gradient(ctx, ctm, stops, count, 0,
						x1 + dx * i, y1 + dy * i,
						x0 + dx * i, y0 + dy * i);
			else
				xps_draw_one_linear_gradient(ctx, ctm, stops, count, 0,
						x0 + dx * i, y0 + dy * i,
						x1 + dx * i, y1 + dy * i);
		}
	}
#endif
}

/*
 * Parse XML tag and attributes for a gradient brush, create color/opacity
 * function objects and call gradient drawing primitives.
 */

static void
xps_parse_gradient_brush(xps_context *ctx, fz_matrix ctm,
	char *base_uri, xps_resource *dict, xps_item *root,
	void (*draw)(xps_context *, fz_matrix, struct stop *, int, xps_item *, int))
{
	xps_item *node;

	char *opacity_att;
	char *interpolation_att;
	char *spread_att;
	char *mapping_att;
	char *transform_att;

	xps_item *transform_tag = NULL;
	xps_item *stop_tag = NULL;

	struct stop stop_list[MAX_STOPS];
	int stop_count;
	fz_matrix transform;
	int spread_method;

	fz_rect bbox;

	opacity_att = xps_att(root, "Opacity");
	interpolation_att = xps_att(root, "ColorInterpolationMode");
	spread_att = xps_att(root, "SpreadMethod");
	mapping_att = xps_att(root, "MappingMode");
	transform_att = xps_att(root, "Transform");

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "LinearGradientBrush.Transform"))
			transform_tag = xps_down(node);
		if (!strcmp(xps_tag(node), "RadialGradientBrush.Transform"))
			transform_tag = xps_down(node);
		if (!strcmp(xps_tag(node), "LinearGradientBrush.GradientStops"))
			stop_tag = xps_down(node);
		if (!strcmp(xps_tag(node), "RadialGradientBrush.GradientStops"))
			stop_tag = xps_down(node);
	}

	xps_resolve_resource_reference(ctx, dict, &transform_att, &transform_tag, NULL);

	spread_method = SPREAD_PAD;
	if (spread_att)
	{
		if (!strcmp(spread_att, "Pad"))
			spread_method = SPREAD_PAD;
		if (!strcmp(spread_att, "Reflect"))
			spread_method = SPREAD_REFLECT;
		if (!strcmp(spread_att, "Repeat"))
			spread_method = SPREAD_REPEAT;
	}

	transform = fz_identity;
	if (transform_att)
		xps_parse_render_transform(ctx, transform_att, &transform);
	if (transform_tag)
		xps_parse_matrix_transform(ctx, transform_tag, &transform);
	ctm = fz_concat(transform, ctm);

	if (!stop_tag) {
		fz_warn("missing gradient stops tag");
		return;
	}

	stop_count = xps_parse_gradient_stops(ctx, base_uri, stop_tag, stop_list, MAX_STOPS);
	if (stop_count == 0)
	{
		fz_warn("no gradient stops found");
		return;
	}

	xps_bounds_in_user_space(ctx, &bbox);

	xps_begin_opacity(ctx, ctm, base_uri, dict, opacity_att, NULL);

	draw(ctx, ctm, stop_list, stop_count, root, spread_method);

	xps_end_opacity(ctx, base_uri, dict, opacity_att, NULL);
}

void
xps_parse_linear_gradient_brush(xps_context *ctx, fz_matrix ctm,
	char *base_uri, xps_resource *dict, xps_item *root)
{
	xps_parse_gradient_brush(ctx, ctm, base_uri, dict, root, xps_draw_linear_gradient);
}

void
xps_parse_radial_gradient_brush(xps_context *ctx, fz_matrix ctm,
	char *base_uri, xps_resource *dict, xps_item *root)
{
	xps_parse_gradient_brush(ctx, ctm, base_uri, dict, root, xps_draw_radial_gradient);
}
