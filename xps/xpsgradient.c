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

/* XPS interpreter - gradient support */

#include "ghostxps.h"

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
	float color[4];
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
xps_parse_gradient_stops(xps_context_t *ctx, char *base_uri, xps_item_t *node,
	struct stop *stops, int maxcount)
{
	unsigned short sample_in[8], sample_out[8]; /* XPS allows up to 8 bands */
	gsicc_rendering_param_t rendering_params;
	gsicc_link_t *icclink;
	gs_color_space *colorspace;
	float sample[8];
	int before, after;
	int count;
	int i, k;

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

				/* Set the rendering parameters */
				rendering_params.black_point_comp = BP_ON;
				rendering_params.object_type = GS_PATH_TAG;
				rendering_params.rendering_intent = gsPERCEPTUAL;

				/* Get link to map from source to sRGB */
				icclink = gsicc_get_link((gs_imager_state*) ctx->pgs,
										 NULL, colorspace, ctx->srgb,
										 &rendering_params, ctx->memory, false);

				if (icclink != NULL && !icclink->is_identity)
				{
					/* Transform the color */
					int num_colors = gsicc_getsrc_channel_count(colorspace->cmm_icc_profile_data);
					for (i = 0; i < num_colors; i++)
					{
						sample_in[i] = sample[i+1]*65535;
					}
					gscms_transform_color(icclink, sample_in, sample_out, 2, NULL);

					stops[count].color[0] = sample[0]; /* Alpha */
					stops[count].color[1] = (float) sample_out[0] / 65535.0; /* sRGB */
					stops[count].color[2] = (float) sample_out[1] / 65535.0;
					stops[count].color[3] = (float) sample_out[2] / 65535.0;
				}
				else
				{
					stops[count].color[0] = sample[0];
					stops[count].color[1] = sample[1];
					stops[count].color[2] = sample[2];
					stops[count].color[3] = sample[3];
				}

				count ++;
			}
		}

		if (icclink != NULL)
			gsicc_release_link(icclink);
		icclink = NULL;
		node = xps_next(node);

	}

	if (count == 0)
	{
		gs_warn("gradient brush has no gradient stops");
		stops[0].offset = 0;
		stops[0].color[0] = 1;
		stops[0].color[1] = 0;
		stops[0].color[2] = 0;
		stops[0].color[3] = 0;
		stops[1].offset = 1;
		stops[1].color[0] = 1;
		stops[1].color[1] = 1;
		stops[1].color[2] = 1;
		stops[1].color[3] = 1;
		return 2;
	}

	if (count == maxcount)
		gs_warn("gradient brush exceeded maximum number of gradient stops");

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
		for (k = 0; k < 4; k++)
			stops[0].color[k] = lerp(stops[0].color[k], stops[1].color[k], d);
	}

	/* Last stop > 1 -- interpolate value to 1 */
	if (stops[count-1].offset > 1)
	{
		float d = (1 - stops[count-2].offset) / (stops[count-1].offset - stops[count-2].offset);
		stops[count-1].offset = 1;
		for (k = 0; k < 4; k++)
			stops[count-1].color[k] = lerp(stops[count-2].color[k], stops[count-1].color[k], d);
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

static int
xps_gradient_has_transparent_colors(struct stop *stops, int count)
{
	int i;
	for (i = 0; i < count; i++)
		if (stops[i].color[0] < 1)
			return 1;
	return 0;
}

/*
 * Create a Function object to map [0..1] to RGB colors
 * based on the gradient stop arrays.
 *
 * We do this by creating a stitching function that joins
 * a series of linear functions (one linear function
 * for each gradient stop-pair).
 */

static gs_function_t *
xps_create_gradient_stop_function(xps_context_t *ctx, struct stop *stops, int count, int opacity_only)
{
	gs_function_1ItSg_params_t sparams;
	gs_function_ElIn_params_t lparams;
	gs_function_t *sfunc;
	gs_function_t *lfunc;

	float *domain, *range, *c0, *c1, *bounds, *encode;
	const gs_function_t **functions;

	int code;
	int k;
	int i;

	k = count - 1; /* number of intervals / functions */

	domain = xps_alloc(ctx, 2 * sizeof(float));
	domain[0] = 0.0;
	domain[1] = 1.0;
	sparams.m = 1;
	sparams.Domain = domain;

	range = xps_alloc(ctx, 6 * sizeof(float));
	range[0] = 0.0;
	range[1] = 1.0;
	range[2] = 0.0;
	range[3] = 1.0;
	range[4] = 0.0;
	range[5] = 1.0;
	sparams.n = 3;
	sparams.Range = range;

	functions = xps_alloc(ctx, k * sizeof(void*));
	bounds = xps_alloc(ctx, (k - 1) * sizeof(float));
	encode = xps_alloc(ctx, (k * 2) * sizeof(float));

	sparams.k = k;
	sparams.Functions = functions;
	sparams.Bounds = bounds;
	sparams.Encode = encode;

	for (i = 0; i < k; i++)
	{
		domain = xps_alloc(ctx, 2 * sizeof(float));
		domain[0] = 0.0;
		domain[1] = 1.0;
		lparams.m = 1;
		lparams.Domain = domain;

		range = xps_alloc(ctx, 6 * sizeof(float));
		range[0] = 0.0;
		range[1] = 1.0;
		range[2] = 0.0;
		range[3] = 1.0;
		range[4] = 0.0;
		range[5] = 1.0;
		lparams.n = 3;
		lparams.Range = range;

		c0 = xps_alloc(ctx, 3 * sizeof(float));
		lparams.C0 = c0;

		c1 = xps_alloc(ctx, 3 * sizeof(float));
		lparams.C1 = c1;

		if (opacity_only)
		{
			c0[0] = stops[i].color[0];
			c0[1] = stops[i].color[0];
			c0[2] = stops[i].color[0];

			c1[0] = stops[i+1].color[0];
			c1[1] = stops[i+1].color[0];
			c1[2] = stops[i+1].color[0];
		}
		else
		{
			c0[0] = stops[i].color[1];
			c0[1] = stops[i].color[2];
			c0[2] = stops[i].color[3];

			c1[0] = stops[i+1].color[1];
			c1[1] = stops[i+1].color[2];
			c1[2] = stops[i+1].color[3];
		}

		lparams.N = 1;

		code = gs_function_ElIn_init(&lfunc, &lparams, ctx->memory);
		if (code < 0)
		{
			gs_rethrow(code, "gs_function_ElIn_init failed");
			return NULL;
		}

		functions[i] = lfunc;

		if (i > 0)
			bounds[i - 1] = stops[i].offset;

		encode[i * 2 + 0] = 0.0;
		encode[i * 2 + 1] = 1.0;
	}

	code = gs_function_1ItSg_init(&sfunc, &sparams, ctx->memory);
	if (code < 0)
	{
		gs_rethrow(code, "gs_function_1ItSg_init failed");
		return NULL;
	}

	return sfunc;
}

/*
 * Shadings and functions are ghostscript type objects,
 * and as such rely on the garbage collector for cleanup.
 * We can't have none of that here, so we have to
 * write our own destructors.
 */

static void
xps_free_gradient_stop_function(xps_context_t *ctx, gs_function_t *func)
{
	gs_function_t *lfunc;
	gs_function_1ItSg_params_t *sparams;
	gs_function_ElIn_params_t *lparams;
	int i;

	sparams = (gs_function_1ItSg_params_t*) &func->params;
	xps_free(ctx, (void*)sparams->Domain);
	xps_free(ctx, (void*)sparams->Range);

	for (i = 0; i < sparams->k; i++)
	{
		lfunc = (gs_function_t*) sparams->Functions[i]; /* discard const */
		lparams = (gs_function_ElIn_params_t*) &lfunc->params;
		xps_free(ctx, (void*)lparams->Domain);
		xps_free(ctx, (void*)lparams->Range);
		xps_free(ctx, (void*)lparams->C0);
		xps_free(ctx, (void*)lparams->C1);
		xps_free(ctx, lfunc);
	}

	xps_free(ctx, (void*)sparams->Bounds);
	xps_free(ctx, (void*)sparams->Encode);
	xps_free(ctx, (void*)sparams->Functions);
	xps_free(ctx, func);
}

/*
 * For radial gradients that have a cone drawing we have to
 * reverse the direction of the gradient because we draw
 * the shading in the opposite direction with the
 * big circle first.
 */
static gs_function_t *
xps_reverse_function(xps_context_t *ctx, gs_function_t *func, float *fary, void *vary)
{
	gs_function_1ItSg_params_t sparams;
	gs_function_t *sfunc;
	int code;

	/* take from stack allocated arrays that the caller provides */
	float *domain = fary + 0;
	float *range = fary + 2;
	float *encode = fary + 2 + 6;
	const gs_function_t **functions = vary;

	domain[0] = 0.0;
	domain[1] = 1.0;

	range[0] = 0.0;
	range[1] = 1.0;
	range[2] = 0.0;
	range[3] = 1.0;
	range[4] = 0.0;
	range[5] = 1.0;

	functions[0] = func;

	encode[0] = 1.0;
	encode[1] = 0.0;

	sparams.m = 1;
	sparams.Domain = domain;
	sparams.n = 3;
	sparams.Range = range;
	sparams.k = 1;
	sparams.Functions = functions;
	sparams.Bounds = NULL;
	sparams.Encode = encode;

	code = gs_function_1ItSg_init(&sfunc, &sparams, ctx->memory);
	if (code < 0)
	{
		gs_rethrow(code, "gs_function_1ItSg_init failed");
		return NULL;
	}

	return sfunc;
}

/*
 * Radial gradients map more or less to Radial shadings.
 * The inner circle is always a point.
 * The outer circle is actually an ellipse,
 * mess with the transform to squash the circle into the right aspect.
 */

static int
xps_draw_one_radial_gradient(xps_context_t *ctx,
		gs_function_t *func, int extend,
		float x0, float y0, float r0,
		float x1, float y1, float r1)
{
	gs_memory_t *mem = ctx->memory;
	gs_shading_t *shading;
	gs_shading_R_params_t params;
	int code;

	gs_shading_R_params_init(&params);
	{
		params.ColorSpace = ctx->srgb;

		params.Coords[0] = x0;
		params.Coords[1] = y0;
		params.Coords[2] = r0;
		params.Coords[3] = x1;
		params.Coords[4] = y1;
		params.Coords[5] = r1;

		params.Extend[0] = extend;
		params.Extend[1] = extend;

		params.Function = func;
	}

	code = gs_shading_R_init(&shading, &params, mem);
	if (code < 0)
		return gs_rethrow(code, "gs_shading_R_init failed");

	gs_setsmoothness(ctx->pgs, 0.02);

	code = gs_shfill(ctx->pgs, shading);
	if (code < 0)
	{
		gs_free_object(mem, shading, "gs_shading_R");
		return gs_rethrow(code, "gs_shfill failed");
	}

	gs_free_object(mem, shading, "gs_shading_R");

	return 0;
}

/*
 * Linear gradients map to Axial shadings.
 */

static int
xps_draw_one_linear_gradient(xps_context_t *ctx,
		gs_function_t *func, int extend,
		float x0, float y0, float x1, float y1)
{
	gs_memory_t *mem = ctx->memory;
	gs_shading_t *shading;
	gs_shading_A_params_t params;
	int code;

	gs_shading_A_params_init(&params);
	{
		params.ColorSpace = ctx->srgb;

		params.Coords[0] = x0;
		params.Coords[1] = y0;
		params.Coords[2] = x1;
		params.Coords[3] = y1;

		params.Extend[0] = extend;
		params.Extend[1] = extend;

		params.Function = func;
	}

	code = gs_shading_A_init(&shading, &params, mem);
	if (code < 0)
		return gs_rethrow(code, "gs_shading_A_init failed");

	gs_setsmoothness(ctx->pgs, 0.02);

	code = gs_shfill(ctx->pgs, shading);
	if (code < 0)
	{
		gs_free_object(mem, shading, "gs_shading_A");
		return gs_rethrow(code, "gs_shfill failed");
	}

	gs_free_object(mem, shading, "gs_shading_A");

	return 0;
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
	return (dx * dx + dy * dy) <= (r * r);
}

static int
xps_draw_radial_gradient(xps_context_t *ctx, xps_item_t *root, int spread, gs_function_t *func)
{
	gs_rect bbox;
	float x0, y0, r0;
	float x1, y1, r1;
	float xrad = 1;
	float yrad = 1;
	float invscale;
	float dx, dy;
	int code;
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
	gs_gsave(ctx->pgs);
	gs_scale(ctx->pgs, 1.0, yrad / xrad);

	invscale = xrad / yrad;
	y0 = y0 * invscale;
	y1 = y1 * invscale;

	r0 = 0.0;
	r1 = xrad;

	dx = x1 - x0;
	dy = y1 - y0;

	xps_bounds_in_user_space(ctx, &bbox);

	if (spread == SPREAD_PAD)
	{
		if (!point_inside_circle(x0, y0, x1, y1, r1))
		{
			gs_function_t *reverse;
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

			reverse = xps_reverse_function(ctx, func, fary, vary);
			if (!reverse)
			{
				gs_grestore(ctx->pgs);
				return gs_rethrow(-1, "could not create the reversed function");
			}

			code = xps_draw_one_radial_gradient(ctx, reverse, 1, x1, y1, r1, x0, y0, r0);
			if (code < 0)
			{
				xps_free(ctx, reverse);
				gs_grestore(ctx->pgs);
				return gs_rethrow(code, "could not draw radial gradient");
			}

			xps_free(ctx, reverse);
		}
		else
		{
			code = xps_draw_one_radial_gradient(ctx, func, 1, x0, y0, r0, x1, y1, r1);
			if (code < 0)
			{
				gs_grestore(ctx->pgs);
				return gs_rethrow(code, "could not draw radial gradient");
			}
		}
	}
	else
	{
		for (i = 0; i < 100; i++)
		{
			/* Draw current circle */

			if (!point_inside_circle(x0, y0, x1, y1, r1))
				dputs("xps: we should reverse gradient here too\n");

			if (spread == SPREAD_REFLECT && (i & 1))
				code = xps_draw_one_radial_gradient(ctx, func, 0, x1, y1, r1, x0, y0, r0);
			else
				code = xps_draw_one_radial_gradient(ctx, func, 0, x0, y0, r0, x1, y1, r1);
			if (code < 0)
			{
				gs_grestore(ctx->pgs);
				return gs_rethrow(code, "could not draw axial gradient");
			}

			/* Check if circle encompassed the entire bounding box (break loop if we do) */

			done = 1;
			if (!point_inside_circle(bbox.p.x, bbox.p.y, x1, y1, r1)) done = 0;
			if (!point_inside_circle(bbox.p.x, bbox.q.y, x1, y1, r1)) done = 0;
			if (!point_inside_circle(bbox.q.x, bbox.q.y, x1, y1, r1)) done = 0;
			if (!point_inside_circle(bbox.q.x, bbox.p.y, x1, y1, r1)) done = 0;
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

	gs_grestore(ctx->pgs);

	return 0;
}

/*
 * Calculate how many iterations are needed to cover
 * the bounding box.
 */

static int
xps_draw_linear_gradient(xps_context_t *ctx, xps_item_t *root, int spread, gs_function_t *func)
{
	gs_rect bbox;
	float x0, y0, x1, y1;
	float dx, dy;
	int code;
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

	xps_bounds_in_user_space(ctx, &bbox);

	if (spread == SPREAD_PAD)
	{
		code = xps_draw_one_linear_gradient(ctx, func, 1, x0, y0, x1, y1);
		if (code < 0)
			return gs_rethrow(code, "could not draw axial gradient");
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

		dist[0] = a * (bbox.p.x - x0) + b * (bbox.p.y - y0);
		dist[1] = a * (bbox.p.x - x0) + b * (bbox.q.y - y0);
		dist[2] = a * (bbox.q.x - x0) + b * (bbox.q.y - y0);
		dist[3] = a * (bbox.q.x - x0) + b * (bbox.p.y - y0);

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
			{
				code = xps_draw_one_linear_gradient(ctx, func, 0,
						x1 + dx * i, y1 + dy * i,
						x0 + dx * i, y0 + dy * i);
			}
			else
			{
				code = xps_draw_one_linear_gradient(ctx, func, 0,
						x0 + dx * i, y0 + dy * i,
						x1 + dx * i, y1 + dy * i);
			}
			if (code < 0)
				return gs_rethrow(code, "could not draw axial gradient");
		}
	}

	return 0;
}

/*
 * Parse XML tag and attributes for a gradient brush, create color/opacity
 * function objects and call gradient drawing primitives.
 */

static int
xps_parse_gradient_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root,
		int (*draw)(xps_context_t *, xps_item_t *, int, gs_function_t *))
{
	xps_item_t *node;

	char *opacity_att;
	char *interpolation_att;
	char *spread_att;
	char *mapping_att;
	char *transform_att;

	xps_item_t *transform_tag = NULL;
	xps_item_t *stop_tag = NULL;

	struct stop stop_list[MAX_STOPS];
	int stop_count;
	gs_matrix transform;
	int spread_method;
	int code;

	gs_rect bbox;

	gs_function_t *color_func;
	gs_function_t *opacity_func;
	int has_opacity = 0;

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

	gs_make_identity(&transform);
	if (transform_att)
		xps_parse_render_transform(ctx, transform_att, &transform);
	if (transform_tag)
		xps_parse_matrix_transform(ctx, transform_tag, &transform);

	if (!stop_tag)
		return gs_throw(-1, "missing gradient stops tag");

	stop_count = xps_parse_gradient_stops(ctx, base_uri, stop_tag, stop_list, MAX_STOPS);
	if (stop_count == 0)
		return gs_throw(-1, "no gradient stops found");

	color_func = xps_create_gradient_stop_function(ctx, stop_list, stop_count, 0);
	if (!color_func)
		return gs_rethrow(-1, "could not create color gradient function");

	opacity_func = xps_create_gradient_stop_function(ctx, stop_list, stop_count, 1);
	if (!opacity_func)
		return gs_rethrow(-1, "could not create opacity gradient function");

	has_opacity = xps_gradient_has_transparent_colors(stop_list, stop_count);

	xps_clip(ctx);

	gs_gsave(ctx->pgs);
	gs_concat(ctx->pgs, &transform);

	xps_bounds_in_user_space(ctx, &bbox);

	code = xps_begin_opacity(ctx, base_uri, dict, opacity_att, NULL);
	if (code)
	{
		gs_grestore(ctx->pgs);
		return gs_rethrow(code, "cannot create transparency group");
	}

	if (ctx->opacity_only)
	{
		code = draw(ctx, root, spread_method, opacity_func);
		if (code)
		{
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot draw gradient opacity");
		}
	}
	else
	{
		if (has_opacity)
		{
			gs_transparency_mask_params_t params;
			gs_transparency_group_params_t tgp;

			gs_trans_mask_params_init(&params, TRANSPARENCY_MASK_Luminosity);
			gs_begin_transparency_mask(ctx->pgs, &params, &bbox, 0);
			code = draw(ctx, root, spread_method, opacity_func);
			if (code)
			{
				gs_end_transparency_mask(ctx->pgs, TRANSPARENCY_CHANNEL_Opacity);
				gs_grestore(ctx->pgs);
				return gs_rethrow(code, "cannot draw gradient opacity");
			}
			gs_end_transparency_mask(ctx->pgs, TRANSPARENCY_CHANNEL_Opacity);

			gs_trans_group_params_init(&tgp);
			gs_begin_transparency_group(ctx->pgs, &tgp, &bbox);
			code = draw(ctx, root, spread_method, color_func);
			if (code)
			{
				gs_end_transparency_group(ctx->pgs);
				gs_grestore(ctx->pgs);
				return gs_rethrow(code, "cannot draw gradient color");
			}
			gs_end_transparency_group(ctx->pgs);
		}
		else
		{
			code = draw(ctx, root, spread_method, color_func);
			if (code)
			{
				gs_grestore(ctx->pgs);
				return gs_rethrow(code, "cannot draw gradient color");
			}
		}
	}

	xps_end_opacity(ctx, base_uri, dict, opacity_att, NULL);

	gs_grestore(ctx->pgs);

	xps_free_gradient_stop_function(ctx, opacity_func);
	xps_free_gradient_stop_function(ctx, color_func);

	return 0;
}

int
xps_parse_linear_gradient_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root)
{
	int code;
	code = xps_parse_gradient_brush(ctx, base_uri, dict, root, xps_draw_linear_gradient);
	if (code < 0)
		return gs_rethrow(code, "cannot parse linear gradient brush");
	return gs_okay;
}

int
xps_parse_radial_gradient_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root)
{
	int code;
	code = xps_parse_gradient_brush(ctx, base_uri, dict, root, xps_draw_radial_gradient);
	if (code < 0)
		return gs_rethrow(code, "cannot parse radial gradient brush");
	return gs_okay;
}
