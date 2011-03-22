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

/* XPS interpreter - path (vector drawing) support */

#include "ghostxps.h"

void
xps_clip(xps_context_t *ctx)
{
	if (ctx->fill_rule == 0)
		gs_eoclip(ctx->pgs);
	else
		gs_clip(ctx->pgs);
	gs_newpath(ctx->pgs);
}

void
xps_fill(xps_context_t *ctx)
{
	if (gs_currentopacityalpha(ctx->pgs) < 0.001)
		gs_newpath(ctx->pgs);
	else if (ctx->fill_rule == 0) {
		if (gs_eofill(ctx->pgs) == gs_error_Remap_Color)
			xps_high_level_pattern(ctx);
		gs_eofill(ctx->pgs);
	}
	else {
		if (gs_fill(ctx->pgs) == gs_error_Remap_Color)
			xps_high_level_pattern(ctx);
		gs_fill(ctx->pgs);
	}
}

/* Draw an arc segment transformed by the matrix, we approximate with straight
 * line segments. We cannot use the gs_arc function because they only draw
 * circular arcs, we need to transform the line to make them elliptical but
 * without transforming the line width.
 */
static inline void
xps_draw_arc_segment(xps_context_t *ctx, gs_matrix *mtx, float th0, float th1, int iscw)
{
	float t, d;
	gs_point p;

	while (th1 < th0)
		th1 += M_PI * 2.0;

	d = 1 * (M_PI / 180.0); /* 1-degree precision */

	if (iscw)
	{
		gs_point_transform(cos(th0), sin(th0), mtx, &p);
		gs_lineto(ctx->pgs, p.x, p.y);
		for (t = th0; t < th1; t += d)
		{
			gs_point_transform(cos(t), sin(t), mtx, &p);
			gs_lineto(ctx->pgs, p.x, p.y);
		}
		gs_point_transform(cos(th1), sin(th1), mtx, &p);
		gs_lineto(ctx->pgs, p.x, p.y);
	}
	else
	{
		th0 += M_PI * 2;
		gs_point_transform(cos(th0), sin(th0), mtx, &p);
		gs_lineto(ctx->pgs, p.x, p.y);
		for (t = th0; t > th1; t -= d)
		{
			gs_point_transform(cos(t), sin(t), mtx, &p);
			gs_lineto(ctx->pgs, p.x, p.y);
		}
		gs_point_transform(cos(th1), sin(th1), mtx, &p);
		gs_lineto(ctx->pgs, p.x, p.y);
	}
}

/* Given two vectors find the angle between them. */
static inline double
angle_between(const gs_point u, const gs_point v)
{
	double det = u.x * v.y - u.y * v.x;
	double sign = (det < 0 ? -1.0 : 1.0);
	double magu = u.x * u.x + u.y * u.y;
	double magv = v.x * v.x + v.y * v.y;
	double udotv = u.x * v.x + u.y * v.y;
	double t = udotv / (magu * magv);
	/* guard against rounding errors when near |1| (where acos will return NaN) */
	if (t < -1.0) t = -1.0;
	if (t > 1.0) t = 1.0;
	return sign * acos(t);
}

static void
xps_draw_arc(xps_context_t *ctx,
		float size_x, float size_y, float rotation_angle,
		int is_large_arc, int is_clockwise,
		float point_x, float point_y)
{
	gs_matrix rotmat, revmat;
	gs_matrix mtx;
	gs_point pt;
	double rx, ry;
	double x1, y1, x2, y2;
	double x1t, y1t;
	double cxt, cyt, cx, cy;
	double t1, t2, t3;
	double sign;
	double th1, dth;

	gs_currentpoint(ctx->pgs, &pt);
	x1 = pt.x;
	y1 = pt.y;
	x2 = point_x;
	y2 = point_y;
	rx = size_x;
	ry = size_y;

	if (is_clockwise != is_large_arc)
		sign = 1;
	else
		sign = -1;

	gs_make_rotation(rotation_angle, &rotmat);
	gs_make_rotation(-rotation_angle, &revmat);

	/* http://www.w3.org/TR/SVG11/implnote.html#ArcImplementationNotes */
	/* Conversion from endpoint to center parameterization */

	/* F.6.6.1 -- ensure radii are positive and non-zero */
	rx = fabsf(rx);
	ry = fabsf(ry);
	if (rx < 0.001 || ry < 0.001)
	{
		gs_lineto(ctx->pgs, x2, y2);
		return;
	}

	/* F.6.5.1 */
	gs_distance_transform((x1 - x2) / 2.0, (y1 - y2) / 2.0, &revmat, &pt);
	x1t = pt.x;
	y1t = pt.y;

	/* F.6.6.2 -- ensure radii are large enough */
	t1 = (x1t * x1t) / (rx * rx) + (y1t * y1t) / (ry * ry);
	if (t1 > 1.0)
	{
		rx = rx * sqrtf(t1);
		ry = ry * sqrtf(t1);
	}

	/* F.6.5.2 */
	t1 = (rx * rx * ry * ry) - (rx * rx * y1t * y1t) - (ry * ry * x1t * x1t);
	t2 = (rx * rx * y1t * y1t) + (ry * ry * x1t * x1t);
	t3 = t1 / t2;
	/* guard against rounding errors; sqrt of negative numbers is bad for your health */
	if (t3 < 0.0) t3 = 0.0;
	t3 = sqrtf(t3);

	cxt = sign * t3 * (rx * y1t) / ry;
	cyt = sign * t3 * -(ry * x1t) / rx;

	/* F.6.5.3 */
	gs_distance_transform(cxt, cyt, &rotmat, &pt);
	cx = pt.x + (x1 + x2) / 2;
	cy = pt.y + (y1 + y2) / 2;

	/* F.6.5.4 */
	{
		gs_point coord1, coord2, coord3, coord4;
		coord1.x = 1;
		coord1.y = 0;
		coord2.x = (x1t - cxt) / rx;
		coord2.y = (y1t - cyt) / ry;
		coord3.x = (x1t - cxt) / rx;
		coord3.y = (y1t - cyt) / ry;
		coord4.x = (-x1t - cxt) / rx;
		coord4.y = (-y1t - cyt) / ry;
		th1 = angle_between(coord1, coord2);
		dth = angle_between(coord3, coord4);
		if (dth < 0 && !is_clockwise)
			dth += (degrees_to_radians * 360);
		if (dth > 0 && is_clockwise)
			dth -= (degrees_to_radians * 360);
	}

	gs_make_identity(&mtx);
	gs_matrix_translate(&mtx, cx, cy, &mtx);
	gs_matrix_rotate(&mtx, rotation_angle, &mtx);
	gs_matrix_scale(&mtx, rx, ry, &mtx);
	xps_draw_arc_segment(ctx, &mtx, th1, th1 + dth, is_clockwise);

	gs_lineto(ctx->pgs, point_x, point_y);
}

/*
 * Parse an abbreviated geometry string, and call
 * ghostscript moveto/lineto/curveto functions to
 * build up a path.
 */

void
xps_parse_abbreviated_geometry(xps_context_t *ctx, char *geom)
{
	char **args;
	char **pargs;
	char *s = geom;
	gs_point pt;
	int i, n;
	int cmd, old;
	float x1, y1, x2, y2, x3, y3;
	float smooth_x, smooth_y; /* saved cubic bezier control point for smooth curves */
	int reset_smooth;

	args = xps_alloc(ctx, sizeof(char*) * (strlen(geom) + 1));
	pargs = args;

	//dprintf1("new path (%.70s)\n", geom);
	gs_newpath(ctx->pgs);

	while (*s)
	{
		if ((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z'))
		{
			*pargs++ = s++;
		}
		else if ((*s >= '0' && *s <= '9') || *s == '.' || *s == '+' || *s == '-' || *s == 'e' || *s == 'E')
		{
			*pargs++ = s;
			while ((*s >= '0' && *s <= '9') || *s == '.' || *s == '+' || *s == '-' || *s == 'e' || *s == 'E')
				s ++;
		}
		else
		{
			s++;
		}
	}

	pargs[0] = s;
	pargs[1] = 0;

	n = pargs - args;
	i = 0;

	old = 0;

	reset_smooth = 1;
	smooth_x = 0.0;
	smooth_y = 0.0;

	while (i < n)
	{
		cmd = args[i][0];
		if (cmd == '+' || cmd == '.' || cmd == '-' || (cmd >= '0' && cmd <= '9'))
			cmd = old; /* it's a number, repeat old command */
		else
			i ++;

		if (reset_smooth)
		{
			smooth_x = 0.0;
			smooth_y = 0.0;
		}

		reset_smooth = 1;

		switch (cmd)
		{
		case 'F':
			ctx->fill_rule = atoi(args[i]);
			i ++;
			break;

		case 'M':
			gs_moveto(ctx->pgs, atof(args[i]), atof(args[i+1]));
			//dprintf2("moveto %g %g\n", atof(args[i]), atof(args[i+1]));
			i += 2;
			break;
		case 'm':
			gs_rmoveto(ctx->pgs, atof(args[i]), atof(args[i+1]));
			//dprintf2("rmoveto %g %g\n", atof(args[i]), atof(args[i+1]));
			i += 2;
			break;

		case 'L':
			gs_lineto(ctx->pgs, atof(args[i]), atof(args[i+1]));
			//dprintf2("lineto %g %g\n", atof(args[i]), atof(args[i+1]));
			i += 2;
			break;
		case 'l':
			gs_rlineto(ctx->pgs, atof(args[i]), atof(args[i+1]));
			//dprintf2("rlineto %g %g\n", atof(args[i]), atof(args[i+1]));
			i += 2;
			break;

		case 'H':
			gs_currentpoint(ctx->pgs, &pt);
			gs_lineto(ctx->pgs, atof(args[i]), pt.y);
			//dprintf1("hlineto %g\n", atof(args[i]));
			i += 1;
			break;
		case 'h':
			gs_rlineto(ctx->pgs, atof(args[i]), 0.0);
			//dprintf1("rhlineto %g\n", atof(args[i]));
			i += 1;
			break;

		case 'V':
			gs_currentpoint(ctx->pgs, &pt);
			gs_lineto(ctx->pgs, pt.x, atof(args[i]));
			//dprintf1("vlineto %g\n", atof(args[i]));
			i += 1;
			break;
		case 'v':
			gs_rlineto(ctx->pgs, 0.0, atof(args[i]));
			//dprintf1("rvlineto %g\n", atof(args[i]));
			i += 1;
			break;

		case 'C':
			x1 = atof(args[i+0]);
			y1 = atof(args[i+1]);
			x2 = atof(args[i+2]);
			y2 = atof(args[i+3]);
			x3 = atof(args[i+4]);
			y3 = atof(args[i+5]);
			gs_curveto(ctx->pgs, x1, y1, x2, y2, x3, y3);
			i += 6;
			reset_smooth = 0;
			smooth_x = x3 - x2;
			smooth_y = y3 - y2;
			break;

		case 'c':
			gs_currentpoint(ctx->pgs, &pt);
			x1 = atof(args[i+0]) + pt.x;
			y1 = atof(args[i+1]) + pt.y;
			x2 = atof(args[i+2]) + pt.x;
			y2 = atof(args[i+3]) + pt.y;
			x3 = atof(args[i+4]) + pt.x;
			y3 = atof(args[i+5]) + pt.y;
			gs_curveto(ctx->pgs, x1, y1, x2, y2, x3, y3);
			i += 6;
			reset_smooth = 0;
			smooth_x = x3 - x2;
			smooth_y = y3 - y2;
			break;

		case 'S':
			gs_currentpoint(ctx->pgs, &pt);
			x1 = atof(args[i+0]);
			y1 = atof(args[i+1]);
			x2 = atof(args[i+2]);
			y2 = atof(args[i+3]);
			//dprintf2("smooth %g %g\n", smooth_x, smooth_y);
			gs_curveto(ctx->pgs, pt.x + smooth_x, pt.y + smooth_y, x1, y1, x2, y2);
			i += 4;
			reset_smooth = 0;
			smooth_x = x2 - x1;
			smooth_y = y2 - y1;
			break;

		case 's':
			gs_currentpoint(ctx->pgs, &pt);
			x1 = atof(args[i+0]) + pt.x;
			y1 = atof(args[i+1]) + pt.y;
			x2 = atof(args[i+2]) + pt.x;
			y2 = atof(args[i+3]) + pt.y;
			//dprintf2("smooth %g %g\n", smooth_x, smooth_y);
			gs_curveto(ctx->pgs, pt.x + smooth_x, pt.y + smooth_y, x1, y1, x2, y2);
			i += 4;
			reset_smooth = 0;
			smooth_x = x2 - x1;
			smooth_y = y2 - y1;
			break;

		case 'Q':
			gs_currentpoint(ctx->pgs, &pt);
			x1 = atof(args[i+0]);
			y1 = atof(args[i+1]);
			x2 = atof(args[i+2]);
			y2 = atof(args[i+3]);
			//dprintf4("conicto %g %g %g %g\n", x1, y1, x2, y2);
			gs_curveto(ctx->pgs,
					(pt.x + 2 * x1) / 3, (pt.y + 2 * y1) / 3,
					(x2 + 2 * x1) / 3, (y2 + 2 * y1) / 3,
					x2, y2);
			i += 4;
			break;
		case 'q':
			gs_currentpoint(ctx->pgs, &pt);
			x1 = atof(args[i+0]) + pt.x;
			y1 = atof(args[i+1]) + pt.y;
			x2 = atof(args[i+2]) + pt.x;
			y2 = atof(args[i+3]) + pt.y;
			//dprintf4("conicto %g %g %g %g\n", x1, y1, x2, y2);
			gs_curveto(ctx->pgs,
					(pt.x + 2 * x1) / 3, (pt.y + 2 * y1) / 3,
					(x2 + 2 * x1) / 3, (y2 + 2 * y1) / 3,
					x2, y2);
			i += 4;
			break;

		case 'A':
			xps_draw_arc(ctx,
					atof(args[i+0]), atof(args[i+1]), atof(args[i+2]),
					atoi(args[i+3]), atoi(args[i+4]),
					atof(args[i+5]), atof(args[i+6]));
			i += 7;
			break;
		case 'a':
			gs_currentpoint(ctx->pgs, &pt);
			xps_draw_arc(ctx,
					atof(args[i+0]), atof(args[i+1]), atof(args[i+2]),
					atoi(args[i+3]), atoi(args[i+4]),
					atof(args[i+5]) + pt.x, atof(args[i+6]) + pt.y);
			i += 7;
			break;

		case 'Z':
		case 'z':
			gs_closepath(ctx->pgs);
			//dputs("closepath\n");
			break;

		default:
			/* eek */
			break;
		}

		old = cmd;
	}

	xps_free(ctx, args);
}

static void
xps_parse_arc_segment(xps_context_t *ctx, xps_item_t *root, int stroking, int *skipped_stroke)
{
	/* ArcSegment pretty much follows the SVG algorithm for converting an
	 * arc in endpoint representation to an arc in centerpoint
	 * representation. Once in centerpoint it can be given to the
	 * graphics library in the form of a postscript arc. */

	float rotation_angle;
	int is_large_arc, is_clockwise;
	float point_x, point_y;
	float size_x, size_y;
	int is_stroked;

	char *point_att = xps_att(root, "Point");
	char *size_att = xps_att(root, "Size");
	char *rotation_angle_att = xps_att(root, "RotationAngle");
	char *is_large_arc_att = xps_att(root, "IsLargeArc");
	char *sweep_direction_att = xps_att(root, "SweepDirection");
	char *is_stroked_att = xps_att(root, "IsStroked");

	if (!point_att || !size_att || !rotation_angle_att || !is_large_arc_att || !sweep_direction_att)
	{
		gs_warn("ArcSegment element is missing attributes");
		return;
	}

	is_stroked = 1;
	if (is_stroked_att && !strcmp(is_stroked_att, "false"))
			is_stroked = 0;
	if (!is_stroked)
		*skipped_stroke = 1;

	sscanf(point_att, "%g,%g", &point_x, &point_y);
	sscanf(size_att, "%g,%g", &size_x, &size_y);
	rotation_angle = atof(rotation_angle_att);
	is_large_arc = !strcmp(is_large_arc_att, "true");
	is_clockwise = !strcmp(sweep_direction_att, "Clockwise");

	if (stroking && !is_stroked)
	{
		gs_moveto(ctx->pgs, point_x, point_y);
		return;
	}

	xps_draw_arc(ctx, size_x, size_y, rotation_angle, is_large_arc, is_clockwise, point_x, point_y);
}

static void
xps_parse_poly_quadratic_bezier_segment(xps_context_t *ctx, xps_item_t *root, int stroking, int *skipped_stroke)
{
	char *points_att = xps_att(root, "Points");
	char *is_stroked_att = xps_att(root, "IsStroked");
	float x[2], y[2];
	int is_stroked;
	gs_point pt;
	char *s;
	int n;

	if (!points_att)
	{
		gs_warn("PolyQuadraticBezierSegment element has no points");
		return;
	}

	is_stroked = 1;
	if (is_stroked_att && !strcmp(is_stroked_att, "false"))
			is_stroked = 0;
	if (!is_stroked)
		*skipped_stroke = 1;

	s = points_att;
	n = 0;
	while (*s != 0)
	{
		while (*s == ' ') s++;
		sscanf(s, "%g,%g", &x[n], &y[n]);
		while (*s != ' ' && *s != 0) s++;
		n ++;
		if (n == 2)
		{
			if (stroking && !is_stroked)
			{
				gs_moveto(ctx->pgs, x[1], y[1]);
			}
			else
			{
				gs_currentpoint(ctx->pgs, &pt);
				gs_curveto(ctx->pgs,
						(pt.x + 2 * x[0]) / 3, (pt.y + 2 * y[0]) / 3,
						(x[1] + 2 * x[0]) / 3, (y[1] + 2 * y[0]) / 3,
						x[1], y[1]);
			}
			n = 0;
		}
	}
}

static void
xps_parse_poly_bezier_segment(xps_context_t *ctx, xps_item_t *root, int stroking, int *skipped_stroke)
{
	char *points_att = xps_att(root, "Points");
	char *is_stroked_att = xps_att(root, "IsStroked");
	float x[3], y[3];
	int is_stroked;
	char *s;
	int n;

	if (!points_att)
	{
		gs_warn("PolyBezierSegment element has no points");
		return;
	}

	is_stroked = 1;
	if (is_stroked_att && !strcmp(is_stroked_att, "false"))
			is_stroked = 0;
	if (!is_stroked)
		*skipped_stroke = 1;

	s = points_att;
	n = 0;
	while (*s != 0)
	{
		while (*s == ' ') s++;
		sscanf(s, "%g,%g", &x[n], &y[n]);
		while (*s != ' ' && *s != 0) s++;
		n ++;
		if (n == 3)
		{
			if (stroking && !is_stroked)
				gs_moveto(ctx->pgs, x[2], y[2]);
			else
				gs_curveto(ctx->pgs, x[0], y[0], x[1], y[1], x[2], y[2]);
			n = 0;
		}
	}
}

static void
xps_parse_poly_line_segment(xps_context_t *ctx, xps_item_t *root, int stroking, int *skipped_stroke)
{
	char *points_att = xps_att(root, "Points");
	char *is_stroked_att = xps_att(root, "IsStroked");
	int is_stroked;
	float x, y;
	char *s;

	if (!points_att)
	{
		gs_warn("PolyLineSegment element has no points");
		return;
	}

	is_stroked = 1;
	if (is_stroked_att && !strcmp(is_stroked_att, "false"))
			is_stroked = 0;
	if (!is_stroked)
		*skipped_stroke = 1;

	s = points_att;
	while (*s != 0)
	{
		while (*s == ' ') s++;
		sscanf(s, "%g,%g", &x, &y);
		if (stroking && !is_stroked)
			gs_moveto(ctx->pgs, x, y);
		else
			gs_lineto(ctx->pgs, x, y);
		while (*s != ' ' && *s != 0) s++;
	}
}

static void
xps_parse_path_figure(xps_context_t *ctx, xps_item_t *root, int stroking)
{
	xps_item_t *node;

	char *is_closed_att;
	char *start_point_att;
	char *is_filled_att;

	int is_closed = 0;
	int is_filled = 1;
	float start_x = 0.0;
	float start_y = 0.0;

	int skipped_stroke = 0;

	is_closed_att = xps_att(root, "IsClosed");
	start_point_att = xps_att(root, "StartPoint");
	is_filled_att = xps_att(root, "IsFilled");

	if (is_closed_att)
		is_closed = !strcmp(is_closed_att, "true");
	if (is_filled_att)
		is_filled = !strcmp(is_filled_att, "true");
	if (start_point_att)
		sscanf(start_point_att, "%g,%g", &start_x, &start_y);

	if (!stroking && !is_filled) /* not filled, when filling */
		return;

	gs_moveto(ctx->pgs, start_x, start_y);

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "ArcSegment"))
			xps_parse_arc_segment(ctx, node, stroking, &skipped_stroke);
		if (!strcmp(xps_tag(node), "PolyBezierSegment"))
			xps_parse_poly_bezier_segment(ctx, node, stroking, &skipped_stroke);
		if (!strcmp(xps_tag(node), "PolyLineSegment"))
			xps_parse_poly_line_segment(ctx, node, stroking, &skipped_stroke);
		if (!strcmp(xps_tag(node), "PolyQuadraticBezierSegment"))
			xps_parse_poly_quadratic_bezier_segment(ctx, node, stroking, &skipped_stroke);
	}

	if (is_closed)
	{
		if (stroking && skipped_stroke)
			gs_lineto(ctx->pgs, start_x, start_y); /* we've skipped using gs_moveto... */
		else
			gs_closepath(ctx->pgs); /* no skipped segments, safe to closepath properly */
	}
}

void
xps_parse_path_geometry(xps_context_t *ctx, xps_resource_t *dict, xps_item_t *root, int stroking)
{
	xps_item_t *node;

	char *figures_att;
	char *fill_rule_att;
	char *transform_att;

	xps_item_t *transform_tag = NULL;
	xps_item_t *figures_tag = NULL; /* only used by resource */

	gs_matrix transform;
	gs_matrix saved_transform;

	gs_newpath(ctx->pgs);

	figures_att = xps_att(root, "Figures");
	fill_rule_att = xps_att(root, "FillRule");
	transform_att = xps_att(root, "Transform");

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "PathGeometry.Transform"))
			transform_tag = xps_down(node);
	}

	xps_resolve_resource_reference(ctx, dict, &transform_att, &transform_tag, NULL);
	xps_resolve_resource_reference(ctx, dict, &figures_att, &figures_tag, NULL);

	if (fill_rule_att)
	{
		if (!strcmp(fill_rule_att, "NonZero"))
			ctx->fill_rule = 1;
		if (!strcmp(fill_rule_att, "EvenOdd"))
			ctx->fill_rule = 0;
	}

	gs_make_identity(&transform);
	if (transform_att || transform_tag)
	{
		if (transform_att)
			xps_parse_render_transform(ctx, transform_att, &transform);
		if (transform_tag)
			xps_parse_matrix_transform(ctx, transform_tag, &transform);
	}

	gs_currentmatrix(ctx->pgs, &saved_transform);
	gs_concat(ctx->pgs, &transform);

	if (figures_att)
	{
		xps_parse_abbreviated_geometry(ctx, figures_att);
	}

	if (figures_tag)
	{
		xps_parse_path_figure(ctx, figures_tag, stroking);
	}

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "PathFigure"))
			xps_parse_path_figure(ctx, node, stroking);
	}

	gs_setmatrix(ctx->pgs, &saved_transform);
}

static int
xps_parse_line_cap(char *attr)
{
	if (attr)
	{
		if (!strcmp(attr, "Flat")) return gs_cap_butt;
		if (!strcmp(attr, "Square")) return gs_cap_square;
		if (!strcmp(attr, "Round")) return gs_cap_round;
		if (!strcmp(attr, "Triangle")) return gs_cap_triangle;
	}
	return gs_cap_butt;
}

/*
 * Parse an XPS <Path> element, and call relevant ghostscript
 * functions for drawing and/or clipping the child elements.
 */

int
xps_parse_path(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root)
{
	xps_item_t *node;
	int code;

	char *fill_uri;
	char *stroke_uri;
	char *opacity_mask_uri;

	char *transform_att;
	char *clip_att;
	char *data_att;
	char *fill_att;
	char *stroke_att;
	char *opacity_att;
	char *opacity_mask_att;

	xps_item_t *transform_tag = NULL;
	xps_item_t *clip_tag = NULL;
	xps_item_t *data_tag = NULL;
	xps_item_t *fill_tag = NULL;
	xps_item_t *stroke_tag = NULL;
	xps_item_t *opacity_mask_tag = NULL;

	char *fill_opacity_att = NULL;
	char *stroke_opacity_att = NULL;

	char *stroke_dash_array_att;
	char *stroke_dash_cap_att;
	char *stroke_dash_offset_att;
	char *stroke_end_line_cap_att;
	char *stroke_start_line_cap_att;
	char *stroke_line_join_att;
	char *stroke_miter_limit_att;
	char *stroke_thickness_att;

	gs_line_join linejoin;
	float linewidth;
	float miterlimit;
	float samples[32];
	gs_color_space *colorspace;

	gs_gsave(ctx->pgs);

	ctx->fill_rule = 0;

	/*
	 * Extract attributes and extended attributes.
	 */

	transform_att = xps_att(root, "RenderTransform");
	clip_att = xps_att(root, "Clip");
	data_att = xps_att(root, "Data");
	fill_att = xps_att(root, "Fill");
	stroke_att = xps_att(root, "Stroke");
	opacity_att = xps_att(root, "Opacity");
	opacity_mask_att = xps_att(root, "OpacityMask");

	stroke_dash_array_att = xps_att(root, "StrokeDashArray");
	stroke_dash_cap_att = xps_att(root, "StrokeDashCap");
	stroke_dash_offset_att = xps_att(root, "StrokeDashOffset");
	stroke_end_line_cap_att = xps_att(root, "StrokeEndLineCap");
	stroke_start_line_cap_att = xps_att(root, "StrokeStartLineCap");
	stroke_line_join_att = xps_att(root, "StrokeLineJoin");
	stroke_miter_limit_att = xps_att(root, "StrokeMiterLimit");
	stroke_thickness_att = xps_att(root, "StrokeThickness");

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "Path.RenderTransform"))
			transform_tag = xps_down(node);

		if (!strcmp(xps_tag(node), "Path.OpacityMask"))
			opacity_mask_tag = xps_down(node);

		if (!strcmp(xps_tag(node), "Path.Clip"))
			clip_tag = xps_down(node);

		if (!strcmp(xps_tag(node), "Path.Fill"))
			fill_tag = xps_down(node);

		if (!strcmp(xps_tag(node), "Path.Stroke"))
			stroke_tag = xps_down(node);

		if (!strcmp(xps_tag(node), "Path.Data"))
			data_tag = xps_down(node);
	}

	fill_uri = base_uri;
	stroke_uri = base_uri;
	opacity_mask_uri = base_uri;

	xps_resolve_resource_reference(ctx, dict, &data_att, &data_tag, NULL);
	xps_resolve_resource_reference(ctx, dict, &clip_att, &clip_tag, NULL);
	xps_resolve_resource_reference(ctx, dict, &transform_att, &transform_tag, NULL);
	xps_resolve_resource_reference(ctx, dict, &fill_att, &fill_tag, &fill_uri);
	xps_resolve_resource_reference(ctx, dict, &stroke_att, &stroke_tag, &stroke_uri);
	xps_resolve_resource_reference(ctx, dict, &opacity_mask_att, &opacity_mask_tag, &opacity_mask_uri);

	/*
	 * Act on the information we have gathered:
	 */

	if (fill_tag && !strcmp(xps_tag(fill_tag), "SolidColorBrush"))
	{
		fill_opacity_att = xps_att(fill_tag, "Opacity");
		fill_att = xps_att(fill_tag, "Color");
		fill_tag = NULL;
	}

	if (stroke_tag && !strcmp(xps_tag(stroke_tag), "SolidColorBrush"))
	{
		stroke_opacity_att = xps_att(stroke_tag, "Opacity");
		stroke_att = xps_att(stroke_tag, "Color");
		stroke_tag = NULL;
	}

	gs_setlinestartcap(ctx->pgs, xps_parse_line_cap(stroke_start_line_cap_att));
	gs_setlineendcap(ctx->pgs, xps_parse_line_cap(stroke_end_line_cap_att));
	gs_setlinedashcap(ctx->pgs, xps_parse_line_cap(stroke_dash_cap_att));

	linejoin = gs_join_miter;
	if (stroke_line_join_att)
	{
		if (!strcmp(stroke_line_join_att, "Miter")) linejoin = gs_join_miter;
		if (!strcmp(stroke_line_join_att, "Bevel")) linejoin = gs_join_bevel;
		if (!strcmp(stroke_line_join_att, "Round")) linejoin = gs_join_round;
	}
	gs_setlinejoin(ctx->pgs, linejoin);

	miterlimit = 10.0;
	if (stroke_miter_limit_att)
		miterlimit = atof(stroke_miter_limit_att);
	gs_setmiterlimit(ctx->pgs, miterlimit);

	linewidth = 1.0;
	if (stroke_thickness_att)
		linewidth = atof(stroke_thickness_att);
	gs_setlinewidth(ctx->pgs, linewidth);

	if (stroke_dash_array_att)
	{
		char *s = stroke_dash_array_att;
		float dash_array[100];
		float dash_offset = 0.0;
		int dash_count = 0;

		if (stroke_dash_offset_att)
			dash_offset = atof(stroke_dash_offset_att) * linewidth;

		while (*s)
		{
			while (*s == ' ')
				s++;
			dash_array[dash_count++] = atof(s) * linewidth;
			while (*s && *s != ' ')
				s++;
		}

		gs_setdash(ctx->pgs, dash_array, dash_count, dash_offset);
	}
	else
	{
		gs_setdash(ctx->pgs, NULL, 0, 0.0);
	}

	if (transform_att || transform_tag)
	{
		gs_matrix transform;

		if (transform_att)
			xps_parse_render_transform(ctx, transform_att, &transform);
		if (transform_tag)
			xps_parse_matrix_transform(ctx, transform_tag, &transform);

		gs_concat(ctx->pgs, &transform);
	}

	if (clip_att || clip_tag)
	{
		if (clip_att)
			xps_parse_abbreviated_geometry(ctx, clip_att);
		if (clip_tag)
			xps_parse_path_geometry(ctx, dict, clip_tag, 0);
		xps_clip(ctx);
	}

#if 0 // XXX
	if (opacity_att || opacity_mask_tag)
	{
		/* clip the bounds with the actual path */
		if (data_att)
			xps_parse_abbreviated_geometry(ctx, data_att);
		if (data_tag)
			xps_parse_path_geometry(ctx, dict, data_tag, 0);
		xps_update_bounds(ctx, &saved_bounds_opacity);
		gs_newpath(ctx->pgs);
	}
#endif

	code = xps_begin_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);
	if (code)
	{
		gs_grestore(ctx->pgs);
		return gs_rethrow(code, "cannot create transparency group");
	}

	if (fill_att)
	{
		xps_parse_color(ctx, base_uri, fill_att, &colorspace, samples);
		if (fill_opacity_att)
			samples[0] = atof(fill_opacity_att);
		xps_set_color(ctx, colorspace, samples);

		if (data_att)
			xps_parse_abbreviated_geometry(ctx, data_att);
		if (data_tag)
			xps_parse_path_geometry(ctx, dict, data_tag, 0);

		xps_fill(ctx);
	}

	if (fill_tag)
	{
		if (data_att)
			xps_parse_abbreviated_geometry(ctx, data_att);
		if (data_tag)
			xps_parse_path_geometry(ctx, dict, data_tag, 0);

		code = xps_parse_brush(ctx, fill_uri, dict, fill_tag);
		if (code < 0)
		{
			xps_end_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot parse fill brush");
		}
	}

	if (stroke_att)
	{
		xps_parse_color(ctx, base_uri, stroke_att, &colorspace, samples);
		if (stroke_opacity_att)
			samples[0] = atof(stroke_opacity_att);
		xps_set_color(ctx, colorspace, samples);

		if (data_att)
			xps_parse_abbreviated_geometry(ctx, data_att);
		if (data_tag)
			xps_parse_path_geometry(ctx, dict, data_tag, 1);

		gs_stroke(ctx->pgs);
	}

	if (stroke_tag)
	{
		if (data_att)
			xps_parse_abbreviated_geometry(ctx, data_att);
		if (data_tag)
			xps_parse_path_geometry(ctx, dict, data_tag, 1);

		ctx->fill_rule = 1; /* over-ride fill rule when converting outline to stroked */
		gs_strokepath2(ctx->pgs);

		code = xps_parse_brush(ctx, stroke_uri, dict, stroke_tag);
		if (code < 0)
		{
			xps_end_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot parse stroke brush");
		}
	}

	xps_end_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);
	gs_grestore(ctx->pgs);
	return 0;
}
