#include "mupdf/fitz.h"
#include "draw-imp.h"

#define MAX_DEPTH 8

static void
line(fz_context *ctx, fz_gel *gel, const fz_matrix *ctm, float x0, float y0, float x1, float y1)
{
	float tx0 = ctm->a * x0 + ctm->c * y0 + ctm->e;
	float ty0 = ctm->b * x0 + ctm->d * y0 + ctm->f;
	float tx1 = ctm->a * x1 + ctm->c * y1 + ctm->e;
	float ty1 = ctm->b * x1 + ctm->d * y1 + ctm->f;
	fz_insert_gel(ctx, gel, tx0, ty0, tx1, ty1);
}

static void
bezier(fz_context *ctx, fz_gel *gel, const fz_matrix *ctm, float flatness,
	float xa, float ya,
	float xb, float yb,
	float xc, float yc,
	float xd, float yd, int depth)
{
	float dmax;
	float xab, yab;
	float xbc, ybc;
	float xcd, ycd;
	float xabc, yabc;
	float xbcd, ybcd;
	float xabcd, yabcd;

	/* termination check */
	dmax = fz_abs(xa - xb);
	dmax = fz_max(dmax, fz_abs(ya - yb));
	dmax = fz_max(dmax, fz_abs(xd - xc));
	dmax = fz_max(dmax, fz_abs(yd - yc));
	if (dmax < flatness || depth >= MAX_DEPTH)
	{
		line(ctx, gel, ctm, xa, ya, xd, yd);
		return;
	}

	xab = xa + xb;
	yab = ya + yb;
	xbc = xb + xc;
	ybc = yb + yc;
	xcd = xc + xd;
	ycd = yc + yd;

	xabc = xab + xbc;
	yabc = yab + ybc;
	xbcd = xbc + xcd;
	ybcd = ybc + ycd;

	xabcd = xabc + xbcd;
	yabcd = yabc + ybcd;

	xab *= 0.5f; yab *= 0.5f;
	/* xbc *= 0.5f; ybc *= 0.5f; */
	xcd *= 0.5f; ycd *= 0.5f;

	xabc *= 0.25f; yabc *= 0.25f;
	xbcd *= 0.25f; ybcd *= 0.25f;

	xabcd *= 0.125f; yabcd *= 0.125f;

	bezier(ctx, gel, ctm, flatness, xa, ya, xab, yab, xabc, yabc, xabcd, yabcd, depth + 1);
	bezier(ctx, gel, ctm, flatness, xabcd, yabcd, xbcd, ybcd, xcd, ycd, xd, yd, depth + 1);
}

static void
quad(fz_context *ctx, fz_gel *gel, const fz_matrix *ctm, float flatness,
	float xa, float ya,
	float xb, float yb,
	float xc, float yc, int depth)
{
	float dmax;
	float xab, yab;
	float xbc, ybc;
	float xabc, yabc;

	/* termination check */
	dmax = fz_abs(xa - xb);
	dmax = fz_max(dmax, fz_abs(ya - yb));
	dmax = fz_max(dmax, fz_abs(xc - xb));
	dmax = fz_max(dmax, fz_abs(yc - yb));
	if (dmax < flatness || depth >= MAX_DEPTH)
	{
		line(ctx, gel, ctm, xa, ya, xc, yc);
		return;
	}

	xab = xa + xb;
	yab = ya + yb;
	xbc = xb + xc;
	ybc = yb + yc;

	xabc = xab + xbc;
	yabc = yab + ybc;

	xab *= 0.5f; yab *= 0.5f;
	xbc *= 0.5f; ybc *= 0.5f;

	xabc *= 0.25f; yabc *= 0.25f;

	quad(ctx, gel, ctm, flatness, xa, ya, xab, yab, xabc, yabc, depth + 1);
	quad(ctx, gel, ctm, flatness, xabc, yabc, xbc, ybc, xc, yc, depth + 1);
}

typedef struct
{
	fz_gel *gel;
	const fz_matrix *ctm;
	float flatness;
	fz_point b;
	fz_point c;
}
flatten_arg;

static void
flatten_moveto(fz_context *ctx, void *arg_, float x, float y)
{
	flatten_arg *arg = (flatten_arg *)arg_;

	/* implicit closepath before moveto */
	if (arg->c.x != arg->b.x || arg->c.y != arg->b.y)
		line(ctx, arg->gel, arg->ctm, arg->c.x, arg->c.y, arg->b.x, arg->b.y);
	arg->c.x = arg->b.x = x;
	arg->c.y = arg->b.y = y;
}

static void
flatten_lineto(fz_context *ctx, void *arg_, float x, float y)
{
	flatten_arg *arg = (flatten_arg *)arg_;

	line(ctx, arg->gel, arg->ctm, arg->c.x, arg->c.y, x, y);
	arg->c.x = x;
	arg->c.y = y;
}

static void
flatten_curveto(fz_context *ctx, void *arg_, float x1, float y1, float x2, float y2, float x3, float y3)
{
	flatten_arg *arg = (flatten_arg *)arg_;

	bezier(ctx, arg->gel, arg->ctm, arg->flatness, arg->c.x, arg->c.y, x1, y1, x2, y2, x3, y3, 0);
	arg->c.x = x3;
	arg->c.y = y3;
}

static void
flatten_quadto(fz_context *ctx, void *arg_, float x1, float y1, float x2, float y2)
{
	flatten_arg *arg = (flatten_arg *)arg_;

	quad(ctx, arg->gel, arg->ctm, arg->flatness, arg->c.x, arg->c.y, x1, y1, x2, y2, 0);
	arg->c.x = x2;
	arg->c.y = y2;
}

static void
flatten_close(fz_context *ctx, void *arg_)
{
	flatten_arg *arg = (flatten_arg *)arg_;

	line(ctx, arg->gel, arg->ctm, arg->c.x, arg->c.y, arg->b.x, arg->b.y);
	arg->c.x = arg->b.x;
	arg->c.y = arg->b.y;
}

static void
flatten_rectto(fz_context *ctx, void *arg_, float x0, float y0, float x1, float y1)
{
	flatten_arg *arg = (flatten_arg *)arg_;
	const fz_matrix *ctm = arg->ctm;

	flatten_moveto(ctx, arg_, x0, y0);
	/* In the case where we have an axis aligned rectangle, do some
	 * horrid antidropout stuff. */
	if (ctm->b == 0 && ctm->c == 0)
	{
		float tx0 = ctm->a * x0 + ctm->e;
		float ty0 = ctm->d * y0 + ctm->f;
		float tx1 = ctm->a * x1 + ctm->e;
		float ty1 = ctm->d * y1 + ctm->f;
		fz_insert_gel_rect(ctx, arg->gel, tx0, ty0, tx1, ty1);
	}
	else if (ctm->a == 0 && ctm->d == 0)
	{
		float tx0 = ctm->c * y0 + ctm->e;
		float ty0 = ctm->b * x0 + ctm->f;
		float tx1 = ctm->c * y1 + ctm->e;
		float ty1 = ctm->b * x1 + ctm->f;
		fz_insert_gel_rect(ctx, arg->gel, tx0, ty1, tx1, ty0);
	}
	else
	{
		flatten_lineto(ctx, arg_, x1, y0);
		flatten_lineto(ctx, arg_, x1, y1);
		flatten_lineto(ctx, arg_, x0, y1);
		flatten_close(ctx, arg_);
	}
}

static const fz_path_processor flatten_proc =
{
	flatten_moveto,
	flatten_lineto,
	flatten_curveto,
	flatten_close,
	flatten_quadto,
	NULL,
	NULL,
	flatten_rectto
};

void
fz_flatten_fill_path(fz_context *ctx, fz_gel *gel, fz_path *path, const fz_matrix *ctm, float flatness)
{
	flatten_arg arg;

	arg.gel = gel;
	arg.ctm = ctm;
	arg.flatness = flatness;
	arg.b.x = arg.b.y = arg.c.x = arg.c.y = 0;

	fz_process_path(ctx, &flatten_proc, &arg, path);
	if (arg.c.x != arg.b.x || arg.c.y != arg.b.y)
		line(ctx, gel, ctm, arg.c.x, arg.c.y, arg.b.x, arg.b.y);
}

typedef struct sctx
{
	fz_gel *gel;
	const fz_matrix *ctm;
	float flatness;
	const fz_stroke_state *stroke;

	int linejoin;
	float linewidth;
	float miterlimit;
	fz_point beg[2];
	fz_point seg[2];
	int sn;
	int dot;
	int from_bezier;
	fz_point cur;

	fz_rect rect;
	const float *dash_list;
	float dash_phase;
	int dash_len;
	float dash_total;
	int toggle, cap;
	int offset;
	float phase;
	fz_point dash_cur;
	fz_point dash_beg;
} sctx;

static void
fz_add_line(fz_context *ctx, sctx *s, float x0, float y0, float x1, float y1)
{
	float tx0 = s->ctm->a * x0 + s->ctm->c * y0 + s->ctm->e;
	float ty0 = s->ctm->b * x0 + s->ctm->d * y0 + s->ctm->f;
	float tx1 = s->ctm->a * x1 + s->ctm->c * y1 + s->ctm->e;
	float ty1 = s->ctm->b * x1 + s->ctm->d * y1 + s->ctm->f;
	fz_insert_gel(ctx, s->gel, tx0, ty0, tx1, ty1);
}

static void
fz_add_horiz_rect(fz_context *ctx, sctx *s, float x0, float y0, float x1, float y1)
{
	if (s->ctm->b == 0 && s->ctm->c == 0)
	{
		float tx0 = s->ctm->a * x0 + s->ctm->e;
		float ty0 = s->ctm->d * y0 + s->ctm->f;
		float tx1 = s->ctm->a * x1 + s->ctm->e;
		float ty1 = s->ctm->d * y1 + s->ctm->f;
		fz_insert_gel_rect(ctx, s->gel, tx1, ty1, tx0, ty0);
	}
	else if (s->ctm->a == 0 && s->ctm->d == 0)
	{
		float tx0 = s->ctm->c * y0 + s->ctm->e;
		float ty0 = s->ctm->b * x0 + s->ctm->f;
		float tx1 = s->ctm->c * y1 + s->ctm->e;
		float ty1 = s->ctm->b * x1 + s->ctm->f;
		fz_insert_gel_rect(ctx, s->gel, tx1, ty0, tx0, ty1);
	}
	else
	{
		fz_add_line(ctx, s, x0, y0, x1, y0);
		fz_add_line(ctx, s, x1, y1, x0, y1);
	}
}

static void
fz_add_vert_rect(fz_context *ctx, sctx *s, float x0, float y0, float x1, float y1)
{
	if (s->ctm->b == 0 && s->ctm->c == 0)
	{
		float tx0 = s->ctm->a * x0 + s->ctm->e;
		float ty0 = s->ctm->d * y0 + s->ctm->f;
		float tx1 = s->ctm->a * x1 + s->ctm->e;
		float ty1 = s->ctm->d * y1 + s->ctm->f;
		fz_insert_gel_rect(ctx, s->gel, tx0, ty1, tx1, ty0);
	}
	else if (s->ctm->a == 0 && s->ctm->d == 0)
	{
		float tx0 = s->ctm->c * y0 + s->ctm->e;
		float ty0 = s->ctm->b * x0 + s->ctm->f;
		float tx1 = s->ctm->c * y1 + s->ctm->e;
		float ty1 = s->ctm->b * x1 + s->ctm->f;
		fz_insert_gel_rect(ctx, s->gel, tx0, ty0, tx1, ty1);
	}
	else
	{
		fz_add_line(ctx, s, x1, y0, x0, y0);
		fz_add_line(ctx, s, x0, y1, x1, y1);
	}
}

static void
fz_add_arc(fz_context *ctx, sctx *s,
	float xc, float yc,
	float x0, float y0,
	float x1, float y1)
{
	float th0, th1, r;
	float theta;
	float ox, oy, nx, ny;
	int n, i;

	r = fabsf(s->linewidth);
	theta = 2 * (float)M_SQRT2 * sqrtf(s->flatness / r);
	th0 = atan2f(y0, x0);
	th1 = atan2f(y1, x1);

	if (r > 0)
	{
		if (th0 < th1)
			th0 += (float)M_PI * 2;
		n = ceilf((th0 - th1) / theta);
	}
	else
	{
		if (th1 < th0)
			th1 += (float)M_PI * 2;
		n = ceilf((th1 - th0) / theta);
	}

	ox = x0;
	oy = y0;
	for (i = 1; i < n; i++)
	{
		theta = th0 + (th1 - th0) * i / n;
		nx = cosf(theta) * r;
		ny = sinf(theta) * r;
		fz_add_line(ctx, s, xc + ox, yc + oy, xc + nx, yc + ny);
		ox = nx;
		oy = ny;
	}

	fz_add_line(ctx, s, xc + ox, yc + oy, xc + x1, yc + y1);
}

static void
fz_add_line_stroke(fz_context *ctx, sctx *s, float ax, float ay, float bx, float by)
{
	float dx = bx - ax;
	float dy = by - ay;
	float scale = s->linewidth / sqrtf(dx * dx + dy * dy);
	float dlx = dy * scale;
	float dly = -dx * scale;

	if (0 && dx == 0)
	{
		fz_add_vert_rect(ctx, s, ax - dlx, ay, bx + dlx, by);
	}
	else if (dy == 0)
	{
		fz_add_horiz_rect(ctx, s, ax, ay - dly, bx, by + dly);
	}
	else
	{
		fz_add_line(ctx, s, ax - dlx, ay - dly, bx - dlx, by - dly);
		fz_add_line(ctx, s, bx + dlx, by + dly, ax + dlx, ay + dly);
	}
}

static void
fz_add_line_join(fz_context *ctx, sctx *s, float ax, float ay, float bx, float by, float cx, float cy, int join_under)
{
	float miterlimit = s->miterlimit;
	float linewidth = s->linewidth;
	fz_linejoin linejoin = s->linejoin;
	float dx0, dy0;
	float dx1, dy1;
	float dlx0, dly0;
	float dlx1, dly1;
	float dmx, dmy;
	float dmr2;
	float scale;
	float cross;
	float len0, len1;

	dx0 = bx - ax;
	dy0 = by - ay;

	dx1 = cx - bx;
	dy1 = cy - by;

	cross = dx1 * dy0 - dx0 * dy1;
	/* Ensure that cross >= 0 */
	if (cross < 0)
	{
		float tmp;
		tmp = dx1; dx1 = -dx0; dx0 = -tmp;
		tmp = dy1; dy1 = -dy0; dy0 = -tmp;
		cross = -cross;
	}

	len0 = dx0 * dx0 + dy0 * dy0;
	if (len0 < FLT_EPSILON)
	{
		linejoin = FZ_LINEJOIN_BEVEL;
		dlx0 = 0;
		dly0 = 0;
	}
	else
	{
		scale = linewidth / sqrtf(len0);
		dlx0 = dy0 * scale;
		dly0 = -dx0 * scale;
	}

	len1 = dx1 * dx1 + dy1 * dy1;
	if (len1 < FLT_EPSILON)
	{
		linejoin = FZ_LINEJOIN_BEVEL;
		dlx1 = 0;
		dly1 = 0;
	}
	else
	{
		scale = linewidth / sqrtf(len1);
		dlx1 = dy1 * scale;
		dly1 = -dx1 * scale;
	}

	dmx = (dlx0 + dlx1) * 0.5f;
	dmy = (dly0 + dly1) * 0.5f;
	dmr2 = dmx * dmx + dmy * dmy;

	if (cross * cross < FLT_EPSILON && dx0 * dx1 + dy0 * dy1 >= 0)
		linejoin = FZ_LINEJOIN_BEVEL;

	if (join_under)
	{
		fz_add_line(ctx, s, bx + dlx1, by + dly1, bx + dlx0, by + dly0);
	}
	else
	{
		fz_add_line(ctx, s, bx + dlx1, by + dly1, bx, by);
		fz_add_line(ctx, s, bx, by, bx + dlx0, by + dly0);
	}

	/* XPS miter joins are clipped at miterlength, rather than simply
	 * being converted to bevelled joins. */
	if (linejoin == FZ_LINEJOIN_MITER_XPS)
	{
		if (cross == 0)
			linejoin = FZ_LINEJOIN_BEVEL;
		else if (dmr2 * miterlimit * miterlimit >= linewidth * linewidth)
			linejoin = FZ_LINEJOIN_MITER;
		else
		{
			float k, t0x, t0y, t1x, t1y;
			scale = linewidth * linewidth / dmr2;
			dmx *= scale;
			dmy *= scale;
			k = (scale - linewidth * miterlimit / sqrtf(dmr2)) / (scale - 1);
			t0x = bx - dmx + k * (dmx - dlx0);
			t0y = by - dmy + k * (dmy - dly0);
			t1x = bx - dmx + k * (dmx - dlx1);
			t1y = by - dmy + k * (dmy - dly1);

			fz_add_line(ctx, s, bx - dlx0, by - dly0, t0x, t0y);
			fz_add_line(ctx, s, t0x, t0y, t1x, t1y);
			fz_add_line(ctx, s, t1x, t1y, bx - dlx1, by - dly1);
		}
	}
	else if (linejoin == FZ_LINEJOIN_MITER)
		if (dmr2 * miterlimit * miterlimit < linewidth * linewidth)
			linejoin = FZ_LINEJOIN_BEVEL;

	switch (linejoin)
	{
	case FZ_LINEJOIN_MITER_XPS:
		break;

	case FZ_LINEJOIN_MITER:
		scale = linewidth * linewidth / dmr2;
		dmx *= scale;
		dmy *= scale;

		fz_add_line(ctx, s, bx - dlx0, by - dly0, bx - dmx, by - dmy);
		fz_add_line(ctx, s, bx - dmx, by - dmy, bx - dlx1, by - dly1);
		break;

	case FZ_LINEJOIN_BEVEL:
		fz_add_line(ctx, s, bx - dlx0, by - dly0, bx - dlx1, by - dly1);
		break;

	case FZ_LINEJOIN_ROUND:
		fz_add_arc(ctx, s, bx, by, -dlx0, -dly0, -dlx1, -dly1);
		break;

	default:
		assert("Invalid line join" == NULL);
	}
}

static void
fz_add_line_cap(fz_context *ctx, sctx *s, float ax, float ay, float bx, float by, fz_linecap linecap)
{
	float flatness = s->flatness;
	float linewidth = s->linewidth;

	float dx = bx - ax;
	float dy = by - ay;

	float scale = linewidth / sqrtf(dx * dx + dy * dy);
	float dlx = dy * scale;
	float dly = -dx * scale;

	switch (linecap)
	{
	case FZ_LINECAP_BUTT:
		fz_add_line(ctx, s, bx - dlx, by - dly, bx + dlx, by + dly);
		break;

	case FZ_LINECAP_ROUND:
	{
		int i;
		int n = ceilf((float)M_PI / (2.0f * (float)M_SQRT2 * sqrtf(flatness / linewidth)));
		float ox = bx - dlx;
		float oy = by - dly;
		for (i = 1; i < n; i++)
		{
			float theta = (float)M_PI * i / n;
			float cth = cosf(theta);
			float sth = sinf(theta);
			float nx = bx - dlx * cth - dly * sth;
			float ny = by - dly * cth + dlx * sth;
			fz_add_line(ctx, s, ox, oy, nx, ny);
			ox = nx;
			oy = ny;
		}
		fz_add_line(ctx, s, ox, oy, bx + dlx, by + dly);
		break;
	}

	case FZ_LINECAP_SQUARE:
		fz_add_line(ctx, s, bx - dlx, by - dly,
			bx - dlx - dly, by - dly + dlx);
		fz_add_line(ctx, s, bx - dlx - dly, by - dly + dlx,
			bx + dlx - dly, by + dly + dlx);
		fz_add_line(ctx, s, bx + dlx - dly, by + dly + dlx,
			bx + dlx, by + dly);
		break;

	case FZ_LINECAP_TRIANGLE:
	{
		float mx = -dly;
		float my = dlx;
		fz_add_line(ctx, s, bx - dlx, by - dly, bx + mx, by + my);
		fz_add_line(ctx, s, bx + mx, by + my, bx + dlx, by + dly);
		break;
	}

	default:
		assert("Invalid line cap" == NULL);
	}
}

static void
fz_add_line_dot(fz_context *ctx, sctx *s, float ax, float ay)
{
	float flatness = s->flatness;
	float linewidth = s->linewidth;
	int n = ceilf((float)M_PI / ((float)M_SQRT2 * sqrtf(flatness / linewidth)));
	float ox = ax - linewidth;
	float oy = ay;
	int i;

	for (i = 1; i < n; i++)
	{
		float theta = (float)M_PI * 2 * i / n;
		float cth = cosf(theta);
		float sth = sinf(theta);
		float nx = ax - cth * linewidth;
		float ny = ay + sth * linewidth;
		fz_add_line(ctx, s, ox, oy, nx, ny);
		ox = nx;
		oy = ny;
	}

	fz_add_line(ctx, s, ox, oy, ax - linewidth, ay);
}

static void
fz_stroke_flush(fz_context *ctx, sctx *s, fz_linecap start_cap, fz_linecap end_cap)
{
	if (s->sn == 2)
	{
		fz_add_line_cap(ctx, s, s->beg[1].x, s->beg[1].y, s->beg[0].x, s->beg[0].y, start_cap);
		fz_add_line_cap(ctx, s, s->seg[0].x, s->seg[0].y, s->seg[1].x, s->seg[1].y, end_cap);
	}
	else if (s->dot)
	{
		fz_add_line_dot(ctx, s, s->beg[0].x, s->beg[0].y);
	}
}

static void
fz_stroke_moveto(fz_context *ctx, void *s_, float x, float y)
{
	struct sctx *s = (struct sctx *)s_;

	s->seg[0].x = s->beg[0].x = x;
	s->seg[0].y = s->beg[0].y = y;
	s->sn = 1;
	s->dot = 0;
	s->from_bezier = 0;
}

static void
fz_stroke_lineto(fz_context *ctx, sctx *s, float x, float y, int from_bezier)
{
	float dx = x - s->seg[s->sn-1].x;
	float dy = y - s->seg[s->sn-1].y;

	if (dx * dx + dy * dy < FLT_EPSILON)
	{
		if (s->cap == FZ_LINECAP_ROUND || s->dash_list)
			s->dot = 1;
		return;
	}

	fz_add_line_stroke(ctx, s, s->seg[s->sn-1].x, s->seg[s->sn-1].y, x, y);

	if (s->sn == 2)
	{
		fz_add_line_join(ctx, s, s->seg[0].x, s->seg[0].y, s->seg[1].x, s->seg[1].y, x, y, s->from_bezier & from_bezier);
		s->seg[0] = s->seg[1];
		s->seg[1].x = x;
		s->seg[1].y = y;
	}
	else
	{
		s->seg[1].x = s->beg[1].x = x;
		s->seg[1].y = s->beg[1].y = y;
		s->sn = 2;
	}
	s->from_bezier = from_bezier;
}

static void
fz_stroke_closepath(fz_context *ctx, sctx *s)
{
	if (s->sn == 2)
	{
		fz_stroke_lineto(ctx, s, s->beg[0].x, s->beg[0].y, 0);
		if (s->seg[1].x == s->beg[0].x && s->seg[1].y == s->beg[0].y)
			fz_add_line_join(ctx, s, s->seg[0].x, s->seg[0].y, s->beg[0].x, s->beg[0].y, s->beg[1].x, s->beg[1].y, 0);
		else
			fz_add_line_join(ctx, s, s->seg[1].x, s->seg[1].y, s->beg[0].x, s->beg[0].y, s->beg[1].x, s->beg[1].y, 0);
	}
	else if (s->dot)
	{
		fz_add_line_dot(ctx, s, s->beg[0].x, s->beg[0].y);
	}

	s->seg[0] = s->beg[0];
	s->sn = 1;
	s->dot = 0;
	s->from_bezier = 0;
}

static void
fz_stroke_bezier(fz_context *ctx, struct sctx *s,
	float xa, float ya,
	float xb, float yb,
	float xc, float yc,
	float xd, float yd, int depth)
{
	float dmax;
	float xab, yab;
	float xbc, ybc;
	float xcd, ycd;
	float xabc, yabc;
	float xbcd, ybcd;
	float xabcd, yabcd;

	/* termination check */
	dmax = fz_abs(xa - xb);
	dmax = fz_max(dmax, fz_abs(ya - yb));
	dmax = fz_max(dmax, fz_abs(xd - xc));
	dmax = fz_max(dmax, fz_abs(yd - yc));
	if (dmax < s->flatness || depth >= MAX_DEPTH)
	{
		fz_stroke_lineto(ctx, s, xd, yd, 1);
		return;
	}

	xab = xa + xb;
	yab = ya + yb;
	xbc = xb + xc;
	ybc = yb + yc;
	xcd = xc + xd;
	ycd = yc + yd;

	xabc = xab + xbc;
	yabc = yab + ybc;
	xbcd = xbc + xcd;
	ybcd = ybc + ycd;

	xabcd = xabc + xbcd;
	yabcd = yabc + ybcd;

	xab *= 0.5f; yab *= 0.5f;
	/* xbc *= 0.5f; ybc *= 0.5f; */
	xcd *= 0.5f; ycd *= 0.5f;

	xabc *= 0.25f; yabc *= 0.25f;
	xbcd *= 0.25f; ybcd *= 0.25f;

	xabcd *= 0.125f; yabcd *= 0.125f;

	fz_stroke_bezier(ctx, s, xa, ya, xab, yab, xabc, yabc, xabcd, yabcd, depth + 1);
	fz_stroke_bezier(ctx, s, xabcd, yabcd, xbcd, ybcd, xcd, ycd, xd, yd, depth + 1);
}

static void
fz_stroke_quad(fz_context *ctx, struct sctx *s,
	float xa, float ya,
	float xb, float yb,
	float xc, float yc, int depth)
{
	float dmax;
	float xab, yab;
	float xbc, ybc;
	float xabc, yabc;

	/* termination check */
	dmax = fz_abs(xa - xb);
	dmax = fz_max(dmax, fz_abs(ya - yb));
	dmax = fz_max(dmax, fz_abs(xc - xb));
	dmax = fz_max(dmax, fz_abs(yc - yb));
	if (dmax < s->flatness || depth >= MAX_DEPTH)
	{
		fz_stroke_lineto(ctx, s, xc, yc, 1);
		return;
	}

	xab = xa + xb;
	yab = ya + yb;
	xbc = xb + xc;
	ybc = yb + yc;

	xabc = xab + xbc;
	yabc = yab + ybc;

	xab *= 0.5f; yab *= 0.5f;
	xbc *= 0.5f; ybc *= 0.5f;

	xabc *= 0.25f; yabc *= 0.25f;

	fz_stroke_quad(ctx, s, xa, ya, xab, yab, xabc, yabc, depth + 1);
	fz_stroke_quad(ctx, s, xabc, yabc, xbc, ybc, xc, yc, depth + 1);
}

static void
stroke_moveto(fz_context *ctx, void *s_, float x, float y)
{
	sctx *s = (sctx *)s_;

	fz_stroke_flush(ctx, s, s->stroke->start_cap, s->stroke->end_cap);
	fz_stroke_moveto(ctx, s, x, y);
	s->cur.x = x;
	s->cur.y = y;
}

static void
stroke_lineto(fz_context *ctx, void *s_, float x, float y)
{
	sctx *s = (sctx *)s_;

	fz_stroke_lineto(ctx, s, x, y, 0);
	s->cur.x = x;
	s->cur.y = y;
}

static void
stroke_curveto(fz_context *ctx, void *s_, float x1, float y1, float x2, float y2, float x3, float y3)
{
	sctx *s = (sctx *)s_;

	fz_stroke_bezier(ctx, s, s->cur.x, s->cur.y, x1, y1, x2, y2, x3, y3, 0);
	s->cur.x = x3;
	s->cur.y = y3;
}

static void
stroke_quadto(fz_context *ctx, void *s_, float x1, float y1, float x2, float y2)
{
	sctx *s = (sctx *)s_;

	fz_stroke_quad(ctx, s, s->cur.x, s->cur.y, x1, y1, x2, y2, 0);
	s->cur.x = x2;
	s->cur.y = y2;
}

static void
stroke_close(fz_context *ctx, void *s_)
{
	sctx *s = (sctx *)s_;

	fz_stroke_closepath(ctx, s);
}

static const fz_path_processor stroke_proc =
{
	stroke_moveto,
	stroke_lineto,
	stroke_curveto,
	stroke_close,
	stroke_quadto
};

void
fz_flatten_stroke_path(fz_context *ctx, fz_gel *gel, fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, float flatness, float linewidth)
{
	struct sctx s;

	s.stroke = stroke;
	s.gel = gel;
	s.ctm = ctm;
	s.flatness = flatness;

	s.linejoin = stroke->linejoin;
	s.linewidth = linewidth * 0.5f; /* hairlines use a different value from the path value */
	s.miterlimit = stroke->miterlimit;
	s.sn = 0;
	s.dot = 0;

	s.dash_list = NULL;
	s.dash_phase = 0;
	s.dash_len = 0;
	s.toggle = 0;
	s.offset = 0;
	s.phase = 0;

	s.cap = stroke->start_cap;

	s.cur.x = s.cur.y = 0;
	s.stroke = stroke;

	fz_process_path(ctx, &stroke_proc, &s, path);
	fz_stroke_flush(ctx, &s, stroke->start_cap, stroke->end_cap);
}

static void
fz_dash_moveto(fz_context *ctx, struct sctx *s, float x, float y)
{
	s->toggle = 1;
	s->offset = 0;
	s->phase = s->dash_phase;

	while (s->phase >= s->dash_list[s->offset])
	{
		s->toggle = !s->toggle;
		s->phase -= s->dash_list[s->offset];
		s->offset ++;
		if (s->offset == s->dash_len)
			s->offset = 0;
	}

	s->dash_cur.x = x;
	s->dash_cur.y = y;

	if (s->toggle)
	{
		fz_stroke_flush(ctx, s, s->cap, s->stroke->end_cap);
		s->cap = s->stroke->start_cap;
		fz_stroke_moveto(ctx, s, x, y);
	}
}

static void
fz_dash_lineto(fz_context *ctx, struct sctx *s, float bx, float by, int from_bezier)
{
	float dx, dy, d;
	float total, used, ratio, tail;
	float ax, ay;
	float mx, my;
	float old_bx, old_by;
	int n;
	int dash_cap = s->stroke->dash_cap;

	ax = s->dash_cur.x;
	ay = s->dash_cur.y;
	dx = bx - ax;
	dy = by - ay;
	used = 0;
	tail = 0;
	total = sqrtf(dx * dx + dy * dy);

	/* If a is off screen, bring it onto the screen. First
	 * horizontally... */
	if ((d = s->rect.x0 - ax) > 0)
	{
		if (bx < s->rect.x0)
		{
			/* Entirely off screen */
			tail = total;
			old_bx = bx;
			old_by = by;
			goto adjust_for_tail;
		}
		ax = s->rect.x0;	/* d > 0, dx > 0 */
		goto a_moved_horizontally;
	}
	else if (d < 0 && (d = (s->rect.x1 - ax)) < 0)
	{
		if (bx > s->rect.x1)
		{
			/* Entirely off screen */
			tail = total;
			old_bx = bx;
			old_by = by;
			goto adjust_for_tail;
		}
		ax = s->rect.x1;	/* d < 0, dx < 0 */
a_moved_horizontally:	/* d and dx have the same sign */
		ay += dy * d/dx;
		used = total * d/dx;
		total -= used;
		dx = bx - ax;
		dy = by - ay;
	}
	/* Then vertically... */
	if ((d = s->rect.y0 - ay) > 0)
	{
		if (by < s->rect.y0)
		{
			/* Entirely off screen */
			tail = total;
			old_bx = bx;
			old_by = by;
			goto adjust_for_tail;
		}
		ay = s->rect.y0;	/* d > 0, dy > 0 */
		goto a_moved_vertically;
	}
	else if (d < 0 && (d = (s->rect.y1 - ay)) < 0)
	{
		if (by > s->rect.y1)
		{
			/* Entirely off screen */
			tail = total;
			old_bx = bx;
			old_by = by;
			goto adjust_for_tail;
		}
		ay = s->rect.y1;	/* d < 0, dy < 0 */
a_moved_vertically:	/* d and dy have the same sign */
		ax += dx * d/dy;
		d = total * d/dy;
		total -= d;
		used += d;
		dx = bx - ax;
		dy = by - ay;
	}
	if (used != 0.0f)
	{
		/* Update the position in the dash array */
		if (s->toggle)
		{
			fz_stroke_lineto(ctx, s, ax, ay, from_bezier);
		}
		else
		{
			fz_stroke_flush(ctx, s, s->cap, s->stroke->dash_cap);
			s->cap = s->stroke->dash_cap;
			fz_stroke_moveto(ctx, s, ax, ay);
		}
		used += s->phase;
		n = used/s->dash_total;
		used -= n*s->dash_total;
		if (n & s->dash_len & 1)
			s->toggle = !s->toggle;
		while (used >= s->dash_list[s->offset])
		{
			used -= s->dash_list[s->offset];
			s->offset++;
			if (s->offset == s->dash_len)
				s->offset = 0;
			s->toggle = !s->toggle;
		}
		if (s->toggle)
		{
			fz_stroke_lineto(ctx, s, ax, ay, from_bezier);
		}
		else
		{
			fz_stroke_flush(ctx, s, s->cap, s->stroke->dash_cap);
			s->cap = s->stroke->dash_cap;
			fz_stroke_moveto(ctx, s, ax, ay);
		}
		s->phase = used;
		used = 0;
	}

	/* Now if bx is off screen, bring it back */
	if ((d = bx - s->rect.x0) < 0)
	{
		old_bx = bx;
		old_by = by;
		bx = s->rect.x0;	/* d < 0, dx < 0 */
		goto b_moved_horizontally;
	}
	else if (d > 0 && (d = (bx - s->rect.x1)) > 0)
	{
		old_bx = bx;
		old_by = by;
		bx = s->rect.x1;	/* d > 0, dx > 0 */
b_moved_horizontally:	/* d and dx have the same sign */
		by -= dy * d/dx;
		tail = total * d/dx;
		total -= tail;
		dx = bx - ax;
		dy = by - ay;
	}
	/* Then vertically... */
	if ((d = by - s->rect.y0) < 0)
	{
		old_bx = bx;
		old_by = by;
		by = s->rect.y0;	/* d < 0, dy < 0 */
		goto b_moved_vertically;
	}
	else if (d > 0 && (d = (by - s->rect.y1)) > 0)
	{
		float t;
		old_bx = bx;
		old_by = by;
		by = s->rect.y1;	/* d > 0, dy > 0 */
b_moved_vertically:	/* d and dy have the same sign */
		bx -= dx * d/dy;
		t = total * d/dy;
		tail += t;
		total -= t;
		dx = bx - ax;
		dy = by - ay;
	}

	while (total - used > s->dash_list[s->offset] - s->phase)
	{
		used += s->dash_list[s->offset] - s->phase;
		ratio = used / total;
		mx = ax + ratio * dx;
		my = ay + ratio * dy;

		if (s->toggle)
		{
			fz_stroke_lineto(ctx, s, mx, my, from_bezier);
		}
		else
		{
			fz_stroke_flush(ctx, s, s->cap, dash_cap);
			s->cap = dash_cap;
			fz_stroke_moveto(ctx, s, mx, my);
		}

		s->toggle = !s->toggle;
		s->phase = 0;
		s->offset ++;
		if (s->offset == s->dash_len)
			s->offset = 0;
	}

	s->phase += total - used;

	if (tail == 0.0f)
	{
		s->dash_cur.x = bx;
		s->dash_cur.y = by;

		if (s->toggle)
		{
			fz_stroke_lineto(ctx, s, bx, by, from_bezier);
		}
	}
	else
	{
adjust_for_tail:
		s->dash_cur.x = old_bx;
		s->dash_cur.y = old_by;
		/* Update the position in the dash array */
		if (s->toggle)
		{
			fz_stroke_lineto(ctx, s, old_bx, old_by, from_bezier);
		}
		else
		{
			fz_stroke_flush(ctx, s, s->cap, dash_cap);
			s->cap = dash_cap;
			fz_stroke_moveto(ctx, s, old_bx, old_by);
		}
		tail += s->phase;
		n = tail/s->dash_total;
		tail -= n*s->dash_total;
		if (n & s->dash_len & 1)
			s->toggle = !s->toggle;
		while (tail > s->dash_list[s->offset])
		{
			tail -= s->dash_list[s->offset];
			s->offset++;
			if (s->offset == s->dash_len)
				s->offset = 0;
			s->toggle = !s->toggle;
		}
		if (s->toggle)
		{
			fz_stroke_lineto(ctx, s, old_bx, old_by, from_bezier);
		}
		else
		{
			fz_stroke_flush(ctx, s, s->cap, dash_cap);
			s->cap = dash_cap;
			fz_stroke_moveto(ctx, s, old_bx, old_by);
		}
		s->phase = tail;
	}
}

static void
fz_dash_bezier(fz_context *ctx, struct sctx *s,
	float xa, float ya,
	float xb, float yb,
	float xc, float yc,
	float xd, float yd, int depth)
{
	float dmax;
	float xab, yab;
	float xbc, ybc;
	float xcd, ycd;
	float xabc, yabc;
	float xbcd, ybcd;
	float xabcd, yabcd;

	/* termination check */
	dmax = fz_abs(xa - xb);
	dmax = fz_max(dmax, fz_abs(ya - yb));
	dmax = fz_max(dmax, fz_abs(xd - xc));
	dmax = fz_max(dmax, fz_abs(yd - yc));
	if (dmax < s->flatness || depth >= MAX_DEPTH)
	{
		fz_dash_lineto(ctx, s, xd, yd, 1);
		return;
	}

	xab = xa + xb;
	yab = ya + yb;
	xbc = xb + xc;
	ybc = yb + yc;
	xcd = xc + xd;
	ycd = yc + yd;

	xabc = xab + xbc;
	yabc = yab + ybc;
	xbcd = xbc + xcd;
	ybcd = ybc + ycd;

	xabcd = xabc + xbcd;
	yabcd = yabc + ybcd;

	xab *= 0.5f; yab *= 0.5f;
	/* xbc *= 0.5f; ybc *= 0.5f; */
	xcd *= 0.5f; ycd *= 0.5f;

	xabc *= 0.25f; yabc *= 0.25f;
	xbcd *= 0.25f; ybcd *= 0.25f;

	xabcd *= 0.125f; yabcd *= 0.125f;

	fz_dash_bezier(ctx, s, xa, ya, xab, yab, xabc, yabc, xabcd, yabcd, depth + 1);
	fz_dash_bezier(ctx, s, xabcd, yabcd, xbcd, ybcd, xcd, ycd, xd, yd, depth + 1);
}

static void
fz_dash_quad(fz_context *ctx, struct sctx *s,
	float xa, float ya,
	float xb, float yb,
	float xc, float yc, int depth)
{
	float dmax;
	float xab, yab;
	float xbc, ybc;
	float xabc, yabc;

	/* termination check */
	dmax = fz_abs(xa - xb);
	dmax = fz_max(dmax, fz_abs(ya - yb));
	dmax = fz_max(dmax, fz_abs(xc - xb));
	dmax = fz_max(dmax, fz_abs(yc - yb));
	if (dmax < s->flatness || depth >= MAX_DEPTH)
	{
		fz_dash_lineto(ctx, s, xc, yc, 1);
		return;
	}

	xab = xa + xb;
	yab = ya + yb;
	xbc = xb + xc;
	ybc = yb + yc;

	xabc = xab + xbc;
	yabc = yab + ybc;

	xab *= 0.5f; yab *= 0.5f;
	xbc *= 0.5f; ybc *= 0.5f;

	xabc *= 0.25f; yabc *= 0.25f;

	fz_dash_quad(ctx, s, xa, ya, xab, yab, xabc, yabc, depth + 1);
	fz_dash_quad(ctx, s, xabc, yabc, xbc, ybc, xc, yc, depth + 1);
}

static void
dash_moveto(fz_context *ctx, void *s_, float x, float y)
{
	sctx *s = (sctx *)s_;

	fz_dash_moveto(ctx, s, x, y);
	s->dash_beg.x = s->cur.x = x;
	s->dash_beg.y = s->cur.y = y;
}

static void
dash_lineto(fz_context *ctx, void *s_, float x, float y)
{
	sctx *s = (sctx *)s_;

	fz_dash_lineto(ctx, s, x, y, 0);
	s->cur.x = x;
	s->cur.y = y;
}

static void
dash_curveto(fz_context *ctx, void *s_, float x1, float y1, float x2, float y2, float x3, float y3)
{
	sctx *s = (sctx *)s_;

	fz_dash_bezier(ctx, s, s->cur.x, s->cur.y, x1, y1, x2, y2, x3, y3, 0);
	s->cur.x = x3;
	s->cur.y = y3;
}

static void
dash_quadto(fz_context *ctx, void *s_, float x1, float y1, float x2, float y2)
{
	sctx *s = (sctx *)s_;

	fz_dash_quad(ctx, s, s->cur.x, s->cur.y, x1, y1, x2, y2, 0);
	s->cur.x = x2;
	s->cur.y = y2;
}

static void
dash_close(fz_context *ctx, void *s_)
{
	sctx *s = (sctx *)s_;

	fz_dash_lineto(ctx, s, s->dash_beg.x, s->dash_beg.y, 0);
	s->cur.x = s->dash_beg.x;
	s->cur.y = s->dash_beg.y;
}

static const fz_path_processor dash_proc =
{
	dash_moveto,
	dash_lineto,
	dash_curveto,
	dash_close,
	dash_quadto
};

void
fz_flatten_dash_path(fz_context *ctx, fz_gel *gel, fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, float flatness, float linewidth)
{
	struct sctx s;
	float phase_len, max_expand;
	int i;
	fz_matrix inv;

	s.stroke = stroke;
	s.gel = gel;
	s.ctm = ctm;
	s.flatness = flatness;

	s.linejoin = stroke->linejoin;
	s.linewidth = linewidth * 0.5f;
	s.miterlimit = stroke->miterlimit;
	s.sn = 0;
	s.dot = 0;

	s.dash_list = stroke->dash_list;
	s.dash_phase = stroke->dash_phase;
	s.dash_len = stroke->dash_len;
	s.toggle = 0;
	s.offset = 0;
	s.phase = 0;

	s.cap = stroke->start_cap;

	phase_len = 0;
	for (i = 0; i < stroke->dash_len; i++)
		phase_len += stroke->dash_list[i];
	if (stroke->dash_len > 0 && phase_len == 0)
		return;
	fz_gel_scissor(ctx, gel, &s.rect);
	if (fz_try_invert_matrix(&inv, ctm))
		return;
	fz_transform_rect(&s.rect, &inv);
	s.rect.x0 -= linewidth;
	s.rect.x1 += linewidth;
	s.rect.y0 -= linewidth;
	s.rect.y1 += linewidth;

	max_expand = fz_matrix_max_expansion(ctm);
	if (phase_len < 0.01f || phase_len * max_expand < 0.5f)
	{
		fz_flatten_stroke_path(ctx, gel, path, stroke, ctm, flatness, linewidth);
		return;
	}
	s.dash_total = phase_len;

	s.cur.x = s.cur.y = 0;
	fz_process_path(ctx, &dash_proc, &s, path);
	fz_stroke_flush(ctx, &s, s.cap, stroke->end_cap);
}
