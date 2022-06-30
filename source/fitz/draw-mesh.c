// Copyright (C) 2004-2021 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 1305 Grant Avenue - Suite 200, Novato,
// CA 94945, U.S.A., +1(415)492-9861, for further information.

#include "mupdf/fitz.h"

#include "color-imp.h"
#include "draw-imp.h"
#include "pixmap-imp.h"

#include <assert.h>
#include <math.h>

enum { MAXN = 2 + FZ_MAX_COLORS };

static void paint_scan(fz_pixmap *FZ_RESTRICT pix, int y, int fx0, int fx1, int cx0, int cx1, const int *FZ_RESTRICT v0, const int *FZ_RESTRICT v1, int n)
{
	unsigned char *p;
	int c[MAXN], dc[MAXN];
	int k, w;
	float div, mul;
	int x0, x1, pa;

	/* Ensure that fx0 is left edge, and fx1 is right */
	if (fx0 > fx1)
	{
		const int *v;
		int t = fx0; fx0 = fx1; fx1 = t;
		v = v0; v0 = v1; v1 = v;
	}
	else if (fx0 == fx1)
		return;

	/* Clip fx0, fx1 to range */
	if (fx0 >= cx1)
		return;
	if (fx1 <= cx0)
		return;
	x0 = (fx0 > cx0 ? fx0 : cx0);
	x1 = (fx1 < cx1 ? fx1 : cx1);

	w = x1 - x0;
	if (w == 0)
		return;

	div = 1.0f / (fx1 - fx0);
	mul = (x0 - fx0);
	for (k = 0; k < n; k++)
	{
		dc[k] = (v1[k] - v0[k]) * div;
		c[k] = v0[k] + dc[k] * mul;
	}

	p = pix->samples + ((x0 - pix->x) * pix->n) + ((y - pix->y) * pix->stride);
	pa = pix->alpha;
	do
	{
		for (k = 0; k < n; k++)
		{
			*p++ = c[k]>>16;
			c[k] += dc[k];
		}
		if (pa)
			*p++ = 255;
	}
	while (--w);
}

typedef struct
{
	float x;
	float dx;
	int v[2*MAXN];
} edge_data;

static inline void prepare_edge(const float *FZ_RESTRICT vtop, const float *FZ_RESTRICT vbot, edge_data *FZ_RESTRICT edge, float y, int n)
{
	float r = 1.0f / (vbot[1] - vtop[1]);
	float t = (y - vtop[1]) * r;
	float diff = vbot[0] - vtop[0];
	int i;

	edge->x = vtop[0] + diff * t;
	edge->dx = diff * r;

	for (i = 0; i < n; i++)
	{
		diff = vbot[i+2] - vtop[i+2];
		edge->v[i] = (int)(65536.0f * (vtop[i+2] + diff * t));
		edge->v[i+MAXN] = (int)(65536.0f * diff * r);
	}
}

static inline void step_edge(edge_data *edge, int n)
{
	int i;

	edge->x += edge->dx;

	for (i = 0; i < n; i++)
	{
		edge->v[i] += edge->v[i + MAXN];
	}
}

static void
fz_paint_triangle(fz_pixmap *pix, float *v[3], int n, fz_irect bbox)
{
	edge_data e0, e1;
	int top, mid, bot;
	float y, y1;
	int minx, maxx;

	top = bot = 0;
	if (v[1][1] < v[0][1]) top = 1; else bot = 1;
	if (v[2][1] < v[top][1]) top = 2;
	else if (v[2][1] > v[bot][1]) bot = 2;
	if (v[top][1] == v[bot][1]) return;

	/* Test if the triangle is completely outside the scissor rect */
	if (v[bot][1] < bbox.y0) return;
	if (v[top][1] > bbox.y1) return;

	/* Magic! Ensure that mid/top/bot are all different */
	mid = 3^top^bot;

	assert(top != bot && top != mid && mid != bot);

	minx = fz_maxi(bbox.x0, pix->x);
	maxx = fz_mini(bbox.x1, pix->x + pix->w);

	y = ceilf(fz_max(bbox.y0, v[top][1]));
	y1 = ceilf(fz_min(bbox.y1, v[mid][1]));

	n -= 2;
	prepare_edge(v[top], v[bot], &e0, y, n);
	if (y < y1)
	{
		prepare_edge(v[top], v[mid], &e1, y, n);

		do
		{
			paint_scan(pix, y, (int)e0.x, (int)e1.x, minx, maxx, &e0.v[0], &e1.v[0], n);
			step_edge(&e0, n);
			step_edge(&e1, n);
			y ++;
		}
		while (y < y1);
	}

	y1 = ceilf(fz_min(bbox.y1, v[bot][1]));
	if (y < y1)
	{
		prepare_edge(v[mid], v[bot], &e1, y, n);

		do
		{
			paint_scan(pix, y, (int)e0.x, (int)e1.x, minx, maxx, &e0.v[0], &e1.v[0], n);
			y ++;
			if (y >= y1)
				break;
			step_edge(&e0, n);
			step_edge(&e1, n);
		}
		while (1);
	}
}

struct paint_tri_data
{
	const fz_shade *shade;
	fz_pixmap *dest;
	fz_irect bbox;
	fz_color_converter cc;
};

static void
prepare_mesh_vertex(fz_context *ctx, void *arg, fz_vertex *v, const float *input)
{
	struct paint_tri_data *ptd = (struct paint_tri_data *)arg;
	const fz_shade *shade = ptd->shade;
	fz_pixmap *dest = ptd->dest;
	float *output = v->c;
	int i;

	if (shade->use_function)
	{
		float f = input[0];
		if (shade->type >= 4 && shade->type <= 7)
			f = (f - shade->u.m.c0[0]) / (shade->u.m.c1[0] - shade->u.m.c0[0]);
		output[0] = f * 255;
	}
	else
	{
		int n = fz_colorspace_n(ctx, dest->colorspace);
		int a = dest->alpha;
		int m = dest->n - a;
		if (ptd->cc.convert)
			ptd->cc.convert(ctx, &ptd->cc, input, output);
		for (i = 0; i < n; i++)
			output[i] *= 255;
		for (; i < m; i++)
			output[i] = 0;
		if (a)
			output[i] = 255;
	}
}

static void
do_paint_tri(fz_context *ctx, void *arg, fz_vertex *av, fz_vertex *bv, fz_vertex *cv)
{
	struct paint_tri_data *ptd = (struct paint_tri_data *)arg;
	float *vertices[3];
	fz_pixmap *dest;

	vertices[0] = (float *)av;
	vertices[1] = (float *)bv;
	vertices[2] = (float *)cv;

	dest = ptd->dest;
	fz_paint_triangle(dest, vertices, 2 + dest->n - dest->alpha, ptd->bbox);
}

struct fz_shade_color_cache
{
	fz_colorspace *src;
	fz_colorspace *dst;
	fz_color_params params;
	int full;
	fz_color_converter cached;
	fz_colorspace *src2;
	fz_colorspace *dst2;
	fz_color_params params2;
	int full2;
	fz_color_converter cached2;
};

void
fz_drop_shade_color_cache(fz_context *ctx, fz_shade_color_cache *cache)
{
	if (cache == NULL)
		return;

	fz_drop_colorspace(ctx, cache->src);
	fz_drop_colorspace(ctx, cache->dst);
	if (cache->full)
		fz_fin_cached_color_converter(ctx, &cache->cached);

	fz_drop_colorspace(ctx, cache->src2);
	fz_drop_colorspace(ctx, cache->dst2);
	if (cache->full2)
		fz_drop_color_converter(ctx, &cache->cached2);

	fz_free(ctx, cache);
}

void
fz_paint_shade(fz_context *ctx, fz_shade *shade, fz_colorspace *colorspace, fz_matrix ctm, fz_pixmap *dest, fz_color_params color_params, fz_irect bbox, const fz_overprint *eop, fz_shade_color_cache **color_cache)
{
	unsigned char clut[256][FZ_MAX_COLORS];
	fz_pixmap *temp = NULL;
	fz_pixmap *conv = NULL;
	fz_color_converter cc = { 0 };
	float color[FZ_MAX_COLORS];
	struct paint_tri_data ptd = { 0 };
	int i, k;
	fz_matrix local_ctm;
	fz_shade_color_cache *cache = NULL;
	int recache = 0;
	int recache2 = 0;

	fz_var(temp);
	fz_var(conv);
	fz_var(recache);
	fz_var(recache2);
	fz_var(cc);

	if (colorspace == NULL)
		colorspace = shade->colorspace;

	if (color_cache)
	{
		cache = *color_cache;
		if (cache == NULL)
			*color_cache = cache = fz_malloc_struct(ctx, fz_shade_color_cache);
	}

	fz_try(ctx)
	{
		local_ctm = fz_concat(shade->matrix, ctm);

		if (shade->use_function)
		{
			/* We need to use alpha = 1 here, because the shade might not fill the bbox. */
			temp = fz_new_pixmap_with_bbox(ctx, fz_device_gray(ctx), bbox, NULL, 1);
			fz_clear_pixmap(ctx, temp);
		}
		else
		{
			temp = dest;
		}

		ptd.dest = temp;
		ptd.shade = shade;
		ptd.bbox = bbox;

		if (temp->colorspace)
		{
			if (cache && cache->full && cache->src == colorspace && cache->dst == temp->colorspace &&
				cache->params.op == color_params.op &&
				cache->params.opm == color_params.opm &&
				cache->params.ri == color_params.ri)
			{
				ptd.cc = cache->cached;
				cache->full = 0;
			}
			else
				fz_init_cached_color_converter(ctx, &ptd.cc, colorspace, temp->colorspace, NULL, color_params);

			/* Drop the existing contents of the cache. */
			if (cache)
			{
				fz_drop_colorspace(ctx, cache->src);
				cache->src = NULL;
				fz_drop_colorspace(ctx, cache->dst);
				cache->dst = NULL;
				if (cache->full)
					fz_fin_cached_color_converter(ctx, &cache->cached);
				cache->full = 0;

				/* Remember that we can put stuff back into the cache. */
				recache = 1;
			}
		}

		fz_process_shade(ctx, shade, local_ctm, fz_rect_from_irect(bbox), prepare_mesh_vertex, &do_paint_tri, &ptd);

		if (shade->use_function)
		{
			/* If the shade is defined in a deviceN (or separation,
			 * which is the same internally to MuPDF) space, then
			 * we need to render it in deviceN before painting it
			 * to the destination. If not, we are free to render it
			 * direct to the target. */
			if (fz_colorspace_is_device_n(ctx, colorspace))
			{
				/* We've drawn it as greyscale, with the values being
				 * the input to the function. Now make DevN version
				 * by mapping that greyscale through the function.
				 * This seems inefficient, but it's actually required,
				 * because we need to apply the function lookup POST
				 * interpolation in the do_paint_tri routines, not
				 * before it to avoid problems with some test files
				 * (tests/GhentV3.0/061_Shading_x1a.pdf for example).
				 */
				unsigned char *s = temp->samples;
				unsigned char *d;
				int hh = temp->h;
				int n = fz_colorspace_n(ctx, colorspace);

				/* alpha = 1 here for the same reason as earlier */
				conv = fz_new_pixmap_with_bbox(ctx, colorspace, bbox, NULL, 1);
				d = conv->samples;
				while (hh--)
				{
					int len = temp->w;
					while (len--)
					{
						int v = *s++;
						int a = *s++;
						const float *f = shade->function[v];
						for (k = 0; k < n; k++)
							*d++ = fz_clampi(255 * f[k], 0, 255);
						*d++ = a;
					}
					d += conv->stride - conv->w * (size_t)conv->n;
					s += temp->stride - temp->w * (size_t)temp->n;
				}
				fz_drop_pixmap(ctx, temp);
				temp = conv;
				conv = NULL;

				/* Now Change from our device_n colorspace into the target colorspace/spots. */
				conv = fz_clone_pixmap_area_with_different_seps(ctx, temp, NULL, dest->colorspace, dest->seps, color_params, NULL);
			}
			else
			{
				unsigned char *s = temp->samples;
				unsigned char *d;
				int da;
				int sa = temp->alpha;
				int hh = temp->h;
				int cn = fz_colorspace_n(ctx, colorspace);
				int m = dest->n - dest->alpha;
				int n = fz_colorspace_n(ctx, dest->colorspace);

				if (dest->colorspace)
				{
					if (cache && cache->full2 && cache->src2 == colorspace && cache->dst2 == dest->colorspace &&
						cache->params2.op == color_params.op &&
						cache->params2.opm == color_params.opm &&
						cache->params2.ri == color_params.ri)
					{
						cc = cache->cached2;
						cache->full2 = 0;
					}
					else
						fz_find_color_converter(ctx, &cc, colorspace, dest->colorspace, NULL, color_params);

					/* Drop the existing contents of the cache */
					if (cache)
					{
						fz_drop_colorspace(ctx, cache->src2);
						cache->src2 = NULL;
						fz_drop_colorspace(ctx, cache->dst2);
						cache->dst2 = NULL;
						if (cache->full2)
							fz_drop_color_converter(ctx, &cache->cached2);
						cache->full2 = 0;

						/* Remember that we can put stuff back into the cache. */
						recache2 = 1;
					}
					for (i = 0; i < 256; i++)
					{
						cc.convert(ctx, &cc, shade->function[i], color);
						for (k = 0; k < n; k++)
							clut[i][k] = color[k] * 255;
						for (; k < m; k++)
							clut[i][k] = 0;
						clut[i][k] = shade->function[i][cn] * 255;
					}
				}
				else
				{
					for (i = 0; i < 256; i++)
					{
						for (k = 0; k < m; k++)
							clut[i][k] = 0;
						clut[i][k] = shade->function[i][cn] * 255;
					}
				}

				conv = fz_new_pixmap_with_bbox(ctx, dest->colorspace, bbox, dest->seps, 1);
				d = conv->samples;
				da = conv->alpha;
				while (hh--)
				{
					int len = temp->w;
					while (len--)
					{
						int v = *s++;
						int a = (da ? clut[v][conv->n - 1] : 255);
						if (sa)
							a = fz_mul255(*s++, a);
						for (k = 0; k < conv->n - da; k++)
							*d++ = fz_mul255(clut[v][k], a);
						if (da)
							*d++ = a;
					}
					d += conv->stride - conv->w * (size_t)conv->n;
					s += temp->stride - temp->w * (size_t)temp->n;
				}
			}
			fz_paint_pixmap_with_overprint(dest, conv, eop);
		}
	}
	fz_always(ctx)
	{
		if (recache)
		{
			cache->src = fz_keep_colorspace(ctx, colorspace);
			cache->dst = fz_keep_colorspace(ctx, temp->colorspace);
			cache->params = color_params;
			cache->cached = ptd.cc;
			cache->full = 1;
		}
		else
			fz_fin_cached_color_converter(ctx, &ptd.cc);
		if (shade->use_function)
		{
			if (recache2)
			{
				cache->src2 = fz_keep_colorspace(ctx, colorspace);
				cache->dst2 = fz_keep_colorspace(ctx, dest->colorspace);
				cache->params2 = color_params;
				cache->cached2 = cc;
				cache->full2 = 1;
			}
			else
				fz_drop_color_converter(ctx, &cc);
			fz_drop_pixmap(ctx, temp);
			fz_drop_pixmap(ctx, conv);
		}
	}
	fz_catch(ctx)
		fz_rethrow(ctx);
}
