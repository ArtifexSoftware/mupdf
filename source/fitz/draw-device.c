#include "mupdf/fitz.h"
#include "draw-imp.h"

#define STACK_SIZE 96

/* Enable the following to attempt to support knockout and/or isolated
 * blending groups. */
#define ATTEMPT_KNOCKOUT_AND_ISOLATED

/* Enable the following to help debug group blending. */
#undef DUMP_GROUP_BLENDS

/* Enable the following to help debug graphics stack pushes/pops */
#undef DUMP_STACK_CHANGES

typedef struct fz_draw_device_s fz_draw_device;

enum {
	FZ_DRAWDEV_FLAGS_TYPE3 = 1,
};

typedef struct fz_draw_state_s fz_draw_state;

struct fz_draw_state_s {
	fz_irect scissor;
	fz_pixmap *dest;
	fz_pixmap *mask;
	fz_pixmap *shape;
	int blendmode;
	int luminosity;
	int id;
	float alpha;
	fz_matrix ctm;
	float xstep, ystep;
	fz_irect area;
};

struct fz_draw_device_s
{
	fz_device super;
	fz_gel *gel;
	int flags;
	int top;
	fz_scale_cache *cache_x;
	fz_scale_cache *cache_y;
	fz_draw_state *stack;
	int stack_cap;
	fz_draw_state init_stack[STACK_SIZE];
};

#ifdef DUMP_GROUP_BLENDS
static int group_dump_count = 0;

static void fz_dump_blend(fz_context *ctx, fz_pixmap *pix, const char *s)
{
	char name[80];

	if (!pix)
		return;

	sprintf(name, "dump%02d.png", group_dump_count);
	if (s)
		printf("%s%02d", s, group_dump_count);
	group_dump_count++;

	fz_save_pixmap_as_png(ctx, pix, name, (pix->n > 1));
}

static void dump_spaces(int x, const char *s)
{
	int i;
	for (i = 0; i < x; i++)
		printf(" ");
	printf("%s", s);
}

#endif

#ifdef DUMP_STACK_CHANGES
#define STACK_PUSHED(A) stack_change(ctx, dev, ">" ## A)
#define STACK_POPPED(A) stack_change(ctx, dev, "<" ## A)
#define STACK_CONVERT(A) stack_change(ctx, dev, A)

static void stack_change(fz_context *ctx, fz_draw_device *dev, char *s)
{
	int depth = dev->top;
	int n;

	if (*s != '<')
		depth--;
	n = depth;
	while (n--)
		fputc(' ', stderr);
	fprintf(stderr, "%s (%d)\n", s, depth);
}
#else
#define STACK_PUSHED(A) do {} while (0)
#define STACK_POPPED(A) do {} while (0)
#define STACK_CONVERT(A) do {} while (0)
#endif

static void fz_grow_stack(fz_context *ctx, fz_draw_device *dev)
{
	int max = dev->stack_cap * 2;
	fz_draw_state *stack;

	if (dev->stack == &dev->init_stack[0])
	{
		stack = Memento_label(fz_malloc_array(ctx, max, sizeof *stack), "draw device stack");
		memcpy(stack, dev->stack, sizeof(*stack) * dev->stack_cap);
	}
	else
	{
		stack = fz_resize_array(ctx, dev->stack, max, sizeof(*stack));
	}
	dev->stack = stack;
	dev->stack_cap = max;
}

/* 'Push' the stack. Returns a pointer to the current state, with state[1]
 * already having been initialised to contain the same thing. Simply
 * change any contents of state[1] that you want to and continue. */
static fz_draw_state *
push_stack(fz_context *ctx, fz_draw_device *dev)
{
	fz_draw_state *state;

	if (dev->top == dev->stack_cap-1)
		fz_grow_stack(ctx, dev);
	state = &dev->stack[dev->top];
	dev->top++;
	memcpy(&state[1], state, sizeof(*state));
	return state;
}

static void emergency_pop_stack(fz_context *ctx, fz_draw_device *dev, fz_draw_state *state)
{
	if (state[1].mask != state[0].mask)
		fz_drop_pixmap(ctx, state[1].mask);
	if (state[1].dest != state[0].dest)
		fz_drop_pixmap(ctx, state[1].dest);
	if (state[1].shape != state[0].shape)
		fz_drop_pixmap(ctx, state[1].shape);
	dev->top--;
	STACK_POPPED("emergency");
	fz_rethrow(ctx);
}

static fz_draw_state *
fz_knockout_begin(fz_context *ctx, fz_draw_device *dev)
{
	fz_irect bbox;
	fz_pixmap *dest, *shape;
	fz_draw_state *state = &dev->stack[dev->top];
	int isolated = state->blendmode & FZ_BLEND_ISOLATED;

	if ((state->blendmode & FZ_BLEND_KNOCKOUT) == 0)
		return state;

	state = push_stack(ctx, dev);
	STACK_PUSHED("knockout");

	fz_pixmap_bbox(ctx, state->dest, &bbox);
	fz_intersect_irect(&bbox, &state->scissor);
	dest = fz_new_pixmap_with_bbox(ctx, state->dest->colorspace, &bbox);

	if (isolated)
	{
		fz_clear_pixmap(ctx, dest);
	}
	else
	{
		/* Find the last but one destination to copy */
		int i = dev->top-1; /* i = the one on entry (i.e. the last one) */
		fz_pixmap *prev = state->dest;
		while (i > 0)
		{
			prev = dev->stack[--i].dest;
			if (prev != state->dest)
				break;
		}
		if (prev)
			fz_copy_pixmap_rect(ctx, dest, prev, &bbox);
		else
			fz_clear_pixmap(ctx, dest);
	}

	if ((state->blendmode & FZ_BLEND_MODEMASK) == 0 && isolated)
	{
		/* We can render direct to any existing shape plane. If there
		 * isn't one, we don't need to make one. */
		shape = state->shape;
	}
	else
	{
		shape = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
		fz_clear_pixmap(ctx, shape);
	}
#ifdef DUMP_GROUP_BLENDS
	dump_spaces(dev->top-1, "Knockout begin\n");
#endif
	state[1].scissor = bbox;
	state[1].dest = dest;
	state[1].shape = shape;
	state[1].blendmode &= ~FZ_BLEND_MODEMASK;

	return &state[1];
}

static void fz_knockout_end(fz_context *ctx, fz_draw_device *dev)
{
	fz_draw_state *state;
	int blendmode;
	int isolated;

	if (dev->top == 0)
	{
		fz_warn(ctx, "unexpected knockout end");
		return;
	}
	state = &dev->stack[--dev->top];
	STACK_POPPED("knockout");
	if ((state[0].blendmode & FZ_BLEND_KNOCKOUT) == 0)
		return;

	blendmode = state->blendmode & FZ_BLEND_MODEMASK;
	isolated = state->blendmode & FZ_BLEND_ISOLATED;

#ifdef DUMP_GROUP_BLENDS
	dump_spaces(dev->top, "");
	fz_dump_blend(ctx, state[1].dest, "Knockout end: blending ");
	if (state[1].shape)
		fz_dump_blend(ctx, state[1].shape, "/");
	fz_dump_blend(ctx, state[0].dest, " onto ");
	if (state[0].shape)
		fz_dump_blend(ctx, state[0].shape, "/");
	if (blendmode != 0)
		printf(" (blend %d)", blendmode);
	if (isolated != 0)
		printf(" (isolated)");
	printf(" (knockout)");
#endif
	if ((blendmode == 0) && (state[0].shape == state[1].shape))
		fz_paint_pixmap(state[0].dest, state[1].dest, 255);
	else
		fz_blend_pixmap(state[0].dest, state[1].dest, 255, blendmode, isolated, state[1].shape);

	/* The following test should not be required, but just occasionally
	 * errors can cause the stack to get out of sync, and this saves our
	 * bacon. */
	if (state[0].dest != state[1].dest)
		fz_drop_pixmap(ctx, state[1].dest);
	if (state[0].shape != state[1].shape)
	{
		if (state[0].shape)
			fz_paint_pixmap(state[0].shape, state[1].shape, 255);
		fz_drop_pixmap(ctx, state[1].shape);
	}
#ifdef DUMP_GROUP_BLENDS
	fz_dump_blend(ctx, state[0].dest, " to get ");
	if (state[0].shape)
		fz_dump_blend(ctx, state[0].shape, "/");
	printf("\n");
#endif
}

static void
fz_draw_fill_path(fz_context *ctx, fz_device *devp, const fz_path *path, int even_odd, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_gel *gel = dev->gel;

	float expansion = fz_matrix_expansion(ctm);
	float flatness = 0.3f / expansion;
	unsigned char colorbv[FZ_MAX_COLORS + 1];
	float colorfv[FZ_MAX_COLORS];
	fz_irect bbox;
	int i;
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model = state->dest->colorspace;

	if (model == NULL)
		model = fz_device_gray(ctx);

	if (flatness < 0.001f)
		flatness = 0.001f;

	fz_reset_gel(ctx, gel, &state->scissor);
	fz_flatten_fill_path(ctx, gel, path, ctm, flatness);
	fz_sort_gel(ctx, gel);

	fz_intersect_irect(fz_bound_gel(ctx, gel, &bbox), &state->scissor);

	if (fz_is_empty_irect(&bbox))
		return;

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		state = fz_knockout_begin(ctx, dev);

	fz_convert_color(ctx, model, colorfv, colorspace, color);
	for (i = 0; i < model->n; i++)
		colorbv[i] = colorfv[i] * 255;
	colorbv[i] = alpha * 255;

	fz_scan_convert(ctx, gel, even_odd, &bbox, state->dest, colorbv);
	if (state->shape)
	{
		fz_reset_gel(ctx, gel, &state->scissor);
		fz_flatten_fill_path(ctx, gel, path, ctm, flatness);
		fz_sort_gel(ctx, gel);

		colorbv[0] = alpha * 255;
		fz_scan_convert(ctx, gel, even_odd, &bbox, state->shape, colorbv);
	}

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		fz_knockout_end(ctx, dev);
}

static void
fz_draw_stroke_path(fz_context *ctx, fz_device *devp, const fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_gel *gel = dev->gel;

	float expansion = fz_matrix_expansion(ctm);
	float flatness = 0.3f / expansion;
	float linewidth = stroke->linewidth;
	unsigned char colorbv[FZ_MAX_COLORS + 1];
	float colorfv[FZ_MAX_COLORS];
	fz_irect bbox;
	int i;
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model = state->dest->colorspace;

	if (model == NULL)
		model = fz_device_gray(ctx);

	if (linewidth * expansion < 0.1f)
		linewidth = 1 / expansion;
	if (flatness < 0.001f)
		flatness = 0.001f;

	fz_reset_gel(ctx, gel, &state->scissor);
	if (stroke->dash_len > 0)
		fz_flatten_dash_path(ctx, gel, path, stroke, ctm, flatness, linewidth);
	else
		fz_flatten_stroke_path(ctx, gel, path, stroke, ctm, flatness, linewidth);
	fz_sort_gel(ctx, gel);

	fz_intersect_irect(fz_bound_gel(ctx, gel, &bbox), &state->scissor);

	if (fz_is_empty_irect(&bbox))
		return;

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		state = fz_knockout_begin(ctx, dev);

	fz_convert_color(ctx, model, colorfv, colorspace, color);
	for (i = 0; i < model->n; i++)
		colorbv[i] = colorfv[i] * 255;
	colorbv[i] = alpha * 255;

	fz_scan_convert(ctx, gel, 0, &bbox, state->dest, colorbv);
	if (state->shape)
	{
		fz_reset_gel(ctx, gel, &state->scissor);
		if (stroke->dash_len > 0)
			fz_flatten_dash_path(ctx, gel, path, stroke, ctm, flatness, linewidth);
		else
			fz_flatten_stroke_path(ctx, gel, path, stroke, ctm, flatness, linewidth);
		fz_sort_gel(ctx, gel);

		colorbv[0] = 255;
		fz_scan_convert(ctx, gel, 0, &bbox, state->shape, colorbv);
	}

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		fz_knockout_end(ctx, dev);
}

static void
fz_draw_clip_path(fz_context *ctx, fz_device *devp, const fz_path *path, int even_odd, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_gel *gel = dev->gel;

	float expansion = fz_matrix_expansion(ctm);
	float flatness = 0.3f / expansion;
	fz_irect bbox;
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model;

	if (flatness < 0.001f)
		flatness = 0.001f;

	fz_reset_gel(ctx, gel, &state->scissor);
	fz_flatten_fill_path(ctx, gel, path, ctm, flatness);
	fz_sort_gel(ctx, gel);

	state = push_stack(ctx, dev);
	STACK_PUSHED("clip path");
	model = state->dest->colorspace;

	fz_intersect_irect(fz_bound_gel(ctx, gel, &bbox), &state->scissor);
	if (scissor)
	{
		fz_irect bbox2;
		fz_intersect_irect(&bbox, fz_irect_from_rect(&bbox2, scissor));
	}

	if (fz_is_empty_irect(&bbox) || fz_is_rect_gel(ctx, gel))
	{
		state[1].scissor = bbox;
		state[1].mask = NULL;
#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top-1, "Clip (rectangular) begin\n");
#endif
		return;
	}

	fz_try(ctx)
	{
		state[1].mask = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
		fz_clear_pixmap(ctx, state[1].mask);
		state[1].dest = fz_new_pixmap_with_bbox(ctx, model, &bbox);
		fz_clear_pixmap(ctx, state[1].dest);
		if (state[1].shape)
		{
			state[1].shape = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
			fz_clear_pixmap(ctx, state[1].shape);
		}

		fz_scan_convert(ctx, gel, even_odd, &bbox, state[1].mask, NULL);

		state[1].blendmode |= FZ_BLEND_ISOLATED;
		state[1].scissor = bbox;
#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top-1, "Clip (non-rectangular) begin\n");
#endif
	}
	fz_catch(ctx)
	{
		emergency_pop_stack(ctx, dev, state);
	}
}

static void
fz_draw_clip_stroke_path(fz_context *ctx, fz_device *devp, const fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_gel *gel = dev->gel;

	float expansion = fz_matrix_expansion(ctm);
	float flatness = 0.3f / expansion;
	float linewidth = stroke->linewidth;
	fz_irect bbox;
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model;

	if (linewidth * expansion < 0.1f)
		linewidth = 1 / expansion;
	if (flatness < 0.001f)
		flatness = 0.001f;

	fz_reset_gel(ctx, gel, &state->scissor);
	if (stroke->dash_len > 0)
		fz_flatten_dash_path(ctx, gel, path, stroke, ctm, flatness, linewidth);
	else
		fz_flatten_stroke_path(ctx, gel, path, stroke, ctm, flatness, linewidth);
	fz_sort_gel(ctx, gel);

	state = push_stack(ctx, dev);
	STACK_PUSHED("clip stroke");
	model = state->dest->colorspace;

	fz_intersect_irect(fz_bound_gel(ctx, gel, &bbox), &state->scissor);
	if (scissor)
	{
		fz_irect bbox2;
		fz_intersect_irect(&bbox, fz_irect_from_rect(&bbox2, scissor));
	}

	fz_try(ctx)
	{
		state[1].mask = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
		fz_clear_pixmap(ctx, state[1].mask);
		state[1].dest = fz_new_pixmap_with_bbox(ctx, model, &bbox);
		fz_clear_pixmap(ctx, state[1].dest);
		if (state->shape)
		{
			state[1].shape = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
			fz_clear_pixmap(ctx, state[1].shape);
		}

		if (!fz_is_empty_irect(&bbox))
			fz_scan_convert(ctx, gel, 0, &bbox, state[1].mask, NULL);

		state[1].blendmode |= FZ_BLEND_ISOLATED;
		state[1].scissor = bbox;
#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top-1, "Clip (stroke) begin\n");
#endif
	}
	fz_catch(ctx)
	{
		emergency_pop_stack(ctx, dev, state);
	}
}

static void
draw_glyph(unsigned char *colorbv, fz_pixmap *dst, fz_glyph *glyph,
	int xorig, int yorig, const fz_irect *scissor)
{
	unsigned char *dp;
	fz_irect bbox, bbox2;
	int x, y, w, h;
	int skip_x, skip_y;
	fz_pixmap *msk;

	fz_glyph_bbox_no_ctx(glyph, &bbox);
	fz_translate_irect(&bbox, xorig, yorig);
	fz_intersect_irect(&bbox, scissor); /* scissor < dst */

	if (fz_is_empty_irect(fz_intersect_irect(&bbox, fz_pixmap_bbox_no_ctx(dst, &bbox2))))
		return;

	x = bbox.x0;
	y = bbox.y0;
	w = bbox.x1 - bbox.x0;
	h = bbox.y1 - bbox.y0;

	skip_x = x - glyph->x - xorig;
	skip_y = y - glyph->y - yorig;

	dp = dst->samples + (unsigned int)(((y - dst->y) * dst->w + (x - dst->x)) * dst->n);

	msk = glyph->pixmap;
	if (msk == NULL)
	{
		fz_paint_glyph(colorbv, dst, dp, glyph, w, h, skip_x, skip_y);
	}
	else
	{
		unsigned char *mp = msk->samples + skip_y * msk->w + skip_x;
		while (h--)
		{
			if (dst->colorspace)
				fz_paint_span_with_color(dp, mp, dst->n, w, colorbv);
			else
				fz_paint_span(dp, mp, 1, w, 255);
			dp += dst->w * dst->n;
			mp += msk->w;
		}
	}
}

static void
fz_draw_fill_text(fz_context *ctx, fz_device *devp, const fz_text *text, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model = state->dest->colorspace;
	unsigned char colorbv[FZ_MAX_COLORS + 1];
	unsigned char shapebv;
	float colorfv[FZ_MAX_COLORS];
	fz_text_span *span;
	int i;

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		state = fz_knockout_begin(ctx, dev);

	fz_convert_color(ctx, model, colorfv, colorspace, color);
	for (i = 0; i < model->n; i++)
		colorbv[i] = colorfv[i] * 255;
	colorbv[i] = alpha * 255;
	shapebv = 255;

	for (span = text->head; span; span = span->next)
	{
		fz_matrix tm, trm;
		fz_glyph *glyph;
		int gid;

		tm = span->trm;

		for (i = 0; i < span->len; i++)
		{
			gid = span->items[i].gid;
			if (gid < 0)
				continue;

			tm.e = span->items[i].x;
			tm.f = span->items[i].y;
			fz_concat(&trm, &tm, ctm);

			glyph = fz_render_glyph(ctx, span->font, gid, &trm, model, &state->scissor);
			if (glyph)
			{
				fz_pixmap *pixmap = glyph->pixmap;
				int x = floorf(trm.e);
				int y = floorf(trm.f);
				if (pixmap == NULL || pixmap->n == 1)
				{
					draw_glyph(colorbv, state->dest, glyph, x, y, &state->scissor);
					if (state->shape)
						draw_glyph(&shapebv, state->shape, glyph, x, y, &state->scissor);
				}
				else
				{
					fz_matrix mat;
					mat.a = pixmap->w; mat.b = mat.c = 0; mat.d = pixmap->h;
					mat.e = x + pixmap->x; mat.f = y + pixmap->y;
					fz_paint_image(state->dest, &state->scissor, state->shape, pixmap, &mat, alpha * 255, !(devp->hints & FZ_DONT_INTERPOLATE_IMAGES), devp->flags & FZ_DEVFLAG_GRIDFIT_AS_TILED);
				}
				fz_drop_glyph(ctx, glyph);
			}
			else
			{
				fz_path *path = fz_outline_glyph(ctx, span->font, gid, &tm);
				if (path)
				{
					fz_draw_fill_path(ctx, devp, path, 0, ctm, colorspace, color, alpha);
					fz_drop_path(ctx, path);
				}
				else
				{
					fz_warn(ctx, "cannot render glyph");
				}
			}
		}
	}

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		fz_knockout_end(ctx, dev);
}

static void
fz_draw_stroke_text(fz_context *ctx, fz_device *devp, const fz_text *text, const fz_stroke_state *stroke,
	const fz_matrix *ctm, fz_colorspace *colorspace,
	const float *color, float alpha)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model = state->dest->colorspace;
	unsigned char colorbv[FZ_MAX_COLORS + 1];
	float colorfv[FZ_MAX_COLORS];
	fz_text_span *span;
	int i;

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		state = fz_knockout_begin(ctx, dev);

	fz_convert_color(ctx, model, colorfv, colorspace, color);
	for (i = 0; i < model->n; i++)
		colorbv[i] = colorfv[i] * 255;
	colorbv[i] = alpha * 255;

	for (span = text->head; span; span = span->next)
	{
		fz_matrix tm, trm;
		fz_glyph *glyph;
		int gid;

		tm = span->trm;

		for (i = 0; i < span->len; i++)
		{
			gid = span->items[i].gid;
			if (gid < 0)
				continue;

			tm.e = span->items[i].x;
			tm.f = span->items[i].y;
			fz_concat(&trm, &tm, ctm);

			glyph = fz_render_stroked_glyph(ctx, span->font, gid, &trm, ctm, stroke, &state->scissor);
			if (glyph)
			{
				int x = (int)trm.e;
				int y = (int)trm.f;
				draw_glyph(colorbv, state->dest, glyph, x, y, &state->scissor);
				if (state->shape)
					draw_glyph(colorbv, state->shape, glyph, x, y, &state->scissor);
				fz_drop_glyph(ctx, glyph);
			}
			else
			{
				fz_path *path = fz_outline_glyph(ctx, span->font, gid, &tm);
				if (path)
				{
					fz_draw_stroke_path(ctx, devp, path, stroke, ctm, colorspace, color, alpha);
					fz_drop_path(ctx, path);
				}
				else
				{
					fz_warn(ctx, "cannot render glyph");
				}
			}
		}
	}

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		fz_knockout_end(ctx, dev);
}

static void
fz_draw_clip_text(fz_context *ctx, fz_device *devp, const fz_text *text, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_irect bbox;
	fz_pixmap *mask, *dest, *shape;
	fz_matrix tm, trm;
	fz_glyph *glyph;
	int i, gid;
	fz_draw_state *state;
	fz_colorspace *model;
	fz_text_span *span;
	fz_rect rect;

	state = push_stack(ctx, dev);
	STACK_PUSHED("clip text");
	model = state->dest->colorspace;

	/* make the mask the exact size needed */
	fz_irect_from_rect(&bbox, fz_bound_text(ctx, text, NULL, ctm, &rect));
	fz_intersect_irect(&bbox, &state->scissor);
	if (scissor)
	{
		fz_irect bbox2;
		fz_intersect_irect(&bbox, fz_irect_from_rect(&bbox2, scissor));
	}

	fz_try(ctx)
	{
		mask = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
		fz_clear_pixmap(ctx, mask);
		dest = fz_new_pixmap_with_bbox(ctx, model, &bbox);
		fz_clear_pixmap(ctx, dest);
		if (state->shape)
		{
			shape = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
			fz_clear_pixmap(ctx, shape);
		}
		else
			shape = NULL;

		state[1].blendmode |= FZ_BLEND_ISOLATED;
		state[1].scissor = bbox;
		state[1].dest = dest;
		state[1].mask = mask;
		state[1].shape = shape;
#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top-1, "Clip (text) begin\n");
#endif

		if (!fz_is_empty_irect(&bbox) && mask)
		{
			for (span = text->head; span; span = span->next)
			{
				tm = span->trm;

				for (i = 0; i < span->len; i++)
				{
					gid = span->items[i].gid;
					if (gid < 0)
						continue;

					tm.e = span->items[i].x;
					tm.f = span->items[i].y;
					fz_concat(&trm, &tm, ctm);

					glyph = fz_render_glyph(ctx, span->font, gid, &trm, model, &state->scissor);
					if (glyph)
					{
						int x = (int)trm.e;
						int y = (int)trm.f;
						draw_glyph(NULL, mask, glyph, x, y, &bbox);
						if (state[1].shape)
							draw_glyph(NULL, state[1].shape, glyph, x, y, &bbox);
						fz_drop_glyph(ctx, glyph);
					}
					else
					{
						fz_path *path = fz_outline_glyph(ctx, span->font, gid, &tm);
						if (path)
						{
							fz_pixmap *old_dest;
							float white = 1;

							old_dest = state[1].dest;
							state[1].dest = state[1].mask;
							state[1].mask = NULL;
							fz_try(ctx)
							{
								fz_draw_fill_path(ctx, devp, path, 0, ctm, fz_device_gray(ctx), &white, 1);
							}
							fz_always(ctx)
							{
								state[1].mask = state[1].dest;
								state[1].dest = old_dest;
								fz_drop_path(ctx, path);
							}
							fz_catch(ctx)
							{
								fz_rethrow(ctx);
							}
						}
						else
						{
							fz_warn(ctx, "cannot render glyph for clipping");
						}
					}
				}
			}
		}
	}
	fz_catch(ctx)
	{
		emergency_pop_stack(ctx, dev, state);
		fz_rethrow(ctx);
	}
}

static void
fz_draw_clip_stroke_text(fz_context *ctx, fz_device *devp, const fz_text *text, const fz_stroke_state *stroke, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_irect bbox;
	fz_pixmap *mask, *dest, *shape;
	fz_matrix tm, trm;
	fz_glyph *glyph;
	int i, gid;
	fz_draw_state *state = push_stack(ctx, dev);
	fz_colorspace *model = state->dest->colorspace;
	fz_text_span *span;
	fz_rect rect;

	STACK_PUSHED("clip stroke text");
	/* make the mask the exact size needed */
	fz_irect_from_rect(&bbox, fz_bound_text(ctx, text, stroke, ctm, &rect));
	fz_intersect_irect(&bbox, &state->scissor);
	if (scissor)
	{
		fz_irect bbox2;
		fz_intersect_irect(&bbox, fz_irect_from_rect(&bbox2, scissor));
	}

	fz_try(ctx)
	{
		state[1].mask = mask = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
		fz_clear_pixmap(ctx, mask);
		state[1].dest = dest = fz_new_pixmap_with_bbox(ctx, model, &bbox);
		fz_clear_pixmap(ctx, dest);
		if (state->shape)
		{
			state[1].shape = shape = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
			fz_clear_pixmap(ctx, shape);
		}
		else
			shape = state->shape;

		state[1].blendmode |= FZ_BLEND_ISOLATED;
		state[1].scissor = bbox;
#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top-1, "Clip (stroke text) begin\n");
#endif

		if (!fz_is_empty_irect(&bbox))
		{
			for (span = text->head; span; span = span->next)
			{
				tm = span->trm;

				for (i = 0; i < span->len; i++)
				{
					gid = span->items[i].gid;
					if (gid < 0)
						continue;

					tm.e = span->items[i].x;
					tm.f = span->items[i].y;
					fz_concat(&trm, &tm, ctm);

					glyph = fz_render_stroked_glyph(ctx, span->font, gid, &trm, ctm, stroke, &state->scissor);
					if (glyph)
					{
						int x = (int)trm.e;
						int y = (int)trm.f;
						draw_glyph(NULL, mask, glyph, x, y, &bbox);
						if (shape)
							draw_glyph(NULL, shape, glyph, x, y, &bbox);
						fz_drop_glyph(ctx, glyph);
					}
					else
					{
						fz_path *path = fz_outline_glyph(ctx, span->font, gid, &tm);
						if (path)
						{
							fz_pixmap *old_dest;
							float white = 1;

							state = &dev->stack[dev->top];
							old_dest = state[0].dest;
							state[0].dest = state[0].mask;
							state[0].mask = NULL;
							fz_try(ctx)
							{
								fz_draw_stroke_path(ctx, devp, path, stroke, ctm, fz_device_gray(ctx), &white, 1);
							}
							fz_always(ctx)
							{
								state[0].mask = state[0].dest;
								state[0].dest = old_dest;
								fz_drop_path(ctx, path);
							}
							fz_catch(ctx)
							{
								fz_rethrow(ctx);
							}
						}
						else
						{
							fz_warn(ctx, "cannot render glyph for stroked clipping");
						}
					}
				}
			}
		}
	}
	fz_catch(ctx)
	{
		emergency_pop_stack(ctx, dev, state);
	}
}

static void
fz_draw_ignore_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm)
{
}

static void
fz_draw_fill_shade(fz_context *ctx, fz_device *devp, fz_shade *shade, const fz_matrix *ctm, float alpha)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_rect bounds;
	fz_irect bbox, scissor;
	fz_pixmap *dest, *shape;
	float colorfv[FZ_MAX_COLORS];
	unsigned char colorbv[FZ_MAX_COLORS + 1];
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model = state->dest->colorspace;

	fz_bound_shade(ctx, shade, ctm, &bounds);
	scissor = state->scissor;
	fz_intersect_irect(fz_irect_from_rect(&bbox, &bounds), &scissor);

	if (fz_is_empty_irect(&bbox))
		return;

	if (!model)
	{
		fz_warn(ctx, "cannot render shading directly to an alpha mask");
		return;
	}

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		state = fz_knockout_begin(ctx, dev);

	dest = state->dest;
	shape = state->shape;

	if (alpha < 1)
	{
		dest = fz_new_pixmap_with_bbox(ctx, state->dest->colorspace, &bbox);
		fz_clear_pixmap(ctx, dest);
		if (shape)
		{
			shape = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
			fz_clear_pixmap(ctx, shape);
		}
	}

	if (shade->use_background)
	{
		unsigned char *s;
		int x, y, n, i;
		fz_convert_color(ctx, model, colorfv, shade->colorspace, shade->background);
		for (i = 0; i < model->n; i++)
			colorbv[i] = colorfv[i] * 255;
		colorbv[i] = 255;

		n = dest->n;
		for (y = scissor.y0; y < scissor.y1; y++)
		{
			s = dest->samples + (unsigned int)(((scissor.x0 - dest->x) + (y - dest->y) * dest->w) * dest->n);
			for (x = scissor.x0; x < scissor.x1; x++)
			{
				for (i = 0; i < n; i++)
					*s++ = colorbv[i];
			}
		}
		if (shape)
		{
			for (y = scissor.y0; y < scissor.y1; y++)
			{
				s = shape->samples + (unsigned int)((scissor.x0 - shape->x) + (y - shape->y) * shape->w);
				for (x = scissor.x0; x < scissor.x1; x++)
				{
					*s++ = 255;
				}
			}
		}
	}

	fz_paint_shade(ctx, shade, ctm, dest, &bbox);
	if (shape)
		fz_clear_pixmap_rect_with_value(ctx, shape, 255, &bbox);

	if (alpha < 1)
	{
		fz_paint_pixmap(state->dest, dest, alpha * 255);
		fz_drop_pixmap(ctx, dest);
		if (shape)
		{
			fz_paint_pixmap(state->shape, shape, alpha * 255);
			fz_drop_pixmap(ctx, shape);
		}
	}

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		fz_knockout_end(ctx, dev);
}

static fz_pixmap *
fz_transform_pixmap(fz_context *ctx, fz_draw_device *dev, const fz_pixmap *image, fz_matrix *ctm, int x, int y, int dx, int dy, int gridfit, const fz_irect *clip)
{
	fz_pixmap *scaled;

	if (ctm->a != 0 && ctm->b == 0 && ctm->c == 0 && ctm->d != 0)
	{
		/* Unrotated or X-flip or Y-flip or XY-flip */
		fz_matrix m = *ctm;
		if (gridfit)
		{
			fz_gridfit_matrix(dev->flags & FZ_DEVFLAG_GRIDFIT_AS_TILED, &m);
		}
		scaled = fz_scale_pixmap_cached(ctx, image, m.e, m.f, m.a, m.d, clip, dev->cache_x, dev->cache_y);
		if (!scaled)
			return NULL;
		ctm->a = scaled->w;
		ctm->d = scaled->h;
		ctm->e = scaled->x;
		ctm->f = scaled->y;
		return scaled;
	}

	if (ctm->a == 0 && ctm->b != 0 && ctm->c != 0 && ctm->d == 0)
	{
		/* Other orthogonal flip/rotation cases */
		fz_matrix m = *ctm;
		fz_irect rclip;
		if (gridfit)
			fz_gridfit_matrix(dev->flags & FZ_DEVFLAG_GRIDFIT_AS_TILED, &m);
		if (clip)
		{
			rclip.x0 = clip->y0;
			rclip.y0 = clip->x0;
			rclip.x1 = clip->y1;
			rclip.y1 = clip->x1;
		}
		scaled = fz_scale_pixmap_cached(ctx, image, m.f, m.e, m.b, m.c, (clip ? &rclip : NULL), dev->cache_x, dev->cache_y);
		if (!scaled)
			return NULL;
		ctm->b = scaled->w;
		ctm->c = scaled->h;
		ctm->f = scaled->x;
		ctm->e = scaled->y;
		return scaled;
	}

	/* Downscale, non rectilinear case */
	if (dx > 0 && dy > 0)
	{
		scaled = fz_scale_pixmap_cached(ctx, image, 0, 0, (float)dx, (float)dy, NULL, dev->cache_x, dev->cache_y);
		return scaled;
	}

	return NULL;
}

static void
fz_draw_fill_image(fz_context *ctx, fz_device *devp, fz_image *image, const fz_matrix *ctm, float alpha)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_pixmap *converted = NULL;
	fz_pixmap *scaled = NULL;
	fz_pixmap *pixmap;
	fz_pixmap *orig_pixmap;
	int after;
	int dx, dy;
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model = state->dest->colorspace;
	fz_irect clip;
	fz_matrix local_ctm = *ctm;

	fz_intersect_irect(fz_pixmap_bbox(ctx, state->dest, &clip), &state->scissor);

	fz_var(scaled);

	if (!model)
	{
		fz_warn(ctx, "cannot render image directly to an alpha mask");
		return;
	}

	if (image->w == 0 || image->h == 0)
		return;

	dx = sqrtf(local_ctm.a * local_ctm.a + local_ctm.b * local_ctm.b);
	dy = sqrtf(local_ctm.c * local_ctm.c + local_ctm.d * local_ctm.d);

	pixmap = fz_get_pixmap_from_image(ctx, image, dx, dy);
	orig_pixmap = pixmap;

	/* convert images with more components (cmyk->rgb) before scaling */
	/* convert images with fewer components (gray->rgb after scaling */
	/* convert images with expensive colorspace transforms after scaling */

	fz_try(ctx)
	{
		if (state->blendmode & FZ_BLEND_KNOCKOUT)
			state = fz_knockout_begin(ctx, dev);

		after = 0;
		if (pixmap->colorspace == fz_device_gray(ctx))
			after = 1;

		if (pixmap->colorspace != model && !after)
		{
			fz_irect bbox;
			fz_pixmap_bbox(ctx, pixmap, &bbox);
			converted = fz_new_pixmap_with_bbox(ctx, model, &bbox);
			fz_convert_pixmap(ctx, converted, pixmap);
			pixmap = converted;
		}

		if (dx < pixmap->w && dy < pixmap->h && !(devp->hints & FZ_DONT_INTERPOLATE_IMAGES))
		{
			int gridfit = alpha == 1.0f && !(dev->flags & FZ_DRAWDEV_FLAGS_TYPE3);
			scaled = fz_transform_pixmap(ctx, dev, pixmap, &local_ctm, state->dest->x, state->dest->y, dx, dy, gridfit, &clip);
			if (!scaled)
			{
				if (dx < 1)
					dx = 1;
				if (dy < 1)
					dy = 1;
				scaled = fz_scale_pixmap_cached(ctx, pixmap, pixmap->x, pixmap->y, dx, dy, NULL, dev->cache_x, dev->cache_y);
			}
			if (scaled)
				pixmap = scaled;
		}

		if (pixmap->colorspace != model)
		{
			if ((pixmap->colorspace == fz_device_gray(ctx) && model == fz_device_rgb(ctx)) ||
				(pixmap->colorspace == fz_device_gray(ctx) && model == fz_device_bgr(ctx)))
			{
				/* We have special case rendering code for gray -> rgb/bgr */
			}
			else
			{
				fz_irect bbox;
				fz_pixmap_bbox(ctx, pixmap, &bbox);
				converted = fz_new_pixmap_with_bbox(ctx, model, &bbox);
				fz_convert_pixmap(ctx, converted, pixmap);
				pixmap = converted;
			}
		}

		fz_paint_image(state->dest, &state->scissor, state->shape, pixmap, &local_ctm, alpha * 255, !(devp->hints & FZ_DONT_INTERPOLATE_IMAGES), devp->flags & FZ_DEVFLAG_GRIDFIT_AS_TILED);

		if (state->blendmode & FZ_BLEND_KNOCKOUT)
			fz_knockout_end(ctx, dev);
	}
	fz_always(ctx)
	{
		fz_drop_pixmap(ctx, scaled);
		fz_drop_pixmap(ctx, converted);
		fz_drop_pixmap(ctx, orig_pixmap);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void
fz_draw_fill_image_mask(fz_context *ctx, fz_device *devp, fz_image *image, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	unsigned char colorbv[FZ_MAX_COLORS + 1];
	float colorfv[FZ_MAX_COLORS];
	fz_pixmap *scaled = NULL;
	fz_pixmap *pixmap;
	fz_pixmap *orig_pixmap;
	int dx, dy;
	int i;
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model = state->dest->colorspace;
	fz_irect clip;
	fz_matrix local_ctm = *ctm;

	fz_pixmap_bbox(ctx, state->dest, &clip);
	fz_intersect_irect(&clip, &state->scissor);

	if (image->w == 0 || image->h == 0)
		return;

	dx = sqrtf(local_ctm.a * local_ctm.a + local_ctm.b * local_ctm.b);
	dy = sqrtf(local_ctm.c * local_ctm.c + local_ctm.d * local_ctm.d);
	pixmap = fz_get_pixmap_from_image(ctx, image, dx, dy);
	orig_pixmap = pixmap;

	fz_try(ctx)
	{
		if (state->blendmode & FZ_BLEND_KNOCKOUT)
			state = fz_knockout_begin(ctx, dev);

		if (dx < pixmap->w && dy < pixmap->h)
		{
			int gridfit = alpha == 1.0f && !(dev->flags & FZ_DRAWDEV_FLAGS_TYPE3);
			scaled = fz_transform_pixmap(ctx, dev, pixmap, &local_ctm, state->dest->x, state->dest->y, dx, dy, gridfit, &clip);
			if (!scaled)
			{
				if (dx < 1)
					dx = 1;
				if (dy < 1)
					dy = 1;
				scaled = fz_scale_pixmap_cached(ctx, pixmap, pixmap->x, pixmap->y, dx, dy, NULL, dev->cache_x, dev->cache_y);
			}
			if (scaled)
				pixmap = scaled;
		}

		fz_convert_color(ctx, model, colorfv, colorspace, color);
		for (i = 0; i < model->n; i++)
			colorbv[i] = colorfv[i] * 255;
		colorbv[i] = alpha * 255;

		fz_paint_image_with_color(state->dest, &state->scissor, state->shape, pixmap, &local_ctm, colorbv, !(devp->hints & FZ_DONT_INTERPOLATE_IMAGES), devp->flags & FZ_DEVFLAG_GRIDFIT_AS_TILED);

		if (scaled)
			fz_drop_pixmap(ctx, scaled);

		if (state->blendmode & FZ_BLEND_KNOCKOUT)
			fz_knockout_end(ctx, dev);
	}
	fz_always(ctx)
	{
		fz_drop_pixmap(ctx, orig_pixmap);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void
fz_draw_clip_image_mask(fz_context *ctx, fz_device *devp, fz_image *image, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_irect bbox;
	fz_pixmap *mask = NULL;
	fz_pixmap *dest = NULL;
	fz_pixmap *shape = NULL;
	fz_pixmap *scaled = NULL;
	fz_pixmap *pixmap = NULL;
	fz_pixmap *orig_pixmap = NULL;
	int dx, dy;
	fz_draw_state *state = push_stack(ctx, dev);
	fz_colorspace *model = state->dest->colorspace;
	fz_irect clip;
	fz_matrix local_ctm = *ctm;
	fz_rect urect;

	STACK_PUSHED("clip image mask");
	fz_pixmap_bbox(ctx, state->dest, &clip);
	fz_intersect_irect(&clip, &state->scissor);

	fz_var(mask);
	fz_var(dest);
	fz_var(shape);
	fz_var(pixmap);
	fz_var(orig_pixmap);

	if (image->w == 0 || image->h == 0)
	{
#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top-1, "Clip (image mask) (empty) begin\n");
#endif
		state[1].scissor = fz_empty_irect;
		state[1].mask = NULL;
		return;
	}

#ifdef DUMP_GROUP_BLENDS
	dump_spaces(dev->top-1, "Clip (image mask) begin\n");
#endif

	urect = fz_unit_rect;
	fz_irect_from_rect(&bbox, fz_transform_rect(&urect, &local_ctm));
	fz_intersect_irect(&bbox, &state->scissor);
	if (scissor)
	{
		fz_irect bbox2;
		fz_intersect_irect(&bbox, fz_irect_from_rect(&bbox2, scissor));
	}

	dx = sqrtf(local_ctm.a * local_ctm.a + local_ctm.b * local_ctm.b);
	dy = sqrtf(local_ctm.c * local_ctm.c + local_ctm.d * local_ctm.d);

	fz_try(ctx)
	{
		pixmap = fz_get_pixmap_from_image(ctx, image, dx, dy);
		orig_pixmap = pixmap;

		state[1].mask = mask = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
		fz_clear_pixmap(ctx, mask);

		state[1].dest = dest = fz_new_pixmap_with_bbox(ctx, model, &bbox);
		fz_clear_pixmap(ctx, dest);
		if (state->shape)
		{
			state[1].shape = shape = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
			fz_clear_pixmap(ctx, shape);
		}

		state[1].blendmode |= FZ_BLEND_ISOLATED;
		state[1].scissor = bbox;

		if (dx < pixmap->w && dy < pixmap->h)
		{
			int gridfit = !(dev->flags & FZ_DRAWDEV_FLAGS_TYPE3);
			scaled = fz_transform_pixmap(ctx, dev, pixmap, &local_ctm, state->dest->x, state->dest->y, dx, dy, gridfit, &clip);
			if (!scaled)
			{
				if (dx < 1)
					dx = 1;
				if (dy < 1)
					dy = 1;
				scaled = fz_scale_pixmap_cached(ctx, pixmap, pixmap->x, pixmap->y, dx, dy, NULL, dev->cache_x, dev->cache_y);
			}
			if (scaled)
				pixmap = scaled;
		}
		fz_paint_image(mask, &bbox, state->shape, pixmap, &local_ctm, 255, !(devp->hints & FZ_DONT_INTERPOLATE_IMAGES), devp->flags & FZ_DEVFLAG_GRIDFIT_AS_TILED);
	}
	fz_always(ctx)
	{
		fz_drop_pixmap(ctx, scaled);
		fz_drop_pixmap(ctx, orig_pixmap);
	}
	fz_catch(ctx)
	{
		emergency_pop_stack(ctx, dev, state);
	}
}

static void
fz_draw_pop_clip(fz_context *ctx, fz_device *devp)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_draw_state *state;

	if (dev->top == 0)
	{
		fz_warn(ctx, "Unexpected pop clip");
		return;
	}
	state = &dev->stack[--dev->top];
	STACK_POPPED("clip");

	/* We can get here with state[1].mask == NULL if the clipping actually
	 * resolved to a rectangle earlier.
	 */
	if (state[1].mask)
	{
#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top, "");
		fz_dump_blend(ctx, state[1].dest, "Clipping ");
		if (state[1].shape)
			fz_dump_blend(ctx, state[1].shape, "/");
		fz_dump_blend(ctx, state[0].dest, " onto ");
		if (state[0].shape)
			fz_dump_blend(ctx, state[0].shape, "/");
		fz_dump_blend(ctx, state[1].mask, " with ");
#endif
		fz_paint_pixmap_with_mask(state[0].dest, state[1].dest, state[1].mask);
		if (state[0].shape != state[1].shape)
		{
			fz_paint_pixmap_with_mask(state[0].shape, state[1].shape, state[1].mask);
			fz_drop_pixmap(ctx, state[1].shape);
		}
		/* The following tests should not be required, but just occasionally
		 * errors can cause the stack to get out of sync, and this might save
		 * our bacon. */
		if (state[0].mask != state[1].mask)
			fz_drop_pixmap(ctx, state[1].mask);
		if (state[0].dest != state[1].dest)
			fz_drop_pixmap(ctx, state[1].dest);
#ifdef DUMP_GROUP_BLENDS
		fz_dump_blend(ctx, state[0].dest, " to get ");
		if (state[0].shape)
			fz_dump_blend(ctx, state[0].shape, "/");
		printf("\n");
#endif
	}
	else
	{
#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top, "Clip end\n");
#endif
	}
}

static void
fz_draw_begin_mask(fz_context *ctx, fz_device *devp, const fz_rect *rect, int luminosity, fz_colorspace *colorspace, const float *colorfv)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_pixmap *dest;
	fz_irect bbox;
	fz_draw_state *state = push_stack(ctx, dev);
	fz_pixmap *shape = state->shape;

	STACK_PUSHED("mask");
	fz_intersect_irect(fz_irect_from_rect(&bbox, rect), &state->scissor);

	fz_try(ctx)
	{
		state[1].dest = dest = fz_new_pixmap_with_bbox(ctx, fz_device_gray(ctx), &bbox);
		if (state->shape)
		{
			/* FIXME: If we ever want to support AIS true, then
			 * we probably want to create a shape pixmap here,
			 * using: shape = fz_new_pixmap_with_bbox(NULL, bbox);
			 * then, in the end_mask code, we create the mask
			 * from this rather than dest.
			 */
			state[1].shape = shape = NULL;
		}

		if (luminosity)
		{
			float bc;
			if (!colorspace)
				colorspace = fz_device_gray(ctx);
			fz_convert_color(ctx, fz_device_gray(ctx), &bc, colorspace, colorfv);
			fz_clear_pixmap_with_value(ctx, dest, bc * 255);
			if (shape)
				fz_clear_pixmap_with_value(ctx, shape, 255);
		}
		else
		{
			fz_clear_pixmap(ctx, dest);
			if (shape)
				fz_clear_pixmap(ctx, shape);
		}

#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top-1, "Mask begin\n");
#endif
		state[1].scissor = bbox;
		state[1].luminosity = luminosity;
	}
	fz_catch(ctx)
	{
		emergency_pop_stack(ctx, dev, state);
	}
}

static void
fz_draw_end_mask(fz_context *ctx, fz_device *devp)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_pixmap *temp, *dest;
	fz_irect bbox;
	int luminosity;
	fz_draw_state *state;

	if (dev->top == 0)
	{
		fz_warn(ctx, "Unexpected draw_end_mask");
		return;
	}
	state = &dev->stack[dev->top-1];
	STACK_CONVERT("(mask)");
	/* pop soft mask buffer */
	luminosity = state[1].luminosity;

#ifdef DUMP_GROUP_BLENDS
	dump_spaces(dev->top-1, "Mask -> Clip\n");
#endif
	fz_try(ctx)
	{
		/* convert to alpha mask */
		temp = fz_alpha_from_gray(ctx, state[1].dest, luminosity);
		if (state[1].mask != state[0].mask)
			fz_drop_pixmap(ctx, state[1].mask);
		state[1].mask = temp;
		if (state[1].dest != state[0].dest)
			fz_drop_pixmap(ctx, state[1].dest);
		state[1].dest = NULL;
		if (state[1].shape != state[0].shape)
			fz_drop_pixmap(ctx, state[1].shape);
		state[1].shape = NULL;

		/* create new dest scratch buffer */
		fz_pixmap_bbox(ctx, temp, &bbox);
		dest = fz_new_pixmap_with_bbox(ctx, state->dest->colorspace, &bbox);
		fz_clear_pixmap(ctx, dest);

		/* push soft mask as clip mask */
		state[1].dest = dest;
		state[1].blendmode |= FZ_BLEND_ISOLATED;
		/* If we have a shape, then it'll need to be masked with the
		 * clip mask when we pop. So create a new shape now. */
		if (state[0].shape)
		{
			state[1].shape = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
			fz_clear_pixmap(ctx, state[1].shape);
		}
		state[1].scissor = bbox;
	}
	fz_catch(ctx)
	{
		emergency_pop_stack(ctx, dev, state);
	}
}

static void
fz_draw_begin_group(fz_context *ctx, fz_device *devp, const fz_rect *rect, int isolated, int knockout, int blendmode, float alpha)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_irect bbox;
	fz_pixmap *dest;
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model = state->dest->colorspace;

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		fz_knockout_begin(ctx, dev);

	state = push_stack(ctx, dev);
	STACK_PUSHED("group");
	fz_intersect_irect(fz_irect_from_rect(&bbox, rect), &state->scissor);

	fz_try(ctx)
	{
		state[1].dest = dest = fz_new_pixmap_with_bbox(ctx, model, &bbox);

#ifndef ATTEMPT_KNOCKOUT_AND_ISOLATED
		knockout = 0;
		isolated = 1;
#endif

		if (isolated)
		{
			fz_clear_pixmap(ctx, dest);
		}
		else
		{
			fz_copy_pixmap_rect(ctx, dest, state[0].dest, &bbox);
		}

		if (blendmode == 0 && alpha == 1.0 && isolated)
		{
			/* We can render direct to any existing shape plane.
			 * If there isn't one, we don't need to make one. */
			state[1].shape = state[0].shape;
		}
		else
		{
			state[1].shape = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
			fz_clear_pixmap(ctx, state[1].shape);
		}

		state[1].alpha = alpha;
#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top-1, "Group begin\n");
#endif

		state[1].scissor = bbox;
		state[1].blendmode = blendmode | (isolated ? FZ_BLEND_ISOLATED : 0) | (knockout ? FZ_BLEND_KNOCKOUT : 0);
	}
	fz_catch(ctx)
	{
		emergency_pop_stack(ctx, dev, state);
	}
}

static void
fz_draw_end_group(fz_context *ctx, fz_device *devp)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	int blendmode;
	int isolated;
	float alpha;
	fz_draw_state *state;

	if (dev->top == 0)
	{
		fz_warn(ctx, "Unexpected end_group");
		return;
	}

	state = &dev->stack[--dev->top];
	STACK_POPPED("group");
	alpha = state[1].alpha;
	blendmode = state[1].blendmode & FZ_BLEND_MODEMASK;
	isolated = state[1].blendmode & FZ_BLEND_ISOLATED;
#ifdef DUMP_GROUP_BLENDS
	dump_spaces(dev->top, "");
	fz_dump_blend(ctx, state[1].dest, "Group end: blending ");
	if (state[1].shape)
		fz_dump_blend(ctx, state[1].shape, "/");
	fz_dump_blend(ctx, state[0].dest, " onto ");
	if (state[0].shape)
		fz_dump_blend(ctx, state[0].shape, "/");
	if (alpha != 1.0f)
		printf(" (alpha %g)", alpha);
	if (blendmode != 0)
		printf(" (blend %d)", blendmode);
	if (isolated != 0)
		printf(" (isolated)");
	if (state[1].blendmode & FZ_BLEND_KNOCKOUT)
		printf(" (knockout)");
#endif
	if ((blendmode == 0) && (state[0].shape == state[1].shape))
		fz_paint_pixmap(state[0].dest, state[1].dest, alpha * 255);
	else
		fz_blend_pixmap(state[0].dest, state[1].dest, alpha * 255, blendmode, isolated, state[1].shape);

	/* The following test should not be required, but just occasionally
	 * errors can cause the stack to get out of sync, and this might save
	 * our bacon. */
	if (state[0].dest != state[1].dest)
		fz_drop_pixmap(ctx, state[1].dest);
	if (state[0].shape != state[1].shape)
	{
		if (state[0].shape)
			fz_paint_pixmap(state[0].shape, state[1].shape, alpha * 255);
		fz_drop_pixmap(ctx, state[1].shape);
	}
#ifdef DUMP_GROUP_BLENDS
	fz_dump_blend(ctx, state[0].dest, " to get ");
	if (state[0].shape)
		fz_dump_blend(ctx, state[0].shape, "/");
	printf("\n");
#endif

	if (state[0].blendmode & FZ_BLEND_KNOCKOUT)
		fz_knockout_end(ctx, dev);
}

typedef struct
{
	int refs;
	float ctm[4];
	int id;
} tile_key;

typedef struct
{
	fz_storable storable;
	fz_pixmap *dest;
	fz_pixmap *shape;
} tile_record;

static int
fz_make_hash_tile_key(fz_context *ctx, fz_store_hash *hash, void *key_)
{
	tile_key *key = (tile_key *)key_;

	hash->u.im.id = key->id;
	hash->u.im.m[0] = key->ctm[0];
	hash->u.im.m[1] = key->ctm[1];
	hash->u.im.m[2] = key->ctm[2];
	hash->u.im.m[3] = key->ctm[3];
	return 1;
}

static void *
fz_keep_tile_key(fz_context *ctx, void *key_)
{
	tile_key *key = (tile_key *)key_;
	return fz_keep_imp(ctx, key, &key->refs);
}

static void
fz_drop_tile_key(fz_context *ctx, void *key_)
{
	tile_key *key = (tile_key *)key_;
	if (fz_drop_imp(ctx, key, &key->refs))
		fz_free(ctx, key);
}

static int
fz_cmp_tile_key(fz_context *ctx, void *k0_, void *k1_)
{
	tile_key *k0 = (tile_key *)k0_;
	tile_key *k1 = (tile_key *)k1_;
	return k0->id == k1->id && k0->ctm[0] == k1->ctm[0] && k0->ctm[1] == k1->ctm[1] && k0->ctm[2] == k1->ctm[2] && k0->ctm[3] == k1->ctm[3];
}

static void
fz_print_tile(fz_context *ctx, fz_output *out, void *key_)
{
	tile_key *key = (tile_key *)key_;
	fz_printf(ctx, out, "(tile id=%x, ctm=%g %g %g %g) ", key->id, key->ctm[0], key->ctm[1], key->ctm[2], key->ctm[3]);
}

static fz_store_type fz_tile_store_type =
{
	fz_make_hash_tile_key,
	fz_keep_tile_key,
	fz_drop_tile_key,
	fz_cmp_tile_key,
	fz_print_tile
};

static void
fz_drop_tile_record_imp(fz_context *ctx, fz_storable *storable)
{
	tile_record *tr = (tile_record *)storable;
	fz_drop_pixmap(ctx, tr->dest);
	fz_drop_pixmap(ctx, tr->shape);
	fz_free(ctx, tr);
}

static void
fz_drop_tile_record(fz_context *ctx, tile_record *tile)
{
	fz_drop_storable(ctx, &tile->storable);
}

static tile_record *
fz_new_tile_record(fz_context *ctx, fz_pixmap *dest, fz_pixmap *shape)
{
	tile_record *tile = fz_malloc_struct(ctx, tile_record);
	FZ_INIT_STORABLE(tile, 1, fz_drop_tile_record_imp);
	tile->dest = fz_keep_pixmap(ctx, dest);
	tile->shape = fz_keep_pixmap(ctx, shape);
	return tile;
}

unsigned int
fz_tile_size(fz_context *ctx, tile_record *tile)
{
	if (!tile)
		return 0;
	return sizeof(*tile) + fz_pixmap_size(ctx, tile->dest) + fz_pixmap_size(ctx, tile->shape);
}

static int
fz_draw_begin_tile(fz_context *ctx, fz_device *devp, const fz_rect *area, const fz_rect *view, float xstep, float ystep, const fz_matrix *ctm, int id)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_pixmap *dest = NULL;
	fz_pixmap *shape;
	fz_irect bbox;
	fz_draw_state *state = &dev->stack[dev->top];
	fz_colorspace *model = state->dest->colorspace;
	fz_rect local_view = *view;

	/* area, view, xstep, ystep are in pattern space */
	/* ctm maps from pattern space to device space */

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		fz_knockout_begin(ctx, dev);

	state = push_stack(ctx, dev);
	STACK_PUSHED("tile");
	fz_irect_from_rect(&bbox, fz_transform_rect(&local_view, ctm));
	/* We should never have a bbox that entirely covers our destination.
	 * If we do, then the check for only 1 tile being visible above has
	 * failed. Actually, this *can* fail due to the round_rect, at extreme
	 * resolutions, so disable this assert.
	 * assert(bbox.x0 > state->dest->x || bbox.x1 < state->dest->x + state->dest->w ||
	 *	bbox.y0 > state->dest->y || bbox.y1 < state->dest->y + state->dest->h);
	 */

	/* Check to see if we have one cached */
	if (id)
	{
		tile_key tk;
		tile_record *tile;
		tk.ctm[0] = ctm->a;
		tk.ctm[1] = ctm->b;
		tk.ctm[2] = ctm->c;
		tk.ctm[3] = ctm->d;
		tk.id = id;

		tile = fz_find_item(ctx, fz_drop_tile_record_imp, &tk, &fz_tile_store_type);
		if (tile)
		{
			state[1].dest = fz_keep_pixmap(ctx, tile->dest);
			state[1].shape = fz_keep_pixmap(ctx, tile->shape);
			state[1].blendmode |= FZ_BLEND_ISOLATED;
			state[1].xstep = xstep;
			state[1].ystep = ystep;
			state[1].id = id;
			fz_irect_from_rect(&state[1].area, area);
			state[1].ctm = *ctm;
#ifdef DUMP_GROUP_BLENDS
			dump_spaces(dev->top-1, "Tile begin (cached)\n");
#endif

			state[1].scissor = bbox;
			fz_drop_tile_record(ctx, tile);
			return 1;
		}
	}

	fz_try(ctx)
	{
		state[1].dest = dest = fz_new_pixmap_with_bbox(ctx, model, &bbox);
		fz_clear_pixmap(ctx, dest);
		shape = state[0].shape;
		if (shape)
		{
			state[1].shape = shape = fz_new_pixmap_with_bbox(ctx, NULL, &bbox);
			fz_clear_pixmap(ctx, shape);
		}
		state[1].blendmode |= FZ_BLEND_ISOLATED;
		state[1].xstep = xstep;
		state[1].ystep = ystep;
		state[1].id = id;
		fz_irect_from_rect(&state[1].area, area);
		state[1].ctm = *ctm;
#ifdef DUMP_GROUP_BLENDS
		dump_spaces(dev->top-1, "Tile begin\n");
#endif

		state[1].scissor = bbox;
	}
	fz_catch(ctx)
	{
		emergency_pop_stack(ctx, dev, state);
	}

	return 0;
}

static void
fz_draw_end_tile(fz_context *ctx, fz_device *devp)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	float xstep, ystep;
	fz_matrix ttm, ctm, shapectm;
	fz_irect area, scissor;
	fz_rect scissor_tmp;
	int x0, y0, x1, y1, x, y;
	fz_draw_state *state;
	tile_record *tile;
	tile_key *key;

	if (dev->top == 0)
	{
		fz_warn(ctx, "Unexpected end_tile");
		return;
	}

	state = &dev->stack[--dev->top];
	STACK_PUSHED("tile");
	xstep = state[1].xstep;
	ystep = state[1].ystep;
	area = state[1].area;
	ctm = state[1].ctm;

	/* Fudge the scissor bbox a little to allow for inaccuracies in the
	 * matrix inversion. */
	fz_rect_from_irect(&scissor_tmp, &state[0].scissor);
	fz_transform_rect(fz_expand_rect(&scissor_tmp, 1), fz_invert_matrix(&ttm, &ctm));
	fz_intersect_irect(&area, fz_irect_from_rect(&scissor, &scissor_tmp));

	/* FIXME: area is a bbox, so FP not appropriate here */
	/* In PDF files xstep/ystep can be smaller than view (the area of a
	 * single tile) (see fts_15_1506.pdf for an example). This means that
	 * we have to bias the left hand/bottom edge calculations by the
	 * difference between the step and the width/height of the tile. */
	/* scissor, xstep and area are all in pattern space. */
	x0 = xstep - scissor.x1 + scissor.x0;
	if (x0 > 0)
		x0 = 0;
	y0 = ystep - scissor.y1 + scissor.y0;
	if (y0 > 0)
		y0 = 0;
	x0 = floorf((area.x0 + x0) / xstep);
	y0 = floorf((area.y0 + y0) / ystep);
	x1 = ceilf(area.x1 / xstep);
	y1 = ceilf(area.y1 / ystep);

	ctm.e = state[1].dest->x;
	ctm.f = state[1].dest->y;
	if (state[1].shape)
	{
		shapectm = ctm;
		shapectm.e = state[1].shape->x;
		shapectm.f = state[1].shape->y;
	}

#ifdef DUMP_GROUP_BLENDS
	dump_spaces(dev->top, "");
	fz_dump_blend(ctx, state[1].dest, "Tiling ");
	if (state[1].shape)
		fz_dump_blend(ctx, state[1].shape, "/");
	fz_dump_blend(ctx, state[0].dest, " onto ");
	if (state[0].shape)
		fz_dump_blend(ctx, state[0].shape, "/");
#endif

	for (y = y0; y < y1; y++)
	{
		for (x = x0; x < x1; x++)
		{
			ttm = ctm;
			fz_pre_translate(&ttm, x * xstep, y * ystep);
			state[1].dest->x = ttm.e;
			state[1].dest->y = ttm.f;
			if (state[1].dest->x > 0 && state[1].dest->x + state[1].dest->w < 0)
				continue;
			if (state[1].dest->y > 0 && state[1].dest->y + state[1].dest->h < 0)
				continue;
			fz_paint_pixmap_with_bbox(state[0].dest, state[1].dest, 255, state[0].scissor);
			if (state[1].shape)
			{
				ttm = shapectm;
				fz_pre_translate(&ttm, x * xstep, y * ystep);
				state[1].shape->x = ttm.e;
				state[1].shape->y = ttm.f;
				fz_paint_pixmap_with_bbox(state[0].shape, state[1].shape, 255, state[0].scissor);
			}
		}
	}

	state[1].dest->x = ctm.e;
	state[1].dest->y = ctm.f;
	if (state[1].shape)
	{
		state[1].shape->x = shapectm.e;
		state[1].shape->y = shapectm.f;
	}

	/* Now we try to cache the tiles. Any failure here will just result
	 * in us not caching. */
	tile = NULL;
	key = NULL;
	fz_var(tile);
	fz_var(key);
	fz_try(ctx)
	{
		tile_record *existing_tile;

		tile = fz_new_tile_record(ctx, state[1].dest, state[1].shape);

		key = fz_malloc_struct(ctx, tile_key);
		key->refs = 1;
		key->id = state[1].id;
		key->ctm[0] = ctm.a;
		key->ctm[1] = ctm.b;
		key->ctm[2] = ctm.c;
		key->ctm[3] = ctm.d;
		existing_tile = fz_store_item(ctx, key, tile, fz_tile_size(ctx, tile), &fz_tile_store_type);
		if (existing_tile)
		{
			/* We already have a tile. This will either have been
			 * produced by a racing thread, or there is already
			 * an entry for this one in the store. */
			fz_drop_tile_record(ctx, tile);
			tile = existing_tile;
		}
	}
	fz_always(ctx)
	{
		fz_drop_tile_key(ctx, key);
		fz_drop_tile_record(ctx, tile);
	}
	fz_catch(ctx)
	{
		/* Do nothing */
	}

	/* The following tests should not be required, but just occasionally
	 * errors can cause the stack to get out of sync, and this might save
	 * our bacon. */
	if (state[0].dest != state[1].dest)
		fz_drop_pixmap(ctx, state[1].dest);
	if (state[0].shape != state[1].shape)
		fz_drop_pixmap(ctx, state[1].shape);
#ifdef DUMP_GROUP_BLENDS
	fz_dump_blend(ctx, state[0].dest, " to get ");
	if (state[0].shape)
		fz_dump_blend(ctx, state[0].shape, "/");
	printf("\n");
#endif

	if (state->blendmode & FZ_BLEND_KNOCKOUT)
		fz_knockout_end(ctx, dev);
}

static void
fz_draw_drop_imp(fz_context *ctx, fz_device *devp)
{
	fz_draw_device *dev = (fz_draw_device*)devp;
	fz_gel *gel = dev->gel;

	/* pop and free the stacks */
	if (dev->top > 0)
		fz_warn(ctx, "items left on stack in draw device: %d", dev->top+1);

	while(dev->top-- > 0)
	{
		fz_draw_state *state = &dev->stack[dev->top];
		if (state[1].mask != state[0].mask)
			fz_drop_pixmap(ctx, state[1].mask);
		if (state[1].dest != state[0].dest)
			fz_drop_pixmap(ctx, state[1].dest);
		if (state[1].shape != state[0].shape)
			fz_drop_pixmap(ctx, state[1].shape);
	}
	/* We never free the dest/mask/shape at level 0, as:
	 * 1) dest is passed in and ownership remains with the caller.
	 * 2) shape and mask are NULL at level 0.
	 */
	if (dev->stack != &dev->init_stack[0])
		fz_free(ctx, dev->stack);
	fz_drop_scale_cache(ctx, dev->cache_x);
	fz_drop_scale_cache(ctx, dev->cache_y);
	fz_drop_gel(ctx, gel);
}

static void
fz_draw_render_flags(fz_context *ctx, fz_device *devp, int set, int clear)
{
	fz_draw_device *dev = (fz_draw_device*)devp;

	dev->flags = (dev->flags | set ) & ~clear;
}

fz_device *
fz_new_draw_device(fz_context *ctx, fz_pixmap *dest)
{
	fz_draw_device *dev = fz_new_device(ctx, sizeof *dev);

	dev->super.drop_imp = fz_draw_drop_imp;

	dev->super.fill_path = fz_draw_fill_path;
	dev->super.stroke_path = fz_draw_stroke_path;
	dev->super.clip_path = fz_draw_clip_path;
	dev->super.clip_stroke_path = fz_draw_clip_stroke_path;

	dev->super.fill_text = fz_draw_fill_text;
	dev->super.stroke_text = fz_draw_stroke_text;
	dev->super.clip_text = fz_draw_clip_text;
	dev->super.clip_stroke_text = fz_draw_clip_stroke_text;
	dev->super.ignore_text = fz_draw_ignore_text;

	dev->super.fill_image_mask = fz_draw_fill_image_mask;
	dev->super.clip_image_mask = fz_draw_clip_image_mask;
	dev->super.fill_image = fz_draw_fill_image;
	dev->super.fill_shade = fz_draw_fill_shade;

	dev->super.pop_clip = fz_draw_pop_clip;

	dev->super.begin_mask = fz_draw_begin_mask;
	dev->super.end_mask = fz_draw_end_mask;
	dev->super.begin_group = fz_draw_begin_group;
	dev->super.end_group = fz_draw_end_group;

	dev->super.begin_tile = fz_draw_begin_tile;
	dev->super.end_tile = fz_draw_end_tile;

	dev->super.render_flags = fz_draw_render_flags;

	dev->flags = 0;
	dev->top = 0;
	dev->stack = &dev->init_stack[0];
	dev->stack_cap = STACK_SIZE;
	dev->stack[0].dest = dest;
	dev->stack[0].shape = NULL;
	dev->stack[0].mask = NULL;
	dev->stack[0].blendmode = 0;
	dev->stack[0].scissor.x0 = dest->x;
	dev->stack[0].scissor.y0 = dest->y;
	dev->stack[0].scissor.x1 = dest->x + dest->w;
	dev->stack[0].scissor.y1 = dest->y + dest->h;

	fz_try(ctx)
	{
		dev->gel = fz_new_gel(ctx);
		dev->cache_x = fz_new_scale_cache(ctx);
		dev->cache_y = fz_new_scale_cache(ctx);
	}
	fz_catch(ctx)
	{
		fz_drop_device(ctx, (fz_device*)dev);
		fz_rethrow(ctx);
	}

	return (fz_device*)dev;
}

fz_device *
fz_new_draw_device_with_bbox(fz_context *ctx, fz_pixmap *dest, const fz_irect *clip)
{
	fz_draw_device *dev = (fz_draw_device*)fz_new_draw_device(ctx, dest);

	if (clip->x0 > dev->stack[0].scissor.x0)
		dev->stack[0].scissor.x0 = clip->x0;
	if (clip->x1 < dev->stack[0].scissor.x1)
		dev->stack[0].scissor.x1 = clip->x1;
	if (clip->y0 > dev->stack[0].scissor.y0)
		dev->stack[0].scissor.y0 = clip->y0;
	if (clip->y1 < dev->stack[0].scissor.y1)
		dev->stack[0].scissor.y1 = clip->y1;

	return (fz_device*)dev;
}

fz_device *
fz_new_draw_device_type3(fz_context *ctx, fz_pixmap *dest)
{
	fz_draw_device *dev = (fz_draw_device*)fz_new_draw_device(ctx, dest);
	dev->flags |= FZ_DRAWDEV_FLAGS_TYPE3;
	return (fz_device*)dev;
}

fz_irect *
fz_bound_path_accurate(fz_context *ctx, fz_irect *bbox, const fz_irect *scissor, const fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, float flatness, float linewidth)
{
	fz_gel *gel = fz_new_gel(ctx);

	fz_reset_gel(ctx, gel, scissor);
	if (stroke)
	{
		if (stroke->dash_len > 0)
			fz_flatten_dash_path(ctx, gel, path, stroke, ctm, flatness, linewidth);
		else
			fz_flatten_stroke_path(ctx, gel, path, stroke, ctm, flatness, linewidth);
	}
	else
		fz_flatten_fill_path(ctx, gel, path, ctm, flatness);
	fz_bound_gel(ctx, gel, bbox);
	fz_drop_gel(ctx, gel);

	return bbox;
}
