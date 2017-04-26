#include "mupdf/fitz.h"
#include "draw-imp.h"

void fz_new_aa_context(fz_context *ctx)
{
#ifndef AA_BITS
	ctx->aa = fz_malloc_struct(ctx, fz_aa_context);
	ctx->aa->hscale = 17;
	ctx->aa->vscale = 15;
	ctx->aa->scale = 256;
	ctx->aa->bits = 8;
	ctx->aa->text_bits = 8;
#endif
}

void fz_copy_aa_context(fz_context *dst, fz_context *src)
{
	if (dst && dst->aa && src && src->aa)
		memcpy(dst->aa, src->aa, sizeof(*src->aa));
}

void fz_drop_aa_context(fz_context *ctx)
{
	if (!ctx)
		return;
#ifndef AA_BITS
	fz_free(ctx, ctx->aa);
	ctx->aa = NULL;
#endif
}

int
fz_aa_level(fz_context *ctx)
{
	return fz_aa_bits;
}

int
fz_graphics_aa_level(fz_context *ctx)
{
	return fz_aa_bits;
}

int
fz_text_aa_level(fz_context *ctx)
{
	return fz_aa_text_bits;
}

#ifndef AA_BITS
static void
set_gfx_level(fz_context *ctx, int level)
{
	if (level == 9 || level == 10)
	{
		fz_aa_hscale = 1;
		fz_aa_vscale = 1;
		fz_aa_bits = level;
	}
	else if (level > 6)
	{
		fz_aa_hscale = 17;
		fz_aa_vscale = 15;
		fz_aa_bits = 8;
	}
	else if (level > 4)
	{
		fz_aa_hscale = 8;
		fz_aa_vscale = 8;
		fz_aa_bits = 6;
	}
	else if (level > 2)
	{
		fz_aa_hscale = 5;
		fz_aa_vscale = 3;
		fz_aa_bits = 4;
	}
	else if (level > 0)
	{
		fz_aa_hscale = 2;
		fz_aa_vscale = 2;
		fz_aa_bits = 2;
	}
	else
	{
		fz_aa_hscale = 1;
		fz_aa_vscale = 1;
		fz_aa_bits = 0;
	}
	fz_aa_scale = 0xFF00 / (fz_aa_hscale * fz_aa_vscale);
}

static void
set_txt_level(fz_context *ctx, int level)
{
	if (level > 6)
		fz_aa_text_bits = 8;
	else if (level > 4)
		fz_aa_text_bits = 6;
	else if (level > 2)
		fz_aa_text_bits = 4;
	else if (level > 0)
		fz_aa_text_bits = 2;
	else
		fz_aa_text_bits = 0;
}
#endif /* AA_BITS */

void
fz_set_aa_level(fz_context *ctx, int level)
{
#ifdef AA_BITS
	fz_warn(ctx, "anti-aliasing was compiled with a fixed precision of %d bits", fz_aa_bits);
#else
	set_gfx_level(ctx, level);
	set_txt_level(ctx, level);
#endif
}

void
fz_set_text_aa_level(fz_context *ctx, int level)
{
#ifdef AA_BITS
	fz_warn(ctx, "anti-aliasing was compiled with a fixed precision of %d bits", fz_aa_bits);
#else
	set_txt_level(ctx, level);
#endif
}

void
fz_set_graphics_aa_level(fz_context *ctx, int level)
{
#ifdef AA_BITS
	fz_warn(ctx, "anti-aliasing was compiled with a fixed precision of %d bits", fz_aa_bits);
#else
	set_gfx_level(ctx, level);
#endif
}

void
fz_set_graphics_min_line_width(fz_context *ctx, float min_line_width)
{
	if (!ctx || !ctx->aa)
		return;

	ctx->aa->min_line_width = min_line_width;
}

float
fz_graphics_min_line_width(fz_context *ctx)
{
	if (!ctx || !ctx->aa)
		return 0;

	return ctx->aa->min_line_width;
}

fz_irect *
fz_bound_rasterizer(fz_context *ctx, const fz_rasterizer *rast, fz_irect *bbox)
{
	const int hscale = fz_aa_hscale;
	const int vscale = fz_aa_vscale;

	if (rast->bbox.x1 < rast->bbox.x0 || rast->bbox.y1 < rast->bbox.y0)
	{
		*bbox = fz_empty_irect;
	}
	else
	{
		bbox->x0 = fz_idiv(rast->bbox.x0, hscale);
		bbox->y0 = fz_idiv(rast->bbox.y0, vscale);
		bbox->x1 = fz_idiv_up(rast->bbox.x1, hscale);
		bbox->y1 = fz_idiv_up(rast->bbox.y1, vscale);
	}
	return bbox;
}

fz_rect *fz_scissor_rasterizer(fz_context *ctx, const fz_rasterizer *rast, fz_rect *r)
{
	const int hscale = fz_aa_hscale;
	const int vscale = fz_aa_vscale;

	r->x0 = ((float)rast->clip.x0) / hscale;
	r->y0 = ((float)rast->clip.y0) / vscale;
	r->x1 = ((float)rast->clip.x1) / hscale;
	r->y1 = ((float)rast->clip.y1) / vscale;

	return r;
}

static fz_irect *fz_clip_rasterizer(fz_context *ctx, const fz_rasterizer *rast, fz_irect *r)
{
	const int hscale = fz_aa_hscale;
	const int vscale = fz_aa_vscale;

	r->x0 = fz_idiv(rast->clip.x0, hscale);
	r->y0 = fz_idiv(rast->clip.y0, vscale);
	r->x1 = fz_idiv_up(rast->clip.x1, hscale);
	r->y1 = fz_idiv_up(rast->clip.y1, vscale);

	return r;
}

int fz_reset_rasterizer(fz_context *ctx, fz_rasterizer *rast, const fz_irect *clip)
{
	const int hscale = fz_aa_hscale;
	const int vscale = fz_aa_vscale;

	if (fz_is_infinite_irect(clip))
	{
		rast->clip.x0 = rast->clip.y0 = BBOX_MIN;
		rast->clip.x1 = rast->clip.y1 = BBOX_MAX;
	}
	else {
		rast->clip.x0 = clip->x0 * hscale;
		rast->clip.x1 = clip->x1 * hscale;
		rast->clip.y0 = clip->y0 * vscale;
		rast->clip.y1 = clip->y1 * vscale;
	}

	rast->bbox.x0 = rast->bbox.y0 = BBOX_MAX;
	rast->bbox.x1 = rast->bbox.y1 = BBOX_MIN;
	if (rast->fns.reset)
		return rast->fns.reset(ctx, rast);
	return 0;
}

void *fz_new_rasterizer_of_size(fz_context *ctx, int size, const fz_rasterizer_fns *fns)
{
	fz_rasterizer *rast = fz_calloc(ctx, 1, size);

	rast->fns = *fns;
	rast->clip.x0 = rast->clip.y0 = BBOX_MIN;
	rast->clip.x1 = rast->clip.y1 = BBOX_MAX;

	rast->bbox.x0 = rast->bbox.y0 = BBOX_MAX;
	rast->bbox.x1 = rast->bbox.y1 = BBOX_MIN;

	return rast;
}

fz_rasterizer *fz_new_rasterizer(fz_context *ctx)
{
	return fz_new_gel(ctx);
}

void fz_convert_rasterizer(fz_context *ctx, fz_rasterizer *r, int eofill, fz_pixmap *pix, unsigned char *colorbv)
{
	fz_irect clip, scissor;
	fz_irect pixmap_clip;

	if (fz_is_empty_irect(fz_intersect_irect(fz_bound_rasterizer(ctx, r, &clip), fz_pixmap_bbox_no_ctx(pix, &pixmap_clip))))
		return;
	if (fz_is_empty_irect(fz_intersect_irect(&clip, fz_clip_rasterizer(ctx, r, &scissor))))
		return;
	r->fns.convert(ctx, r, eofill, &clip, pix, colorbv);
}
