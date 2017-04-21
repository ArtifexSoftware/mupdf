#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>
#include <math.h>

#define TILE

/*
 * Emit graphics calls to device.
 */

typedef struct pdf_material_s pdf_material;
typedef struct pdf_run_processor_s pdf_run_processor;

static void pdf_run_xobject(fz_context *ctx, pdf_run_processor *proc, pdf_xobject *xobj, pdf_obj *page_resources, const fz_matrix *transform);

enum
{
	PDF_FILL,
	PDF_STROKE,
};

enum
{
	PDF_MAT_NONE,
	PDF_MAT_COLOR,
	PDF_MAT_PATTERN,
	PDF_MAT_SHADE,
};

struct pdf_material_s
{
	int kind;
	fz_colorspace *colorspace;
	pdf_pattern *pattern;
	fz_shade *shade;
	int gstate_num;
	float alpha;
	float v[FZ_MAX_COLORS];
};

struct pdf_gstate_s
{
	fz_matrix ctm;
	int clip_depth;

	/* path stroking */
	fz_stroke_state *stroke_state;

	/* materials */
	pdf_material stroke;
	pdf_material fill;

	/* text state */
	float char_space;
	float word_space;
	float scale;
	float leading;
	pdf_font_desc *font;
	float size;
	int render;
	float rise;

	/* transparency */
	int blendmode;
	pdf_xobject *softmask;
	pdf_obj *softmask_resources;
	fz_matrix softmask_ctm;
	float softmask_bc[FZ_MAX_COLORS];
	int luminosity;
};

struct pdf_run_processor_s
{
	pdf_processor super;
	fz_device *dev;

	int nested_depth;

	/* path object state */
	fz_path *path;
	int clip;
	int clip_even_odd;

	/* text object state */
	fz_text *text;
	fz_rect text_bbox;
	fz_matrix tlm;
	fz_matrix tm;
	int text_mode;

	/* graphics state */
	pdf_gstate *gstate;
	int gcap;
	int gtop;
	int gbot;
	int gparent;
};

typedef struct softmask_save_s softmask_save;

struct softmask_save_s
{
	pdf_xobject *softmask;
	pdf_obj *page_resources;
	fz_matrix ctm;
};

static pdf_gstate *
begin_softmask(fz_context *ctx, pdf_run_processor *pr, softmask_save *save)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_xobject *softmask = gstate->softmask;
	fz_rect mask_bbox;
	fz_matrix save_tm, save_tlm, save_ctm;
	fz_matrix mask_matrix;
	fz_colorspace *mask_colorspace;

	save->softmask = softmask;
	if (softmask == NULL)
		return gstate;
	save->page_resources = gstate->softmask_resources;
	save->ctm = gstate->softmask_ctm;
	save_ctm = gstate->ctm;

	pdf_xobject_bbox(ctx, softmask, &mask_bbox);
	pdf_xobject_matrix(ctx, softmask, &mask_matrix);

	save_tm = pr->tm;
	save_tlm = pr->tlm;

	if (gstate->luminosity)
		mask_bbox = fz_infinite_rect;
	else
	{
		fz_transform_rect(&mask_bbox, &mask_matrix);
		fz_transform_rect(&mask_bbox, &gstate->softmask_ctm);
	}
	gstate->softmask = NULL;
	gstate->softmask_resources = NULL;
	gstate->ctm = gstate->softmask_ctm;

	mask_colorspace = pdf_xobject_colorspace(ctx, softmask);

	if (gstate->luminosity && !mask_colorspace)
		mask_colorspace = fz_device_gray(ctx);

	fz_try(ctx)
	{
		fz_begin_mask(ctx, pr->dev, &mask_bbox, gstate->luminosity, mask_colorspace, gstate->softmask_bc);
		pdf_run_xobject(ctx, pr, softmask, save->page_resources, &fz_identity);
	}
	fz_always(ctx)
		fz_drop_colorspace(ctx, mask_colorspace);
	fz_catch(ctx)
	{
		fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
		/* FIXME: Ignore error - nasty, but if we throw from
		 * here the clip stack would be messed up. */
		/* TODO: pass cookie here to increase the cookie error count */
	}

	fz_end_mask(ctx, pr->dev);

	pr->tm = save_tm;
	pr->tlm = save_tlm;

	gstate = pr->gstate + pr->gtop;
	gstate->ctm = save_ctm;

	return gstate;
}

static void
end_softmask(fz_context *ctx, pdf_run_processor *pr, softmask_save *save)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;

	if (save->softmask == NULL)
		return;

	gstate->softmask = save->softmask;
	gstate->softmask_resources = save->page_resources;
	gstate->softmask_ctm = save->ctm;
	fz_pop_clip(ctx, pr->dev);
}

static pdf_gstate *
pdf_begin_group(fz_context *ctx, pdf_run_processor *pr, const fz_rect *bbox, softmask_save *softmask)
{
	pdf_gstate *gstate = begin_softmask(ctx, pr, softmask);

	if (gstate->blendmode)
		fz_begin_group(ctx, pr->dev, bbox, 1, 0, gstate->blendmode, 1);

	return pr->gstate + pr->gtop;
}

static void
pdf_end_group(fz_context *ctx, pdf_run_processor *pr, softmask_save *softmask)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;

	if (gstate->blendmode)
		fz_end_group(ctx, pr->dev);

	end_softmask(ctx, pr, softmask);
}

static void
pdf_show_shade(fz_context *ctx, pdf_run_processor *pr, fz_shade *shd)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	fz_rect bbox;
	softmask_save softmask = { NULL };

	if (pr->super.hidden)
		return;

	fz_bound_shade(ctx, shd, &gstate->ctm, &bbox);

	gstate = pdf_begin_group(ctx, pr, &bbox, &softmask);

	/* FIXME: The gstate->ctm in the next line may be wrong; maybe
	 * it should be the parent gstates ctm? */
	fz_fill_shade(ctx, pr->dev, shd, &gstate->ctm, gstate->fill.alpha);

	pdf_end_group(ctx, pr, &softmask);
}

static pdf_material *
pdf_keep_material(fz_context *ctx, pdf_material *mat)
{
	if (mat->colorspace)
		fz_keep_colorspace(ctx, mat->colorspace);
	if (mat->pattern)
		pdf_keep_pattern(ctx, mat->pattern);
	if (mat->shade)
		fz_keep_shade(ctx, mat->shade);
	return mat;
}

static pdf_material *
pdf_drop_material(fz_context *ctx, pdf_material *mat)
{
	fz_drop_colorspace(ctx, mat->colorspace);
	pdf_drop_pattern(ctx, mat->pattern);
	fz_drop_shade(ctx, mat->shade);
	return mat;
}

static void
pdf_copy_pattern_gstate(fz_context *ctx, pdf_gstate *gs, const pdf_gstate *old)
{
	gs->ctm = old->ctm;

	pdf_drop_font(ctx, gs->font);
	gs->font = pdf_keep_font(ctx, old->font);

	pdf_drop_xobject(ctx, gs->softmask);
	gs->softmask = pdf_keep_xobject(ctx, old->softmask);

	fz_drop_stroke_state(ctx, gs->stroke_state);
	gs->stroke_state = fz_keep_stroke_state(ctx, old->stroke_state);
}

static void
pdf_unset_pattern(fz_context *ctx, pdf_run_processor *pr, int what)
{
	pdf_gstate *gs = pr->gstate + pr->gtop;
	pdf_material *mat;
	mat = what == PDF_FILL ? &gs->fill : &gs->stroke;
	if (mat->kind == PDF_MAT_PATTERN)
	{
		pdf_drop_pattern(ctx, mat->pattern);
		mat->pattern = NULL;
		mat->kind = PDF_MAT_COLOR;
	}
}

static void
pdf_keep_gstate(fz_context *ctx, pdf_gstate *gs)
{
	pdf_keep_material(ctx, &gs->stroke);
	pdf_keep_material(ctx, &gs->fill);
	if (gs->font)
		pdf_keep_font(ctx, gs->font);
	if (gs->softmask)
		pdf_keep_xobject(ctx, gs->softmask);
	if (gs->softmask_resources)
		pdf_keep_obj(ctx, gs->softmask_resources);
	fz_keep_stroke_state(ctx, gs->stroke_state);
}

static void
pdf_drop_gstate(fz_context *ctx, pdf_gstate *gs)
{
	pdf_drop_material(ctx, &gs->stroke);
	pdf_drop_material(ctx, &gs->fill);
	pdf_drop_font(ctx, gs->font);
	pdf_drop_xobject(ctx, gs->softmask);
	pdf_drop_obj(ctx, gs->softmask_resources);
	fz_drop_stroke_state(ctx, gs->stroke_state);
}

static void
pdf_gsave(fz_context *ctx, pdf_run_processor *pr)
{
	if (pr->gtop == pr->gcap-1)
	{
		pr->gstate = fz_resize_array(ctx, pr->gstate, pr->gcap*2, sizeof(pdf_gstate));
		pr->gcap *= 2;
	}

	memcpy(&pr->gstate[pr->gtop + 1], &pr->gstate[pr->gtop], sizeof(pdf_gstate));

	pr->gtop++;
	pdf_keep_gstate(ctx, &pr->gstate[pr->gtop]);
}

static void
pdf_grestore(fz_context *ctx, pdf_run_processor *pr)
{
	pdf_gstate *gs = pr->gstate + pr->gtop;
	int clip_depth = gs->clip_depth;

	if (pr->gtop <= pr->gbot)
	{
		fz_warn(ctx, "gstate underflow in content stream");
		return;
	}

	pdf_drop_gstate(ctx, gs);
	pr->gtop --;

	gs = pr->gstate + pr->gtop;
	while (clip_depth > gs->clip_depth)
	{
		fz_try(ctx)
		{
			fz_pop_clip(ctx, pr->dev);
		}
		fz_catch(ctx)
		{
			/* Silently swallow the problem - restores must
			 * never throw! */
		}
		clip_depth--;
	}
}

static void
pdf_show_pattern(fz_context *ctx, pdf_run_processor *pr, pdf_pattern *pat, pdf_gstate *pat_gstate, const fz_rect *area, int what)
{
	pdf_gstate *gstate;
	int gparent_save;
	fz_matrix ptm, invptm, gparent_save_ctm;
	int x0, y0, x1, y1;
	float fx0, fy0, fx1, fy1;
	fz_rect local_area;

	pdf_gsave(ctx, pr);
	gstate = pr->gstate + pr->gtop;

	/* Patterns are run with the gstate of the parent */
	pdf_copy_pattern_gstate(ctx, gstate, pat_gstate);

	if (pat->ismask)
	{
		pdf_unset_pattern(ctx, pr, PDF_FILL);
		pdf_unset_pattern(ctx, pr, PDF_STROKE);
		if (what == PDF_FILL)
		{
			pdf_drop_material(ctx, &gstate->stroke);
			pdf_keep_material(ctx, &gstate->fill);
			gstate->stroke = gstate->fill;
		}
		if (what == PDF_STROKE)
		{
			pdf_drop_material(ctx, &gstate->fill);
			pdf_keep_material(ctx, &gstate->stroke);
			gstate->fill = gstate->stroke;
		}
	}
	else
	{
		// TODO: unset only the current fill/stroke or both?
		pdf_unset_pattern(ctx, pr, what);
	}

	/* don't apply soft masks to objects in the pattern as well */
	if (gstate->softmask)
	{
		pdf_drop_xobject(ctx, gstate->softmask);
		gstate->softmask = NULL;
	}

	fz_concat(&ptm, &pat->matrix, &pat_gstate->ctm);
	fz_invert_matrix(&invptm, &ptm);

	/* The parent_ctm is amended with our pattern matrix */
	gparent_save = pr->gparent;
	pr->gparent = pr->gtop-1;
	gparent_save_ctm = pr->gstate[pr->gparent].ctm;
	pr->gstate[pr->gparent].ctm = ptm;

	fz_try(ctx)
	{
		/* patterns are painted using the parent_ctm. area = bbox of
		 * shape to be filled in device space. Map it back to pattern
		 * space. */
		local_area = *area;
		fz_transform_rect(&local_area, &invptm);

		fx0 = (local_area.x0 - pat->bbox.x0) / pat->xstep;
		fy0 = (local_area.y0 - pat->bbox.y0) / pat->ystep;
		fx1 = (local_area.x1 - pat->bbox.x0) / pat->xstep;
		fy1 = (local_area.y1 - pat->bbox.y0) / pat->ystep;
		if (fx0 > fx1)
		{
			float t = fx0; fx0 = fx1; fx1 = t;
		}
		if (fy0 > fy1)
		{
			float t = fy0; fy0 = fy1; fy1 = t;
		}

#ifdef TILE
		/* We have tried various formulations in the past, but this one is
		 * best we've found; only use it as a tile if a whole repeat is
		 * required in at least one direction. Note, that this allows for
		 * 'sections' of 4 tiles to be show, but all non-overlapping. */
		if (fx1-fx0 > 1 || fy1-fy0 > 1)
#else
		if (0)
#endif
		{
			fz_begin_tile(ctx, pr->dev, &local_area, &pat->bbox, pat->xstep, pat->ystep, &ptm);
			gstate->ctm = ptm;
			pdf_gsave(ctx, pr);
			fz_try(ctx)
			{
				pdf_process_contents(ctx, (pdf_processor*)pr, pat->document, pat->resources, pat->contents, NULL);
			}
			fz_always(ctx)
			{
				pdf_grestore(ctx, pr);
				fz_end_tile(ctx, pr->dev);
			}
			fz_catch(ctx)
			{
				fz_rethrow(ctx);
			}
		}
		else
		{
			int x, y;

			/* When calculating the number of tiles required, we adjust by
			 * a small amount to allow for rounding errors. By choosing
			 * this amount to be smaller than 1/256, we guarantee we won't
			 * cause problems that will be visible even under our most
			 * extreme antialiasing. */
			x0 = floorf(fx0 + 0.001);
			y0 = floorf(fy0 + 0.001);
			x1 = ceilf(fx1 - 0.001);
			y1 = ceilf(fy1 - 0.001);
			/* The above adjustments cause problems for sufficiently
			 * large values for xstep/ystep which may be used if the
			 * pattern is expected to be rendered exactly once. */
			if (fx1 > fx0 && x1 == x0)
				x1 = x0 + 1;
			if (fy1 > fy0 && y1 == y0)
				y1 = y0 + 1;

			for (y = y0; y < y1; y++)
			{
				for (x = x0; x < x1; x++)
				{
					gstate->ctm = ptm;
					fz_pre_translate(&gstate->ctm, x * pat->xstep, y * pat->ystep);
					pdf_gsave(ctx, pr);
					fz_try(ctx)
						pdf_process_contents(ctx, (pdf_processor*)pr, pat->document, pat->resources, pat->contents, NULL);
					fz_always(ctx)
						pdf_grestore(ctx, pr);
					fz_catch(ctx)
						fz_rethrow(ctx);
				}
			}
		}
	}
	fz_always(ctx)
	{
		pr->gstate[pr->gparent].ctm = gparent_save_ctm;
		pr->gparent = gparent_save;
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	pdf_grestore(ctx, pr);
}

static void
pdf_show_image(fz_context *ctx, pdf_run_processor *pr, fz_image *image)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	fz_matrix image_ctm;
	fz_rect bbox;
	softmask_save softmask = { NULL };

	if (pr->super.hidden)
		return;

	/* PDF has images bottom-up, so flip them right side up here */
	image_ctm = gstate->ctm;
	fz_pre_scale(fz_pre_translate(&image_ctm, 0, 1), 1, -1);

	bbox = fz_unit_rect;
	fz_transform_rect(&bbox, &image_ctm);

	if (image->mask)
	{
		/* apply blend group even though we skip the soft mask */
		if (gstate->blendmode)
			fz_begin_group(ctx, pr->dev, &bbox, 0, 0, gstate->blendmode, 1);
		fz_clip_image_mask(ctx, pr->dev, image->mask, &image_ctm, &bbox);
	}
	else
		gstate = pdf_begin_group(ctx, pr, &bbox, &softmask);

	if (!image->colorspace)
	{
		switch (gstate->fill.kind)
		{
		case PDF_MAT_NONE:
			break;
		case PDF_MAT_COLOR:
			fz_fill_image_mask(ctx, pr->dev, image, &image_ctm,
				gstate->fill.colorspace, gstate->fill.v, gstate->fill.alpha);
			break;
		case PDF_MAT_PATTERN:
			if (gstate->fill.pattern)
			{
				fz_clip_image_mask(ctx, pr->dev, image, &image_ctm, &bbox);
				pdf_show_pattern(ctx, pr, gstate->fill.pattern, &pr->gstate[gstate->fill.gstate_num], &bbox, PDF_FILL);
				fz_pop_clip(ctx, pr->dev);
			}
			break;
		case PDF_MAT_SHADE:
			if (gstate->fill.shade)
			{
				fz_clip_image_mask(ctx, pr->dev, image, &image_ctm, &bbox);
				fz_fill_shade(ctx, pr->dev, gstate->fill.shade, &pr->gstate[gstate->fill.gstate_num].ctm, gstate->fill.alpha);
				fz_pop_clip(ctx, pr->dev);
			}
			break;
		}
	}
	else
	{
		fz_fill_image(ctx, pr->dev, image, &image_ctm, gstate->fill.alpha);
	}

	if (image->mask)
	{
		fz_pop_clip(ctx, pr->dev);
		if (gstate->blendmode)
			fz_end_group(ctx, pr->dev);
	}
	else
		pdf_end_group(ctx, pr, &softmask);
}

static void
pdf_show_path(fz_context *ctx, pdf_run_processor *pr, int doclose, int dofill, int dostroke, int even_odd)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	fz_path *path;
	fz_rect bbox;
	softmask_save softmask = { NULL };
	int knockout_group = 0;

	if (dostroke) {
		if (pr->dev->flags & (FZ_DEVFLAG_STROKECOLOR_UNDEFINED | FZ_DEVFLAG_LINEJOIN_UNDEFINED | FZ_DEVFLAG_LINEWIDTH_UNDEFINED))
			pr->dev->flags |= FZ_DEVFLAG_UNCACHEABLE;
		else if (gstate->stroke_state->dash_len != 0 && pr->dev->flags & (FZ_DEVFLAG_STARTCAP_UNDEFINED | FZ_DEVFLAG_DASHCAP_UNDEFINED | FZ_DEVFLAG_ENDCAP_UNDEFINED))
			pr->dev->flags |= FZ_DEVFLAG_UNCACHEABLE;
		else if (gstate->stroke_state->linejoin == FZ_LINEJOIN_MITER && (pr->dev->flags & FZ_DEVFLAG_MITERLIMIT_UNDEFINED))
			pr->dev->flags |= FZ_DEVFLAG_UNCACHEABLE;
	}
	if (dofill) {
		if (pr->dev->flags & FZ_DEVFLAG_FILLCOLOR_UNDEFINED)
			pr->dev->flags |= FZ_DEVFLAG_UNCACHEABLE;
	}

	path = pr->path;
	pr->path = fz_new_path(ctx);

	fz_try(ctx)
	{
		if (doclose)
			fz_closepath(ctx, path);

		fz_bound_path(ctx, path, (dostroke ? gstate->stroke_state : NULL), &gstate->ctm, &bbox);

		if (pr->clip)
		{
			gstate->clip_depth++;
			fz_clip_path(ctx, pr->dev, path, pr->clip_even_odd, &gstate->ctm, &bbox);
			pr->clip = 0;
		}

		if (pr->super.hidden)
			dostroke = dofill = 0;

		if (dofill || dostroke)
			gstate = pdf_begin_group(ctx, pr, &bbox, &softmask);

		if (dofill && dostroke)
		{
			/* We may need to push a knockout group */
			if (gstate->stroke.alpha == 0)
			{
				/* No need for group, as stroke won't do anything */
			}
			else if (gstate->stroke.alpha == 1.0f && gstate->blendmode == FZ_BLEND_NORMAL)
			{
				/* No need for group, as stroke won't show up */
			}
			else
			{
				knockout_group = 1;
				fz_begin_group(ctx, pr->dev, &bbox, 0, 1, FZ_BLEND_NORMAL, 1);
			}
		}

		if (dofill)
		{
			switch (gstate->fill.kind)
			{
			case PDF_MAT_NONE:
				break;
			case PDF_MAT_COLOR:
				fz_fill_path(ctx, pr->dev, path, even_odd, &gstate->ctm,
					gstate->fill.colorspace, gstate->fill.v, gstate->fill.alpha);
				break;
			case PDF_MAT_PATTERN:
				if (gstate->fill.pattern)
				{
					fz_clip_path(ctx, pr->dev, path, even_odd, &gstate->ctm, &bbox);
					pdf_show_pattern(ctx, pr, gstate->fill.pattern, &pr->gstate[gstate->fill.gstate_num], &bbox, PDF_FILL);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			case PDF_MAT_SHADE:
				if (gstate->fill.shade)
				{
					fz_clip_path(ctx, pr->dev, path, even_odd, &gstate->ctm, &bbox);
					/* The cluster and page 2 of patterns.pdf shows that fz_fill_shade should NOT be called with gstate->ctm. */
					fz_fill_shade(ctx, pr->dev, gstate->fill.shade, &pr->gstate[gstate->fill.gstate_num].ctm, gstate->fill.alpha);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			}
		}

		if (dostroke)
		{
			switch (gstate->stroke.kind)
			{
			case PDF_MAT_NONE:
				break;
			case PDF_MAT_COLOR:
				fz_stroke_path(ctx, pr->dev, path, gstate->stroke_state, &gstate->ctm,
					gstate->stroke.colorspace, gstate->stroke.v, gstate->stroke.alpha);
				break;
			case PDF_MAT_PATTERN:
				if (gstate->stroke.pattern)
				{
					fz_clip_stroke_path(ctx, pr->dev, path, gstate->stroke_state, &gstate->ctm, &bbox);
					pdf_show_pattern(ctx, pr, gstate->stroke.pattern, &pr->gstate[gstate->stroke.gstate_num], &bbox, PDF_STROKE);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			case PDF_MAT_SHADE:
				if (gstate->stroke.shade)
				{
					fz_clip_stroke_path(ctx, pr->dev, path, gstate->stroke_state, &gstate->ctm, &bbox);
					fz_fill_shade(ctx, pr->dev, gstate->stroke.shade, &pr->gstate[gstate->stroke.gstate_num].ctm, gstate->stroke.alpha);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			}
		}

		if (knockout_group)
			fz_end_group(ctx, pr->dev);

		if (dofill || dostroke)
			pdf_end_group(ctx, pr, &softmask);
	}
	fz_always(ctx)
	{
		fz_drop_path(ctx, path);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

/*
 * Assemble and emit text
 */

static pdf_gstate *
pdf_flush_text(fz_context *ctx, pdf_run_processor *pr)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	fz_text *text;
	int dofill;
	int dostroke;
	int doclip;
	int doinvisible;
	softmask_save softmask = { NULL };
	int knockout_group = 0;

	if (!pr->text)
		return gstate;
	text = pr->text;
	pr->text = NULL;

	dofill = dostroke = doclip = doinvisible = 0;
	switch (pr->text_mode)
	{
	case 0: dofill = 1; break;
	case 1: dostroke = 1; break;
	case 2: dofill = dostroke = 1; break;
	case 3: doinvisible = 1; break;
	case 4: dofill = doclip = 1; break;
	case 5: dostroke = doclip = 1; break;
	case 6: dofill = dostroke = doclip = 1; break;
	case 7: doclip = 1; break;
	}

	if (pr->super.hidden)
		dostroke = dofill = 0;

	fz_try(ctx)
	{
		fz_rect tb = pr->text_bbox;

		fz_transform_rect(&tb, &gstate->ctm);
		if (dostroke)
			fz_adjust_rect_for_stroke(ctx, &tb, gstate->stroke_state, &gstate->ctm);

		/* Don't bother sending a text group with nothing in it */
		if (!text->head)
			break;

		if (dofill || dostroke)
			gstate = pdf_begin_group(ctx, pr, &tb, &softmask);

		if (dofill && dostroke)
		{
			/* We may need to push a knockout group */
			if (gstate->stroke.alpha == 0)
			{
				/* No need for group, as stroke won't do anything */
			}
			else if (gstate->stroke.alpha == 1.0f && gstate->blendmode == FZ_BLEND_NORMAL)
			{
				/* No need for group, as stroke won't show up */
			}
			else
			{
				knockout_group = 1;
				fz_begin_group(ctx, pr->dev, &tb, 0, 1, FZ_BLEND_NORMAL, 1);
			}
		}

		if (doinvisible)
			fz_ignore_text(ctx, pr->dev, text, &gstate->ctm);

		if (dofill)
		{
			switch (gstate->fill.kind)
			{
			case PDF_MAT_NONE:
				break;
			case PDF_MAT_COLOR:
				fz_fill_text(ctx, pr->dev, text, &gstate->ctm,
					gstate->fill.colorspace, gstate->fill.v, gstate->fill.alpha);
				break;
			case PDF_MAT_PATTERN:
				if (gstate->fill.pattern)
				{
					fz_clip_text(ctx, pr->dev, text, &gstate->ctm, &tb);
					pdf_show_pattern(ctx, pr, gstate->fill.pattern, &pr->gstate[gstate->fill.gstate_num], &tb, PDF_FILL);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			case PDF_MAT_SHADE:
				if (gstate->fill.shade)
				{
					fz_clip_text(ctx, pr->dev, text, &gstate->ctm, &tb);
					/* Page 2 of patterns.pdf shows that fz_fill_shade should NOT be called with gstate->ctm */
					fz_fill_shade(ctx, pr->dev, gstate->fill.shade, &pr->gstate[gstate->fill.gstate_num].ctm, gstate->fill.alpha);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			}
		}

		if (dostroke)
		{
			switch (gstate->stroke.kind)
			{
			case PDF_MAT_NONE:
				break;
			case PDF_MAT_COLOR:
				fz_stroke_text(ctx, pr->dev, text, gstate->stroke_state, &gstate->ctm,
					gstate->stroke.colorspace, gstate->stroke.v, gstate->stroke.alpha);
				break;
			case PDF_MAT_PATTERN:
				if (gstate->stroke.pattern)
				{
					fz_clip_stroke_text(ctx, pr->dev, text, gstate->stroke_state, &gstate->ctm, &tb);
					pdf_show_pattern(ctx, pr, gstate->stroke.pattern, &pr->gstate[gstate->stroke.gstate_num], &tb, PDF_STROKE);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			case PDF_MAT_SHADE:
				if (gstate->stroke.shade)
				{
					fz_clip_stroke_text(ctx, pr->dev, text, gstate->stroke_state, &gstate->ctm, &tb);
					fz_fill_shade(ctx, pr->dev, gstate->stroke.shade, &pr->gstate[gstate->stroke.gstate_num].ctm, gstate->stroke.alpha);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			}
		}

		if (knockout_group)
			fz_end_group(ctx, pr->dev);

		if (dofill || dostroke)
			pdf_end_group(ctx, pr, &softmask);

		if (doclip)
		{
			gstate->clip_depth++;
			fz_clip_text(ctx, pr->dev, text, &gstate->ctm, &tb);
		}
	}
	fz_always(ctx)
	{
		fz_drop_text(ctx, text);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return pr->gstate + pr->gtop;
}

static void
pdf_show_char(fz_context *ctx, pdf_run_processor *pr, int cid)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_font_desc *fontdesc = gstate->font;
	fz_matrix tsm, trm;
	float w0, w1, tx, ty;
	pdf_hmtx h;
	pdf_vmtx v;
	int gid;
	int ucsbuf[8];
	int ucslen;
	int i;
	fz_rect bbox;
	int render_direct;

	tsm.a = gstate->size * gstate->scale;
	tsm.b = 0;
	tsm.c = 0;
	tsm.d = gstate->size;
	tsm.e = 0;
	tsm.f = gstate->rise;

	ucslen = 0;
	if (fontdesc->to_unicode)
		ucslen = pdf_lookup_cmap_full(fontdesc->to_unicode, cid, ucsbuf);
	if (ucslen == 0 && (size_t)cid < fontdesc->cid_to_ucs_len)
	{
		ucsbuf[0] = fontdesc->cid_to_ucs[cid];
		ucslen = 1;
	}
	if (ucslen == 0 || (ucslen == 1 && ucsbuf[0] == 0))
	{
		ucsbuf[0] = 0xFFFD;
		ucslen = 1;
	}

	gid = pdf_font_cid_to_gid(ctx, fontdesc, cid);

	if (fontdesc->wmode == 1)
	{
		v = pdf_lookup_vmtx(ctx, fontdesc, cid);
		tsm.e -= v.x * fabsf(gstate->size) * 0.001f;
		tsm.f -= v.y * gstate->size * 0.001f;
	}

	fz_concat(&trm, &tsm, &pr->tm);

	/* Compensate for the glyph cache limited positioning precision */
	fz_expand_rect(fz_bound_glyph(ctx, fontdesc->font, gid, &trm, &bbox), 1);

	/* If we are a type3 font within a type 3 font, or are otherwise
	 * uncachable, then render direct. */
	render_direct = (!fz_font_ft_face(ctx, fontdesc->font) && pr->nested_depth > 0) || !fz_glyph_cacheable(ctx, fontdesc->font, gid);

	/* flush buffered text if rendermode has changed */
	if (!pr->text || gstate->render != pr->text_mode || render_direct)
	{
		gstate = pdf_flush_text(ctx, pr);

		pr->text = fz_new_text(ctx);
		pr->text_mode = gstate->render;
		pr->text_bbox = fz_empty_rect;
	}

	if (render_direct)
	{
		/* Render the glyph stream direct here (only happens for
		 * type3 glyphs that seem to inherit current graphics
		 * attributes, or type 3 glyphs within type3 glyphs). */
		fz_matrix composed;
		fz_concat(&composed, &trm, &gstate->ctm);
		fz_render_t3_glyph_direct(ctx, pr->dev, fontdesc->font, gid, &composed, gstate, pr->nested_depth);
		/* Render text invisibly so that it can still be extracted. */
		pr->text_mode = 3;
	}

	fz_union_rect(&pr->text_bbox, &bbox);

	/* add glyph to textobject */
	fz_show_glyph(ctx, pr->text, fontdesc->font, &trm, gid, ucsbuf[0], fontdesc->wmode, 0, FZ_BIDI_NEUTRAL, FZ_LANG_UNSET);

	/* add filler glyphs for one-to-many unicode mapping */
	for (i = 1; i < ucslen; i++)
		fz_show_glyph(ctx, pr->text, fontdesc->font, &trm, -1, ucsbuf[i], fontdesc->wmode, 0, FZ_BIDI_NEUTRAL, FZ_LANG_UNSET);

	if (fontdesc->wmode == 0)
	{
		h = pdf_lookup_hmtx(ctx, fontdesc, cid);
		w0 = h.w * 0.001f;
		tx = (w0 * gstate->size + gstate->char_space) * gstate->scale;
		fz_pre_translate(&pr->tm, tx, 0);
	}

	if (fontdesc->wmode == 1)
	{
		w1 = v.w * 0.001f;
		ty = w1 * gstate->size + gstate->char_space;
		fz_pre_translate(&pr->tm, 0, ty);
	}
}

static void
pdf_show_space(fz_context *ctx, pdf_run_processor *pr, float tadj)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_font_desc *fontdesc = gstate->font;

	if (!fontdesc)
	{
		fz_warn(ctx, "cannot draw text since font and size not set");
		return;
	}

	if (fontdesc->wmode == 0)
		fz_pre_translate(&pr->tm, tadj * gstate->scale, 0);
	else
		fz_pre_translate(&pr->tm, 0, tadj);
}

static void
pdf_show_string(fz_context *ctx, pdf_run_processor *pr, unsigned char *buf, int len)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_font_desc *fontdesc = gstate->font;
	unsigned char *end = buf + len;
	unsigned int cpt;
	int cid;

	if (!fontdesc)
	{
		fz_warn(ctx, "cannot draw text since font and size not set");
		return;
	}

	while (buf < end)
	{
		int w = pdf_decode_cmap(fontdesc->encoding, buf, end, &cpt);
		buf += w;

		cid = pdf_lookup_cmap(fontdesc->encoding, cpt);
		if (cid >= 0)
			pdf_show_char(ctx, pr, cid);
		else
			fz_warn(ctx, "cannot encode character");
		if (cpt == 32 && w == 1)
			pdf_show_space(ctx, pr, gstate->word_space);
	}
}

static void
pdf_show_text(fz_context *ctx, pdf_run_processor *pr, pdf_obj *text)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	int i;

	if (pdf_is_array(ctx, text))
	{
		int n = pdf_array_len(ctx, text);
		for (i = 0; i < n; i++)
		{
			pdf_obj *item = pdf_array_get(ctx, text, i);
			if (pdf_is_string(ctx, item))
				pdf_show_string(ctx, pr, (unsigned char *)pdf_to_str_buf(ctx, item), pdf_to_str_len(ctx, item));
			else
				pdf_show_space(ctx, pr, - pdf_to_real(ctx, item) * gstate->size * 0.001f);
		}
	}
	else if (pdf_is_string(ctx, text))
	{
		pdf_show_string(ctx, pr, (unsigned char *)pdf_to_str_buf(ctx, text), pdf_to_str_len(ctx, text));
	}
}

/*
 * Interpreter and graphics state stack.
 */

static void
pdf_init_gstate(fz_context *ctx, pdf_gstate *gs, const fz_matrix *ctm)
{
	gs->ctm = *ctm;
	gs->clip_depth = 0;

	gs->stroke_state = fz_new_stroke_state(ctx);

	gs->stroke.kind = PDF_MAT_COLOR;
	gs->stroke.colorspace = fz_device_gray(ctx); /* No fz_keep_colorspace as static */
	gs->stroke.v[0] = 0;
	gs->stroke.pattern = NULL;
	gs->stroke.shade = NULL;
	gs->stroke.alpha = 1;
	gs->stroke.gstate_num = -1;

	gs->fill.kind = PDF_MAT_COLOR;
	gs->fill.colorspace = fz_device_gray(ctx); /* No fz_keep_colorspace as static */
	gs->fill.v[0] = 0;
	gs->fill.pattern = NULL;
	gs->fill.shade = NULL;
	gs->fill.alpha = 1;
	gs->fill.gstate_num = -1;

	gs->char_space = 0;
	gs->word_space = 0;
	gs->scale = 1;
	gs->leading = 0;
	gs->font = NULL;
	gs->size = -1;
	gs->render = 0;
	gs->rise = 0;

	gs->blendmode = 0;
	gs->softmask = NULL;
	gs->softmask_resources = NULL;
	gs->softmask_ctm = fz_identity;
	gs->luminosity = 0;
}

static void
pdf_copy_gstate(fz_context *ctx, pdf_gstate *gs, pdf_gstate *old)
{
	pdf_drop_gstate(ctx, gs);
	*gs = *old;
	pdf_keep_gstate(ctx, gs);
}

/*
 * Material state
 */

static void
pdf_set_colorspace(fz_context *ctx, pdf_run_processor *pr, int what, fz_colorspace *colorspace)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_material *mat;
	int n = fz_colorspace_n(ctx, colorspace);

	gstate = pdf_flush_text(ctx, pr);

	mat = what == PDF_FILL ? &gstate->fill : &gstate->stroke;

	fz_drop_colorspace(ctx, mat->colorspace);

	mat->kind = PDF_MAT_COLOR;
	mat->colorspace = fz_keep_colorspace(ctx, colorspace);

	mat->v[0] = 0;
	mat->v[1] = 0;
	mat->v[2] = 0;
	mat->v[3] = 1;

	if (pdf_is_tint_colorspace(ctx, colorspace))
	{
		int i;
		for (i = 0; i < n; i++)
			mat->v[i] = 1.0f;
	}
}

static void
pdf_set_color(fz_context *ctx, pdf_run_processor *pr, int what, float *v)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_material *mat;
	int i, n;

	gstate = pdf_flush_text(ctx, pr);

	mat = what == PDF_FILL ? &gstate->fill : &gstate->stroke;

	switch (mat->kind)
	{
	case PDF_MAT_PATTERN:
	case PDF_MAT_COLOR:
		/* ICC Colorspaces would be handled here too, if we handled them */
		if (fz_colorspace_is_indexed(ctx, mat->colorspace))
		{
			mat->v[0] = fz_clamp(v[0], 0, 1) / 255;
			break;
		}
		else if (fz_colorspace_is_lab(ctx, mat->colorspace))
		{
			n = fz_colorspace_n(ctx, mat->colorspace);
			/* input is in range (0..100, -128..127, -128..127) not (0..1, 0..1, 0..1) */
			for (i = 0; i < n; i++)
				mat->v[i] = fz_clamp(v[i], i ? -128 : 0, i ? 127 : 100);
		}
		else
		{
			n = fz_colorspace_n(ctx, mat->colorspace);
			for (i = 0; i < n; i++)
				mat->v[i] = fz_clamp(v[i], 0, 1);
		}
		break;
	default:
		fz_warn(ctx, "color incompatible with material");
	}

	mat->gstate_num = pr->gparent;
}

static void
pdf_set_shade(fz_context *ctx, pdf_run_processor *pr, int what, fz_shade *shade)
{
	pdf_gstate *gs;
	pdf_material *mat;

	gs = pdf_flush_text(ctx, pr);

	mat = what == PDF_FILL ? &gs->fill : &gs->stroke;

	fz_drop_shade(ctx, mat->shade);

	mat->kind = PDF_MAT_SHADE;
	mat->shade = fz_keep_shade(ctx, shade);

	mat->gstate_num = pr->gparent;
}

static void
pdf_set_pattern(fz_context *ctx, pdf_run_processor *pr, int what, pdf_pattern *pat, float *v)
{
	pdf_gstate *gs;
	pdf_material *mat;

	gs = pdf_flush_text(ctx, pr);

	mat = what == PDF_FILL ? &gs->fill : &gs->stroke;

	pdf_drop_pattern(ctx, mat->pattern);
	mat->pattern = NULL;

	mat->kind = PDF_MAT_PATTERN;
	if (pat)
		mat->pattern = pdf_keep_pattern(ctx, pat);

	if (v)
		pdf_set_color(ctx, pr, what, v);

	mat->gstate_num = pr->gparent;
}

static void
pdf_run_xobject(fz_context *ctx, pdf_run_processor *proc, pdf_xobject *xobj, pdf_obj *page_resources, const fz_matrix *transform)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = NULL;
	int oldtop = 0;
	int oldbot = -1;
	fz_matrix local_transform = *transform;
	softmask_save softmask = { NULL };
	int gparent_save;
	fz_matrix gparent_save_ctm;
	int cleanup_state = 0;
	char errmess[256] = "";
	pdf_obj *resources;
	fz_rect xobj_bbox;
	fz_matrix xobj_matrix;
	int transparency;
	pdf_document *doc;

	/* Avoid infinite recursion */
	if (xobj == NULL || pdf_mark_obj(ctx, xobj->obj))
		return;

	fz_var(cleanup_state);
	fz_var(gstate);
	fz_var(oldtop);
	fz_var(oldbot);

	gparent_save = pr->gparent;
	pr->gparent = pr->gtop;
	oldtop = pr->gtop;

	fz_try(ctx)
	{
		pdf_gsave(ctx, pr);

		gstate = pr->gstate + pr->gtop;

		pdf_xobject_bbox(ctx, xobj, &xobj_bbox);
		pdf_xobject_matrix(ctx, xobj, &xobj_matrix);
		transparency = pdf_xobject_transparency(ctx, xobj);

		/* apply xobject's transform matrix */
		fz_concat(&local_transform, &xobj_matrix, &local_transform);
		fz_concat(&gstate->ctm, &local_transform, &gstate->ctm);

		/* The gparent is updated with the modified ctm */
		gparent_save_ctm = pr->gstate[pr->gparent].ctm;
		pr->gstate[pr->gparent].ctm = gstate->ctm;

		/* apply soft mask, create transparency group and reset state */
		if (transparency)
		{
			fz_rect bbox;
			bbox = xobj_bbox;
			fz_transform_rect(&bbox, &gstate->ctm);

			/* Remember that we tried to call begin_softmask. Even
			 * if it throws an error, we must call end_softmask. */
			cleanup_state = 1;
			gstate = begin_softmask(ctx, pr, &softmask);

			/* Remember that we tried to call fz_begin_group. Even
			 * if it throws an error, we must call fz_end_group. */
			cleanup_state = 2;
			fz_begin_group(ctx, pr->dev, &bbox,
					pdf_xobject_isolated(ctx, xobj),
					pdf_xobject_knockout(ctx, xobj),
					gstate->blendmode, gstate->fill.alpha);

			gstate->blendmode = 0;
			gstate->stroke.alpha = 1;
			gstate->fill.alpha = 1;
		}

		/* Remember that we tried to save for the clippath. Even if it
		 * throws an error, we must pop it. */
		cleanup_state = 3;
		pdf_gsave(ctx, pr); /* Save here so the clippath doesn't persist */

		/* clip to the bounds */
		fz_moveto(ctx, pr->path, xobj_bbox.x0, xobj_bbox.y0);
		fz_lineto(ctx, pr->path, xobj_bbox.x1, xobj_bbox.y0);
		fz_lineto(ctx, pr->path, xobj_bbox.x1, xobj_bbox.y1);
		fz_lineto(ctx, pr->path, xobj_bbox.x0, xobj_bbox.y1);
		fz_closepath(ctx, pr->path);
		pr->clip = 1;
		pdf_show_path(ctx, pr, 0, 0, 0, 0);

		/* run contents */

		resources = pdf_xobject_resources(ctx, xobj);
		if (!resources)
			resources = page_resources;

		doc = pdf_get_bound_document(ctx, xobj->obj);

		oldbot = pr->gbot;
		pr->gbot = pr->gtop;

		pdf_process_contents(ctx, (pdf_processor*)pr, doc, resources, xobj->obj, NULL);
	}
	fz_always(ctx)
	{
		/* Undo any gstate mismatches due to the pdf_process_contents call */
		if (oldbot != -1)
		{
			while (pr->gtop > pr->gbot)
			{
				pdf_grestore(ctx, pr);
			}
			pr->gbot = oldbot;
		}

		if (cleanup_state >= 3)
			pdf_grestore(ctx, pr); /* Remove the state we pushed for the clippath */

		/* wrap up transparency stacks */
		if (transparency)
		{
			if (cleanup_state >= 2)
			{
				fz_try(ctx)
				{
					fz_end_group(ctx, pr->dev);
				}
				fz_catch(ctx)
				{
					/* Postpone the problem */
					strcpy(errmess, fz_caught_message(ctx));
				}
			}
			if (cleanup_state >= 1)
			{
				fz_try(ctx)
				{
					end_softmask(ctx, pr, &softmask);
				}
				fz_catch(ctx)
				{
					/* Postpone the problem */
					strcpy(errmess, fz_caught_message(ctx));
				}
			}
		}

		pr->gstate[pr->gparent].ctm = gparent_save_ctm;
		pr->gparent = gparent_save;

		while (oldtop < pr->gtop)
			pdf_grestore(ctx, pr);

		pdf_unmark_obj(ctx, xobj->obj);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	/* Rethrow postponed errors */
	if (errmess[0])
		fz_throw(ctx, FZ_ERROR_GENERIC, "%s", errmess);
}

/* general graphics state */

static void pdf_run_w(fz_context *ctx, pdf_processor *proc, float linewidth)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);

	pr->dev->flags &= ~FZ_DEVFLAG_LINEWIDTH_UNDEFINED;
	gstate->stroke_state = fz_unshare_stroke_state(ctx, gstate->stroke_state);
	gstate->stroke_state->linewidth = linewidth;
}

static void pdf_run_j(fz_context *ctx, pdf_processor *proc, int linejoin)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);

	pr->dev->flags &= ~FZ_DEVFLAG_LINEJOIN_UNDEFINED;
	gstate->stroke_state = fz_unshare_stroke_state(ctx, gstate->stroke_state);
	gstate->stroke_state->linejoin = linejoin;
}

static void pdf_run_J(fz_context *ctx, pdf_processor *proc, int linecap)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);

	pr->dev->flags &= ~(FZ_DEVFLAG_STARTCAP_UNDEFINED | FZ_DEVFLAG_DASHCAP_UNDEFINED | FZ_DEVFLAG_ENDCAP_UNDEFINED);
	gstate->stroke_state = fz_unshare_stroke_state(ctx, gstate->stroke_state);
	gstate->stroke_state->start_cap = linecap;
	gstate->stroke_state->dash_cap = linecap;
	gstate->stroke_state->end_cap = linecap;
}

static void pdf_run_M(fz_context *ctx, pdf_processor *proc, float miterlimit)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);

	pr->dev->flags &= ~FZ_DEVFLAG_MITERLIMIT_UNDEFINED;
	gstate->stroke_state = fz_unshare_stroke_state(ctx, gstate->stroke_state);
	gstate->stroke_state->miterlimit = miterlimit;
}

static void pdf_run_d(fz_context *ctx, pdf_processor *proc, pdf_obj *array, float phase)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	int len, i;

	len = pdf_array_len(ctx, array);
	gstate->stroke_state = fz_unshare_stroke_state_with_dash_len(ctx, gstate->stroke_state, len);
	gstate->stroke_state->dash_len = len;
	for (i = 0; i < len; i++)
		gstate->stroke_state->dash_list[i] = pdf_to_real(ctx, pdf_array_get(ctx, array, i));
	gstate->stroke_state->dash_phase = phase;
}

static void pdf_run_ri(fz_context *ctx, pdf_processor *proc, const char *intent)
{
}

static void pdf_run_i(fz_context *ctx, pdf_processor *proc, float flatness)
{
}

static void pdf_run_gs_begin(fz_context *ctx, pdf_processor *proc, const char *name, pdf_obj *extgstate)
{
}

static void pdf_run_gs_end(fz_context *ctx, pdf_processor *proc)
{
}

/* transparency graphics state */

static void pdf_run_gs_BM(fz_context *ctx, pdf_processor *proc, const char *blendmode)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	gstate->blendmode = fz_lookup_blendmode(blendmode);
}

static void pdf_run_gs_CA(fz_context *ctx, pdf_processor *proc, float alpha)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	gstate->stroke.alpha = fz_clamp(alpha, 0, 1);
}

static void pdf_run_gs_ca(fz_context *ctx, pdf_processor *proc, float alpha)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	gstate->fill.alpha = fz_clamp(alpha, 0, 1);
}

static void pdf_run_gs_SMask(fz_context *ctx, pdf_processor *proc, pdf_xobject *smask, pdf_obj *page_resources, float *bc, int luminosity)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	int i;

	if (gstate->softmask)
	{
		pdf_drop_xobject(ctx, gstate->softmask);
		gstate->softmask = NULL;
		pdf_drop_obj(ctx, gstate->softmask_resources);
		gstate->softmask_resources = NULL;
	}

	if (smask)
	{
		fz_colorspace *cs = pdf_xobject_colorspace(ctx, smask);
		int cs_n = 1;
		if (cs)
		{
			cs_n = fz_colorspace_n(ctx, cs);
			fz_drop_colorspace(ctx, cs);
		}
		gstate->softmask_ctm = gstate->ctm;
		gstate->softmask = pdf_keep_xobject(ctx, smask);
		gstate->softmask_resources = pdf_keep_obj(ctx, page_resources);
		for (i = 0; i < cs_n; ++i)
			gstate->softmask_bc[i] = bc[i];
		gstate->luminosity = luminosity;
		fz_drop_colorspace(ctx, cs);
	}
}

/* special graphics state */

static void pdf_run_q(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gsave(ctx, pr);
}

static void pdf_run_Q(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_grestore(ctx, pr);
}

static void pdf_run_cm(fz_context *ctx, pdf_processor *proc, float a, float b, float c, float d, float e, float f)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	fz_matrix m;

	m.a = a;
	m.b = b;
	m.c = c;
	m.d = d;
	m.e = e;
	m.f = f;
	fz_concat(&gstate->ctm, &m, &gstate->ctm);
}

/* path construction */

static void pdf_run_m(fz_context *ctx, pdf_processor *proc, float x, float y)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	fz_moveto(ctx, pr->path, x, y);
}

static void pdf_run_l(fz_context *ctx, pdf_processor *proc, float x, float y)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	fz_lineto(ctx, pr->path, x, y);
}
static void pdf_run_c(fz_context *ctx, pdf_processor *proc, float x1, float y1, float x2, float y2, float x3, float y3)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	fz_curveto(ctx, pr->path, x1, y1, x2, y2, x3, y3);
}

static void pdf_run_v(fz_context *ctx, pdf_processor *proc, float x2, float y2, float x3, float y3)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	fz_curvetov(ctx, pr->path, x2, y2, x3, y3);
}

static void pdf_run_y(fz_context *ctx, pdf_processor *proc, float x1, float y1, float x3, float y3)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	fz_curvetoy(ctx, pr->path, x1, y1, x3, y3);
}

static void pdf_run_h(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	fz_closepath(ctx, pr->path);
}

static void pdf_run_re(fz_context *ctx, pdf_processor *proc, float x, float y, float w, float h)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	fz_rectto(ctx, pr->path, x, y, x+w, y+h);
}

/* path painting */

static void pdf_run_S(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_path(ctx, pr, 0, 0, 1, 0);
}

static void pdf_run_s(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_path(ctx, pr, 1, 0, 1, 0);
}

static void pdf_run_F(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_path(ctx, pr, 0, 1, 0, 0);
}

static void pdf_run_f(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_path(ctx, pr, 0, 1, 0, 0);
}

static void pdf_run_fstar(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_path(ctx, pr, 0, 1, 0, 1);
}

static void pdf_run_B(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_path(ctx, pr, 0, 1, 1, 0);
}

static void pdf_run_Bstar(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_path(ctx, pr, 0, 1, 1, 1);
}

static void pdf_run_b(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_path(ctx, pr, 1, 1, 1, 0);
}

static void pdf_run_bstar(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_path(ctx, pr, 1, 1, 1, 1);
}

static void pdf_run_n(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_path(ctx, pr, 0, 0, 0, 0);
}

/* clipping paths */

static void pdf_run_W(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->clip = 1;
	pr->clip_even_odd = 0;
}

static void pdf_run_Wstar(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->clip = 1;
	pr->clip_even_odd = 1;
}

/* text objects */

static void pdf_run_BT(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->tm = fz_identity;
	pr->tlm = fz_identity;
}

static void pdf_run_ET(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_flush_text(ctx, pr);
}

/* text state */

static void pdf_run_Tc(fz_context *ctx, pdf_processor *proc, float charspace)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->char_space = charspace;
}

static void pdf_run_Tw(fz_context *ctx, pdf_processor *proc, float wordspace)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->word_space = wordspace;
}

static void pdf_run_Tz(fz_context *ctx, pdf_processor *proc, float scale)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->scale = scale / 100;
}

static void pdf_run_TL(fz_context *ctx, pdf_processor *proc, float leading)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->leading = leading;
}

static void pdf_run_Tf(fz_context *ctx, pdf_processor *proc, const char *name, pdf_font_desc *font, float size)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_drop_font(ctx, gstate->font);
	gstate->font = pdf_keep_font(ctx, font);
	gstate->size = size;
}

static void pdf_run_Tr(fz_context *ctx, pdf_processor *proc, int render)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->render = render;
}

static void pdf_run_Ts(fz_context *ctx, pdf_processor *proc, float rise)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->rise = rise;
}

/* text positioning */

static void pdf_run_Td(fz_context *ctx, pdf_processor *proc, float tx, float ty)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	fz_pre_translate(&pr->tlm, tx, ty);
	pr->tm = pr->tlm;
}

static void pdf_run_TD(fz_context *ctx, pdf_processor *proc, float tx, float ty)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->leading = -ty;
	fz_pre_translate(&pr->tlm, tx, ty);
	pr->tm = pr->tlm;
}

static void pdf_run_Tm(fz_context *ctx, pdf_processor *proc, float a, float b, float c, float d, float e, float f)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->tm.a = a;
	pr->tm.b = b;
	pr->tm.c = c;
	pr->tm.d = d;
	pr->tm.e = e;
	pr->tm.f = f;
	pr->tlm = pr->tm;
}

static void pdf_run_Tstar(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	fz_pre_translate(&pr->tlm, 0, -gstate->leading);
	pr->tm = pr->tlm;
}

/* text showing */

static void pdf_run_TJ(fz_context *ctx, pdf_processor *proc, pdf_obj *obj)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_text(ctx, pr, obj);
}

static void pdf_run_Tj(fz_context *ctx, pdf_processor *proc, char *string, int string_len)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_string(ctx, pr, (unsigned char *)string, string_len);
}

static void pdf_run_squote(fz_context *ctx, pdf_processor *proc, char *string, int string_len)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	fz_pre_translate(&pr->tlm, 0, -gstate->leading);
	pr->tm = pr->tlm;
	pdf_show_string(ctx, pr, (unsigned char*)string, string_len);
}

static void pdf_run_dquote(fz_context *ctx, pdf_processor *proc, float aw, float ac, char *string, int string_len)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->word_space = aw;
	gstate->char_space = ac;
	fz_pre_translate(&pr->tlm, 0, -gstate->leading);
	pr->tm = pr->tlm;
	pdf_show_string(ctx, pr, (unsigned char*)string, string_len);
}

/* type 3 fonts */

static void pdf_run_d0(fz_context *ctx, pdf_processor *proc, float wx, float wy)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	if (pr->nested_depth > 1)
		return;
	pr->dev->flags |= FZ_DEVFLAG_COLOR;
}

static void pdf_run_d1(fz_context *ctx, pdf_processor *proc, float wx, float wy, float llx, float lly, float urx, float ury)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	if (pr->nested_depth > 1)
		return;
	pr->dev->flags |= FZ_DEVFLAG_MASK | FZ_DEVFLAG_BBOX_DEFINED;
	pr->dev->flags &= ~(FZ_DEVFLAG_FILLCOLOR_UNDEFINED |
				FZ_DEVFLAG_STROKECOLOR_UNDEFINED |
				FZ_DEVFLAG_STARTCAP_UNDEFINED |
				FZ_DEVFLAG_DASHCAP_UNDEFINED |
				FZ_DEVFLAG_ENDCAP_UNDEFINED |
				FZ_DEVFLAG_LINEJOIN_UNDEFINED |
				FZ_DEVFLAG_MITERLIMIT_UNDEFINED |
				FZ_DEVFLAG_LINEWIDTH_UNDEFINED);
	pr->dev->d1_rect.x0 = fz_min(llx, urx);
	pr->dev->d1_rect.y0 = fz_min(lly, ury);
	pr->dev->d1_rect.x1 = fz_max(llx, urx);
	pr->dev->d1_rect.y1 = fz_max(lly, ury);
}

/* color */

static void pdf_run_CS(fz_context *ctx, pdf_processor *proc, const char *name, fz_colorspace *colorspace)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	if (!strcmp(name, "Pattern"))
		pdf_set_pattern(ctx, pr, PDF_STROKE, NULL, NULL);
	else
		pdf_set_colorspace(ctx, pr, PDF_STROKE, colorspace);
}

static void pdf_run_cs(fz_context *ctx, pdf_processor *proc, const char *name, fz_colorspace *colorspace)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	if (!strcmp(name, "Pattern"))
		pdf_set_pattern(ctx, pr, PDF_FILL, NULL, NULL);
	else
		pdf_set_colorspace(ctx, pr, PDF_FILL, colorspace);
}

static void pdf_run_SC_color(fz_context *ctx, pdf_processor *proc, int n, float *color)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	pdf_set_color(ctx, pr, PDF_STROKE, color);
}

static void pdf_run_sc_color(fz_context *ctx, pdf_processor *proc, int n, float *color)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	pdf_set_color(ctx, pr, PDF_FILL, color);
}

static void pdf_run_SC_pattern(fz_context *ctx, pdf_processor *proc, const char *name, pdf_pattern *pat, int n, float *color)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	pdf_set_pattern(ctx, pr, PDF_STROKE, pat, color);
}

static void pdf_run_sc_pattern(fz_context *ctx, pdf_processor *proc, const char *name, pdf_pattern *pat, int n, float *color)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	pdf_set_pattern(ctx, pr, PDF_FILL, pat, color);
}

static void pdf_run_SC_shade(fz_context *ctx, pdf_processor *proc, const char *name, fz_shade *shade)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	pdf_set_shade(ctx, pr, PDF_STROKE, shade);
}

static void pdf_run_sc_shade(fz_context *ctx, pdf_processor *proc, const char *name, fz_shade *shade)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	pdf_set_shade(ctx, pr, PDF_FILL, shade);
}

static void pdf_run_G(fz_context *ctx, pdf_processor *proc, float g)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	pdf_set_colorspace(ctx, pr, PDF_STROKE, fz_device_gray(ctx));
	pdf_set_color(ctx, pr, PDF_STROKE, &g);
}

static void pdf_run_g(fz_context *ctx, pdf_processor *proc, float g)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	pdf_set_colorspace(ctx, pr, PDF_FILL, fz_device_gray(ctx));
	pdf_set_color(ctx, pr, PDF_FILL, &g);
}

static void pdf_run_K(fz_context *ctx, pdf_processor *proc, float c, float m, float y, float k)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	float color[4] = {c, m, y, k};
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	pdf_set_colorspace(ctx, pr, PDF_STROKE, fz_device_cmyk(ctx));
	pdf_set_color(ctx, pr, PDF_STROKE, color);
}

static void pdf_run_k(fz_context *ctx, pdf_processor *proc, float c, float m, float y, float k)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	float color[4] = {c, m, y, k};
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	pdf_set_colorspace(ctx, pr, PDF_FILL, fz_device_cmyk(ctx));
	pdf_set_color(ctx, pr, PDF_FILL, color);
}

static void pdf_run_RG(fz_context *ctx, pdf_processor *proc, float r, float g, float b)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	float color[3] = {r, g, b};
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	pdf_set_colorspace(ctx, pr, PDF_STROKE, fz_device_rgb(ctx));
	pdf_set_color(ctx, pr, PDF_STROKE, color);
}

static void pdf_run_rg(fz_context *ctx, pdf_processor *proc, float r, float g, float b)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	float color[3] = {r, g, b};
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	pdf_set_colorspace(ctx, pr, PDF_FILL, fz_device_rgb(ctx));
	pdf_set_color(ctx, pr, PDF_FILL, color);
}

/* shadings, images, xobjects */

static void pdf_run_BI(fz_context *ctx, pdf_processor *proc, fz_image *image)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	if ((pr->dev->hints & FZ_IGNORE_IMAGE) == 0)
		pdf_show_image(ctx, pr, image);
}

static void pdf_run_sh(fz_context *ctx, pdf_processor *proc, const char *name, fz_shade *shade)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	if ((pr->dev->hints & FZ_IGNORE_SHADE) == 0)
		pdf_show_shade(ctx, pr, shade);
}

static void pdf_run_Do_image(fz_context *ctx, pdf_processor *proc, const char *name, fz_image *image)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	if ((pr->dev->hints & FZ_IGNORE_IMAGE) == 0)
		pdf_show_image(ctx, pr, image);
}

static void pdf_run_Do_form(fz_context *ctx, pdf_processor *proc, const char *name, pdf_xobject *xobj, pdf_obj *page_resources)
{
	pdf_run_xobject(ctx, (pdf_run_processor*)proc, xobj, page_resources, &fz_identity);
}

/* marked content */

static void pdf_run_MP(fz_context *ctx, pdf_processor *proc, const char *tag)
{
}

static void pdf_run_DP(fz_context *ctx, pdf_processor *proc, const char *tag, pdf_obj *raw, pdf_obj *cooked)
{
}

static void pdf_run_BMC(fz_context *ctx, pdf_processor *proc, const char *tag)
{
}

static void pdf_run_BDC(fz_context *ctx, pdf_processor *proc, const char *tag, pdf_obj *raw, pdf_obj *cooked)
{
}

static void pdf_run_EMC(fz_context *ctx, pdf_processor *proc)
{
}

/* compatibility */

static void pdf_run_BX(fz_context *ctx, pdf_processor *proc)
{
}

static void pdf_run_EX(fz_context *ctx, pdf_processor *proc)
{
}

static void pdf_run_END(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_flush_text(ctx, pr);
}

static void
pdf_drop_run_processor(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;

	while (pr->gtop)
		pdf_grestore(ctx, pr);

	pdf_drop_material(ctx, &pr->gstate[0].fill);
	pdf_drop_material(ctx, &pr->gstate[0].stroke);
	pdf_drop_font(ctx, pr->gstate[0].font);
	pdf_drop_xobject(ctx, pr->gstate[0].softmask);
	fz_drop_stroke_state(ctx, pr->gstate[0].stroke_state);

	while (pr->gstate[0].clip_depth--)
		fz_pop_clip(ctx, pr->dev);

	fz_drop_path(ctx, pr->path);
	fz_drop_text(ctx, pr->text);

	fz_free(ctx, pr->gstate);
}

pdf_processor *
pdf_new_run_processor(fz_context *ctx, fz_device *dev, const fz_matrix *ctm, const char *usage, pdf_gstate *gstate, int nested)
{
	pdf_run_processor *proc = pdf_new_processor(ctx, sizeof *proc);
	{
		proc->super.usage = usage;

		proc->super.drop_processor = pdf_drop_run_processor;

		/* general graphics state */
		proc->super.op_w = pdf_run_w;
		proc->super.op_j = pdf_run_j;
		proc->super.op_J = pdf_run_J;
		proc->super.op_M = pdf_run_M;
		proc->super.op_d = pdf_run_d;
		proc->super.op_ri = pdf_run_ri;
		proc->super.op_i = pdf_run_i;
		proc->super.op_gs_begin = pdf_run_gs_begin;
		proc->super.op_gs_end = pdf_run_gs_end;

		/* transparency graphics state */
		proc->super.op_gs_BM = pdf_run_gs_BM;
		proc->super.op_gs_CA = pdf_run_gs_CA;
		proc->super.op_gs_ca = pdf_run_gs_ca;
		proc->super.op_gs_SMask = pdf_run_gs_SMask;

		/* special graphics state */
		proc->super.op_q = pdf_run_q;
		proc->super.op_Q = pdf_run_Q;
		proc->super.op_cm = pdf_run_cm;

		/* path construction */
		proc->super.op_m = pdf_run_m;
		proc->super.op_l = pdf_run_l;
		proc->super.op_c = pdf_run_c;
		proc->super.op_v = pdf_run_v;
		proc->super.op_y = pdf_run_y;
		proc->super.op_h = pdf_run_h;
		proc->super.op_re = pdf_run_re;

		/* path painting */
		proc->super.op_S = pdf_run_S;
		proc->super.op_s = pdf_run_s;
		proc->super.op_F = pdf_run_F;
		proc->super.op_f = pdf_run_f;
		proc->super.op_fstar = pdf_run_fstar;
		proc->super.op_B = pdf_run_B;
		proc->super.op_Bstar = pdf_run_Bstar;
		proc->super.op_b = pdf_run_b;
		proc->super.op_bstar = pdf_run_bstar;
		proc->super.op_n = pdf_run_n;

		/* clipping paths */
		proc->super.op_W = pdf_run_W;
		proc->super.op_Wstar = pdf_run_Wstar;

		/* text objects */
		proc->super.op_BT = pdf_run_BT;
		proc->super.op_ET = pdf_run_ET;

		/* text state */
		proc->super.op_Tc = pdf_run_Tc;
		proc->super.op_Tw = pdf_run_Tw;
		proc->super.op_Tz = pdf_run_Tz;
		proc->super.op_TL = pdf_run_TL;
		proc->super.op_Tf = pdf_run_Tf;
		proc->super.op_Tr = pdf_run_Tr;
		proc->super.op_Ts = pdf_run_Ts;

		/* text positioning */
		proc->super.op_Td = pdf_run_Td;
		proc->super.op_TD = pdf_run_TD;
		proc->super.op_Tm = pdf_run_Tm;
		proc->super.op_Tstar = pdf_run_Tstar;

		/* text showing */
		proc->super.op_TJ = pdf_run_TJ;
		proc->super.op_Tj = pdf_run_Tj;
		proc->super.op_squote = pdf_run_squote;
		proc->super.op_dquote = pdf_run_dquote;

		/* type 3 fonts */
		proc->super.op_d0 = pdf_run_d0;
		proc->super.op_d1 = pdf_run_d1;

		/* color */
		proc->super.op_CS = pdf_run_CS;
		proc->super.op_cs = pdf_run_cs;
		proc->super.op_SC_color = pdf_run_SC_color;
		proc->super.op_sc_color = pdf_run_sc_color;
		proc->super.op_SC_pattern = pdf_run_SC_pattern;
		proc->super.op_sc_pattern = pdf_run_sc_pattern;
		proc->super.op_SC_shade = pdf_run_SC_shade;
		proc->super.op_sc_shade = pdf_run_sc_shade;

		proc->super.op_G = pdf_run_G;
		proc->super.op_g = pdf_run_g;
		proc->super.op_RG = pdf_run_RG;
		proc->super.op_rg = pdf_run_rg;
		proc->super.op_K = pdf_run_K;
		proc->super.op_k = pdf_run_k;

		/* shadings, images, xobjects */
		proc->super.op_BI = pdf_run_BI;
		proc->super.op_sh = pdf_run_sh;
		proc->super.op_Do_image = pdf_run_Do_image;
		proc->super.op_Do_form = pdf_run_Do_form;

		/* marked content */
		proc->super.op_MP = pdf_run_MP;
		proc->super.op_DP = pdf_run_DP;
		proc->super.op_BMC = pdf_run_BMC;
		proc->super.op_BDC = pdf_run_BDC;
		proc->super.op_EMC = pdf_run_EMC;

		/* compatibility */
		proc->super.op_BX = pdf_run_BX;
		proc->super.op_EX = pdf_run_EX;

		proc->super.op_END = pdf_run_END;
	}

	proc->dev = dev;

	proc->nested_depth = nested;

	proc->path = NULL;
	proc->clip = 0;
	proc->clip_even_odd = 0;

	proc->text = NULL;
	proc->tlm = fz_identity;
	proc->tm = fz_identity;
	proc->text_mode = 0;

	fz_try(ctx)
	{
		proc->path = fz_new_path(ctx);

		proc->gcap = 64;
		proc->gstate = fz_malloc_array(ctx, proc->gcap, sizeof(pdf_gstate));

		pdf_init_gstate(ctx, &proc->gstate[0], ctm);
		if (gstate)
		{
			pdf_copy_gstate(ctx, &proc->gstate[0], gstate);
			proc->gstate[0].clip_depth = 0;
			proc->gstate[0].ctm = *ctm;
		}
		proc->gtop = 0;
		proc->gbot = 0;
		proc->gparent = 0;
	}
	fz_catch(ctx)
	{
		fz_drop_path(ctx, proc->path);
		fz_free(ctx, proc);
		fz_rethrow(ctx);
	}

	/* We need to save an extra level to allow for level 0 to be the parent gstate level. */
	pdf_gsave(ctx, proc);

	return (pdf_processor*)proc;
}
