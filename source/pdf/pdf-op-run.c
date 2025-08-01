// Copyright (C) 2004-2025 Artifex Software, Inc.
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
// Artifex Software, Inc., 39 Mesa Street, Suite 108A, San Francisco,
// CA 94129, USA, for further information.

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>
#include <math.h>

#include "mupdf/ucdn.h"

#define TILE

/* Enable this to watch changes in the structure stack. */
#undef DEBUG_STRUCTURE

/*
 * Emit graphics calls to device.
 */

typedef struct pdf_run_processor pdf_run_processor;

static void pdf_run_xobject(fz_context *ctx, pdf_run_processor *proc, pdf_obj *xobj, pdf_obj *page_resources, fz_matrix transform, int is_smask);

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

typedef struct
{
	int kind;
	fz_colorspace *colorspace;
	pdf_pattern *pattern;
	fz_shade *shade;
	int gstate_num;
	fz_color_params color_params;
	float alpha;
	float v[FZ_MAX_COLORS];
} pdf_material;

struct pdf_gstate
{
	fz_matrix ctm;
	int clip_depth;

	/* path stroking */
	fz_stroke_state *stroke_state;

	/* materials */
	pdf_material stroke;
	pdf_material fill;

	/* pattern paint type 2 */
	int ismask;

	/* text state */
	pdf_text_state text;

	/* transparency */
	int blendmode;
	pdf_obj *softmask;
	pdf_obj *softmask_resources;
	pdf_obj *softmask_tr;
	fz_matrix softmask_ctm;
	fz_colorspace *softmask_cs;
	float softmask_bc[FZ_MAX_COLORS];
	int luminosity;
};

typedef struct resources_stack
{
	struct resources_stack *next;
	pdf_obj *resources;
} resources_stack;

typedef struct marked_content_stack
{
	struct marked_content_stack *next;
	pdf_obj *tag;
	pdf_obj *val;
	int structure_pushed;
} marked_content_stack;

typedef struct begin_layer_stack
{
	struct begin_layer_stack *next;
	char *layer;
} begin_layer_stack;

struct pdf_run_processor
{
	pdf_processor super;
	pdf_document *doc;
	fz_device *dev;
	fz_cookie *cookie;

	fz_default_colorspaces *default_cs;

	resources_stack *rstack;

	/* path object state */
	fz_path *path;
	int clip;
	int clip_even_odd;

	/* text object state */
	pdf_text_object_state tos;
	int bidi;

	/* graphics state */
	pdf_gstate *gstate;
	int gcap;
	int gtop;
	int gbot;
	int gparent;

	/* xobject cycle detector */
	pdf_cycle_list *cycle;

	pdf_obj *role_map;

	marked_content_stack *marked_content;
	pdf_obj *mcid_sent;
	pdf_obj *pending_mcid_pop;

	int struct_parent;
	int broken_struct_tree;

	/* Pending begin layers */
	begin_layer_stack *begin_layer;
	begin_layer_stack **next_begin_layer;

	int mc_depth;
	/* The nest_mark array holds a record of the way in which clips and
	 * marked content are nested to ensure we pop stuff in the same order
	 * that we push it - i.e. to keep calls nested nicely. An entry x,
	 * where x >= 0 represents that a push has happened for mc_depth == x.
	 * An entry x, where x < 0 means that -x clips have happened at this
	 * position. */
	int nest_depth;
	int nest_mark[1024];
};

/* Forward definition */
static void
pop_any_pending_mcid_changes(fz_context *ctx, pdf_run_processor *pr);

static void
push_begin_layer(fz_context *ctx, pdf_run_processor *proc, const char *str)
{
	begin_layer_stack *s = fz_malloc_struct(ctx, begin_layer_stack);

	fz_try(ctx)
		s->layer = fz_strdup(ctx, str);
	fz_catch(ctx)
	{
		fz_free(ctx, s);
		fz_rethrow(ctx);
	}

	s->next = NULL;
	*proc->next_begin_layer = s;
	proc->next_begin_layer = &s->next;
}

static void
flush_begin_layer(fz_context *ctx, pdf_run_processor *proc)
{
	begin_layer_stack *s;

	while (proc->begin_layer)
	{
		s = proc->begin_layer;

		if (proc->nest_depth == nelem(proc->nest_mark))
			fz_throw(ctx, FZ_ERROR_LIMIT, "layer/clip nesting too deep");

		proc->nest_mark[proc->nest_depth++] = ++proc->mc_depth;

		fz_begin_layer(ctx, proc->dev, s->layer);
		proc->begin_layer = s->next;
		fz_free(ctx, s->layer);
		fz_free(ctx, s);
	}
	proc->next_begin_layer = &proc->begin_layer;
}

static void nest_layer_clip(fz_context *ctx, pdf_run_processor *proc)
{
	if (proc->nest_depth == nelem(proc->nest_mark))
		fz_throw(ctx, FZ_ERROR_LIMIT, "layer/clip nesting too deep");
	if (proc->nest_depth > 0 && proc->nest_mark[proc->nest_depth-1] < 0)
	{
		/* The last mark was a clip. Just increase that count. */
		proc->nest_mark[proc->nest_depth-1]--;
	}
	else
	{
		/* Create a new entry for a single clip. */
		proc->nest_mark[proc->nest_depth++] = -1;
	}
}

static void
do_end_layer(fz_context *ctx, pdf_run_processor *proc)
{
	if (proc->nest_depth > 0 && proc->nest_mark[proc->nest_depth-1] == proc->mc_depth)
	{
		fz_end_layer(ctx, proc->dev);
		proc->nest_depth--;
	}
	else
	{
		/* If EMC is unbalanced with q/Q, we will emit the end layer
		 * device call before or after the Q operator instead of its true location
		 */
		 fz_warn(ctx, "invalid marked content and clip nesting");
	}

	if (proc->mc_depth > 0)
		proc->mc_depth--;
}

typedef struct
{
	pdf_obj *softmask;
	fz_colorspace *softmask_cs;
	pdf_obj *page_resources;
	fz_matrix ctm;
} softmask_save;

static fz_function *
load_transfer_function(fz_context *ctx, pdf_obj *obj)
{
	if (obj == NULL || pdf_name_eq(ctx, obj, PDF_NAME(Identity)))
		return NULL;

	return (fz_function *)pdf_load_function(ctx, obj, 1, 1);
}

static pdf_gstate *
begin_softmask(fz_context *ctx, pdf_run_processor *pr, softmask_save *save, fz_rect bbox)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_obj *softmask = gstate->softmask;
	fz_colorspace *softmask_cs = gstate->softmask_cs;
	fz_rect mask_bbox;
	fz_matrix tos_save[2], save_ctm;
	fz_matrix mask_matrix;
	fz_colorspace *mask_colorspace;
	int saved_blendmode;
	fz_function *tr = NULL;

	fz_var(tr);

	save->softmask = softmask;
	if (softmask == NULL)
		return gstate;
	save->softmask_cs = softmask_cs;
	save->page_resources = gstate->softmask_resources;
	save->ctm = gstate->softmask_ctm;
	save_ctm = gstate->ctm;

	mask_bbox = pdf_xobject_bbox(ctx, softmask);
	mask_matrix = pdf_xobject_matrix(ctx, softmask);

	pdf_tos_save(ctx, &pr->tos, tos_save);

	mask_colorspace = gstate->softmask_cs;
	if (gstate->luminosity && !mask_colorspace)
		mask_colorspace = fz_device_gray(ctx);

	if (gstate->luminosity)
		mask_bbox = fz_infinite_rect;
	else
	{
		mask_bbox = fz_transform_rect(mask_bbox, mask_matrix);
		mask_bbox = fz_transform_rect(mask_bbox, gstate->softmask_ctm);
	}
	mask_bbox = fz_intersect_rect(mask_bbox, bbox);
	gstate->softmask = NULL;
	gstate->softmask_cs = NULL;
	gstate->softmask_resources = NULL;
	gstate->ctm = gstate->softmask_ctm;

	saved_blendmode = gstate->blendmode;

	fz_try(ctx)
	{
		if (gstate->softmask_tr)
		{
			tr = load_transfer_function(ctx, gstate->softmask_tr);
			pdf_drop_obj(ctx, gstate->softmask_tr);
			gstate->softmask_tr = NULL;
		}

		fz_begin_mask(ctx, pr->dev, mask_bbox, gstate->luminosity, mask_colorspace, gstate->softmask_bc, gstate->fill.color_params);
		gstate->blendmode = 0;
		pdf_run_xobject(ctx, pr, softmask, save->page_resources, fz_identity, 1);
		gstate = pr->gstate + pr->gtop;
		gstate->blendmode = saved_blendmode;
		fz_end_mask_tr(ctx, pr->dev, tr);
	}
	fz_always(ctx)
	{
		fz_drop_function(ctx, tr);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);

	pdf_tos_restore(ctx, &pr->tos, tos_save);

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
	gstate->softmask_cs = save->softmask_cs;
	gstate->softmask_resources = save->page_resources;
	gstate->softmask_ctm = save->ctm;
	save->softmask = NULL;
	save->page_resources = NULL;

	fz_pop_clip(ctx, pr->dev);
}

static pdf_gstate *
pdf_begin_group(fz_context *ctx, pdf_run_processor *pr, fz_rect bbox, softmask_save *softmask)
{
	pdf_gstate *gstate = begin_softmask(ctx, pr, softmask, bbox);

	if (gstate->blendmode)
		fz_begin_group(ctx, pr->dev, bbox, NULL, 0, 0, gstate->blendmode, 1);

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

	bbox = fz_bound_shade(ctx, shd, gstate->ctm);

	fz_try(ctx)
	{
		gstate = pdf_begin_group(ctx, pr, bbox, &softmask);

		/* FIXME: The gstate->ctm in the next line may be wrong; maybe
		 * it should be the parent gstates ctm? */
		fz_fill_shade(ctx, pr->dev, shd, gstate->ctm, gstate->fill.alpha, gstate->fill.color_params);

		pdf_end_group(ctx, pr, &softmask);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, softmask.softmask);
		fz_drop_colorspace(ctx, softmask.softmask_cs);
		pdf_drop_obj(ctx, softmask.page_resources);
		fz_rethrow(ctx);
	}
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
pdf_copy_pattern_gstate(fz_context *ctx, pdf_gstate *dst, const pdf_gstate *src)
{
	pdf_font_desc *old_font = dst->text.font;

	dst->ctm = src->ctm;

	dst->text = src->text;
	pdf_keep_font(ctx, src->text.font);
	pdf_drop_font(ctx, old_font);

	pdf_drop_obj(ctx, dst->softmask);
	dst->softmask = pdf_keep_obj(ctx, src->softmask);

	pdf_drop_obj(ctx, dst->softmask_resources);
	dst->softmask_resources = pdf_keep_obj(ctx, src->softmask_resources);

	fz_drop_colorspace(ctx, dst->softmask_cs);
	dst->softmask_cs = fz_keep_colorspace(ctx, src->softmask_cs);

	fz_drop_stroke_state(ctx, dst->stroke_state);
	dst->stroke_state = fz_keep_stroke_state(ctx, src->stroke_state);
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
	if (gs->text.font)
		pdf_keep_font(ctx, gs->text.font);
	if (gs->softmask)
		pdf_keep_obj(ctx, gs->softmask);
	if (gs->softmask_cs)
		fz_keep_colorspace(ctx, gs->softmask_cs);
	if (gs->softmask_resources)
		pdf_keep_obj(ctx, gs->softmask_resources);
	fz_keep_stroke_state(ctx, gs->stroke_state);
	pdf_keep_obj(ctx, gs->softmask_tr);
}

static void
pdf_drop_gstate(fz_context *ctx, pdf_gstate *gs)
{
	pdf_drop_material(ctx, &gs->stroke);
	pdf_drop_material(ctx, &gs->fill);
	pdf_drop_font(ctx, gs->text.font);
	pdf_drop_obj(ctx, gs->softmask);
	fz_drop_colorspace(ctx, gs->softmask_cs);
	pdf_drop_obj(ctx, gs->softmask_resources);
	fz_drop_stroke_state(ctx, gs->stroke_state);
	pdf_drop_obj(ctx, gs->softmask_tr);
}

static void
pdf_gsave(fz_context *ctx, pdf_run_processor *pr)
{
	if (pr->gtop == pr->gcap-1)
	{
		if (pr->gcap * 2 >= 4096)
			fz_throw(ctx, FZ_ERROR_LIMIT, "too many nested graphics states");

		pr->gstate = fz_realloc_array(ctx, pr->gstate, pr->gcap*2, pdf_gstate);
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
			// End layer early (before Q) if unbalanced Q appears between BMC and EMC.
			while (pr->nest_depth > 0 && pr->nest_mark[pr->nest_depth-1] >= 0)
			{
				fz_end_layer(ctx, pr->dev);
				pr->nest_depth--;
			}

			if (pr->nest_depth > 0)
			{
				/* So this one must be a clip record. */
				fz_pop_clip(ctx, pr->dev);
				/* Pop a single clip record off. */
				pr->nest_mark[pr->nest_depth-1]++;
				if (pr->nest_mark[pr->nest_depth-1] == 0)
					pr->nest_depth--;
			}

			// End layer late (after Q) if unbalanced EMC appears between q and Q.
			while (pr->nest_depth > 0 && pr->nest_mark[pr->nest_depth-1] > pr->mc_depth)
			{
				fz_end_layer(ctx, pr->dev);
				pr->nest_depth--;
			}
		}
		fz_catch(ctx)
		{
			/* Silently swallow the problem - restores must
			 * never throw! */
			fz_rethrow_if(ctx, FZ_ERROR_SYSTEM); // FIXME - unsure if we can throw here?
			fz_report_error(ctx);
		}
		clip_depth--;
	}
}

static pdf_gstate *
pdf_show_pattern(fz_context *ctx, pdf_run_processor *pr, pdf_pattern *pat, int pat_gstate_num, fz_rect area, int what)
{
	pdf_gstate *gstate;
	pdf_gstate *pat_gstate;
	int gparent_save;
	fz_matrix ptm, invptm, gparent_save_ctm;
	int x0, y0, x1, y1;
	float fx0, fy0, fx1, fy1;
	fz_rect local_area;
	int oldbot;
	int id;

	pdf_gsave(ctx, pr);
	gstate = pr->gstate + pr->gtop;
	pat_gstate = pr->gstate + pat_gstate_num;

	/* Patterns are run with the gstate of the parent */
	pdf_copy_pattern_gstate(ctx, gstate, pat_gstate);

	if (pat->ismask)
	{
		/* Inhibit any changes to the color since we're drawing an uncolored pattern. */
		gstate->ismask = 1;
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
		id = 0; /* don't cache uncolored patterns, since we colorize them when drawing */
	}
	else
	{
		// TODO: unset only the current fill/stroke or both?
		pdf_unset_pattern(ctx, pr, what);
		id = pat->id;
	}

	/* don't apply soft masks to objects in the pattern as well */
	if (gstate->softmask)
	{
		pdf_drop_obj(ctx, gstate->softmask);
		gstate->softmask = NULL;
	}

	ptm = fz_concat(pat->matrix, pat_gstate->ctm);
	invptm = fz_invert_matrix(ptm);

	/* The parent_ctm is amended with our pattern matrix */
	gparent_save = pr->gparent;
	pr->gparent = pr->gtop-1;
	gparent_save_ctm = pr->gstate[pr->gparent].ctm;
	pr->gstate[pr->gparent].ctm = ptm;

	/* patterns are painted using the parent_ctm. area = bbox of
	 * shape to be filled in device space. Map it back to pattern
	 * space. */
	local_area = fz_transform_rect(area, invptm);

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
		int cached = fz_begin_tile_tid(ctx, pr->dev, local_area, pat->bbox, pat->xstep, pat->ystep, ptm, id, pat->document->super.id);
		if (!cached)
		{
			gstate->ctm = ptm;

			oldbot = pr->gbot;
			pr->gbot = pr->gtop;

			pdf_gsave(ctx, pr);
			pdf_process_contents(ctx, (pdf_processor*)pr, pat->document, pat->resources, pat->contents, NULL, NULL);
			pdf_grestore(ctx, pr);

			while (pr->gtop > pr->gbot)
				pdf_grestore(ctx, pr);
			pr->gbot = oldbot;
		}
		fz_end_tile(ctx, pr->dev);
	}
	else
	{
		int x, y;

		/* When calculating the number of tiles required, we adjust by
		 * a small amount to allow for rounding errors. By choosing
		 * this amount to be smaller than 1/256, we guarantee we won't
		 * cause problems that will be visible even under our most
		 * extreme antialiasing. */
		x0 = floorf(fx0 + 0.001f);
		y0 = floorf(fy0 + 0.001f);
		x1 = ceilf(fx1 - 0.001f);
		y1 = ceilf(fy1 - 0.001f);
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
				/* Calls to pdf_process_contents may cause the
				 * gstate array to be realloced to be larger.
				 * That can invalidate gstate. Hence reload
				 * it each time round the loop. */
				gstate = pr->gstate + pr->gtop;
				gstate->ctm = fz_pre_translate(ptm, x * pat->xstep, y * pat->ystep);

				oldbot = pr->gbot;
				pr->gbot = pr->gtop;

				pdf_gsave(ctx, pr);
				pdf_process_contents(ctx, (pdf_processor*)pr, pat->document, pat->resources, pat->contents, NULL, NULL);
				pdf_grestore(ctx, pr);

				while (pr->gtop > pr->gbot)
					pdf_grestore(ctx, pr);
				pr->gbot = oldbot;
			}
		}
	}

	pr->gstate[pr->gparent].ctm = gparent_save_ctm;
	pr->gparent = gparent_save;

	pdf_grestore(ctx, pr);

	return pr->gstate + pr->gtop;
}

static void
pdf_show_image_imp(fz_context *ctx, pdf_run_processor *pr, fz_image *image, fz_matrix image_ctm, fz_rect bbox)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	fz_color_params cp = gstate->fill.color_params;

	if (image->has_intent)
		cp.ri = image->intent;

	if (image->colorspace)
	{
		fz_fill_image(ctx, pr->dev, image, image_ctm, gstate->fill.alpha, cp);
	}
	else if (gstate->fill.kind == PDF_MAT_COLOR)
	{
		fz_fill_image_mask(ctx, pr->dev, image, image_ctm, gstate->fill.colorspace, gstate->fill.v, gstate->fill.alpha, cp);
	}
	else if (gstate->fill.kind == PDF_MAT_PATTERN && gstate->fill.pattern)
	{
		fz_clip_image_mask(ctx, pr->dev, image, image_ctm, bbox);
		gstate = pdf_show_pattern(ctx, pr, gstate->fill.pattern, gstate->fill.gstate_num, bbox, PDF_FILL);
		fz_pop_clip(ctx, pr->dev);
	}
	else if (gstate->fill.kind == PDF_MAT_SHADE && gstate->fill.shade)
	{
		fz_clip_image_mask(ctx, pr->dev, image, image_ctm, bbox);
		fz_fill_shade(ctx, pr->dev, gstate->fill.shade, pr->gstate[gstate->fill.gstate_num].ctm, gstate->fill.alpha, cp);
		fz_pop_clip(ctx, pr->dev);
	}
}

static void
pdf_show_image(fz_context *ctx, pdf_run_processor *pr, fz_image *image)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	fz_matrix image_ctm;
	fz_rect bbox;

	if (pr->super.hidden)
		return;

	/* image can be NULL here if we are, for example, running to an
	 * stext device. */
	if (image == NULL)
		return;

	pop_any_pending_mcid_changes(ctx, pr);
	flush_begin_layer(ctx, pr);

	/* PDF has images bottom-up, so flip them right side up here */
	image_ctm = fz_pre_scale(fz_pre_translate(gstate->ctm, 0, 1), 1, -1);

	bbox = fz_transform_rect(fz_unit_rect, image_ctm);

	if (image->mask && gstate->blendmode)
	{
		/* apply blend group even though we skip the soft mask */
		fz_begin_group(ctx, pr->dev, bbox, NULL, 0, 0, gstate->blendmode, 1);
		fz_clip_image_mask(ctx, pr->dev, image->mask, image_ctm, bbox);
		pdf_show_image_imp(ctx, pr, image, image_ctm, bbox);
		fz_pop_clip(ctx, pr->dev);
		fz_end_group(ctx, pr->dev);
	}
	else if (image->mask)
	{
		fz_clip_image_mask(ctx, pr->dev, image->mask, image_ctm, bbox);
		pdf_show_image_imp(ctx, pr, image, image_ctm, bbox);
		fz_pop_clip(ctx, pr->dev);
	}
	else
	{
		softmask_save softmask = { NULL };
		fz_try(ctx)
		{
			gstate = pdf_begin_group(ctx, pr, bbox, &softmask);
			pdf_show_image_imp(ctx, pr, image, image_ctm, bbox);
			pdf_end_group(ctx, pr, &softmask);
		}
		fz_catch(ctx)
		{
			pdf_drop_obj(ctx, softmask.softmask);
			fz_drop_colorspace(ctx, softmask.softmask_cs);
			pdf_drop_obj(ctx, softmask.page_resources);
			fz_rethrow(ctx);
		}
	}
}

static void
pdf_show_path(fz_context *ctx, pdf_run_processor *pr, int doclose, int dofill, int dostroke, int even_odd)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	fz_path *path;
	fz_rect bbox;
	softmask_save softmask = { NULL };
	int knockout_group = 0;

	pop_any_pending_mcid_changes(ctx, pr);
	flush_begin_layer(ctx, pr);

	if (dostroke) {
		if (pr->dev->flags & (FZ_DEVFLAG_STROKECOLOR_UNDEFINED | FZ_DEVFLAG_LINEJOIN_UNDEFINED | FZ_DEVFLAG_LINEWIDTH_UNDEFINED | FZ_DEVFLAG_DASH_PATTERN_UNDEFINED))
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

		bbox = fz_bound_path(ctx, path, (dostroke ? gstate->stroke_state : NULL), gstate->ctm);

		if (pr->super.hidden)
			dostroke = dofill = 0;

		if (dofill || dostroke)
			gstate = pdf_begin_group(ctx, pr, bbox, &softmask);

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
				fz_begin_group(ctx, pr->dev, bbox, NULL, 0, 1, FZ_BLEND_NORMAL, 1);
			}
		}

		if (dofill)
		{
			switch (gstate->fill.kind)
			{
			case PDF_MAT_NONE:
				break;
			case PDF_MAT_COLOR:
				fz_fill_path(ctx, pr->dev, path, even_odd, gstate->ctm,
					gstate->fill.colorspace, gstate->fill.v, gstate->fill.alpha, gstate->fill.color_params);
				break;
			case PDF_MAT_PATTERN:
				if (gstate->fill.pattern)
				{
					fz_clip_path(ctx, pr->dev, path, even_odd, gstate->ctm, bbox);
					gstate = pdf_show_pattern(ctx, pr, gstate->fill.pattern, gstate->fill.gstate_num, bbox, PDF_FILL);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			case PDF_MAT_SHADE:
				if (gstate->fill.shade)
				{
					fz_clip_path(ctx, pr->dev, path, even_odd, gstate->ctm, bbox);
					/* The cluster and page 2 of patterns.pdf shows that fz_fill_shade should NOT be called with gstate->ctm. */
					fz_fill_shade(ctx, pr->dev, gstate->fill.shade, pr->gstate[gstate->fill.gstate_num].ctm, gstate->fill.alpha, gstate->fill.color_params);
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
				fz_stroke_path(ctx, pr->dev, path, gstate->stroke_state, gstate->ctm,
					gstate->stroke.colorspace, gstate->stroke.v, gstate->stroke.alpha, gstate->stroke.color_params);
				break;
			case PDF_MAT_PATTERN:
				if (gstate->stroke.pattern)
				{
					fz_clip_stroke_path(ctx, pr->dev, path, gstate->stroke_state, gstate->ctm, bbox);
					gstate = pdf_show_pattern(ctx, pr, gstate->stroke.pattern, gstate->stroke.gstate_num, bbox, PDF_STROKE);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			case PDF_MAT_SHADE:
				if (gstate->stroke.shade)
				{
					fz_clip_stroke_path(ctx, pr->dev, path, gstate->stroke_state, gstate->ctm, bbox);
					fz_fill_shade(ctx, pr->dev, gstate->stroke.shade, pr->gstate[gstate->stroke.gstate_num].ctm, gstate->stroke.alpha, gstate->stroke.color_params);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			}
		}

		if (knockout_group)
			fz_end_group(ctx, pr->dev);

		if (dofill || dostroke)
			pdf_end_group(ctx, pr, &softmask);

		if (pr->clip)
		{
			nest_layer_clip(ctx, pr);
			gstate->clip_depth++;
			fz_clip_path(ctx, pr->dev, path, pr->clip_even_odd, gstate->ctm, bbox);
			pr->clip = 0;
		}
	}
	fz_always(ctx)
	{
		fz_drop_path(ctx, path);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, softmask.softmask);
		fz_drop_colorspace(ctx, softmask.softmask_cs);
		pdf_drop_obj(ctx, softmask.page_resources);
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

	text = pdf_tos_get_text(ctx, &pr->tos);
	if (!text)
		return gstate;

	pop_any_pending_mcid_changes(ctx, pr);
	/* If we are going to output text, we need to have flushed any begin layers first. */
	flush_begin_layer(ctx, pr);

	dofill = dostroke = doclip = doinvisible = 0;
	switch (pr->tos.text_mode)
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
		fz_rect tb = fz_transform_rect(pr->tos.text_bbox, gstate->ctm);
		if (dostroke)
			tb = fz_adjust_rect_for_stroke(ctx, tb, gstate->stroke_state, gstate->ctm);

		/* Don't bother sending a text group with nothing in it */
		if (!text->head)
			break;

		if (dofill || dostroke)
			gstate = pdf_begin_group(ctx, pr, tb, &softmask);

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
				fz_begin_group(ctx, pr->dev, tb, NULL, 0, 1, FZ_BLEND_NORMAL, 1);
			}
		}

		if (doinvisible)
			fz_ignore_text(ctx, pr->dev, text, gstate->ctm);

		if (dofill)
		{
			switch (gstate->fill.kind)
			{
			case PDF_MAT_NONE:
				break;
			case PDF_MAT_COLOR:
				fz_fill_text(ctx, pr->dev, text, gstate->ctm,
					gstate->fill.colorspace, gstate->fill.v, gstate->fill.alpha, gstate->fill.color_params);
				break;
			case PDF_MAT_PATTERN:
				if (gstate->fill.pattern)
				{
					fz_clip_text(ctx, pr->dev, text, gstate->ctm, tb);
					gstate = pdf_show_pattern(ctx, pr, gstate->fill.pattern, gstate->fill.gstate_num, tb, PDF_FILL);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			case PDF_MAT_SHADE:
				if (gstate->fill.shade)
				{
					fz_clip_text(ctx, pr->dev, text, gstate->ctm, tb);
					/* Page 2 of patterns.pdf shows that fz_fill_shade should NOT be called with gstate->ctm */
					fz_fill_shade(ctx, pr->dev, gstate->fill.shade, pr->gstate[gstate->fill.gstate_num].ctm, gstate->fill.alpha, gstate->fill.color_params);
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
				fz_stroke_text(ctx, pr->dev, text, gstate->stroke_state, gstate->ctm,
					gstate->stroke.colorspace, gstate->stroke.v, gstate->stroke.alpha, gstate->stroke.color_params);
				break;
			case PDF_MAT_PATTERN:
				if (gstate->stroke.pattern)
				{
					fz_clip_stroke_text(ctx, pr->dev, text, gstate->stroke_state, gstate->ctm, tb);
					gstate = pdf_show_pattern(ctx, pr, gstate->stroke.pattern, gstate->stroke.gstate_num, tb, PDF_STROKE);
					fz_pop_clip(ctx, pr->dev);
				}
				break;
			case PDF_MAT_SHADE:
				if (gstate->stroke.shade)
				{
					fz_clip_stroke_text(ctx, pr->dev, text, gstate->stroke_state, gstate->ctm, tb);
					fz_fill_shade(ctx, pr->dev, gstate->stroke.shade, pr->gstate[gstate->stroke.gstate_num].ctm, gstate->stroke.alpha, gstate->stroke.color_params);
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
			nest_layer_clip(ctx, pr);
			gstate->clip_depth++;
			fz_clip_text(ctx, pr->dev, text, gstate->ctm, tb);
		}
	}
	fz_always(ctx)
	{
		fz_drop_text(ctx, text);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, softmask.softmask);
		fz_drop_colorspace(ctx, softmask.softmask_cs);
		pdf_drop_obj(ctx, softmask.page_resources);
		fz_rethrow(ctx);
	}

	return pr->gstate + pr->gtop;
}

static int
guess_bidi_level(int bidiclass, int cur_bidi)
{
	switch (bidiclass)
	{
	/* strong */
	case UCDN_BIDI_CLASS_L: return 0;
	case UCDN_BIDI_CLASS_R: return 1;
	case UCDN_BIDI_CLASS_AL: return 1;

	/* weak */
	case UCDN_BIDI_CLASS_EN:
	case UCDN_BIDI_CLASS_ES:
	case UCDN_BIDI_CLASS_ET:
		return 0;
	case UCDN_BIDI_CLASS_AN:
		return 1;
	case UCDN_BIDI_CLASS_CS:
	case UCDN_BIDI_CLASS_NSM:
	case UCDN_BIDI_CLASS_BN:
		return cur_bidi;

	/* neutral */
	case UCDN_BIDI_CLASS_B:
	case UCDN_BIDI_CLASS_S:
	case UCDN_BIDI_CLASS_WS:
	case UCDN_BIDI_CLASS_ON:
		return cur_bidi;

	/* embedding, override, pop ... we don't support them */
	default:
		return 0;
	}
}

static void
pdf_show_char(fz_context *ctx, pdf_run_processor *pr, int cid, fz_text_language lang)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_font_desc *fontdesc = gstate->text.font;
	fz_matrix trm;
	float adv;
	int gid;
	int ucsbuf[PDF_MRANGE_CAP];
	int ucslen;
	int i;
	int render_direct;
	int type3_hitr;

	gid = pdf_tos_make_trm(ctx, &pr->tos, &gstate->text, fontdesc, cid, &trm, &adv);

	/* If we are uncachable, then render direct. */
	render_direct = !fz_glyph_cacheable(ctx, fontdesc->font, gid);

	/* PDF spec: ISO 32000-2 latest version at the time of writing:
	 * Section 9.3.6:
	 * Where text is drawn using a Type 3 font:
	 *  + if text rendering mode is set to a value of 3 or 7, the text shall not be rendered.
	 *  + if text rendering mode is set to a value other than 3 or 7, the text shall be rendered using the glyph descriptions in the Type 3 font.
	 *  + If text rendering mode is set to a value of 4, 5, 6 or 7, nothing shall be added to the clipping path.
	 */
	type3_hitr = (fontdesc->font->t3procs && pr->tos.text_mode >= 4);

	/* flush buffered text if rendermode has changed */
	if (!pr->tos.text || gstate->text.render != pr->tos.text_mode || render_direct || type3_hitr)
	{
		gstate = pdf_flush_text(ctx, pr);
		pdf_tos_reset(ctx, &pr->tos, gstate->text.render);
	}

	/* If Type3 and tr >= 4, then ignore the clipping path part. */
	if (type3_hitr)
		pr->tos.text_mode -= 4;

	if (render_direct && pr->tos.text_mode != 3 /* or 7, by type3_hitr */)
	{
		/* Render the glyph stream direct here (only happens for
		 * type3 glyphs that seem to inherit current graphics
		 * attributes, or type 3 glyphs within type3 glyphs). */
		fz_matrix composed = fz_concat(trm, gstate->ctm);
		/* Whatever problems the underlying char has is no concern of
		 * ours. Store the flags, restore them afterwards. */
		int old_flags = pr->dev->flags;
		pdf_gstate *fill_gstate = NULL;
		pdf_gstate *stroke_gstate = NULL;
		pdf_gsave(ctx, pr);
		gstate = pr->gstate + pr->gtop;
		if (gstate->fill.kind == PDF_MAT_PATTERN && gstate->fill.gstate_num >= 0)
			fill_gstate = pr->gstate + gstate->fill.gstate_num;
		if (gstate->stroke.kind == PDF_MAT_PATTERN && gstate->stroke.gstate_num >= 0)
			stroke_gstate = pr->gstate + gstate->stroke.gstate_num;
		pdf_drop_font(ctx, gstate->text.font);
		gstate->text.font = NULL; /* don't inherit the current font... */
		fz_render_t3_glyph_direct(ctx, pr->dev, fontdesc->font, gid, composed, gstate, pr->default_cs, fill_gstate, stroke_gstate);
		pr->dev->flags = old_flags;
		pdf_grestore(ctx, pr);
		/* Render text invisibly so that it can still be extracted. */
		pr->tos.text_mode = 3;
	}

	ucslen = 0;
	if (fontdesc->to_unicode)
		ucslen = pdf_lookup_cmap_full(fontdesc->to_unicode, cid, ucsbuf);

	/* convert ascii whitespace control characters to spaces */
	if (ucslen == 1 && (ucsbuf[0] >= 8 && ucsbuf[0] <= 13))
		ucsbuf[0] = ' ';

	/* ignore obviously bad values in ToUnicode, fall back to the cid_to_ucs table */
	if (ucslen == 1 && (ucsbuf[0] < 32 || (ucsbuf[0] >= 127 && ucsbuf[0] < 160)))
		ucslen = 0;

	if (ucslen == 0 && (size_t)cid < fontdesc->cid_to_ucs_len)
	{
		ucsbuf[0] = fontdesc->cid_to_ucs[cid];
		ucslen = 1;
	}
	if (ucslen == 0 || (ucslen == 1 && ucsbuf[0] == 0))
	{
		ucsbuf[0] = FZ_REPLACEMENT_CHARACTER;
		ucslen = 1;
	}

	/* guess bidi level from unicode value */
	pr->bidi = guess_bidi_level(ucdn_get_bidi_class(ucsbuf[0]), pr->bidi);

	/* add glyph to textobject */
	fz_show_glyph_aux(ctx, pr->tos.text, fontdesc->font, trm, adv, gid, ucsbuf[0], cid, fontdesc->wmode, pr->bidi, FZ_BIDI_NEUTRAL, lang);

	/* add filler glyphs for one-to-many unicode mapping */
	for (i = 1; i < ucslen; i++)
		fz_show_glyph_aux(ctx, pr->tos.text, fontdesc->font, trm, 0, -1, ucsbuf[i], -1, fontdesc->wmode, pr->bidi, FZ_BIDI_NEUTRAL, lang);

	pdf_tos_move_after_char(ctx, &pr->tos);
}

static void
pdf_show_space(fz_context *ctx, pdf_run_processor *pr, float tadj)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_font_desc *fontdesc = gstate->text.font;

	if (fontdesc->wmode == 0)
		pr->tos.tm = fz_pre_translate(pr->tos.tm, tadj * gstate->text.scale, 0);
	else
		pr->tos.tm = fz_pre_translate(pr->tos.tm, 0, tadj);
}

static int
int_in_singleton_or_array(fz_context *ctx, pdf_obj *k, int id)
{
	/* In the most common case the /K value will be id. */
	if (pdf_is_int(ctx, k) && pdf_to_int(ctx, k) == id)
		return 1;

	/* In the next most common case, there will be an array of
	 * items, one of which is k. */
	if (pdf_is_array(ctx, k))
	{
		int i, n = pdf_array_len(ctx, k);

		for (i = 0; i < n; i++)
		{
			pdf_obj *o = pdf_array_get(ctx, k, i);
			if (pdf_is_int(ctx, o) && pdf_to_int(ctx, o) == id)
				return 1;
		}
	}

	return 0;
}

pdf_obj *
pdf_lookup_mcid_in_mcids(fz_context *ctx, int id, pdf_obj *mcids)
{
	pdf_obj *mcid = pdf_array_get(ctx, mcids, id);
	pdf_obj *k = pdf_dict_get(ctx, mcid, PDF_NAME(K));
	int i, n;

	if (int_in_singleton_or_array(ctx, k, id))
		return mcid;

	/* At this point, something has gone wrong. One common case that
	 * appears to fail is where the MCIDs array has the right things
	 * in, but at the wrong indexes. So do some searching. */
	n = pdf_array_len(ctx, mcids);
	for (i = 0; i < n; i++)
	{
		pdf_obj *o = pdf_array_get(ctx, mcids, i);
		if (int_in_singleton_or_array(ctx, pdf_dict_get(ctx, o, PDF_NAME(K)), id))
			return o;
	}

	return NULL;
}

static pdf_obj *
lookup_mcid(fz_context *ctx, pdf_run_processor *proc, pdf_obj *val)
{
	pdf_obj *mcid;
	int id;
	pdf_obj *mcids;

	if (proc->struct_parent == -1)
		return NULL;

	mcid = pdf_dict_get(ctx, val, PDF_NAME(MCID));
	if (!mcid)
		return NULL;

	if (!pdf_is_number(ctx, mcid))
		return NULL;

	id = pdf_to_int(ctx, mcid);
	mcids = pdf_lookup_number(ctx, pdf_dict_getl(ctx, pdf_trailer(ctx, proc->doc), PDF_NAME(Root), PDF_NAME(StructTreeRoot), PDF_NAME(ParentTree), NULL), proc->struct_parent);
	return pdf_lookup_mcid_in_mcids(ctx, id, mcids);
}

static fz_text_language
find_lang_from_mc(fz_context *ctx, pdf_run_processor *pr)
{
	marked_content_stack *mc;

	for (mc = pr->marked_content; mc != NULL; mc = mc->next)
	{
		size_t len;
		const char *lang;

		lang = pdf_dict_get_string(ctx, mc->val, PDF_NAME(Lang), &len);
		if (!lang)
			lang = pdf_dict_get_string(ctx, lookup_mcid(ctx, pr, mc->val), PDF_NAME(Lang), &len);
		if (lang)
		{
			char text[8];
			memcpy(text, lang, len < 8 ? len : 7);
			text[len < 8 ? len : 7] = 0;
			return fz_text_language_from_string(text);
		}
	}

	return FZ_LANG_UNSET;
}

static void
show_string(fz_context *ctx, pdf_run_processor *pr, unsigned char *buf, size_t len)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_font_desc *fontdesc = gstate->text.font;
	unsigned char *end = buf + len;
	unsigned int cpt;
	int cid;
	fz_text_language lang = find_lang_from_mc(ctx, pr);

	pop_any_pending_mcid_changes(ctx, pr);
	flush_begin_layer(ctx, pr);

	while (buf < end)
	{
		int w = pdf_decode_cmap(fontdesc->encoding, buf, end, &cpt);
		buf += w;

		cid = pdf_lookup_cmap(fontdesc->encoding, cpt);
		if (cid >= 0)
			pdf_show_char(ctx, pr, cid, lang);
		else
			fz_warn(ctx, "cannot encode character");
		if (cpt == 32 && w == 1)
		{
			/* Bug 703151: pdf_show_char can realloc gstate. */
			gstate = pr->gstate + pr->gtop;
			pdf_show_space(ctx, pr, gstate->text.word_space);
		}
	}
}

static void
pdf_show_string(fz_context *ctx, pdf_run_processor *pr, unsigned char *buf, size_t len)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_font_desc *fontdesc = gstate->text.font;

	if (!fontdesc)
	{
		fz_warn(ctx, "cannot draw text since font and size not set");
		return;
	}

	show_string(ctx, pr, buf, len);
}

static void
pdf_show_text(fz_context *ctx, pdf_run_processor *pr, pdf_obj *text)
{
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_font_desc *fontdesc = gstate->text.font;
	int i;

	if (!fontdesc)
	{
		fz_warn(ctx, "cannot draw text since font and size not set");
		return;
	}

	if (pdf_is_array(ctx, text))
	{
		int n = pdf_array_len(ctx, text);
		for (i = 0; i < n; i++)
		{
			pdf_obj *item = pdf_array_get(ctx, text, i);
			if (pdf_is_string(ctx, item))
				show_string(ctx, pr, (unsigned char *)pdf_to_str_buf(ctx, item), pdf_to_str_len(ctx, item));
			else
			{
				/* Bug 708615: pdf_show_char inside show_string can realloc gstate. */
				gstate = pr->gstate + pr->gtop;
				pdf_show_space(ctx, pr, - pdf_to_real(ctx, item) * gstate->text.size * 0.001f);
			}
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
pdf_init_gstate(fz_context *ctx, pdf_gstate *gs, fz_matrix ctm)
{
	gs->ctm = ctm;
	gs->clip_depth = 0;

	gs->stroke_state = fz_new_stroke_state(ctx);

	gs->stroke.kind = PDF_MAT_COLOR;
	gs->stroke.colorspace = fz_keep_colorspace(ctx, fz_device_gray(ctx));
	gs->stroke.v[0] = 0;
	gs->stroke.pattern = NULL;
	gs->stroke.shade = NULL;
	gs->stroke.alpha = 1;
	gs->stroke.gstate_num = -1;

	gs->fill.kind = PDF_MAT_COLOR;
	gs->fill.colorspace = fz_keep_colorspace(ctx, fz_device_gray(ctx));
	gs->fill.v[0] = 0;
	gs->fill.pattern = NULL;
	gs->fill.shade = NULL;
	gs->fill.alpha = 1;
	gs->fill.gstate_num = -1;

	gs->text.char_space = 0;
	gs->text.word_space = 0;
	gs->text.scale = 1;
	gs->text.leading = 0;
	gs->text.font = NULL;
	gs->text.size = -1;
	gs->text.render = 0;
	gs->text.rise = 0;

	gs->blendmode = 0;
	gs->softmask = NULL;
	gs->softmask_cs = NULL;
	gs->softmask_resources = NULL;
	gs->softmask_ctm = fz_identity;
	gs->luminosity = 0;

	gs->fill.color_params = fz_default_color_params;
	gs->stroke.color_params = fz_default_color_params;

	gs->ismask = 0;
}

static void
pdf_copy_gstate(fz_context *ctx, pdf_gstate *dst, pdf_gstate *src)
{
	pdf_drop_gstate(ctx, dst);
	*dst = *src;
	pdf_keep_gstate(ctx, dst);
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

	/* Don't change color if we're drawing an uncolored pattern tile! */
	if (gstate->ismask)
		return;

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

	gstate = pdf_flush_text(ctx, pr);

	/* Don't change color if we're drawing an uncolored pattern tile! */
	if (gstate->ismask)
		return;

	mat = what == PDF_FILL ? &gstate->fill : &gstate->stroke;

	switch (mat->kind)
	{
	case PDF_MAT_PATTERN:
	case PDF_MAT_COLOR:
		fz_clamp_color(ctx, mat->colorspace, v, mat->v);
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
begin_metatext(fz_context *ctx, pdf_run_processor *proc, pdf_obj *val, pdf_obj *mcid, fz_metatext meta, pdf_obj *name)
{
	pdf_obj *text = pdf_dict_get(ctx, val, name);

	if (!text)
		text = pdf_dict_get(ctx, mcid, name);
	if (!text)
		return;

	pdf_flush_text(ctx, proc);

	fz_begin_metatext(ctx, proc->dev, meta, pdf_to_text_string(ctx, text));
}

static void
end_metatext(fz_context *ctx, pdf_run_processor *proc, pdf_obj *val, pdf_obj *mcid, pdf_obj *name)
{
	pdf_obj *text = pdf_dict_get(ctx, val, name);

	if (!text)
		text = pdf_dict_get(ctx, mcid, name);
	if (!text)
		return;

	pdf_flush_text(ctx, proc);

	fz_end_metatext(ctx, proc->dev);
}

static void
begin_oc(fz_context *ctx, pdf_run_processor *proc, pdf_obj *val, pdf_cycle_list *cycle_up)
{
	/* val has been resolved to a dict for us by the originally specified name
	 * having been looked up in Properties already for us. Either there will
	 * be a Name entry, or there will be an OCGs and it'll be a group one. */
	pdf_cycle_list cycle;
	pdf_obj *obj;
	int i, n;

	if (pdf_cycle(ctx, &cycle, cycle_up, val))
		return;

	obj = pdf_dict_get(ctx, val, PDF_NAME(Name));
	if (obj)
	{
		const char *name = "";
		pdf_flush_text(ctx, proc);
		if (pdf_is_name(ctx, obj))
			name = pdf_to_name(ctx, obj);
		else if (pdf_is_string(ctx, obj))
			name = pdf_to_text_string(ctx, obj);

		push_begin_layer(ctx, proc, name);
		return;
	}

	obj = pdf_dict_get(ctx, val, PDF_NAME(OCGs));
	n = pdf_array_len(ctx, obj);
	for (i = 0; i < n; i++)
	{
		begin_oc(ctx, proc, pdf_array_get(ctx, obj, i), &cycle);
	}
}

static void
end_oc(fz_context *ctx, pdf_run_processor *proc, pdf_obj *val, pdf_cycle_list *cycle_up)
{
	/* val has been resolved to a dict for us by the originally specified name
	 * having been looked up in Properties already for us. Either there will
	 * be a Name entry, or there will be an OCGs and it'll be a group one. */
	pdf_cycle_list cycle;
	pdf_obj *obj;
	int i, n;

	if (pdf_cycle(ctx, &cycle, cycle_up, val))
		return;

	obj = pdf_dict_get(ctx, val, PDF_NAME(Name));
	if (obj)
	{
		flush_begin_layer(ctx, proc);
		do_end_layer(ctx, proc);
		return;
	}

	obj = pdf_dict_get(ctx, val, PDF_NAME(OCGs));
	n = pdf_array_len(ctx, obj);
	for (i = n-1; i >= 0; i--)
	{
		end_oc(ctx, proc, pdf_array_get(ctx, obj, i), &cycle);
	}
}

static void
begin_layer(fz_context *ctx, pdf_run_processor *proc, pdf_obj *val)
{
	/* val has been resolved to a dict for us by the originally specified name
	 * having been looked up in Properties already for us. Go with the 'Title'
	 * entry. */
	pdf_obj *obj = pdf_dict_get(ctx, val, PDF_NAME(Title));
	if (obj)
	{
		pdf_flush_text(ctx, proc);
		push_begin_layer(ctx, proc, pdf_to_text_string(ctx, obj));
	}
}

static void
end_layer(fz_context *ctx, pdf_run_processor *proc, pdf_obj *val)
{
	/* val has been resolved to a dict for us by the originally specified name
	 * having been looked up in Properties already for us. Go with the 'Title'
	 * entry. */
	pdf_obj *obj = pdf_dict_get(ctx, val, PDF_NAME(Title));
	if (obj)
	{
		do_end_layer(ctx, proc);
	}
}

#ifdef DEBUG_STRUCTURE
static void
structure_dump(fz_context *ctx, const char *str, pdf_obj *obj)
{
	fprintf(stderr, "%s STACK=", str);

	if (obj == NULL)
	{
		fprintf(stderr, "empty\n");
		return;
	}

	do
	{
		pdf_obj *s = pdf_dict_get(ctx, obj, PDF_NAME(S));
		int n = pdf_to_num(ctx, obj);
		fprintf(stderr, " %d", n);
		if (s)
			fprintf(stderr, "[%s]", pdf_to_name(ctx, s));
		obj = pdf_dict_get(ctx, obj, PDF_NAME(P));
	}
	while (obj);
	fprintf(stderr, "\n");
}
#endif

static void
pop_structure_to(fz_context *ctx, pdf_run_processor *proc, pdf_obj *common)
{
	pdf_obj *struct_tree_root = pdf_dict_getl(ctx, pdf_trailer(ctx, proc->doc), PDF_NAME(Root), PDF_NAME(StructTreeRoot), NULL);

#ifdef DEBUG_STRUCTURE
	structure_dump(ctx, "pop_structure_to (before)", proc->mcid_sent);

	{
		int n = pdf_to_num(ctx, common);
		fprintf(stderr, "Popping until %d\n", n);
	}
#endif

	while (proc->mcid_sent != NULL && pdf_objcmp(ctx, proc->mcid_sent, common))
	{
		pdf_obj *p = pdf_dict_get(ctx, proc->mcid_sent, PDF_NAME(P));
		pdf_obj *tag = pdf_dict_get(ctx, proc->mcid_sent, PDF_NAME(S));
		fz_structure standard = pdf_structure_type(ctx, proc->role_map, tag);
#ifdef DEBUG_STRUCTURE
		fprintf(stderr, "sending pop [tag=%s][std=%d]\n", pdf_to_name(ctx, tag) ? pdf_to_name(ctx, tag) : "null", standard);
#endif
		if (standard != FZ_STRUCTURE_INVALID)
			fz_end_structure(ctx, proc->dev);
		pdf_drop_obj(ctx, proc->mcid_sent);
		proc->mcid_sent = pdf_keep_obj(ctx, p);
		if (!pdf_objcmp(ctx, p, struct_tree_root))
		{
			pdf_drop_obj(ctx, proc->mcid_sent);
			proc->mcid_sent = NULL;
			break;
		}
	}
#ifdef DEBUG_STRUCTURE
	structure_dump(ctx, "pop_structure_to (after)", proc->mcid_sent);
#endif
}

static void
pop_any_pending_mcid_changes(fz_context *ctx, pdf_run_processor *pr)
{
	if (pr->pending_mcid_pop == NULL)
		return;

	pop_structure_to(ctx, pr, pr->pending_mcid_pop);
	pr->pending_mcid_pop = NULL;
}

static pdf_obj **
get_lineage(fz_context *ctx, pdf_obj *a, int *lenp)
{
	int max = 0;
	int len = 0;
	pdf_obj **line = NULL;

	fz_var(line);

	fz_try(ctx)
	{
		while (1)
		{
			/* Put a into lineage. */
			if (max == len)
			{
				max *= 2;
				if (max == 0)
					max = 32;
				line = fz_realloc(ctx, line, sizeof(*line) * max);
			}
			line[len++] = a;

			a = pdf_dict_get(ctx, a, PDF_NAME(P));
			if (a == NULL)
				break;

			if (a == line[len>>1])
				fz_throw(ctx, FZ_ERROR_FORMAT, "cycle in structure tree");
		}
	}
	fz_catch(ctx)
	{
		fz_free(ctx, line);
		fz_rethrow(ctx);
	}

	*lenp = len;

	return line;
}

pdf_obj *
find_most_recent_common_ancestor(fz_context *ctx, pdf_obj *a, pdf_obj *b)
{
	/* First ascend one lineage. */
	int a_len, b_len;
	pdf_obj **line_a = NULL;
	pdf_obj **line_b = NULL;
	pdf_obj *common;

	if (!pdf_is_dict(ctx, a) || !pdf_is_dict(ctx, b))
		return NULL;

	fz_var(line_a);
	fz_var(line_b);

	fz_try(ctx)
	{
		line_a = get_lineage(ctx, a, &a_len);
		line_b = get_lineage(ctx, b, &b_len);

		assert(a_len > 0 && b_len > 0);

		/* Once both lineages are know, traverse top-down to find most recent common ancestor. */
		if (line_a[a_len-1] != line_b[b_len-1])
			fz_throw(ctx, FZ_ERROR_FORMAT, "No common ancestor in structure tree");

		while (a_len > 0 && b_len > 0 && line_a[a_len-1] == line_b[b_len-1])
			a_len--, b_len--;

		common = line_a[a_len];
	}
	fz_always(ctx)
	{
		fz_free(ctx, line_a);
		fz_free(ctx, line_b);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
	return common;
}

static int
get_struct_index(fz_context *ctx, pdf_obj *send)
{
	pdf_obj *p = pdf_dict_get(ctx, send, PDF_NAME(P));
	pdf_obj *k;
	int i, n;

	if (p == NULL)
		return 0; /* Presumably the StructTreeRoot */

	/* So, get the kids array. */
	k = pdf_dict_get(ctx, p, PDF_NAME(K));
	n = pdf_array_len(ctx, k);
	if (n == 0)
	{
		/* Not an array, presumably a singleton. */
		if (pdf_objcmp(ctx, k, send) == 0)
			return 0;
		return -1;
	}
	for (i = 0; i < n; i++)
	{
		if (pdf_objcmp(ctx, pdf_array_get(ctx, k, i), send) == 0)
			return i;
	}
	return -1;
}

static int
send_begin_structure(fz_context *ctx, pdf_run_processor *proc, pdf_obj *mc_dict)
{
	pdf_obj *common = NULL;

#ifdef DEBUG_STRUCTURE
	fprintf(stderr, "send_begin_structure  %d\n", pdf_to_num(ctx, mc_dict));
	structure_dump(ctx, "on entry", proc->mcid_sent);
#endif

	/* We are currently nested in A,B,C,...E,F,mcid_sent. We want to update to
	 * being in A,B,C,...G,H,mc_dict. So we need to find the lowest common point. */
	common = find_most_recent_common_ancestor(ctx, proc->mcid_sent, mc_dict);

	/* So, we need to pop everything up to common (i.e. everything below common will be closed). */
	pop_structure_to(ctx, proc, common);

#ifdef DEBUG_STRUCTURE
	structure_dump(ctx, "after popping", proc->mcid_sent);
#endif
	/* Now we need to send everything between common (proc->mcid_sent) and mc_dict.
	 * Again, n^2 will do... */
	while (pdf_objcmp(ctx, proc->mcid_sent, mc_dict))
	{
		pdf_obj *send = mc_dict;
		fz_structure standard;
		pdf_obj *tag;
		int idx;
		pdf_obj *slowptr = send;
		int slow = 0;

		/* Run up the ancestor stack, looking for the first child of mcid_sent.
		 * That's the one we need to send next. */
		while (1) {
			pdf_obj *p = pdf_dict_get(ctx, send, PDF_NAME(P));

			/* If we ever fail to find a dict, then do not step down lest
			 * we can't get back later! */
			if (!pdf_is_dict(ctx, send))
			{
				fz_warn(ctx, "Bad parent link in structure tree. Ignoring structure.");
				proc->broken_struct_tree = 1;
				return 0;
			}
			/* If p is the one we last sent, then we want to send 'send'
			 * next. Exit the loop. */
			if (!pdf_objcmp(ctx, p, proc->mcid_sent))
				break;

			/* We need to go at least one step further up the stack. */
			send = p;

			/* Check for a loop in the parent tree. */
			slow ^= 1;
			if (slow == 0)
				slowptr = pdf_dict_get(ctx, slowptr, PDF_NAME(P));
			if (!pdf_objcmp(ctx, send, slowptr))
			{
				fz_warn(ctx, "Loop found in structure tree. Ignoring structure.");
				proc->broken_struct_tree = 1;
				return 0;
			}
		}

		idx = get_struct_index(ctx, send);
		tag = pdf_dict_get(ctx, send, PDF_NAME(S));
		standard = pdf_structure_type(ctx, proc->role_map, tag);
#ifdef DEBUG_STRUCTURE
		fprintf(stderr, "sending %d[idx=%d][tag=%s][std=%d]\n", pdf_to_num(ctx, send), idx, pdf_to_name(ctx, tag) ? pdf_to_name(ctx, tag) : "null", standard);
#endif
		if (standard != FZ_STRUCTURE_INVALID)
			fz_begin_structure(ctx, proc->dev, standard, pdf_to_name(ctx, tag), idx);

		pdf_drop_obj(ctx, proc->mcid_sent);
		proc->mcid_sent = pdf_keep_obj(ctx, send);
	}
#ifdef DEBUG_STRUCTURE
	structure_dump(ctx, "on exit", proc->mcid_sent);
#endif

	return 1;
}

static void
push_marked_content(fz_context *ctx, pdf_run_processor *proc, const char *tagstr, pdf_obj *val)
{
	pdf_obj *tag;
	marked_content_stack *mc = NULL;
	int drop_tag = 1;
	pdf_obj *mc_dict = NULL;

	/* Ignore any pending pops. */
	proc->pending_mcid_pop = NULL;

	/* Flush any pending text so it's not in the wrong layer. */
	pdf_flush_text(ctx, proc);

	if (!tagstr)
		tagstr = "Untitled";
	tag = pdf_new_name(ctx, tagstr);

	fz_var(drop_tag);

	fz_try(ctx)
	{
		/* First, push it on the stack. */
		mc = fz_malloc_struct(ctx, marked_content_stack);
		mc->next = proc->marked_content;
		mc->tag = tag;
		mc->val = pdf_keep_obj(ctx, val);
		mc->structure_pushed = 0;
		proc->marked_content = mc;
		drop_tag = 0;

		/* Check to see if val contains an MCID. */
		mc_dict = lookup_mcid(ctx, proc, val);

		/* Start any optional content layers. */
		if (pdf_name_eq(ctx, tag, PDF_NAME(OC)))
			begin_oc(ctx, proc, val, NULL);

		/* Special handling for common non-spec extension. */
		if (pdf_name_eq(ctx, tag, PDF_NAME(Layer)))
			begin_layer(ctx, proc, val);

		/* Structure */
		if (mc_dict && !proc->broken_struct_tree)
		{
			fz_try(ctx)
				mc->structure_pushed = send_begin_structure(ctx, proc, mc_dict);
			fz_catch(ctx)
			{
				fz_report_error(ctx);
				fz_warn(ctx, "structure tree broken, assume tree is missing");
				proc->broken_struct_tree = 1;
			}
		}

		/* Previously, I'd tried to send stuff like:
		 *	/Artifact <</Type/Pagination>>BDC
		 * as a structure entry, lured by the fact that 'Artifact' is a
		 * structure tag. I now believe this is wrong. Only stuff with
		 * an MCID pointer should be sent using the structure mechanism.
		 */

		/* ActualText */
		begin_metatext(ctx, proc, val, mc_dict, FZ_METATEXT_ACTUALTEXT, PDF_NAME(ActualText));

		/* Alt */
		begin_metatext(ctx, proc, val, mc_dict, FZ_METATEXT_ALT, PDF_NAME(Alt));

		/* Abbreviation */
		begin_metatext(ctx, proc, val, mc_dict, FZ_METATEXT_ABBREVIATION, PDF_NAME(E));

		/* Title */
		begin_metatext(ctx, proc, val, mc_dict, FZ_METATEXT_TITLE, PDF_NAME(T));
	}
	fz_catch(ctx)
	{
		if (drop_tag)
			pdf_drop_obj(ctx, tag);
		fz_rethrow(ctx);
	}
}

static void
pop_marked_content(fz_context *ctx, pdf_run_processor *proc, int neat)
{
	marked_content_stack *mc = proc->marked_content;
	pdf_obj *val, *tag;
	pdf_obj *mc_dict = NULL;
	int pushed;

	if (mc == NULL)
		return;

	proc->marked_content = mc->next;
	tag = mc->tag;
	val = mc->val;
	pushed = mc->structure_pushed;
	fz_free(ctx, mc);

	/* If we're not interested in neatly closing any open layers etc
	 * in the processor, (maybe we've had errors already), then just
	 * exit here. */
	if (!neat)
	{
		pdf_drop_obj(ctx, tag);
		pdf_drop_obj(ctx, val);
		return;
	}

	/* Close structure/layers here, in reverse order to how we opened them. */
	fz_try(ctx)
	{
		/* Make sure that any pending text is written into the correct layer. */
		pdf_flush_text(ctx, proc);

		/* Check to see if val contains an MCID. */
		mc_dict = lookup_mcid(ctx, proc, val);

		/* Title */
		end_metatext(ctx, proc, val, mc_dict, PDF_NAME(T));

		/* Abbreviation */
		end_metatext(ctx, proc, val, mc_dict, PDF_NAME(E));

		/* Alt */
		end_metatext(ctx, proc, val, mc_dict, PDF_NAME(Alt));

		/* ActualText */
		end_metatext(ctx, proc, val, mc_dict, PDF_NAME(ActualText));

		/* Structure */
		if (mc_dict && !proc->broken_struct_tree && pushed)
		{
			/* Is there a nested mc_dict? If so we want to pop back to that.
			 * If not, we want to pop back to the top.
			 * proc->marked_content = the previous one, but maybe not the
			 * previous one with an mc_dict. So we may need to search further.
			 */
			pdf_obj *previous_mcid = NULL;
			marked_content_stack *mc_with_mcid = proc->marked_content;
			while (mc_with_mcid)
			{
				previous_mcid = lookup_mcid(ctx, proc, mc_with_mcid->val);
				if (previous_mcid != NULL)
					break;
				mc_with_mcid = mc_with_mcid->next;
			}

			proc->pending_mcid_pop = previous_mcid;
		}

		/* Finally, close any layers. */
		if (pdf_name_eq(ctx, tag, PDF_NAME(Layer)))
			end_layer(ctx, proc, val);

		if (pdf_name_eq(ctx, tag, PDF_NAME(OC)))
			end_oc(ctx, proc, val, NULL);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, tag);
		pdf_drop_obj(ctx, val);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void
clear_marked_content(fz_context *ctx, pdf_run_processor *pr)
{
	if (pr->marked_content == NULL)
		return;

	fz_try(ctx)
		while (pr->marked_content)
			pop_marked_content(ctx, pr, 1);
	fz_always(ctx)
		while (pr->marked_content)
			pop_marked_content(ctx, pr, 0);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void
pdf_run_xobject(fz_context *ctx, pdf_run_processor *pr, pdf_obj *xobj, pdf_obj *page_resources, fz_matrix transform, int is_smask)
{
	pdf_cycle_list cycle_here;
	pdf_gstate *gstate = NULL;
	int oldtop = 0;
	int oldbot = -1;
	softmask_save softmask = { NULL };
	int gparent_save;
	fz_matrix gparent_save_ctm;
	pdf_obj *resources;
	fz_rect xobj_bbox;
	fz_matrix xobj_matrix;
	int transparency = 0;
	pdf_document *doc;
	fz_colorspace *cs = NULL;
	fz_default_colorspaces *save_default_cs = NULL;
	fz_default_colorspaces *xobj_default_cs = NULL;
	marked_content_stack *save_marked_content = NULL;
	int save_struct_parent;
	pdf_obj *oc;

	/* Avoid infinite recursion */
	pdf_cycle_list *cycle_up = pr->cycle;
	if (xobj == NULL || pdf_cycle(ctx, &cycle_here, cycle_up, xobj))
		return;
	pr->cycle = &cycle_here;

	pop_any_pending_mcid_changes(ctx, pr);
	flush_begin_layer(ctx, pr);

	fz_var(cs);
	fz_var(xobj_default_cs);

	gparent_save = pr->gparent;
	pr->gparent = pr->gtop;
	oldtop = pr->gtop;

	save_default_cs = pr->default_cs;
	save_marked_content = pr->marked_content;
	pr->marked_content = NULL;
	save_struct_parent = pr->struct_parent;

	fz_try(ctx)
	{
		pr->struct_parent = pdf_dict_get_int_default(ctx, xobj, PDF_NAME(StructParent), -1);

		oc = pdf_dict_get(ctx, xobj, PDF_NAME(OC));
		if (oc)
			begin_oc(ctx, pr, oc, NULL);

		pdf_gsave(ctx, pr);

		gstate = pr->gstate + pr->gtop;

		xobj_bbox = pdf_xobject_bbox(ctx, xobj);
		xobj_matrix = pdf_xobject_matrix(ctx, xobj);
		transparency = pdf_xobject_transparency(ctx, xobj);

		/* apply xobject's transform matrix */
		transform = fz_concat(xobj_matrix, transform);
		gstate->ctm = fz_concat(transform, gstate->ctm);

		/* The gparent is updated with the modified ctm */
		gparent_save_ctm = pr->gstate[pr->gparent].ctm;
		pr->gstate[pr->gparent].ctm = gstate->ctm;

		/* apply soft mask, create transparency group and reset state */
		if (transparency)
		{
			int isolated = pdf_xobject_isolated(ctx, xobj);

			fz_rect bbox = fz_transform_rect(xobj_bbox, gstate->ctm);

			gstate = begin_softmask(ctx, pr, &softmask, bbox);

			if (isolated)
				cs = pdf_xobject_colorspace(ctx, xobj);
			fz_begin_group(ctx, pr->dev, bbox,
					cs,
					(is_smask ? 1 : isolated),
					pdf_xobject_knockout(ctx, xobj),
					gstate->blendmode, gstate->fill.alpha);

			gstate->blendmode = 0;
			gstate->stroke.alpha = 1;
			gstate->fill.alpha = 1;
		}

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

		fz_try(ctx)
			xobj_default_cs = pdf_update_default_colorspaces(ctx, pr->default_cs, resources);
		fz_catch(ctx)
		{
			fz_rethrow_unless(ctx, FZ_ERROR_TRYLATER);
			fz_ignore_error(ctx);
			if (pr->cookie)
				pr->cookie->incomplete = 1;
		}
		if (xobj_default_cs != save_default_cs)
		{
			fz_set_default_colorspaces(ctx, pr->dev, xobj_default_cs);
			pr->default_cs = xobj_default_cs;
		}

		doc = pdf_get_bound_document(ctx, xobj);

		oldbot = pr->gbot;
		pr->gbot = pr->gtop;

		pdf_process_contents(ctx, (pdf_processor*)pr, doc, resources, xobj, pr->cookie, NULL);

		/* Undo any gstate mismatches due to the pdf_process_contents call */
		if (oldbot != -1)
		{
			while (pr->gtop > pr->gbot)
			{
				pdf_grestore(ctx, pr);
			}
			pr->gbot = oldbot;
		}

		pdf_grestore(ctx, pr); /* Remove the state we pushed for the clippath */

		/* wrap up transparency stacks */
		if (transparency)
		{
			fz_end_group(ctx, pr->dev);
			end_softmask(ctx, pr, &softmask);
		}

		pr->gstate[pr->gparent].ctm = gparent_save_ctm;
		pr->gparent = gparent_save;

		while (oldtop < pr->gtop)
			pdf_grestore(ctx, pr);

		if (oc)
			end_oc(ctx, pr, oc, NULL);

		if (xobj_default_cs != save_default_cs)
		{
			fz_set_default_colorspaces(ctx, pr->dev, save_default_cs);
		}
	}
	fz_always(ctx)
	{
		clear_marked_content(ctx, pr);
		pr->marked_content = save_marked_content;
		pr->default_cs = save_default_cs;
		fz_drop_default_colorspaces(ctx, xobj_default_cs);
		fz_drop_colorspace(ctx, cs);
		pr->cycle = cycle_up;
		pr->struct_parent = save_struct_parent;
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, softmask.softmask);
		fz_drop_colorspace(ctx, softmask.softmask_cs);
		pdf_drop_obj(ctx, softmask.page_resources);
		/* Note: Any SYNTAX errors should have been swallowed
		 * by pdf_process_contents, but in case any escape from other
		 * functions, recast the error type here to be safe. */
		fz_morph_error(ctx, FZ_ERROR_SYNTAX, FZ_ERROR_FORMAT);
		fz_rethrow(ctx);
	}
}

/* general graphics state */

static void pdf_run_w(fz_context *ctx, pdf_processor *proc, float linewidth)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);

	pop_any_pending_mcid_changes(ctx, pr);
	flush_begin_layer(ctx, pr);

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

	pr->dev->flags &= ~FZ_DEVFLAG_DASH_PATTERN_UNDEFINED;
	len = pdf_array_len(ctx, array);
	gstate->stroke_state = fz_unshare_stroke_state_with_dash_len(ctx, gstate->stroke_state, len);
	for (i = 0; i < len; i++)
		gstate->stroke_state->dash_list[i] = pdf_array_get_real(ctx, array, i);
	gstate->stroke_state->dash_phase = phase;
}

static void pdf_run_ri(fz_context *ctx, pdf_processor *proc, const char *intent)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	gstate->fill.color_params.ri = fz_lookup_rendering_intent(intent);
	gstate->stroke.color_params.ri = gstate->fill.color_params.ri;
}

static void pdf_run_gs_OP(fz_context *ctx, pdf_processor *proc, int b)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	gstate->stroke.color_params.op = b;
	gstate->fill.color_params.op = b;
}

static void pdf_run_gs_op(fz_context *ctx, pdf_processor *proc, int b)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	gstate->fill.color_params.op = b;
}

static void pdf_run_gs_OPM(fz_context *ctx, pdf_processor *proc, int i)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	gstate->stroke.color_params.opm = i;
	gstate->fill.color_params.opm = i;
}

static void pdf_run_gs_UseBlackPtComp(fz_context *ctx, pdf_processor *proc, pdf_obj *obj)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	int on = pdf_name_eq(ctx, obj, PDF_NAME(ON));
	/* The spec says that "ON" means on, "OFF" means "Off", and
	 * "Default" or anything else means "Meh, do what you want." */
	gstate->stroke.color_params.bp = on;
	gstate->fill.color_params.bp = on;
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

static void pdf_run_gs_SMask(fz_context *ctx, pdf_processor *proc, pdf_obj *smask, fz_colorspace *smask_cs, float *bc, int luminosity, pdf_obj *tr)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pdf_flush_text(ctx, pr);
	int i;

	if (gstate->softmask)
	{
		pdf_drop_obj(ctx, gstate->softmask);
		gstate->softmask = NULL;
		fz_drop_colorspace(ctx, gstate->softmask_cs);
		gstate->softmask_cs = NULL;
		pdf_drop_obj(ctx, gstate->softmask_resources);
		gstate->softmask_resources = NULL;
	}

	if (smask)
	{
		int cs_n = fz_colorspace_n(ctx, smask_cs);
		gstate->softmask_ctm = gstate->ctm;
		gstate->softmask = pdf_keep_obj(ctx, smask);
		gstate->softmask_cs = fz_keep_colorspace(ctx, smask_cs);
		gstate->softmask_resources = pdf_keep_obj(ctx, pr->rstack->resources);
		pdf_drop_obj(ctx, gstate->softmask_tr);
		gstate->softmask_tr = NULL;
		if (tr)
			gstate->softmask_tr = pdf_keep_obj(ctx, tr);
		for (i = 0; i < cs_n; ++i)
			gstate->softmask_bc[i] = bc[i];
		gstate->luminosity = luminosity;
	}
}

/* special graphics state */

static void pdf_run_q(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	flush_begin_layer(ctx, pr);
	pdf_gsave(ctx, pr);
}

static void pdf_run_Q(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_flush_text(ctx, pr);
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
	gstate->ctm = fz_concat(m, gstate->ctm);
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
	pdf_flush_text(ctx, pr);
	pr->clip = 1;
	pr->clip_even_odd = 0;
}

static void pdf_run_Wstar(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_flush_text(ctx, pr);
	pr->clip = 1;
	pr->clip_even_odd = 1;
}

/* text objects */

static void pdf_run_BT(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->tos.tm = fz_identity;
	pr->tos.tlm = fz_identity;
	pr->bidi = 0;
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
	gstate->text.char_space = charspace;
}

static void pdf_run_Tw(fz_context *ctx, pdf_processor *proc, float wordspace)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->text.word_space = wordspace;
}

static void pdf_run_Tz(fz_context *ctx, pdf_processor *proc, float scale)
{
	/* scale is as written in the file. It is 100 times smaller in
	 * the gstate. */
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->text.scale = scale / 100;
}

static void pdf_run_TL(fz_context *ctx, pdf_processor *proc, float leading)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->text.leading = leading;
}

static void pdf_run_Tf(fz_context *ctx, pdf_processor *proc, const char *name, pdf_font_desc *font, float size)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_drop_font(ctx, gstate->text.font);
	gstate->text.font = pdf_keep_font(ctx, font);
	gstate->text.size = size;
}

static void pdf_run_Tr(fz_context *ctx, pdf_processor *proc, int render)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->text.render = render;
}

static void pdf_run_Ts(fz_context *ctx, pdf_processor *proc, float rise)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->text.rise = rise;
}

/* text positioning */

static void pdf_run_Td(fz_context *ctx, pdf_processor *proc, float tx, float ty)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_tos_translate(&pr->tos, tx, ty);
}

static void pdf_run_TD(fz_context *ctx, pdf_processor *proc, float tx, float ty)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->text.leading = -ty;
	pdf_tos_translate(&pr->tos, tx, ty);
}

static void pdf_run_Tm(fz_context *ctx, pdf_processor *proc, float a, float b, float c, float d, float e, float f)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_tos_set_matrix(&pr->tos, a, b, c, d, e, f);
}

static void pdf_run_Tstar(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_tos_newline(&pr->tos, gstate->text.leading);
}

/* text showing */

static void pdf_run_TJ(fz_context *ctx, pdf_processor *proc, pdf_obj *obj)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_text(ctx, pr, obj);
}

static void pdf_run_Tj(fz_context *ctx, pdf_processor *proc, char *string, size_t string_len)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_string(ctx, pr, (unsigned char *)string, string_len);
}

static void pdf_run_squote(fz_context *ctx, pdf_processor *proc, char *string, size_t string_len)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	pdf_tos_newline(&pr->tos, gstate->text.leading);
	pdf_show_string(ctx, pr, (unsigned char*)string, string_len);
}

static void pdf_run_dquote(fz_context *ctx, pdf_processor *proc, float aw, float ac, char *string, size_t string_len)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_gstate *gstate = pr->gstate + pr->gtop;
	gstate->text.word_space = aw;
	gstate->text.char_space = ac;
	pdf_tos_newline(&pr->tos, gstate->text.leading);
	pdf_show_string(ctx, pr, (unsigned char*)string, string_len);
}

/* type 3 fonts */

static void pdf_run_d0(fz_context *ctx, pdf_processor *proc, float wx, float wy)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags |= FZ_DEVFLAG_COLOR;
}

static void pdf_run_d1(fz_context *ctx, pdf_processor *proc, float wx, float wy, float llx, float lly, float urx, float ury)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags |= FZ_DEVFLAG_MASK | FZ_DEVFLAG_BBOX_DEFINED;
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
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	if (!strcmp(name, "Pattern"))
		pdf_set_pattern(ctx, pr, PDF_STROKE, NULL, NULL);
	else
		pdf_set_colorspace(ctx, pr, PDF_STROKE, colorspace);
}

static void pdf_run_cs(fz_context *ctx, pdf_processor *proc, const char *name, fz_colorspace *colorspace)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	if (!strcmp(name, "Pattern"))
		pdf_set_pattern(ctx, pr, PDF_FILL, NULL, NULL);
	else
		pdf_set_colorspace(ctx, pr, PDF_FILL, colorspace);
}

static void pdf_run_SC_color(fz_context *ctx, pdf_processor *proc, int n, float *color)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_color(ctx, pr, PDF_STROKE, color);
}

static void pdf_run_sc_color(fz_context *ctx, pdf_processor *proc, int n, float *color)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_color(ctx, pr, PDF_FILL, color);
}

static void pdf_run_SC_pattern(fz_context *ctx, pdf_processor *proc, const char *name, pdf_pattern *pat, int n, float *color)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_pattern(ctx, pr, PDF_STROKE, pat, color);
}

static void pdf_run_sc_pattern(fz_context *ctx, pdf_processor *proc, const char *name, pdf_pattern *pat, int n, float *color)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_pattern(ctx, pr, PDF_FILL, pat, color);
}

static void pdf_run_SC_shade(fz_context *ctx, pdf_processor *proc, const char *name, fz_shade *shade)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_shade(ctx, pr, PDF_STROKE, shade);
}

static void pdf_run_sc_shade(fz_context *ctx, pdf_processor *proc, const char *name, fz_shade *shade)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_shade(ctx, pr, PDF_FILL, shade);
}

static void pdf_run_G(fz_context *ctx, pdf_processor *proc, float g)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_colorspace(ctx, pr, PDF_STROKE, fz_device_gray(ctx));
	pdf_set_color(ctx, pr, PDF_STROKE, &g);
}

static void pdf_run_g(fz_context *ctx, pdf_processor *proc, float g)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_colorspace(ctx, pr, PDF_FILL, fz_device_gray(ctx));
	pdf_set_color(ctx, pr, PDF_FILL, &g);
}

static void pdf_run_K(fz_context *ctx, pdf_processor *proc, float c, float m, float y, float k)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	float color[4] = {c, m, y, k};
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_colorspace(ctx, pr, PDF_STROKE, fz_device_cmyk(ctx));
	pdf_set_color(ctx, pr, PDF_STROKE, color);
}

static void pdf_run_k(fz_context *ctx, pdf_processor *proc, float c, float m, float y, float k)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	float color[4] = {c, m, y, k};
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_colorspace(ctx, pr, PDF_FILL, fz_device_cmyk(ctx));
	pdf_set_color(ctx, pr, PDF_FILL, color);
}

static void pdf_run_RG(fz_context *ctx, pdf_processor *proc, float r, float g, float b)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	float color[3] = {r, g, b};
	pr->dev->flags &= ~FZ_DEVFLAG_STROKECOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_colorspace(ctx, pr, PDF_STROKE, fz_device_rgb(ctx));
	pdf_set_color(ctx, pr, PDF_STROKE, color);
}

static void pdf_run_rg(fz_context *ctx, pdf_processor *proc, float r, float g, float b)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	float color[3] = {r, g, b};
	pr->dev->flags &= ~FZ_DEVFLAG_FILLCOLOR_UNDEFINED;
	if (pr->dev->flags & FZ_DEVFLAG_MASK)
		return;
	pdf_set_colorspace(ctx, pr, PDF_FILL, fz_device_rgb(ctx));
	pdf_set_color(ctx, pr, PDF_FILL, color);
}

/* shadings, images, xobjects */

static void pdf_run_BI(fz_context *ctx, pdf_processor *proc, fz_image *image, const char *colorspace)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_image(ctx, pr, image);
}

static void pdf_run_sh(fz_context *ctx, pdf_processor *proc, const char *name, fz_shade *shade)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;

	pop_any_pending_mcid_changes(ctx, pr);
	flush_begin_layer(ctx, pr);
	pdf_show_shade(ctx, pr, shade);
}

static void pdf_run_Do_image(fz_context *ctx, pdf_processor *proc, const char *name, fz_image *image)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_show_image(ctx, pr, image);
}

static void pdf_run_Do_form(fz_context *ctx, pdf_processor *proc, const char *name, pdf_obj *xobj)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	pdf_run_xobject(ctx, (pdf_run_processor*)proc, xobj, pr->rstack->resources, fz_identity, 0);
}

/* marked content */

static void pdf_run_BMC(fz_context *ctx, pdf_processor *proc, const char *tag)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	push_marked_content(ctx, pr, tag, NULL);
}

static void pdf_run_BDC(fz_context *ctx, pdf_processor *proc, const char *tag, pdf_obj *raw, pdf_obj *cooked)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	push_marked_content(ctx, pr, tag, cooked);
}

static void pdf_run_EMC(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;

	pop_marked_content(ctx, pr, 1);
}

static void pdf_run_MP(fz_context *ctx, pdf_processor *proc, const char *tag)
{
	pdf_run_BMC(ctx, proc, tag);
	pdf_run_EMC(ctx, proc);
}

static void pdf_run_DP(fz_context *ctx, pdf_processor *proc, const char *tag, pdf_obj *raw, pdf_obj *cooked)
{
	pdf_run_BDC(ctx, proc, tag, raw, cooked);
	pdf_run_EMC(ctx, proc);
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
pdf_close_run_processor(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;

	while (pr->gtop)
		pdf_grestore(ctx, pr);

	while (pr->nest_depth > 0)
	{
		if (pr->nest_mark[pr->nest_depth-1] < 0)
		{
			/* It's a clip. */
			fz_pop_clip(ctx, pr->dev);
			pr->nest_mark[pr->nest_depth-1]++;
			if (pr->nest_mark[pr->nest_depth-1] == 0)
				pr->nest_depth--;
		}
		else
		{
			/* It's a layer. */
			fz_end_layer(ctx, pr->dev);
			pr->nest_depth--;
		}
	}

	pop_structure_to(ctx, pr, NULL);

	clear_marked_content(ctx, pr);
}

static void
pdf_drop_run_processor(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;

	while (pr->gtop >= 0)
	{
		pdf_drop_gstate(ctx, &pr->gstate[pr->gtop]);
		pr->gtop--;
	}

	fz_drop_path(ctx, pr->path);
	fz_drop_text(ctx, pr->tos.text);

	fz_drop_default_colorspaces(ctx, pr->default_cs);

	fz_free(ctx, pr->gstate);

	while (pr->rstack)
	{
		resources_stack *stk = pr->rstack;
		pr->rstack = stk->next;
		pdf_drop_obj(ctx, stk->resources);
		fz_free(ctx, stk);
	}

	while (pr->begin_layer)
	{
		begin_layer_stack *stk = pr->begin_layer;
		pr->begin_layer = stk->next;
		fz_free(ctx, stk->layer);
		fz_free(ctx, stk);
	}

	while (pr->marked_content)
		pop_marked_content(ctx, pr, 0);

	pdf_drop_obj(ctx, pr->mcid_sent);

	pdf_drop_document(ctx, pr->doc);
	pdf_drop_obj(ctx, pr->role_map);
}

static void
pdf_run_push_resources(fz_context *ctx, pdf_processor *proc, pdf_obj *resources)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	resources_stack *stk = fz_malloc_struct(ctx, resources_stack);

	stk->next = pr->rstack;
	pr->rstack = stk;
	stk->resources = pdf_keep_obj(ctx, resources);
}

static pdf_obj *
pdf_run_pop_resources(fz_context *ctx, pdf_processor *proc)
{
	pdf_run_processor *pr = (pdf_run_processor *)proc;
	resources_stack *stk = pr->rstack;

	if (stk)
	{
		pr->rstack = stk->next;
		pdf_drop_obj(ctx, stk->resources);
		fz_free(ctx, stk);
	}

	return NULL;
}

/*
	Create a new "run" processor. This maps
	from PDF operators to fz_device level calls.

	dev: The device to which the resulting device calls are to be
	sent.

	ctm: The initial transformation matrix to use.

	usage: A NULL terminated string that describes the 'usage' of
	this interpretation. Typically 'View', though 'Print' is also
	defined within the PDF reference manual, and others are possible.

	gstate: The initial graphics state.
*/
pdf_processor *
pdf_new_run_processor(fz_context *ctx, pdf_document *doc, fz_device *dev, fz_matrix ctm, int struct_parent, const char *usage, pdf_gstate *gstate, fz_default_colorspaces *default_cs, fz_cookie *cookie, pdf_gstate *fill_gstate, pdf_gstate *stroke_gstate)
{
	pdf_run_processor *proc = pdf_new_processor(ctx, sizeof *proc);
	{
		proc->super.usage = usage;

		proc->super.close_processor = pdf_close_run_processor;
		proc->super.drop_processor = pdf_drop_run_processor;

		proc->super.push_resources = pdf_run_push_resources;
		proc->super.pop_resources = pdf_run_pop_resources;

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
		proc->super.op_sh = pdf_run_sh;
		if (dev->fill_image || dev->fill_image_mask || dev->clip_image_mask)
		{
			proc->super.op_BI = pdf_run_BI;
			proc->super.op_Do_image = pdf_run_Do_image;
		}
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

		/* extgstate */
		proc->super.op_gs_OP = pdf_run_gs_OP;
		proc->super.op_gs_op = pdf_run_gs_op;
		proc->super.op_gs_OPM = pdf_run_gs_OPM;
		proc->super.op_gs_UseBlackPtComp = pdf_run_gs_UseBlackPtComp;

		proc->super.op_END = pdf_run_END;
	}

	proc->super.requirements = 0;
	if ((dev->hints & FZ_DONT_DECODE_IMAGES) == 0)
		proc->super.requirements |= PDF_PROCESSOR_REQUIRES_DECODED_IMAGES;

	proc->doc = pdf_keep_document(ctx, doc);
	proc->dev = dev;
	proc->cookie = cookie;

	proc->default_cs = fz_keep_default_colorspaces(ctx, default_cs);

	proc->path = NULL;
	proc->clip = 0;
	proc->clip_even_odd = 0;

	proc->tos.text = NULL;
	proc->tos.tlm = fz_identity;
	proc->tos.tm = fz_identity;
	proc->tos.text_mode = 0;

	proc->gtop = -1;

	proc->marked_content = NULL;

	proc->next_begin_layer = &proc->begin_layer;

	fz_try(ctx)
	{
		proc->path = fz_new_path(ctx);

		proc->gcap = 64;
		proc->gstate = fz_malloc_struct_array(ctx, proc->gcap, pdf_gstate);

		proc->gtop = 0;
		pdf_init_gstate(ctx, &proc->gstate[0], ctm);

		if (fill_gstate)
		{
			pdf_copy_gstate(ctx, &proc->gstate[0], fill_gstate);
			proc->gstate[0].clip_depth = 0;
			proc->gtop++;
		}
		if (stroke_gstate)
		{
			pdf_copy_gstate(ctx, &proc->gstate[proc->gtop], stroke_gstate);
			proc->gstate[proc->gtop].clip_depth = 0;
			proc->gtop++;
		}
		if (gstate)
		{
			pdf_copy_gstate(ctx, &proc->gstate[proc->gtop], gstate);
			proc->gstate[proc->gtop].clip_depth = 0;
			proc->gstate[proc->gtop].ctm = ctm;
		}
		proc->gparent = proc->gtop;
		if (fill_gstate)
			proc->gstate[proc->gtop].fill.gstate_num = 0;
		if (stroke_gstate)
			proc->gstate[proc->gtop].fill.gstate_num = (fill_gstate != NULL);

		/* We need to save an extra level to allow for the parent gstate level. */
		pdf_gsave(ctx, proc);

		/* Structure details */
		{
			pdf_obj *struct_tree_root = pdf_dict_getl(ctx, pdf_trailer(ctx, doc), PDF_NAME(Root), PDF_NAME(StructTreeRoot), NULL);
			proc->struct_parent = struct_parent;
			proc->role_map = pdf_keep_obj(ctx, pdf_dict_get(ctx, struct_tree_root, PDF_NAME(RoleMap)));

			/* Annotations and XObjects can be their own content items. We spot this by
			 * the struct_parent looking up to be a singular object. */
			if (struct_parent != -1 && struct_tree_root)
			{
				pdf_obj *struct_obj = pdf_lookup_number(ctx, pdf_dict_get(ctx, struct_tree_root, PDF_NAME(ParentTree)), struct_parent);
				if (pdf_is_dict(ctx, struct_obj))
					send_begin_structure(ctx, proc, struct_obj);
				/* We always end structure as required on closedown, so this is safe. */
			}
		}
	}
	fz_catch(ctx)
	{
		pdf_drop_run_processor(ctx, (pdf_processor *) proc);
		fz_free(ctx, proc);
		fz_rethrow(ctx);
	}

	return (pdf_processor*)proc;
}
