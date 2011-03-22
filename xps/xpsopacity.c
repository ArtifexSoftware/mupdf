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

/* XPS interpreter - transparency support */

#include "ghostxps.h"

void
xps_bounds_in_user_space(xps_context_t *ctx, gs_rect *ubox)
{
	gx_clip_path *clip_path;
	gs_rect dbox;
	int code;

	code = gx_effective_clip_path(ctx->pgs, &clip_path);
	if (code < 0)
		gs_warn("gx_effective_clip_path failed");

	dbox.p.x = fixed2float(clip_path->outer_box.p.x);
	dbox.p.y = fixed2float(clip_path->outer_box.p.y);
	dbox.q.x = fixed2float(clip_path->outer_box.q.x);
	dbox.q.y = fixed2float(clip_path->outer_box.q.y);
	gs_bbox_transform_inverse(&dbox, &ctm_only(ctx->pgs), ubox);
}

int
xps_begin_opacity(xps_context_t *ctx, char *base_uri, xps_resource_t *dict,
		char *opacity_att, xps_item_t *opacity_mask_tag)
{
	gs_transparency_group_params_t tgp;
	gs_transparency_mask_params_t tmp;
	gs_rect bbox;
	float opacity;
	int save;
	int code;

	if (!opacity_att && !opacity_mask_tag)
		return 0;

	opacity = 1.0;
	if (opacity_att)
		opacity = atof(opacity_att);
	gs_setopacityalpha(ctx->pgs, opacity);

	xps_bounds_in_user_space(ctx, &bbox);

	if (opacity_mask_tag)
	{
		gs_trans_mask_params_init(&tmp, TRANSPARENCY_MASK_Luminosity);
		gs_begin_transparency_mask(ctx->pgs, &tmp, &bbox, 0);

		gs_gsave(ctx->pgs);

		/* Need a path to fill/clip for the brush */
		gs_moveto(ctx->pgs, bbox.p.x, bbox.p.y);
		gs_lineto(ctx->pgs, bbox.p.x, bbox.q.y);
		gs_lineto(ctx->pgs, bbox.q.x, bbox.q.y);
		gs_lineto(ctx->pgs, bbox.q.x, bbox.p.y);
		gs_closepath(ctx->pgs);

		/* opacity-only mode: use alpha value as gray color to create luminosity mask */
		save = ctx->opacity_only;
		ctx->opacity_only = 1;

		code = xps_parse_brush(ctx, base_uri, dict, opacity_mask_tag);
		if (code)
		{
			gs_grestore(ctx->pgs);
			gs_end_transparency_mask(ctx->pgs, TRANSPARENCY_CHANNEL_Opacity);
			ctx->opacity_only = save;
			return gs_rethrow(code, "cannot parse opacity mask brush");
		}

		gs_grestore(ctx->pgs);
		gs_end_transparency_mask(ctx->pgs, TRANSPARENCY_CHANNEL_Opacity);
		ctx->opacity_only = save;
	}

	gs_trans_group_params_init(&tgp);
	gs_begin_transparency_group(ctx->pgs, &tgp, &bbox);

	return 0;
}

void
xps_end_opacity(xps_context_t *ctx, char *base_uri, xps_resource_t *dict,
		char *opacity_att, xps_item_t *opacity_mask_tag)
{
	if (!opacity_att && !opacity_mask_tag)
		return;
	gs_end_transparency_group(ctx->pgs);
}
