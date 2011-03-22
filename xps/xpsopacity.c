#include "fitz.h"
#include "muxps.h"

void
xps_bounds_in_user_space(xps_context_t *ctx, fz_rect *ubox)
{
#if 0
	gx_clip_path *clip_path;
	fz_rect dbox;
	int code;

	code = gx_effective_clip_path(ctx->pgs, &clip_path);
	if (code < 0)
		fz_warn("gx_effective_clip_path failed");

	dbox.p.x = fixed2float(clip_path->outer_box.p.x);
	dbox.p.y = fixed2float(clip_path->outer_box.p.y);
	dbox.q.x = fixed2float(clip_path->outer_box.q.x);
	dbox.q.y = fixed2float(clip_path->outer_box.q.y);
	gs_bbox_transform_inverse(&dbox, &ctm_only(ctx->pgs), ubox);
#endif
}

int
xps_begin_opacity(xps_context_t *ctx, fz_matrix ctm, char *base_uri, xps_resource_t *dict,
		char *opacity_att, xps_item_t *opacity_mask_tag)
{
	fz_rect bbox;
	float opacity;
	int save;
	int code;

	if (!opacity_att && !opacity_mask_tag)
		return 0;

	opacity = 1.0;
	if (opacity_att)
		opacity = atof(opacity_att);
//	gs_setopacityalpha(ctx->pgs, opacity);

	xps_bounds_in_user_space(ctx, &bbox);

	if (opacity_mask_tag)
	{
		/* opacity-only mode: use alpha value as gray color to create luminosity mask */
		save = ctx->opacity_only;
		ctx->opacity_only = 1;

		// begin mask
		code = xps_parse_brush(ctx, ctm, base_uri, dict, opacity_mask_tag);
		if (code)
		{
			ctx->opacity_only = save;
			return fz_rethrow(code, "cannot parse opacity mask brush");
		}

		ctx->opacity_only = save;
	}

	// begin group

	return 0;
}

void
xps_end_opacity(xps_context_t *ctx, char *base_uri, xps_resource_t *dict,
		char *opacity_att, xps_item_t *opacity_mask_tag)
{
	if (!opacity_att && !opacity_mask_tag)
		return;
	// end mask+group
}
