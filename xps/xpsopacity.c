#include "fitz.h"
#include "muxps.h"

void
xps_begin_opacity(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict,
		char *opacity_att, xps_item *opacity_mask_tag)
{
	fz_rect area;
	float opacity;

	if (!opacity_att && !opacity_mask_tag)
		return;

	opacity = 1.0;
	if (opacity_att)
		opacity = atof(opacity_att);

	if (opacity_mask_tag && !strcmp(xps_tag(opacity_mask_tag), "SolidColorBrush"))
	{
		char *scb_opacity_att = xps_att(opacity_mask_tag, "Opacity");
		char *scb_color_att = xps_att(opacity_mask_tag, "Color");
		if (scb_opacity_att)
			opacity = opacity * atof(scb_opacity_att);
		if (scb_color_att)
		{
			fz_colorspace *colorspace;
			float samples[32];
			xps_parse_color(ctx, base_uri, scb_color_att, &colorspace, samples);
			opacity = opacity * samples[0];
		}
		opacity_mask_tag = NULL;
	}

	area = fz_infiniterect; /* FIXME */

	if (ctx->opacity_top + 1 < nelem(ctx->opacity))
	{
		ctx->opacity[ctx->opacity_top + 1] = ctx->opacity[ctx->opacity_top] * opacity;
		ctx->opacity_top++;
	}

	if (opacity_mask_tag)
	{
		ctx->dev->beginmask(ctx->dev->user, area, 0, NULL, NULL);
		xps_parse_brush(ctx, ctm, area, base_uri, dict, opacity_mask_tag);
		ctx->dev->endmask(ctx->dev->user);
	}
}

void
xps_end_opacity(xps_context *ctx, char *base_uri, xps_resource *dict,
		char *opacity_att, xps_item *opacity_mask_tag)
{
	if (!opacity_att && !opacity_mask_tag)
		return;

	if (ctx->opacity_top > 0)
		ctx->opacity_top--;

	if (opacity_mask_tag)
	{
		if (strcmp(xps_tag(opacity_mask_tag), "SolidColorBrush"))
			ctx->dev->popclip(ctx->dev->user);
	}
}
