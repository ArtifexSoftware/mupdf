#include "fitz.h"
#include "muxps.h"

static int
xps_decode_image(xps_context_t *ctx, xps_part_t *part, xps_image_t *image)
{
	byte *buf = part->data;
	int len = part->size;
	int error;

	if (len < 8)
		return fz_throw("unknown image file format");

	memset(image, 0, sizeof(xps_image_t));

	if (buf[0] == 0xff && buf[1] == 0xd8)
	{
		error = xps_decode_jpeg(ctx, buf, len, image);
		if (error)
			return fz_rethrow(error, "could not decode image");
	}
	else if (memcmp(buf, "\211PNG\r\n\032\n", 8) == 0)
	{
		error = xps_decode_png(ctx, buf, len, image);
		if (error)
			return fz_rethrow(error, "could not decode image");
	}
	else if (memcmp(buf, "II", 2) == 0 && buf[2] == 0xBC)
	{
		error = xps_decode_jpegxr(ctx, buf, len, image);
		if (error)
			return fz_rethrow(error, "could not decode image");
	}
	else if (memcmp(buf, "MM", 2) == 0 || memcmp(buf, "II", 2) == 0)
	{
		error = xps_decode_tiff(ctx, buf, len, image);
		if (error)
			return fz_rethrow(error, "could not decode image");
	}
	else
		return fz_throw("unknown image file format");

	return fz_okay;
}

static void
xps_paint_image_brush_imp(xps_context_t *ctx, fz_matrix ctm, xps_image_t *image)
{
	fz_colorspace *colorspace;
	unsigned int count;
	byte *samples;

	colorspace = image->colorspace;
	samples = image->samples;
	count = image->stride * image->height;

printf("xps_paint_image_brush_imp!\n");
}

static void
xps_paint_image_brush(xps_context_t *ctx, fz_matrix ctm, char *base_uri, xps_resource_t *dict, xps_item_t *root, void *vimage)
{
#if 0
	xps_image_t *image = vimage;
	int code;

	if (ctx->opacity_only)
	{
		if (image->alpha)
		{
			code = xps_paint_image_brush_imp(ctx, image, 1);
			if (code < 0)
				return fz_rethrow(code, "cannot draw alpha channel image");
		}
		return 0;
	}

	if (image->alpha)
	{
		gs_transparency_mask_params_t params;
		gs_transparency_group_params_t tgp;
		fz_rect bbox;

		xps_bounds_in_user_space(ctx, &bbox);

		code = gs_gsave(ctx->pgs);
		if (code < 0)
			return fz_rethrow(code, "cannot gsave before transparency group");

		gs_setcolorspace(ctx->pgs, ctx->gray);
		gs_trans_mask_params_init(&params, TRANSPARENCY_MASK_Luminosity);
		gs_begin_transparency_mask(ctx->pgs, &params, &bbox, 0);
		code = xps_paint_image_brush_imp(ctx, image, 1);
		if (code < 0)
		{
			gs_end_transparency_mask(ctx->pgs, TRANSPARENCY_CHANNEL_Opacity);
			gs_grestore(ctx->pgs);
			return fz_rethrow(code, "cannot draw alpha channel image");
		}
		gs_end_transparency_mask(ctx->pgs, TRANSPARENCY_CHANNEL_Opacity);

		gs_setcolorspace(ctx->pgs, image->colorspace);
		gs_trans_group_params_init(&tgp);
		gs_begin_transparency_group(ctx->pgs, &tgp, &bbox);
		code = xps_paint_image_brush_imp(ctx, image, 0);
		if (code < 0)
		{
			gs_end_transparency_group(ctx->pgs);
			gs_grestore(ctx->pgs);
			return fz_rethrow(code, "cannot draw color channel image");
		}
		gs_end_transparency_group(ctx->pgs);

		code = gs_grestore(ctx->pgs);
		if (code < 0)
			return fz_rethrow(code, "cannot grestore after transparency group");
	}
	else
	{
		code = xps_paint_image_brush_imp(ctx, image, 0);
		if (code < 0)
			return fz_rethrow(code, "cannot draw image");
	}
#endif
}

static int
xps_find_image_brush_source_part(xps_context_t *ctx, char *base_uri, xps_item_t *root,
	xps_part_t **partp, char **profilep)
{
	xps_part_t *part;
	char *image_source_att;
	char buf[1024];
	char partname[1024];
	char *image_name;
	char *profile_name;
	char *p;

	image_source_att = xps_att(root, "ImageSource");
	if (!image_source_att)
		return fz_throw("missing ImageSource attribute");

	/* "{ColorConvertedBitmap /Resources/Image.tiff /Resources/Profile.icc}" */
	if (strstr(image_source_att, "{ColorConvertedBitmap") == image_source_att)
	{
		image_name = NULL;
		profile_name = NULL;

		xps_strlcpy(buf, image_source_att, sizeof buf);
		p = strchr(buf, ' ');
		if (p)
		{
			image_name = p + 1;
			p = strchr(p + 1, ' ');
			if (p)
			{
				*p = 0;
				profile_name = p + 1;
				p = strchr(p + 1, '}');
				if (p)
					*p = 0;
			}
		}
	}
	else
	{
		image_name = image_source_att;
		profile_name = NULL;
	}

	if (!image_name)
		return fz_throw("cannot parse image resource name '%s'", image_source_att);

	xps_absolute_path(partname, base_uri, image_name, sizeof partname);
	part = xps_read_part(ctx, partname);
	if (!part)
		return fz_throw("cannot find image resource part '%s'", partname);

	*partp = part;
	if (profile_name)
		*profilep = xps_strdup(ctx, profile_name);

	return 0;
}

void
xps_parse_image_brush(xps_context_t *ctx, fz_matrix ctm, char *base_uri, xps_resource_t *dict, xps_item_t *root)
{
	xps_part_t *part;
	xps_image_t *image;
	fz_colorspace *colorspace;
	char *profilename;
	int code;

	profilename = NULL;

	code = xps_find_image_brush_source_part(ctx, base_uri, root, &part, &profilename);
	if (code < 0) {
		fz_catch(code, "cannot find image source");
		return;
	}

	image = xps_alloc(ctx, sizeof(xps_image_t));

	code = xps_decode_image(ctx, part, image);
	if (code < 0) {
		fz_free(image);
		fz_catch(-1, "cannot decode image resource");
		return;
	}

	/* Override any embedded colorspace profiles if the external one matches. */
	if (profilename)
	{
		colorspace = xps_read_icc_colorspace(ctx, base_uri, profilename);
		if (colorspace && colorspace->n == image->colorspace->n)
		{
			// TODO: refcount image->colorspace
			image->colorspace = colorspace;
		}
	}

	xps_parse_tiling_brush(ctx, ctm, base_uri, dict, root, xps_paint_image_brush, image);

	if (profilename)
		xps_free(ctx, profilename);
	xps_free_image(ctx, image);
	xps_free_part(ctx, part);
}

void
xps_free_image(xps_context_t *ctx, xps_image_t *image)
{
	// TODO: refcount image->colorspace
	if (image->samples)
		xps_free(ctx, image->samples);
	if (image->profile)
		xps_free(ctx, image->profile);
	xps_free(ctx, image);
}
