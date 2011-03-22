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

/* XPS interpreter - image support */

/* TODO: we should be smarter here and do incremental decoding
 * and rendering instead of uncompressing the whole image to
 * memory before drawing.
 */

#include "ghostxps.h"

/*
 * Un-interleave the alpha channel.
 */

static void
xps_isolate_alpha_channel_8(xps_context_t *ctx, xps_image_t *image)
{
	int n = image->comps;
	int y, x, k;
	byte *sp, *dp, *ap;

	image->alpha = xps_alloc(ctx, image->width * image->height);

	for (y = 0; y < image->height; y++)
	{
		sp = image->samples + image->width * n * y;
		dp = image->samples + image->width * (n - 1) * y;
		ap = image->alpha + image->width * y;
		for (x = 0; x < image->width; x++)
		{
			for (k = 0; k < n - 1; k++)
				*dp++ = *sp++;
			*ap++ = *sp++;
		}
	}

	image->hasalpha = 0;
	image->comps --;
	image->stride = image->width * image->comps;
}

static void
xps_isolate_alpha_channel_16(xps_context_t *ctx, xps_image_t *image)
{
	int n = image->comps;
	int y, x, k;
	unsigned short *sp, *dp, *ap;

	image->alpha = xps_alloc(ctx, image->width * image->height * 2);

	for (y = 0; y < image->height; y++)
	{
		sp = ((unsigned short*)image->samples) + (image->width * n * y);
		dp = ((unsigned short*)image->samples) + (image->width * (n - 1) * y);
		ap = ((unsigned short*)image->alpha) + (image->width * y);
		for (x = 0; x < image->width; x++)
		{
			for (k = 0; k < n - 1; k++)
				*dp++ = *sp++;
			*ap++ = *sp++;
		}
	}

	image->hasalpha = 0;
	image->comps --;
	image->stride = image->width * image->comps * 2;
}

static int
xps_image_has_alpha(xps_context_t *ctx, xps_part_t *part)
{
	byte *buf = part->data;
	int len = part->size;

	if (len < 8)
	{
		gs_warn("unknown image file format");
		return 0;
	}

	if (buf[0] == 0xff && buf[1] == 0xd8)
		return 0; /* JPEG never has an alpha channel */
	else if (memcmp(buf, "\211PNG\r\n\032\n", 8) == 0)
		return xps_png_has_alpha(ctx, buf, len);
	else if (memcmp(buf, "II", 2) == 0 && buf[2] == 0xBC)
		return xps_jpegxr_has_alpha(ctx, buf, len);
	else if (memcmp(buf, "MM", 2) == 0)
		return xps_tiff_has_alpha(ctx, buf, len);
	else if (memcmp(buf, "II", 2) == 0)
		return xps_tiff_has_alpha(ctx, buf, len);

	return 0;
}

static int
xps_decode_image(xps_context_t *ctx, xps_part_t *part, xps_image_t *image)
{
	byte *buf = part->data;
	int len = part->size;
	cmm_profile_t *profile;
	int error;

	if (len < 8)
		return gs_throw(-1, "unknown image file format");

	memset(image, 0, sizeof(xps_image_t));
	image->samples = NULL;
	image->alpha = NULL;

	if (buf[0] == 0xff && buf[1] == 0xd8)
	{
		error = xps_decode_jpeg(ctx, buf, len, image);
		if (error)
			return gs_rethrow(error, "could not decode jpeg image");
	}
	else if (memcmp(buf, "\211PNG\r\n\032\n", 8) == 0)
	{
		error = xps_decode_png(ctx, buf, len, image);
		if (error)
			return gs_rethrow(error, "could not decode png image");
	}
	else if (memcmp(buf, "II", 2) == 0 && buf[2] == 0xBC)
	{
		error = xps_decode_jpegxr(ctx, buf, len, image);
		if (error)
			return gs_rethrow(error, "could not decode jpeg-xr image");
	}
	else if (memcmp(buf, "MM", 2) == 0 || memcmp(buf, "II", 2) == 0)
	{
		error = xps_decode_tiff(ctx, buf, len, image);
		if (error)
			return gs_rethrow(error, "could not decode tiff image");
	}
	else
		return gs_throw(-1, "unknown image file format");

	// TODO: refcount image->colorspace

	/* See if we need to use the embedded profile. */
	if (image->profile)
	{
		/*
		See if we can set up to use the embedded profile.
		Note these profiles are NOT added to the xps color cache.
		As such, they must be destroyed when the image brush ends.
		*/

		/* Create the profile */
		profile = gsicc_profile_new(NULL, ctx->memory, NULL, 0);

		/* Set buffer */
		profile->buffer = image->profile;
		profile->buffer_size = image->profilesize;

		/* Parse */
		gsicc_init_profile_info(profile);

		if (profile->profile_handle == NULL)
		{
			/* Problem with profile. Just ignore it */
			gs_warn("ignoring problem with icc profile embedded in an image");
			gsicc_profile_reference(profile, -1);
		}
		else
		{
			/* Check the profile is OK for channel data count.
			 * Need to be careful here since alpha is put into comps */
			if ((image->comps - image->hasalpha) == gsicc_getsrc_channel_count(profile))
			{
				/* Create a new colorspace and associate with the profile */
				// TODO: refcount image->colorspace
				gs_cspace_build_ICC(&image->colorspace, NULL, ctx->memory);
				image->colorspace->cmm_icc_profile_data = profile;
			}
			else
			{
				/* Problem with profile. Just ignore it */
				gs_warn("ignoring icc profile embedded in an image with wrong number of components");
				gsicc_profile_reference(profile, -1);
			}
		}
	}

	if (image->hasalpha)
	{
		if (image->bits < 8)
			dprintf1("cannot isolate alpha channel in %d bpc images\n", image->bits);
		if (image->bits == 8)
			xps_isolate_alpha_channel_8(ctx, image);
		if (image->bits == 16)
			xps_isolate_alpha_channel_16(ctx, image);
	}

	return gs_okay;
}

static int
xps_paint_image_brush_imp(xps_context_t *ctx, xps_image_t *image, int alpha)
{
	gs_image_enum *penum;
	gs_color_space *colorspace;
	gs_image_t gsimage;
	int code;

	unsigned int count;
	unsigned int used;
	byte *samples;

	if (alpha)
	{
		colorspace = ctx->gray;
		samples = image->alpha;
		count = (image->width * image->bits + 7) / 8 * image->height;
		used = 0;
	}
	else
	{
		colorspace = image->colorspace;
		samples = image->samples;
		count = image->stride * image->height;
		used = 0;
	}

	memset(&gsimage, 0, sizeof(gsimage));
	gs_image_t_init(&gsimage, colorspace);
	gsimage.ColorSpace = colorspace;
	gsimage.BitsPerComponent = image->bits;
	gsimage.Width = image->width;
	gsimage.Height = image->height;

	gsimage.ImageMatrix.xx = image->xres / 96.0;
	gsimage.ImageMatrix.yy = image->yres / 96.0;

	gsimage.Interpolate = 1;

	penum = gs_image_enum_alloc(ctx->memory, "xps_parse_image_brush (gs_image_enum_alloc)");
	if (!penum)
		return gs_throw(-1, "gs_enum_allocate failed");

	if ((code = gs_image_init(penum, &gsimage, false, ctx->pgs)) < 0)
		return gs_throw(code, "gs_image_init failed");

	if ((code = gs_image_next(penum, samples, count, &used)) < 0)
		return gs_throw(code, "gs_image_next failed");

	if (count < used)
		return gs_throw2(-1, "not enough image data (image=%d used=%d)", count, used);

	if (count > used)
		return gs_throw2(0, "too much image data (image=%d used=%d)", count, used);

	gs_image_cleanup_and_free_enum(penum, ctx->pgs);

	return 0;
}

static int
xps_paint_image_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root, void *vimage)
{
	xps_image_t *image = vimage;
	int code;

	if (ctx->opacity_only)
	{
		if (image->alpha)
		{
			code = xps_paint_image_brush_imp(ctx, image, 1);
			if (code < 0)
				return gs_rethrow(code, "cannot draw alpha channel image");
		}
		return 0;
	}

	if (image->alpha)
	{
		gs_transparency_mask_params_t params;
		gs_transparency_group_params_t tgp;
		gs_rect bbox;

		xps_bounds_in_user_space(ctx, &bbox);

		code = gs_gsave(ctx->pgs);
		if (code < 0)
			return gs_rethrow(code, "cannot gsave before transparency group");

		gs_setcolorspace(ctx->pgs, ctx->gray);
		gs_trans_mask_params_init(&params, TRANSPARENCY_MASK_Luminosity);
		gs_begin_transparency_mask(ctx->pgs, &params, &bbox, 0);
		code = xps_paint_image_brush_imp(ctx, image, 1);
		if (code < 0)
		{
			gs_end_transparency_mask(ctx->pgs, TRANSPARENCY_CHANNEL_Opacity);
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot draw alpha channel image");
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
			return gs_rethrow(code, "cannot draw color channel image");
		}
		gs_end_transparency_group(ctx->pgs);

		code = gs_grestore(ctx->pgs);
		if (code < 0)
			return gs_rethrow(code, "cannot grestore after transparency group");
	}
	else
	{
		code = xps_paint_image_brush_imp(ctx, image, 0);
		if (code < 0)
			return gs_rethrow(code, "cannot draw image");
	}
	return 0;
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
		return gs_throw(-1, "missing ImageSource attribute");

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
		return gs_throw1(-1, "cannot parse image resource name '%s'", image_source_att);

	xps_absolute_path(partname, base_uri, image_name, sizeof partname);
	part = xps_read_part(ctx, partname);
	if (!part)
		return gs_throw1(-1, "cannot find image resource part '%s'", partname);

	*partp = part;
	*profilep = xps_strdup(ctx, profile_name);

	return 0;
}

int
xps_parse_image_brush(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root)
{
	xps_part_t *part;
	xps_image_t *image;
	gs_color_space *colorspace;
	char *profilename;
	int code;

	code = xps_find_image_brush_source_part(ctx, base_uri, root, &part, &profilename);
	if (code < 0)
		return gs_rethrow(code, "cannot find image source");

	image = xps_alloc(ctx, sizeof(xps_image_t));
	if (!image)
		return gs_throw(-1, "out of memory: image struct");

	code = xps_decode_image(ctx, part, image);
	if (code < 0)
		return gs_rethrow1(code, "cannot decode image '%s'", part->name);

	/* Override any embedded colorspace profiles if the external one matches. */
	if (profilename)
	{
		colorspace = xps_read_icc_colorspace(ctx, base_uri, profilename);
		if (colorspace && cs_num_components(colorspace) == cs_num_components(image->colorspace))
		{
			// TODO: refcount image->colorspace
			image->colorspace = colorspace;
		}
	}

	code = xps_parse_tiling_brush(ctx, base_uri, dict, root, xps_paint_image_brush, image);
	if (code < 0)
		return gs_rethrow(-1, "cannot parse tiling brush");

	if (profilename)
		xps_free(ctx, profilename);
	xps_free_image(ctx, image);
	xps_free_part(ctx, part);

	return 0;
}

int
xps_image_brush_has_transparency(xps_context_t *ctx, char *base_uri, xps_item_t *root)
{
	xps_part_t *imagepart;
	int code;
	int has_alpha;
	char *profilename;

	code = xps_find_image_brush_source_part(ctx, base_uri, root, &imagepart, &profilename);
	if (code < 0)
	{
		gs_catch(code, "cannot find image source");
		return 0;
	}

	has_alpha = xps_image_has_alpha(ctx, imagepart);

	xps_free_part(ctx, imagepart);

	return has_alpha;
}

void
xps_free_image(xps_context_t *ctx, xps_image_t *image)
{
	// TODO: refcount image->colorspace
	if (image->samples)
		xps_free(ctx, image->samples);
	if (image->alpha)
		xps_free(ctx, image->alpha);
	if (image->profile)
		xps_free(ctx, image->profile);
	xps_free(ctx, image);
}
