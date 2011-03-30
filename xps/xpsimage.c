#include "fitz.h"
#include "muxps.h"

static int
xps_decode_image(xps_context *ctx, xps_part *part, xps_image *image)
{
	byte *buf = part->data;
	int len = part->size;
	int error;

	if (len < 8)
		return fz_throw("unknown image file format");

	memset(image, 0, sizeof(xps_image));

	if (buf[0] == 0xff && buf[1] == 0xd8)
	{
		error = xps_decode_jpeg(ctx, buf, len, image);
		if (error)
			return fz_rethrow(error, "cannot decode jpeg image");
	}
	else if (memcmp(buf, "\211PNG\r\n\032\n", 8) == 0)
	{
		error = xps_decode_png(ctx, buf, len, image);
		if (error)
			return fz_rethrow(error, "cannot decode png image");
	}
	else if (memcmp(buf, "II", 2) == 0 && buf[2] == 0xBC)
	{
		error = xps_decode_jpegxr(ctx, buf, len, image);
		if (error)
			return fz_rethrow(error, "cannot decode JPEG-XR image");
	}
	else if (memcmp(buf, "MM", 2) == 0 || memcmp(buf, "II", 2) == 0)
	{
		error = xps_decode_tiff(ctx, buf, len, image);
		if (error)
			return fz_rethrow(error, "cannot decode TIFF image");
	}
	else
		return fz_throw("unknown image file format");

	image->pixmap = fz_newpixmap(image->colorspace, 0, 0, image->width, image->height);
	fz_unpacktile(image->pixmap, image->samples, image->comps, image->bits, image->stride, 1);
	fz_free(image->samples);
	image->samples = NULL;

	return fz_okay;
}

static void
xps_paint_image_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *root, void *vimage)
{
	xps_image *image = vimage;
	float xs = image->width * 96.0 / image->xres;
	float ys = image->height * 96.0 / image->yres;
	fz_matrix im = fz_scale(xs, -ys);
	im.f = ys;
	ctm = fz_concat(im, ctm);
	ctx->dev->fillimage(ctx->dev->user, image->pixmap, ctm, 1.0);
}

static int
xps_find_image_brush_source_part(xps_context *ctx, char *base_uri, xps_item *root,
	xps_part **partp, char **profilep)
{
	xps_part *part;
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

		fz_strlcpy(buf, image_source_att, sizeof buf);
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
		*profilep = fz_strdup(profile_name);

	return 0;
}

void
xps_parse_image_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *root)
{
	xps_part *part;
	xps_image *image;
	fz_colorspace *colorspace;
	char *profilename;
	int code;

	profilename = NULL;

	code = xps_find_image_brush_source_part(ctx, base_uri, root, &part, &profilename);
	if (code < 0) {
		fz_catch(code, "cannot find image source");
		return;
	}

	image = fz_malloc(sizeof(xps_image));

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
		fz_free(profilename);
	xps_free_image(ctx, image);
	xps_free_part(ctx, part);
}

void
xps_free_image(xps_context *ctx, xps_image *image)
{
	// TODO: refcount image->colorspace
	if (image->pixmap)
		fz_droppixmap(image->pixmap);
	if (image->samples)
		fz_free(image->samples);
	if (image->profile)
		fz_free(image->profile);
	fz_free(image);
}
