#include "fitz.h"
#include "muxps.h"

static int
xps_decode_image(xps_image **imagep, xps_context *ctx, xps_part *part)
{
	byte *buf = part->data;
	int len = part->size;
	int error;

	if (len < 8)
		return fz_throw("unknown image file format");

	if (buf[0] == 0xff && buf[1] == 0xd8)
	{
		error = xps_decode_jpeg(imagep, ctx, buf, len);
		if (error)
			return fz_rethrow(error, "cannot decode jpeg image");
	}
	else if (memcmp(buf, "\211PNG\r\n\032\n", 8) == 0)
	{
		error = xps_decode_png(imagep, ctx, buf, len);
		if (error)
			return fz_rethrow(error, "cannot decode png image");
	}
	else if (memcmp(buf, "II", 2) == 0 && buf[2] == 0xBC)
	{
		error = xps_decode_jpegxr(imagep, ctx, buf, len);
		if (error)
			return fz_rethrow(error, "cannot decode JPEG-XR image");
	}
	else if (memcmp(buf, "MM", 2) == 0 || memcmp(buf, "II", 2) == 0)
	{
		error = xps_decode_tiff(imagep, ctx, buf, len);
		if (error)
			return fz_rethrow(error, "cannot decode TIFF image");
	}
	else
		return fz_throw("unknown image file format");

	return fz_okay;
}

static void
xps_paint_image_brush(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *root, void *vimage)
{
	xps_image *image = vimage;
	fz_pixmap *pixmap = image->pixmap;
	float xs = pixmap->w * 96.0 / image->xres;
	float ys = pixmap->h * 96.0 / image->yres;
	fz_matrix im = fz_scale(xs, -ys);
	im.f = ys;
	ctm = fz_concat(im, ctm);
	ctx->dev->fillimage(ctx->dev->user, pixmap, ctm, 1.0);
}

static xps_part *
xps_find_image_brush_source_part(xps_context *ctx, char *base_uri, xps_item *root)
{
	char *image_source_att;
	char buf[1024];
	char partname[1024];
	char *image_name;
	char *profile_name;
	char *p;

	image_source_att = xps_att(root, "ImageSource");
	if (!image_source_att)
		return NULL;

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
		return NULL;

	xps_absolute_path(partname, base_uri, image_name, sizeof partname);

	return xps_read_part(ctx, partname);
}

void
xps_parse_image_brush(xps_context *ctx, fz_matrix ctm, fz_rect area,
	char *base_uri, xps_resource *dict, xps_item *root)
{
	xps_part *part;
	xps_image *image;
	int code;

	part = xps_find_image_brush_source_part(ctx, base_uri, root);
	if (!part) {
		fz_warn("cannot find image source");
		return;
	}

	code = xps_decode_image(&image, ctx, part);
	if (code < 0) {
		fz_catch(-1, "cannot decode image resource");
		return;
	}

	xps_parse_tiling_brush(ctx, ctm, area, base_uri, dict, root, xps_paint_image_brush, image);

	xps_free_image(ctx, image);
	xps_free_part(ctx, part);
}

void
xps_free_image(xps_context *ctx, xps_image *image)
{
	if (image->pixmap)
		fz_droppixmap(image->pixmap);
	fz_free(image);
}
