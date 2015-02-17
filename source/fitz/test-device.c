#include <mupdf/fitz.h>

typedef struct fz_test_device_s
{
	fz_device super;
	int *is_color;
	float threshold;
} fz_test_device;

static int
is_rgb_color(float threshold, float r, float g, float b)
{
	float rg_diff = fz_abs(r - g);
	float rb_diff = fz_abs(r - b);
	float gb_diff = fz_abs(g - b);
	return rg_diff > threshold || rb_diff > threshold || gb_diff > threshold;
}

static int
is_rgb_color_u8(int threshold_u8, int r, int g, int b)
{
	int rg_diff = fz_absi(r - g);
	int rb_diff = fz_absi(r - b);
	int gb_diff = fz_absi(g - b);
	return rg_diff > threshold_u8 || rb_diff > threshold_u8 || gb_diff > threshold_u8;
}

static void
fz_test_color(fz_context *ctx, fz_device *dev, fz_colorspace *colorspace, const float *color)
{
	fz_test_device *t = (fz_test_device*)dev;

	if (!*t->is_color && colorspace && colorspace != fz_device_gray(ctx))
	{
		if (colorspace == fz_device_rgb(ctx))
		{
			if (is_rgb_color(t->threshold, color[0], color[1], color[2]))
			{
				*t->is_color = 1;
				dev->hints |= FZ_IGNORE_IMAGE;
				fz_throw(ctx, FZ_ERROR_ABORT, "Page found as color; stopping interpretation");
			}
		}
		else
		{
			float rgb[3];
			fz_convert_color(ctx, fz_device_rgb(ctx), rgb, colorspace, color);
			if (is_rgb_color(t->threshold, rgb[0], rgb[1], rgb[2]))
			{
				*t->is_color = 1;
				dev->hints |= FZ_IGNORE_IMAGE;
				fz_throw(ctx, FZ_ERROR_ABORT, "Page found as color; stopping interpretation");
			}
		}
	}
}

static void
fz_test_fill_path(fz_context *ctx, fz_device *dev, fz_path *path, int even_odd, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	if (alpha != 0.0f)
		fz_test_color(ctx, dev, colorspace, color);
}

static void
fz_test_stroke_path(fz_context *ctx, fz_device *dev, fz_path *path, fz_stroke_state *stroke,
	const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha)
{
	if (alpha != 0.0f)
		fz_test_color(ctx, dev, colorspace, color);
}

static void
fz_test_fill_text(fz_context *ctx, fz_device *dev, fz_text *text, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	if (alpha != 0.0f)
		fz_test_color(ctx, dev, colorspace, color);
}

static void
fz_test_stroke_text(fz_context *ctx, fz_device *dev, fz_text *text, fz_stroke_state *stroke,
	const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha)
{
	if (alpha != 0.0f)
		fz_test_color(ctx, dev, colorspace, color);
}

struct shadearg
{
	fz_device *dev;
	fz_shade *shade;
};

static void
prepare_vertex(fz_context *ctx, void *arg_, fz_vertex *v, const float *color)
{
	struct shadearg *arg = arg_;
	fz_device *dev = arg->dev;
	fz_shade *shade = arg->shade;
	if (!shade->use_function)
		fz_test_color(ctx, dev, shade->colorspace, color);
}

static void
fz_test_fill_shade(fz_context *ctx, fz_device *dev, fz_shade *shade, const fz_matrix *ctm, float alpha)
{
	if (shade->use_function)
	{
		int i;
		for (i = 0; i < 256; i++)
			fz_test_color(ctx, dev, shade->colorspace, shade->function[i]);
	}
	else
	{
		struct shadearg arg;
		arg.dev = dev;
		arg.shade = shade;
		fz_process_mesh(ctx, shade, ctm, prepare_vertex, NULL, &arg);
	}
}

static void
fz_test_fill_image(fz_context *ctx, fz_device *dev, fz_image *image, const fz_matrix *ctm, float alpha)
{
	fz_test_device *t = (fz_test_device*)dev;

	fz_pixmap *pix;
	unsigned int count, i, k;
	unsigned char *s;

	if (*t->is_color || !image->colorspace || image->colorspace == fz_device_gray(ctx))
		return;

	if (image->buffer && image->bpc == 8)
	{
		fz_stream *stream = fz_open_compressed_buffer(ctx, image->buffer);
		count = (unsigned int)image->w * (unsigned int)image->h;
		if (image->colorspace == fz_device_rgb(ctx))
		{
			int threshold_u8 = t->threshold * 255;
			for (i = 0; i < count; i++)
			{
				int r = fz_read_byte(ctx, stream);
				int g = fz_read_byte(ctx, stream);
				int b = fz_read_byte(ctx, stream);
				if (is_rgb_color_u8(threshold_u8, r, g, b))
				{
					*t->is_color = 1;
					dev->hints |= FZ_IGNORE_IMAGE;
					fz_drop_stream(ctx, stream);
					fz_throw(ctx, FZ_ERROR_ABORT, "Page found as color; stopping interpretation");
					break;
				}
			}
		}
		else
		{
			fz_color_converter cc;
			unsigned int n = (unsigned int)image->n;

			fz_init_cached_color_converter(ctx, &cc, fz_device_rgb(ctx), image->colorspace);
			for (i = 0; i < count; i++)
			{
				float cs[FZ_MAX_COLORS];
				float ds[FZ_MAX_COLORS];

				for (k = 0; k < n; k++)
					cs[k] = fz_read_byte(ctx, stream) / 255.0f;

				cc.convert(ctx, &cc, ds, cs);

				if (is_rgb_color(t->threshold, ds[0], ds[1], ds[2]))
				{
					*t->is_color = 1;
					dev->hints |= FZ_IGNORE_IMAGE;
					break;
				}
			}
			fz_fin_cached_color_converter(ctx, &cc);
		}
		fz_drop_stream(ctx, stream);
		return;
	}

	pix = fz_new_pixmap_from_image(ctx, image, 0, 0);
	if (pix == NULL) /* Should never happen really, but... */
		return;

	count = (unsigned int)pix->w * (unsigned int)pix->h;
	s = pix->samples;

	if (pix->colorspace == fz_device_rgb(ctx))
	{
		int threshold_u8 = t->threshold * 255;
		for (i = 0; i < count; i++)
		{
			if (s[3] != 0 && is_rgb_color_u8(threshold_u8, s[0], s[1], s[2]))
			{
				*t->is_color = 1;
				dev->hints |= FZ_IGNORE_IMAGE;
				fz_drop_pixmap(ctx, pix);
				fz_throw(ctx, FZ_ERROR_ABORT, "Page found as color; stopping interpretation");
				break;
			}
			s += 4;
		}
	}
	else
	{
		fz_color_converter cc;
		unsigned int n = (unsigned int)pix->n-1;

		fz_init_cached_color_converter(ctx, &cc, fz_device_rgb(ctx), pix->colorspace);
		for (i = 0; i < count; i++)
		{
			float cs[FZ_MAX_COLORS];
			float ds[FZ_MAX_COLORS];

			for (k = 0; k < n; k++)
				cs[k] = (*s++) / 255.0f;
			if (*s++ == 0)
				continue;

			cc.convert(ctx, &cc, ds, cs);

			if (is_rgb_color(t->threshold, ds[0], ds[1], ds[2]))
			{
				*t->is_color = 1;
				dev->hints |= FZ_IGNORE_IMAGE;
				fz_drop_pixmap(ctx, pix);
				fz_throw(ctx, FZ_ERROR_ABORT, "Page found as color; stopping interpretation");
				break;
			}
		}
		fz_fin_cached_color_converter(ctx, &cc);
	}

	fz_drop_pixmap(ctx, pix);
}

static void
fz_test_fill_image_mask(fz_context *ctx, fz_device *dev, fz_image *image, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	/* We assume that at least some of the image pixels are non-zero */
	fz_test_color(ctx, dev, colorspace, color);
}

fz_device *
fz_new_test_device(fz_context *ctx, int *is_color, float threshold)
{
	fz_test_device *dev = fz_new_device(ctx, sizeof *dev);

	dev->super.fill_path = fz_test_fill_path;
	dev->super.stroke_path = fz_test_stroke_path;
	dev->super.fill_text = fz_test_fill_text;
	dev->super.stroke_text = fz_test_stroke_text;
	dev->super.fill_shade = fz_test_fill_shade;
	dev->super.fill_image = fz_test_fill_image;
	dev->super.fill_image_mask = fz_test_fill_image_mask;

	dev->is_color = is_color;
	dev->threshold = threshold;

	*dev->is_color = 0;

	return (fz_device*)dev;
}
