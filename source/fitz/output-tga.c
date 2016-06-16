#include "mupdf/fitz.h"

/*
 * Write pixmap to TGA file (with or without alpha channel)
 */

static inline void tga_put_pixel(fz_context *ctx, fz_output *out, unsigned char *data, int n, int is_bgr)
{
	if (n >= 3 && !is_bgr)
	{
		fz_putc(ctx, out, data[2]);
		fz_putc(ctx, out, data[1]);
		fz_putc(ctx, out, data[0]);
		if (n == 4)
			fz_putc(ctx, out, data[3]);
		return;
	}
	if (n == 2)
	{
		fz_putc(ctx, out, data[0]);
		fz_putc(ctx, out, data[0]);
	}
	fz_write(ctx, out, data, n);
}

void
fz_save_pixmap_as_tga(fz_context *ctx, fz_pixmap *pixmap, const char *filename)
{
	fz_output *out = fz_new_output_with_path(ctx, filename, 0);
	fz_try(ctx)
		fz_write_pixmap_as_tga(ctx, out, pixmap);
	fz_always(ctx)
		fz_drop_output(ctx, out);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void
fz_write_pixmap_as_tga(fz_context *ctx, fz_output *out, fz_pixmap *pixmap)
{
	unsigned char head[18];
	int n = pixmap->n;
	int d = pixmap->alpha || n == 1 ? n : n - 1;
	int is_bgr = pixmap->colorspace == fz_device_bgr(ctx);
	int k;

	if (pixmap->colorspace && pixmap->colorspace != fz_device_gray(ctx) &&
		pixmap->colorspace != fz_device_rgb(ctx) && pixmap->colorspace != fz_device_bgr(ctx))
	{
		fz_throw(ctx, FZ_ERROR_GENERIC, "pixmap must be grayscale or rgb to write as tga");
	}

	memset(head, 0, sizeof(head));
	head[2] = n == 4 ? 10 : 11;
	head[12] = pixmap->w & 0xFF; head[13] = (pixmap->w >> 8) & 0xFF;
	head[14] = pixmap->h & 0xFF; head[15] = (pixmap->h >> 8) & 0xFF;
	head[16] = d * 8;
	head[17] = pixmap->alpha && n > 1 ? 8 : 0;
	if (pixmap->alpha && d == 2)
		head[16] = 32;

	fz_write(ctx, out, head, sizeof(head));
	for (k = 1; k <= pixmap->h; k++)
	{
		int i, j;
		unsigned char *line = pixmap->samples + pixmap->w * n * (pixmap->h - k);
		for (i = 0, j = 1; i < pixmap->w; i += j, j = 1)
		{
			for (; i + j < pixmap->w && j < 128 && !memcmp(line + i * n, line + (i + j) * n, d); j++);
			if (j > 1)
			{
				fz_putc(ctx, out, j - 1 + 128);
				tga_put_pixel(ctx, out, line + i * n, d, is_bgr);
			}
			else
			{
				for (; i + j < pixmap->w && j <= 128 && memcmp(line + (i + j - 1) * n, line + (i + j) * n, d) != 0; j++);
				if (i + j < pixmap->w || j > 128)
					j--;
				fz_putc(ctx, out, j - 1);
				for (; j > 0; j--, i++)
					tga_put_pixel(ctx, out, line + i * n, d, is_bgr);
			}
		}
	}
	fz_write(ctx, out, "\0\0\0\0\0\0\0\0TRUEVISION-XFILE.\0", 26);
}
