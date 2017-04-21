#include "mupdf/fitz.h"

#include <string.h>

/*
 * Write pixmap to TGA file (with or without alpha channel)
 */

typedef struct {
	fz_band_writer super;
	int is_bgr;
} tga_band_writer;

static inline void tga_put_pixel(fz_context *ctx, fz_output *out, const unsigned char *data, int n, int is_bgr)
{
	switch(n)
	{
	case 4: /* RGBA or BGRA */
		if (!is_bgr) {
			fz_write_byte(ctx, out, data[2]);
			fz_write_byte(ctx, out, data[1]);
			fz_write_byte(ctx, out, data[0]);
		} else {
			fz_write_byte(ctx, out, data[0]);
			fz_write_byte(ctx, out, data[1]);
			fz_write_byte(ctx, out, data[2]);
		}
		fz_write_byte(ctx, out, data[3]);
		break;
	case 3: /* RGB or BGR */
		if (!is_bgr) {
			fz_write_byte(ctx, out, data[2]);
			fz_write_byte(ctx, out, data[1]);
			fz_write_byte(ctx, out, data[0]);
		} else {
			fz_write_byte(ctx, out, data[0]);
			fz_write_byte(ctx, out, data[1]);
			fz_write_byte(ctx, out, data[2]);
		}
		break;
	case 2: /* GA */
		fz_write_byte(ctx, out, data[0]);
		fz_write_byte(ctx, out, data[0]);
		fz_write_byte(ctx, out, data[0]);
		fz_write_byte(ctx, out, data[1]);
		break;
	case 1: /* G */
		fz_write_byte(ctx, out, data[0]);
		break;
	}
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
	fz_band_writer *writer = fz_new_tga_band_writer(ctx, out, pixmap->colorspace == fz_device_bgr(ctx));

	fz_try(ctx)
	{
		fz_write_header(ctx, writer, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, pixmap->xres, pixmap->yres, 0);
		fz_write_band(ctx, writer, -pixmap->stride, pixmap->h, pixmap->samples + pixmap->stride * (pixmap->h-1));
	}
	fz_always(ctx)
		fz_drop_band_writer(ctx, writer);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void
tga_write_header(fz_context *ctx, fz_band_writer *writer_)
{
	tga_band_writer *writer = (tga_band_writer *)writer_;
	fz_output *out = writer->super.out;
	int w = writer->super.w;
	int h = writer->super.h;
	int n = writer->super.n;
	int alpha = writer->super.alpha;
	unsigned char head[18];
	int d = (alpha && n > 1) ? 4 : (n == 1 ? 1 : 3);

	if (n-alpha > 1 && n != 3+alpha)
		fz_throw(ctx, FZ_ERROR_GENERIC, "pixmap must be grayscale/rgb/rgba (with or without alpha) to write as tga");
	memset(head, 0, sizeof(head));
	head[2] = n > 1 ? 10 /* RGB or RGBA or GA */ : 11 /* G */;
	head[12] = w & 0xFF; head[13] = (w >> 8) & 0xFF;
	head[14] = h & 0xFF; head[15] = (h >> 8) & 0xFF;
	head[16] = d * 8; /* BPP */
	head[17] = alpha && n > 1 ? 8 : 0; /* Alpha bpp */

	fz_write_data(ctx, out, head, sizeof(head));
}

static void
tga_write_band(fz_context *ctx, fz_band_writer *writer_, int stride, int band_start, int band_height, const unsigned char *samples)
{
	tga_band_writer *writer = (tga_band_writer *)writer_;
	fz_output *out = writer->super.out;
	int w = writer->super.w;
	int h = writer->super.h;
	int n = writer->super.n;
	int d = (writer->super.alpha && n > 1) ? 4 : (n == 1 ? 1 : 3);
	int is_bgr = writer->is_bgr;
	int k;

	for (k = 0; k < h; k++)
	{
		int i, j;
		const unsigned char *line = samples + stride * k;
		for (i = 0, j = 1; i < w; i += j, j = 1)
		{
			for (; i + j < w && j < 128 && !memcmp(line + i * n, line + (i + j) * n, d); j++);
			if (j > 1)
			{
				fz_write_byte(ctx, out, j - 1 + 128);
				tga_put_pixel(ctx, out, line + i * n, n, is_bgr);
			}
			else
			{
				for (; i + j < w && j <= 128 && memcmp(line + (i + j - 1) * n, line + (i + j) * n, d) != 0; j++);
				if (i + j < w || j > 128)
					j--;
				fz_write_byte(ctx, out, j - 1);
				for (; j > 0; j--, i++)
					tga_put_pixel(ctx, out, line + i * n, n, is_bgr);
			}
		}
	}
}

static void
tga_write_trailer(fz_context *ctx, fz_band_writer *writer)
{
	fz_output *out = writer->out;

	fz_write_data(ctx, out, "\0\0\0\0\0\0\0\0TRUEVISION-XFILE.\0", 26);
}

fz_band_writer *fz_new_tga_band_writer(fz_context *ctx, fz_output *out, int is_bgr)
{
	tga_band_writer *writer = fz_new_band_writer(ctx, tga_band_writer, out);

	writer->super.header = tga_write_header;
	writer->super.band = tga_write_band;
	writer->super.trailer = tga_write_trailer;
	writer->is_bgr = is_bgr;

	return &writer->super;
}
