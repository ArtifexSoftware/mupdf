#include "mupdf/fitz.h"

void
fz_save_pixmap_as_psd(fz_context *ctx, fz_pixmap *pixmap, const char *filename)
{
	fz_output *out = fz_new_output_with_path(ctx, filename, 0);
	fz_band_writer *writer = NULL;

	fz_var(writer);

	fz_try(ctx)
	{
		writer = fz_new_psd_band_writer(ctx, out);
		fz_write_header(ctx, writer, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, pixmap->xres, pixmap->yres, 0, pixmap->colorspace);
		fz_write_band(ctx, writer, pixmap->stride, pixmap->h, pixmap->samples);
	}
	fz_always(ctx)
	{
		fz_drop_band_writer(ctx, writer);
		fz_drop_output(ctx, out);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

void
fz_write_pixmap_as_psd(fz_context *ctx, fz_output *out, const fz_pixmap *pixmap)
{
	fz_band_writer *writer;

	if (!out)
		return;

	writer = fz_new_psd_band_writer(ctx, out);

	fz_try(ctx)
	{
		fz_write_header(ctx, writer, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, pixmap->xres, pixmap->yres, 0, pixmap->colorspace);
		fz_write_band(ctx, writer, pixmap->stride, pixmap->h, pixmap->samples);
	}
	fz_always(ctx)
	{
		fz_drop_band_writer(ctx, writer);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

typedef struct psd_band_writer_s
{
	fz_band_writer super;
} psd_band_writer;

static void
psd_write_header(fz_context *ctx, fz_band_writer *writer_, const fz_colorspace *cs)
{
	psd_band_writer *writer = (psd_band_writer *)(void *)writer_;
	fz_output *out = writer->super.out;
	int w = writer->super.w;
	int h = writer->super.h;
	int n = writer->super.n;
	int alpha = writer->super.alpha;
	static const char psdsig[12] = { '8', 'B', 'P', 'S', 0, 1, 0, 0, 0, 0, 0, 0 };
	static const char ressig[4] = { '8', 'B', 'I', 'M' };
	fz_buffer *buffer = fz_icc_data_from_icc_colorspace(ctx, cs);
	unsigned char *data;
	size_t size = fz_buffer_storage(ctx, buffer, &data);

	/* File Header Section */
	fz_write_data(ctx, out, psdsig, 12);
	fz_write_int16_be(ctx, out, n);
	fz_write_int32_be(ctx, out, h);
	fz_write_int32_be(ctx, out, w);
	fz_write_int16_be(ctx, out, 8); /* bits per channel */
	switch (n - alpha)
	{
	case 0:
	case 1:
		fz_write_int16_be(ctx, out, 1); /* Greyscale */
		break;
	case 3:
		fz_write_int16_be(ctx, out, 3); /* RGB */
		break;
	case 4:
		fz_write_int16_be(ctx, out, 4); /* CMYK */
		break;
	default:
		fz_write_int16_be(ctx, out, 7); /* Multichannel */
		break;
	}

	/* Color Mode Data Section - empty */
	fz_write_int32_be(ctx, out, 0);

	/* Image Resources Section */
	if (size == 0)
		fz_write_int32_be(ctx, out, 0);
	else
	{
		/* ICC Profile */
		fz_write_int32_be(ctx, out, 4+2+8+size+(size&1));
		/* Image Resource block */
		fz_write_data(ctx, out, ressig, 4);
		fz_write_int16_be(ctx, out, 0x40f); /* ICC Profile */
		fz_write_data(ctx, out, "\0Profile", 8); /* Profile name (must be even!) */
		fz_write_data(ctx, out, data, size); /* Actual data */
		if (size & 1)
			fz_write_byte(ctx, out, 0); /* Pad to even */
	}

	/* Layer and Mask Information Section */
	fz_write_int32_be(ctx, out, 0);

	/* Image Data Section */
	fz_write_int16_be(ctx, out, 0); /* Raw image data */
}

static void
psd_write_band(fz_context *ctx, fz_band_writer *writer_, int stride, int band_start, int band_height, const unsigned char *sp)
{
	psd_band_writer *writer = (psd_band_writer *)(void *)writer_;
	fz_output *out = writer->super.out;
	int y, x, k, finalband;
	int w, h, n;
	unsigned char buffer[256];
	unsigned char *buffer_end = &buffer[sizeof(buffer)];
	unsigned char *b;
	int plane_inc;
	int line_skip;

	if (!out)
		return;

	w = writer->super.w;
	h = writer->super.h;
	n = writer->super.n;

	finalband = (band_start+band_height >= h);
	if (finalband)
		band_height = h - band_start;

	plane_inc = w * (h - band_height);
	line_skip = stride - w*n;
	b = buffer;
	for (k = 0; k < n; k++)
	{
		for (y = 0; y < band_height; y++)
		{
			for (x = 0; x < w; x++)
			{
				*b++ = *sp;
				sp += n;
				if (b == buffer_end)
				{
					fz_write_data(ctx, out, buffer, sizeof(buffer));
					b = buffer;
				}
			}
			sp += line_skip;
		}
		sp -= stride * band_height - 1;
		if (b != buffer)
		{
			fz_write_data(ctx, out, buffer, b - buffer);
			b = buffer;
		}
		fz_seek_output(ctx, out, plane_inc, FZ_SEEK_CUR);
	}
	fz_seek_output(ctx, out, w * h * (1-n), FZ_SEEK_CUR);
}

static void
psd_write_trailer(fz_context *ctx, fz_band_writer *writer_)
{
	psd_band_writer *writer = (psd_band_writer *)(void *)writer_;
	fz_output *out = writer->super.out;

	(void)out;
	(void)writer;
}

static void
psd_drop_band_writer(fz_context *ctx, fz_band_writer *writer_)
{
	psd_band_writer *writer = (psd_band_writer *)(void *)writer_;

	(void)writer;
}

fz_band_writer *fz_new_psd_band_writer(fz_context *ctx, fz_output *out)
{
	psd_band_writer *writer = fz_new_band_writer(ctx, psd_band_writer, out);

	writer->super.header = psd_write_header;
	writer->super.band = psd_write_band;
	writer->super.trailer = psd_write_trailer;
	writer->super.drop = psd_drop_band_writer;

	return &writer->super;
}
