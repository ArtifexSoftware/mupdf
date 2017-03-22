#include "mupdf/fitz.h"

/*
 * Write pixmap to PNM file (without alpha channel)
 */
static void
pnm_write_header(fz_context *ctx, fz_band_writer *writer)
{
	fz_output *out = writer->out;
	int w = writer->w;
	int h = writer->h;
	int n = writer->n;
	int alpha = writer->alpha;

	n -= alpha;
	if (n != 1 && n != 3)
		fz_throw(ctx, FZ_ERROR_GENERIC, "pixmap must be grayscale or rgb to write as pnm");

	if (n == 1)
		fz_write_printf(ctx, out, "P5\n");
	if (n == 3)
		fz_write_printf(ctx, out, "P6\n");
	fz_write_printf(ctx, out, "%d %d\n", w, h);
	fz_write_printf(ctx, out, "255\n");
}

static void
pnm_write_band(fz_context *ctx, fz_band_writer *writer, int stride, int band_start, int band_height, const unsigned char *p)
{
	fz_output *out = writer->out;
	int w = writer->w;
	int h = writer->h;
	int n = writer->n;
	int alpha = writer->alpha;
	char buffer[2*3*4*5*6]; /* Buffer must be a multiple of 2 and 3 at least. */
	int len;
	int end = band_start + band_height;

	if (n-alpha != 1 && n-alpha != 3)
		fz_throw(ctx, FZ_ERROR_GENERIC, "pixmap must be grayscale or rgb to write as pnm");

	if (!out)
		return;

	if (end > h)
		end = h;
	end -= band_start;

	/* Tests show that writing single bytes out at a time
	 * is appallingly slow. We get a huge improvement
	 * by collating stuff into buffers first. */

	while (end--)
	{
		len = w;
		while (len)
		{
			int num_written = len;

			switch (n)
			{
			case 1:
				/* No collation required */
				fz_write_data(ctx, out, p, num_written);
				p += num_written;
				break;
			case 2:
			{
				char *o = buffer;
				int count;

				if (num_written > sizeof(buffer))
					num_written = sizeof(buffer);

				for (count = num_written; count; count--)
				{
					*o++ = *p;
					p += 2;
				}
				fz_write_data(ctx, out, buffer, num_written);
				break;
			}
			case 3:
				fz_write_data(ctx, out, p, num_written*3);
				p += num_written*3;
				break;
			case 4:
			{
				char *o = buffer;
				int count;

				if (num_written > sizeof(buffer)/3)
					num_written = sizeof(buffer)/3;

				for (count = num_written; count; count--)
				{
					*o++ = p[0];
					*o++ = p[1];
					*o++ = p[2];
					p += n;
				}
				fz_write_data(ctx, out, buffer, num_written * 3);
				break;
			}
			}
			len -= num_written;
		}
		p += stride - w*n;
	}
}

fz_band_writer *fz_new_pnm_band_writer(fz_context *ctx, fz_output *out)
{
	fz_band_writer *writer = fz_new_band_writer(ctx, fz_band_writer, out);

	writer->header = pnm_write_header;
	writer->band = pnm_write_band;

	return writer;
}

void
fz_write_pixmap_as_pnm(fz_context *ctx, fz_output *out, fz_pixmap *pixmap)
{
	fz_band_writer *writer = fz_new_pnm_band_writer(ctx, out);
	fz_write_header(ctx, writer, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, 0, 0, 0);
	fz_write_band(ctx, writer, pixmap->stride, pixmap->h, pixmap->samples);
	fz_drop_band_writer(ctx, writer);
}

void
fz_save_pixmap_as_pnm(fz_context *ctx, fz_pixmap *pixmap, const char *filename)
{
	fz_band_writer *writer = NULL;
	fz_output *out = fz_new_output_with_path(ctx, filename, 0);

	fz_var(writer);

	fz_try(ctx)
	{
		writer = fz_new_pnm_band_writer(ctx, out);
		fz_write_header(ctx, writer, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, 0, 0, 0);
		fz_write_band(ctx, writer, pixmap->stride, pixmap->h, pixmap->samples);
	}
	fz_always(ctx)
	{
		fz_drop_band_writer(ctx, writer);
		fz_drop_output(ctx, out);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);
}

/*
 * Write pixmap to PAM file (with or without alpha channel)
 */

static void
pam_write_header(fz_context *ctx, fz_band_writer *writer)
{
	fz_output *out = writer->out;
	int w = writer->w;
	int h = writer->h;
	int n = writer->n;
	int alpha = writer->alpha;

	fz_write_printf(ctx, out, "P7\n");
	fz_write_printf(ctx, out, "WIDTH %d\n", w);
	fz_write_printf(ctx, out, "HEIGHT %d\n", h);
	fz_write_printf(ctx, out, "DEPTH %d\n", n);
	fz_write_printf(ctx, out, "MAXVAL 255\n");

	n -= alpha;

	if (n == 0 && alpha) fz_write_printf(ctx, out, "TUPLTYPE GRAYSCALE\n");
	else if (n == 1 && !alpha) fz_write_printf(ctx, out, "TUPLTYPE GRAYSCALE\n");
	else if (n == 1 && alpha) fz_write_printf(ctx, out, "TUPLTYPE GRAYSCALE_ALPHA\n");
	else if (n == 3 && !alpha) fz_write_printf(ctx, out, "TUPLTYPE RGB\n");
	else if (n == 3 && alpha) fz_write_printf(ctx, out, "TUPLTYPE RGB_ALPHA\n");
	else if (n == 4 && !alpha) fz_write_printf(ctx, out, "TUPLTYPE CMYK\n");
	else if (n == 5) fz_write_printf(ctx, out, "TUPLTYPE CMYK_ALPHA\n");
	fz_write_printf(ctx, out, "ENDHDR\n");
}

static void
pam_write_band(fz_context *ctx, fz_band_writer *writer, int stride, int band_start, int band_height, const unsigned char *sp)
{
	fz_output *out = writer->out;
	int w = writer->w;
	int h = writer->h;
	int n = writer->n;
	int y;
	int end = band_start + band_height;

	if (!out)
		return;

	if (end > h)
		end = h;
	end -= band_start;

	for (y = 0; y < end; y++)
	{
		fz_write_data(ctx, out, sp, w * n);
		sp += stride;
	}
}

fz_band_writer *fz_new_pam_band_writer(fz_context *ctx, fz_output *out)
{
	fz_band_writer *writer = fz_new_band_writer(ctx, fz_band_writer, out);

	writer->header = pam_write_header;
	writer->band = pam_write_band;

	return writer;
}

void
fz_write_pixmap_as_pam(fz_context *ctx, fz_output *out, fz_pixmap *pixmap)
{
	fz_band_writer *writer = fz_new_pam_band_writer(ctx, out);
	fz_write_header(ctx, writer, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, 0, 0, 0);
	fz_write_band(ctx, writer, pixmap->stride, pixmap->h, pixmap->samples);
	fz_drop_band_writer(ctx, writer);
}

void
fz_save_pixmap_as_pam(fz_context *ctx, fz_pixmap *pixmap, const char *filename)
{
	fz_band_writer *writer = NULL;
	fz_output *out = fz_new_output_with_path(ctx, filename, 0);

	fz_var(writer);

	fz_try(ctx)
	{
		writer = fz_new_pam_band_writer(ctx, out);
		fz_write_header(ctx, writer, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, 0, 0, 0);
		fz_write_band(ctx, writer, pixmap->stride, pixmap->h, pixmap->samples);
	}
	fz_always(ctx)
	{
		fz_drop_band_writer(ctx, writer);
		fz_drop_output(ctx, out);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);
}
