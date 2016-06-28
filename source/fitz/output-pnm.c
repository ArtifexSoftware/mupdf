#include "mupdf/fitz.h"

/*
 * Write pixmap to PNM file (without alpha channel)
 */

void
fz_write_pnm_header(fz_context *ctx, fz_output *out, int w, int h, int n, int alpha)
{
	n -= alpha;
	if (n != 1 && n != 3)
		fz_throw(ctx, FZ_ERROR_GENERIC, "pixmap must be grayscale or rgb to write as pnm");

	if (n == 1)
		fz_printf(ctx, out, "P5\n");
	if (n == 3)
		fz_printf(ctx, out, "P6\n");
	fz_printf(ctx, out, "%d %d\n", w, h);
	fz_printf(ctx, out, "255\n");
}

void
fz_write_pnm_band(fz_context *ctx, fz_output *out, int w, int h, int n, int alpha, int stride, int band_start, int bandheight, unsigned char *p)
{
	char buffer[2*3*4*5*6]; /* Buffer must be a multiple of 2 and 3 at least. */
	int len;
	int end = band_start + bandheight;

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
				fz_write(ctx, out, p, num_written);
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
				fz_write(ctx, out, buffer, num_written);
				break;
			}
			case 3:
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
				fz_write(ctx, out, buffer, num_written * 3);
				break;
			}
			}
			len -= num_written;
		}
		p += stride - w*n;
	}
}

void
fz_write_pixmap_as_pnm(fz_context *ctx, fz_output *out, fz_pixmap *pixmap)
{
	fz_write_pnm_header(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha);
	fz_write_pnm_band(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, pixmap->stride, 0, pixmap->h, pixmap->samples);
}

void
fz_save_pixmap_as_pnm(fz_context *ctx, fz_pixmap *pixmap, char *filename)
{
	fz_output *out = fz_new_output_with_path(ctx, filename, 0);
	fz_write_pnm_header(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha);
	fz_write_pnm_band(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, pixmap->stride, 0, pixmap->h, pixmap->samples);
	fz_drop_output(ctx, out);
}

/*
 * Write pixmap to PAM file (with or without alpha channel)
 */

void
fz_write_pam_header(fz_context *ctx, fz_output *out, int w, int h, int n, int alpha)
{
	fz_printf(ctx, out, "P7\n");
	fz_printf(ctx, out, "WIDTH %d\n", w);
	fz_printf(ctx, out, "HEIGHT %d\n", h);
	fz_printf(ctx, out, "DEPTH %d\n", n);
	fz_printf(ctx, out, "MAXVAL 255\n");

	n -= alpha;

	if (n == 0 && alpha) fz_printf(ctx, out, "TUPLTYPE GRAYSCALE\n");
	else if (n == 1 && !alpha) fz_printf(ctx, out, "TUPLTYPE GRAYSCALE\n");
	else if (n == 1 && alpha) fz_printf(ctx, out, "TUPLTYPE GRAYSCALE_ALPHA\n");
	else if (n == 3 && !alpha) fz_printf(ctx, out, "TUPLTYPE RGB\n");
	else if (n == 3 && alpha) fz_printf(ctx, out, "TUPLTYPE RGB_ALPHA\n");
	else if (n == 4 && !alpha) fz_printf(ctx, out, "TUPLTYPE CMYK\n");
	else if (n == 5) fz_printf(ctx, out, "TUPLTYPE CMYK_ALPHA\n");
	fz_printf(ctx, out, "ENDHDR\n");
}

void
fz_write_pam_band(fz_context *ctx, fz_output *out, int w, int h, int n, int alpha, int stride, int band_start, int bandheight, unsigned char *sp)
{
	int y;
	int end = band_start + bandheight;

	if (!out)
		return;

	if (end > h)
		end = h;
	end -= band_start;

	for (y = 0; y < end; y++)
	{
		fz_write(ctx, out, sp, w * n);
		sp += stride;
	}
}

void
fz_write_pixmap_as_pam(fz_context *ctx, fz_output *out, fz_pixmap *pixmap)
{
	fz_write_pam_header(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha);
	fz_write_pam_band(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, pixmap->stride, 0, pixmap->h, pixmap->samples);
}

void
fz_save_pixmap_as_pam(fz_context *ctx, fz_pixmap *pixmap, char *filename)
{
	fz_output *out = fz_new_output_with_path(ctx, filename, 0);
	fz_try(ctx)
	{
		fz_write_pam_header(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha);
		fz_write_pam_band(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, pixmap->stride, 0, pixmap->h, pixmap->samples);
	}
	fz_always(ctx)
		fz_drop_output(ctx, out);
	fz_catch(ctx)
		fz_rethrow(ctx);
}
