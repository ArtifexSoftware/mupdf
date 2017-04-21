#include "mupdf/fitz.h"

#include <assert.h>
#include <string.h>

typedef struct {
	fz_band_writer super;
	fz_pwg_options pwg;
} pwg_band_writer;

void
fz_write_pwg_file_header(fz_context *ctx, fz_output *out)
{
	static const unsigned char pwgsig[4] = { 'R', 'a', 'S', '2' };

	/* Sync word */
	fz_write_data(ctx, out, pwgsig, 4);
}

static void
pwg_page_header(fz_context *ctx, fz_output *out, const fz_pwg_options *pwg,
		int xres, int yres, int w, int h, int bpp)
{
	static const char zero[64] = { 0 };
	int i;

	/* Page Header: */
	fz_write_data(ctx, out, pwg ? pwg->media_class : zero, 64);
	fz_write_data(ctx, out, pwg ? pwg->media_color : zero, 64);
	fz_write_data(ctx, out, pwg ? pwg->media_type : zero, 64);
	fz_write_data(ctx, out, pwg ? pwg->output_type : zero, 64);
	fz_write_int32_be(ctx, out, pwg ? pwg->advance_distance : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->advance_media : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->collate : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->cut_media : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->duplex : 0);
	fz_write_int32_be(ctx, out, xres);
	fz_write_int32_be(ctx, out, yres);
	/* CUPS format says that 284->300 are supposed to be the bbox of the
	 * page in points. PWG says 'Reserved'. */
	for (i=284; i < 300; i += 4)
		fz_write_data(ctx, out, zero, 4);
	fz_write_int32_be(ctx, out, pwg ? pwg->insert_sheet : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->jog : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->leading_edge : 0);
	/* CUPS format says that 312->320 are supposed to be the margins of
	 * the lower left hand edge of page in points. PWG says 'Reserved'. */
	for (i=312; i < 320; i += 4)
		fz_write_data(ctx, out, zero, 4);
	fz_write_int32_be(ctx, out, pwg ? pwg->manual_feed : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->media_position : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->media_weight : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->mirror_print : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->negative_print : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->num_copies : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->orientation : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->output_face_up : 0);
	fz_write_int32_be(ctx, out, w * 72/ xres);	/* Page size in points */
	fz_write_int32_be(ctx, out, h * 72/ yres);
	fz_write_int32_be(ctx, out, pwg ? pwg->separations : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->tray_switch : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->tumble : 0);
	fz_write_int32_be(ctx, out, w); /* Page image in pixels */
	fz_write_int32_be(ctx, out, h);
	fz_write_int32_be(ctx, out, pwg ? pwg->media_type_num : 0);
	fz_write_int32_be(ctx, out, bpp < 8 ? 1 : 8); /* Bits per color */
	fz_write_int32_be(ctx, out, bpp); /* Bits per pixel */
	fz_write_int32_be(ctx, out, (w * bpp + 7)/8); /* Bytes per line */
	fz_write_int32_be(ctx, out, 0); /* Chunky pixels */
	switch (bpp)
	{
	case 1: fz_write_int32_be(ctx, out, 3); /* Black */ break;
	case 8: fz_write_int32_be(ctx, out, 18); /* Sgray */ break;
	case 24: fz_write_int32_be(ctx, out, 19); /* Srgb */ break;
	case 32: fz_write_int32_be(ctx, out, 6); /* Cmyk */ break;
	default: fz_throw(ctx, FZ_ERROR_GENERIC, "pixmap bpp must be 1, 8, 24 or 32 to write as pwg");
	}
	fz_write_int32_be(ctx, out, pwg ? pwg->compression : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->row_count : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->row_feed : 0);
	fz_write_int32_be(ctx, out, pwg ? pwg->row_step : 0);
	fz_write_int32_be(ctx, out, bpp <= 8 ? 1 : (bpp>>8)); /* Num Colors */
	for (i=424; i < 452; i += 4)
		fz_write_data(ctx, out, zero, 4);
	fz_write_int32_be(ctx, out, 1); /* TotalPageCount */
	fz_write_int32_be(ctx, out, 1); /* CrossFeedTransform */
	fz_write_int32_be(ctx, out, 1); /* FeedTransform */
	fz_write_int32_be(ctx, out, 0); /* ImageBoxLeft */
	fz_write_int32_be(ctx, out, 0); /* ImageBoxTop */
	fz_write_int32_be(ctx, out, w); /* ImageBoxRight */
	fz_write_int32_be(ctx, out, h); /* ImageBoxBottom */
	for (i=480; i < 1668; i += 4)
		fz_write_data(ctx, out, zero, 4);
	fz_write_data(ctx, out, pwg ? pwg->rendering_intent : zero, 64);
	fz_write_data(ctx, out, pwg ? pwg->page_size_name : zero, 64);
}

void
fz_write_pixmap_as_pwg_page(fz_context *ctx, fz_output *out, const fz_pixmap *pixmap, const fz_pwg_options *pwg)
{
	fz_band_writer *writer = fz_new_pwg_band_writer(ctx, out, pwg);

	fz_try(ctx)
	{
		fz_write_header(ctx, writer, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha, pixmap->xres, pixmap->yres, 0);
		fz_write_band(ctx, writer, pixmap->stride, pixmap->h, pixmap->samples);
	}
	fz_always(ctx)
		fz_drop_band_writer(ctx, writer);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void
fz_write_bitmap_as_pwg_page(fz_context *ctx, fz_output *out, const fz_bitmap *bitmap, const fz_pwg_options *pwg)
{
	fz_band_writer *writer = fz_new_mono_pwg_band_writer(ctx, out, pwg);

	fz_try(ctx)
	{
		fz_write_header(ctx, writer, bitmap->w, bitmap->h, bitmap->n, 0, bitmap->xres, bitmap->yres, 0);
		fz_write_band(ctx, writer, bitmap->stride, bitmap->h, bitmap->samples);
	}
	fz_always(ctx)
		fz_drop_band_writer(ctx, writer);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void
fz_write_pixmap_as_pwg(fz_context *ctx, fz_output *out, const fz_pixmap *pixmap, const fz_pwg_options *pwg)
{
	fz_write_pwg_file_header(ctx, out);
	fz_write_pixmap_as_pwg_page(ctx, out, pixmap, pwg);
}

void
fz_write_bitmap_as_pwg(fz_context *ctx, fz_output *out, const fz_bitmap *bitmap, const fz_pwg_options *pwg)
{
	fz_write_pwg_file_header(ctx, out);
	fz_write_bitmap_as_pwg_page(ctx, out, bitmap, pwg);
}

void
fz_save_pixmap_as_pwg(fz_context *ctx, fz_pixmap *pixmap, char *filename, int append, const fz_pwg_options *pwg)
{
	fz_output *out = fz_new_output_with_path(ctx, filename, append);
	fz_try(ctx)
	{
		if (!append)
			fz_write_pwg_file_header(ctx, out);
		fz_write_pixmap_as_pwg_page(ctx, out, pixmap, pwg);
	}
	fz_always(ctx)
		fz_drop_output(ctx, out);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void
fz_save_bitmap_as_pwg(fz_context *ctx, fz_bitmap *bitmap, char *filename, int append, const fz_pwg_options *pwg)
{
	fz_output *out = fz_new_output_with_path(ctx, filename, append);
	fz_try(ctx)
	{
		if (!append)
			fz_write_pwg_file_header(ctx, out);
		fz_write_bitmap_as_pwg_page(ctx, out, bitmap, pwg);
	}
	fz_always(ctx)
		fz_drop_output(ctx, out);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void
pwg_write_mono_header(fz_context *ctx, fz_band_writer *writer_)
{
	pwg_band_writer *writer = (pwg_band_writer *)writer_;

	pwg_page_header(ctx, writer->super.out, &writer->pwg,
		writer->super.xres, writer->super.yres, writer->super.w, writer->super.h, 1);
}

static void
pwg_write_mono_band(fz_context *ctx, fz_band_writer *writer_, int stride, int band_start, int band_height, const unsigned char *samples)
{
	pwg_band_writer *writer = (pwg_band_writer *)writer_;
	fz_output *out = writer->super.out;
	int w = writer->super.w;
	int h = writer->super.h;
	const unsigned char *sp;
	int y, x;
	int byte_width;

	/* Now output the actual bitmap, using a packbits like compression */
	sp = samples;
	byte_width = (w+7)/8;
	y = 0;
	while (y < band_height)
	{
		int yrep;

		assert(sp == samples + y * stride);

		/* Count the number of times this line is repeated */
		for (yrep = 1; yrep < 256 && y+yrep < h; yrep++)
		{
			if (memcmp(sp, sp + yrep * stride, byte_width) != 0)
				break;
		}
		fz_write_byte(ctx, out, yrep-1);

		/* Encode the line */
		x = 0;
		while (x < byte_width)
		{
			int d;

			assert(sp == samples + y * stride + x);

			/* How far do we have to look to find a repeated value? */
			for (d = 1; d < 128 && x+d < byte_width; d++)
			{
				if (sp[d-1] == sp[d])
					break;
			}
			if (d == 1)
			{
				int xrep;

				/* We immediately have a repeat (or we've hit
				 * the end of the line). Count the number of
				 * times this value is repeated. */
				for (xrep = 1; xrep < 128 && x+xrep < byte_width; xrep++)
				{
					if (sp[0] != sp[xrep])
						break;
				}
				fz_write_byte(ctx, out, xrep-1);
				fz_write_data(ctx, out, sp, 1);
				sp += xrep;
				x += xrep;
			}
			else
			{
				fz_write_byte(ctx, out, 257-d);
				fz_write_data(ctx, out, sp, d);
				sp += d;
				x += d;
			}
		}

		/* Move to the next line */
		sp += stride*yrep - byte_width;
		y += yrep;
	}
}

fz_band_writer *fz_new_mono_pwg_band_writer(fz_context *ctx, fz_output *out, const fz_pwg_options *pwg)
{
	pwg_band_writer *writer = fz_new_band_writer(ctx, pwg_band_writer, out);

	writer->super.header = pwg_write_mono_header;
	writer->super.band = pwg_write_mono_band;
	if (pwg)
		writer->pwg = *pwg;
	else
		memset(&writer->pwg, 0, sizeof(writer->pwg));

	return &writer->super;
}

static void
pwg_write_header(fz_context *ctx, fz_band_writer *writer_)
{
	pwg_band_writer *writer = (pwg_band_writer *)writer_;
	int n = writer->super.n;

	if (writer->super.alpha != 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "PWG band writer cannot cope with alpha");
	if (n != 1 && n != 3 && n != 4)
		fz_throw(ctx, FZ_ERROR_GENERIC, "pixmap must be grayscale, rgb or cmyk to write as pwg");

	pwg_page_header(ctx, writer->super.out, &writer->pwg,
			writer->super.xres, writer->super.yres, writer->super.w, writer->super.h, n*8);
}

static void
pwg_write_band(fz_context *ctx, fz_band_writer *writer_, int stride, int band_start, int band_height, const unsigned char *samples)
{
	pwg_band_writer *writer = (pwg_band_writer *)writer_;
	fz_output *out = writer->super.out;
	int w = writer->super.w;
	int h = writer->super.h;
	const unsigned char *sp = samples;
	int n = writer->super.n;
	int ss = w * n;
	int y, x;

	/* Now output the actual bitmap, using a packbits like compression */
	y = 0;
	while (y < h)
	{
		int yrep;

		assert(sp == samples + y * stride);

		/* Count the number of times this line is repeated */
		for (yrep = 1; yrep < 256 && y+yrep < h; yrep++)
		{
			if (memcmp(sp, sp + yrep * stride, ss) != 0)
				break;
		}
		fz_write_byte(ctx, out, yrep-1);

		/* Encode the line */
		x = 0;
		while (x < w)
		{
			int d;

			assert(sp == samples + y * stride + x * n);

			/* How far do we have to look to find a repeated value? */
			for (d = 1; d < 128 && x+d < w; d++)
			{
				if (memcmp(sp + (d-1)*n, sp + d*n, n) == 0)
					break;
			}
			if (d == 1)
			{
				int xrep;

				/* We immediately have a repeat (or we've hit
				 * the end of the line). Count the number of
				 * times this value is repeated. */
				for (xrep = 1; xrep < 128 && x+xrep < w; xrep++)
				{
					if (memcmp(sp, sp + xrep*n, n) != 0)
						break;
				}
				fz_write_byte(ctx, out, xrep-1);
				fz_write_data(ctx, out, sp, n);
				sp += n*xrep;
				x += xrep;
			}
			else
			{
				fz_write_byte(ctx, out, 257-d);
				x += d;
				while (d > 0)
				{
					fz_write_data(ctx, out, sp, n);
					sp += n;
					d--;
				}
			}
		}

		/* Move to the next line */
		sp += stride*(yrep-1);
		y += yrep;
	}
}

fz_band_writer *fz_new_pwg_band_writer(fz_context *ctx, fz_output *out, const fz_pwg_options *pwg)
{
	pwg_band_writer *writer = fz_new_band_writer(ctx, pwg_band_writer, out);

	writer->super.header = pwg_write_header;
	writer->super.band = pwg_write_band;
	if (pwg)
		writer->pwg = *pwg;
	else
		memset(&writer->pwg, 0, sizeof(writer->pwg));

	return &writer->super;
}
