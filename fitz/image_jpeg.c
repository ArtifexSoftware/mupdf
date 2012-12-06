#include "fitz-internal.h"

#include <jpeglib.h>
#include <setjmp.h>

static void error_exit(j_common_ptr cinfo)
{
	char msg[JMSG_LENGTH_MAX];
	fz_context *ctx = (fz_context *)cinfo->client_data;

	cinfo->err->format_message(cinfo, msg);
	fz_throw(ctx, "jpeg error: %s", msg);
}

static void init_source(j_decompress_ptr cinfo)
{
	/* nothing to do */
}

static void term_source(j_decompress_ptr cinfo)
{
	/* nothing to do */
}

static boolean fill_input_buffer(j_decompress_ptr cinfo)
{
	static unsigned char eoi[2] = { 0xFF, JPEG_EOI };
	struct jpeg_source_mgr *src = cinfo->src;
	src->next_input_byte = eoi;
	src->bytes_in_buffer = 2;
	return 1;
}

static void skip_input_data(j_decompress_ptr cinfo, long num_bytes)
{
	struct jpeg_source_mgr *src = cinfo->src;
	if (num_bytes > 0)
	{
		size_t skip = (size_t)num_bytes; /* size_t may be 64bit */
		if (skip > src->bytes_in_buffer)
			skip = (size_t)src->bytes_in_buffer;
		src->next_input_byte += skip;
		src->bytes_in_buffer -= skip;
	}
}

fz_pixmap *
fz_load_jpeg(fz_context *ctx, unsigned char *rbuf, int rlen)
{
	struct jpeg_decompress_struct cinfo;
	struct jpeg_error_mgr err;
	struct jpeg_source_mgr src;
	unsigned char *row[1], *sp, *dp;
	fz_colorspace *colorspace;
	unsigned int x;
	int k;
	fz_pixmap *image = NULL;

	fz_var(image);
	fz_var(row);

	row[0] = NULL;

	fz_try(ctx)
	{
		cinfo.client_data = ctx;
		cinfo.err = jpeg_std_error(&err);
		err.error_exit = error_exit;

		jpeg_create_decompress(&cinfo);

		cinfo.src = &src;
		src.init_source = init_source;
		src.fill_input_buffer = fill_input_buffer;
		src.skip_input_data = skip_input_data;
		src.resync_to_restart = jpeg_resync_to_restart;
		src.term_source = term_source;
		src.next_input_byte = rbuf;
		src.bytes_in_buffer = rlen;

		jpeg_read_header(&cinfo, 1);

		jpeg_start_decompress(&cinfo);

		if (cinfo.output_components == 1)
			colorspace = fz_device_gray;
		else if (cinfo.output_components == 3)
			colorspace = fz_device_rgb;
		else if (cinfo.output_components == 4)
			colorspace = fz_device_cmyk;
		else
			fz_throw(ctx, "bad number of components in jpeg: %d", cinfo.output_components);

		image = fz_new_pixmap(ctx, colorspace, cinfo.output_width, cinfo.output_height);

		if (cinfo.density_unit == 1)
		{
			image->xres = cinfo.X_density;
			image->yres = cinfo.Y_density;
		}
		else if (cinfo.density_unit == 2)
		{
			image->xres = cinfo.X_density * 254 / 100;
			image->yres = cinfo.Y_density * 254 / 100;
		}

		if (image->xres <= 0) image->xres = 72;
		if (image->yres <= 0) image->yres = 72;

		fz_clear_pixmap(ctx, image);

		row[0] = fz_malloc(ctx, cinfo.output_components * cinfo.output_width);
		dp = image->samples;
		while (cinfo.output_scanline < cinfo.output_height)
		{
			jpeg_read_scanlines(&cinfo, row, 1);
			sp = row[0];
			for (x = 0; x < cinfo.output_width; x++)
			{
				for (k = 0; k < cinfo.output_components; k++)
					*dp++ = *sp++;
				*dp++ = 255;
			}
		}
	}
	fz_always(ctx)
	{
		fz_free(ctx, row[0]);
		row[0] = NULL;
		fz_try(ctx)
		{
			/* Annoyingly, jpeg_finish_decompress can throw */
			jpeg_finish_decompress(&cinfo);
		}
		fz_catch(ctx)
		{
			/* Ignore any errors here */
		}
		jpeg_destroy_decompress(&cinfo);
	}
	fz_catch(ctx)
	{
		fz_drop_pixmap(ctx, image);
		fz_rethrow(ctx);
	}

	return image;
}
