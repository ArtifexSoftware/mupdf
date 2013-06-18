#include "mupdf/fitz.h"

#include <jpeglib.h>

static void error_exit(j_common_ptr cinfo)
{
	char msg[JMSG_LENGTH_MAX];
	fz_context *ctx = (fz_context *)cinfo->client_data;

	cinfo->err->format_message(cinfo, msg);
	fz_throw(ctx, FZ_ERROR_GENERIC, "jpeg error: %s", msg);
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

void
fz_load_jpeg_info(fz_context *ctx, unsigned char *rbuf, int rlen, int *xp, int *yp, int *xresp, int *yresp, fz_colorspace **cspacep)
{
	struct jpeg_decompress_struct cinfo;
	struct jpeg_error_mgr err;
	struct jpeg_source_mgr src;

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

		if (cinfo.num_components == 1)
			*cspacep = fz_device_gray(ctx);
		else if (cinfo.num_components == 3)
			*cspacep = fz_device_rgb(ctx);
		else if (cinfo.num_components == 4)
			*cspacep = fz_device_cmyk(ctx);
		else
			fz_throw(ctx, FZ_ERROR_GENERIC, "bad number of components in jpeg: %d", cinfo.num_components);

		*xp = cinfo.image_width;
		*yp = cinfo.image_height;

		if (cinfo.density_unit == 1)
		{
			*xresp = cinfo.X_density;
			*yresp = cinfo.Y_density;
		}
		else if (cinfo.density_unit == 2)
		{
			*xresp = cinfo.X_density * 254 / 100;
			*yresp = cinfo.Y_density * 254 / 100;
		}
		else
		{
			*xresp = 0;
			*yresp = 0;
		}

		if (*xresp <= 0) *xresp = 72;
		if (*yresp <= 0) *yresp = 72;
	}
	fz_always(ctx)
	{
		jpeg_destroy_decompress(&cinfo);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}
