#include "fitz.h"
#include "muxps.h"

#include <jpeglib.h>
#include <setjmp.h>

struct jpeg_error_mgr_jmp
{
	struct jpeg_error_mgr super;
	jmp_buf env;
	char msg[JMSG_LENGTH_MAX];
};

static void error_exit(j_common_ptr cinfo)
{
	struct jpeg_error_mgr_jmp *err = (struct jpeg_error_mgr_jmp *)cinfo->err;
	cinfo->err->format_message(cinfo, err->msg);
	longjmp(err->env, 1);
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
		src->next_input_byte += num_bytes;
		src->bytes_in_buffer -= num_bytes;
	}
}

int
xps_decode_jpeg(xps_context *ctx, byte *rbuf, int rlen, xps_image *image)
{
	struct jpeg_decompress_struct cinfo;
	struct jpeg_error_mgr_jmp err;
	struct jpeg_source_mgr src;
	unsigned char *buffer[1];

	if (setjmp(err.env))
	{
		if (image->samples)
			fz_free(image->samples);
		image->samples = NULL;
		return fz_throw("jpeg error: %s", err.msg);
	}

	cinfo.err = jpeg_std_error(&err.super);
	err.super.error_exit = error_exit;

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

	image->width = cinfo.output_width;
	image->height = cinfo.output_height;
	image->comps = cinfo.output_components;
	image->stride = cinfo.output_width * cinfo.output_components;
	image->bits = 8;
	image->samples = fz_calloc(image->height, image->stride);

	if (image->comps == 1)
		image->colorspace = fz_devicegray;
	if (image->comps == 3)
		image->colorspace = fz_devicergb;
	if (image->comps == 4)
		image->colorspace = fz_devicecmyk;

	if (cinfo.density_unit == 1)
	{
		image->xres = cinfo.X_density;
		image->yres = cinfo.Y_density;
	}
	else if (cinfo.density_unit == 2)
	{
		image->xres = cinfo.X_density * 2.54;
		image->yres = cinfo.Y_density * 2.54;
	}
	else
	{
		image->xres = 96;
		image->yres = 96;
	}

	memset(image->samples, 127, image->stride * image->height);

	buffer[0] = image->samples;
	while (cinfo.output_scanline < cinfo.output_height)
	{
		jpeg_read_scanlines(&cinfo, buffer, 1);
		buffer[0] += image->comps * image->width;
	}

	jpeg_finish_decompress(&cinfo);
	jpeg_destroy_decompress(&cinfo);

	return fz_okay;
}
