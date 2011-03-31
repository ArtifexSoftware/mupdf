#include "fitz.h"
#include "muxps.h"

#include <png.h>

struct xps_png_io_s
{
	byte *ptr;
	byte *lim;
};

static void
xps_png_read(png_structp png, png_bytep data, png_size_t length)
{
	struct xps_png_io_s *io = png_get_io_ptr(png);
	if (io->ptr + length > io->lim)
		png_error(png, "Read Error");
	memcpy(data, io->ptr, length);
	io->ptr += length;
}

static png_voidp
xps_png_malloc(png_structp png, png_size_t size)
{
	return fz_malloc(size);
}

static void
xps_png_free(png_structp png, png_voidp ptr)
{
	fz_free(ptr);
}

int
xps_decode_png(xps_image **imagep, xps_context *ctx, byte *rbuf, int rlen)
{
	png_structp png;
	png_infop info;
	struct xps_png_io_s io;
	int width, height, stride, premul;
	int npasses;
	int pass;
	int y;

	fz_pixmap *pixmap = NULL;
	xps_image *image = NULL;

	/*
	 * Set up PNG structs and input source
	 */

	io.ptr = rbuf;
	io.lim = rbuf + rlen;

	png = png_create_read_struct_2(PNG_LIBPNG_VER_STRING,
			NULL, NULL, NULL,
			ctx, xps_png_malloc, xps_png_free);
	if (!png)
		return fz_throw("png_create_read_struct");

	info = png_create_info_struct(png);
	if (!info)
		return fz_throw("png_create_info_struct");

	png_set_read_fn(png, &io, xps_png_read);
	png_set_crc_action(png, PNG_CRC_WARN_USE, PNG_CRC_WARN_USE);

	/*
	 * Jump to here on errors.
	 */

	if (setjmp(png_jmpbuf(png)))
	{
		if (pixmap)
			fz_droppixmap(pixmap);
		if (image)
			fz_free(image);
		png_destroy_read_struct(&png, &info, NULL);
		return fz_throw("cannot read png image");
	}

	/*
	 * Read PNG header
	 */

	png_read_info(png, info);

	if (png_get_interlace_type(png, info) == PNG_INTERLACE_ADAM7)
		npasses = png_set_interlace_handling(png);
	else
		npasses = 1;

	png_set_expand(png);
	png_set_packing(png);
	png_set_strip_16(png);

	premul = 0;
	if (png_get_color_type(png, info) == PNG_COLOR_TYPE_GRAY)
		png_set_add_alpha(png, 0xff, PNG_FILLER_AFTER);
	else if (png_get_color_type(png, info) == PNG_COLOR_TYPE_RGB)
		png_set_add_alpha(png, 0xff, PNG_FILLER_AFTER);
	else
		premul = 1;

	png_read_update_info(png, info);

	width = png_get_image_width(png, info);
	height = png_get_image_height(png, info);
	stride = png_get_rowbytes(png, info);

	switch (png_get_color_type(png, info))
	{
	case PNG_COLOR_TYPE_GRAY_ALPHA:
		pixmap = fz_newpixmap(fz_devicegray, 0, 0, width, height);
		break;
	case PNG_COLOR_TYPE_RGB_ALPHA:
		pixmap = fz_newpixmap(fz_devicergb, 0, 0, width, height);
		break;
	default:
		return fz_throw("cannot handle this png color type");
	}

	image = fz_malloc(sizeof(xps_image));
	image->pixmap = pixmap;
	image->xres = 96;
	image->yres = 96;

	/*
	 * Extract DPI, default to 96 dpi
	 */

	if (info->valid & PNG_INFO_pHYs)
	{
		png_uint_32 xres, yres;
		int unit;
		png_get_pHYs(png, info, &xres, &yres, &unit);
		if (unit == PNG_RESOLUTION_METER)
		{
			image->xres = xres * 0.0254 + 0.5;
			image->yres = yres * 0.0254 + 0.5;
		}
	}

	/*
	 * Read rows, filling transformed output into image buffer.
	 */

	for (pass = 0; pass < npasses; pass++)
		for (y = 0; y < height; y++)
			png_read_row(png, pixmap->samples + (y * stride), NULL);

	if (premul)
		fz_premultiplypixmap(pixmap);

	/*
	 * Clean up memory.
	 */

	png_destroy_read_struct(&png, &info, NULL);

	*imagep = image;
	return fz_okay;
}
