#include "mupdf/fitz.h"

#include <zlib.h>

#ifndef PATH_MAX
#define PATH_MAX (1024)
#endif

static inline void big32(unsigned char *buf, unsigned int v)
{
	buf[0] = (v >> 24) & 0xff;
	buf[1] = (v >> 16) & 0xff;
	buf[2] = (v >> 8) & 0xff;
	buf[3] = (v) & 0xff;
}

static void putchunk(fz_context *ctx, fz_output *out, char *tag, unsigned char *data, int size)
{
	unsigned int sum;
	fz_write_int32_be(ctx, out, size);
	fz_write(ctx, out, tag, 4);
	fz_write(ctx, out, data, size);
	sum = crc32(0, NULL, 0);
	sum = crc32(sum, (unsigned char*)tag, 4);
	sum = crc32(sum, data, size);
	fz_write_int32_be(ctx, out, sum);
}

void
fz_save_pixmap_as_png(fz_context *ctx, fz_pixmap *pixmap, const char *filename)
{
	fz_output *out = fz_new_output_with_path(ctx, filename, 0);
	fz_png_output_context *poc = NULL;

	fz_var(poc);

	fz_try(ctx)
	{
		poc = fz_write_png_header(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha);
		fz_write_png_band(ctx, out, poc, pixmap->stride, 0, pixmap->h, pixmap->samples);
	}
	fz_always(ctx)
	{
		fz_write_png_trailer(ctx, out, poc);
		fz_drop_output(ctx, out);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

void
fz_write_pixmap_as_png(fz_context *ctx, fz_output *out, const fz_pixmap *pixmap)
{
	fz_png_output_context *poc;

	if (!out)
		return;

	poc = fz_write_png_header(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->alpha);

	fz_try(ctx)
	{
		fz_write_png_band(ctx, out, poc, pixmap->stride, 0, pixmap->h, pixmap->samples);
	}
	fz_always(ctx)
	{
		fz_write_png_trailer(ctx, out, poc);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

struct fz_png_output_context_s
{
	unsigned char *udata;
	unsigned char *cdata;
	uLong usize, csize;
	z_stream stream;
	int w;
	int h;
	int n;
	int alpha;
};

fz_png_output_context *
fz_write_png_header(fz_context *ctx, fz_output *out, int w, int h, int n, int alpha)
{
	static const unsigned char pngsig[8] = { 137, 80, 78, 71, 13, 10, 26, 10 };
	unsigned char head[13];
	int color;
	fz_png_output_context *poc;

	if (!out)
		return NULL;

	/* Treat alpha only as greyscale */
	if (n == 1 && alpha)
		alpha = 0;

	switch (n - alpha)
	{
	case 1: color = (alpha ? 4 : 0); break; /* 0 = Greyscale, 4 = Greyscale + Alpha */
	case 3: color = (alpha ? 6 : 2); break; /* 2 = RGB, 6 = RGBA */
	default:
		fz_throw(ctx, FZ_ERROR_GENERIC, "pixmap must be grayscale or rgb to write as png");
	}

	poc = fz_malloc_struct(ctx, fz_png_output_context);
	poc->w = w;
	poc->h = h;
	poc->n = n;
	poc->alpha = alpha;

	big32(head+0, w);
	big32(head+4, h);
	head[8] = 8; /* depth */
	head[9] = color;
	head[10] = 0; /* compression */
	head[11] = 0; /* filter */
	head[12] = 0; /* interlace */

	fz_write(ctx, out, pngsig, 8);
	putchunk(ctx, out, "IHDR", head, 13);

	return poc;
}

void
fz_write_png_band(fz_context *ctx, fz_output *out, fz_png_output_context *poc, int stride, int band_start, int bandheight, unsigned char *sp)
{
	unsigned char *dp;
	int y, x, k, err, finalband;
	int w, h, n, alpha;

	if (!out || !sp || !poc)
		return;

	w = poc->w;
	h = poc->h;
	n = poc->n;
	alpha = poc->alpha;

	finalband = (band_start+bandheight >= h);
	if (finalband)
		bandheight = h - band_start;

	if (poc->udata == NULL)
	{
		poc->usize = (w * n + 1) * bandheight;
		/* Sadly the bound returned by compressBound is just for a
		 * single usize chunk; if you compress a sequence of them
		 * the buffering can result in you suddenly getting a block
		 * larger than compressBound outputted in one go, even if you
		 * take all the data out each time. */
		poc->csize = compressBound(poc->usize);
		fz_try(ctx)
		{
			poc->udata = fz_malloc(ctx, poc->usize);
			poc->cdata = fz_malloc(ctx, poc->csize);
		}
		fz_catch(ctx)
		{
			fz_free(ctx, poc->udata);
			poc->udata = NULL;
			poc->cdata = NULL;
			fz_rethrow(ctx);
		}
		err = deflateInit(&poc->stream, Z_DEFAULT_COMPRESSION);
		if (err != Z_OK)
			fz_throw(ctx, FZ_ERROR_GENERIC, "compression error %d", err);
	}

	dp = poc->udata;
	stride -= w*n;
	for (y = 0; y < bandheight; y++)
	{
		*dp++ = 1; /* sub prediction filter */
		for (x = 0; x < w; x++)
		{
			for (k = 0; k < n; k++)
			{
				if (x == 0)
					dp[k] = sp[k];
				else
					dp[k] = sp[k] - sp[k-n];
			}
			sp += n;
			dp += n;
		}
		sp += stride;
	}

	poc->stream.next_in = (Bytef*)poc->udata;
	poc->stream.avail_in = (uInt)(dp - poc->udata);
	do
	{
		poc->stream.next_out = poc->cdata;
		poc->stream.avail_out = (uInt)poc->csize;

		if (!finalband)
		{
			err = deflate(&poc->stream, Z_NO_FLUSH);
			if (err != Z_OK)
				fz_throw(ctx, FZ_ERROR_GENERIC, "compression error %d", err);
		}
		else
		{
			err = deflate(&poc->stream, Z_FINISH);
			if (err != Z_STREAM_END)
				fz_throw(ctx, FZ_ERROR_GENERIC, "compression error %d", err);
		}

		if (poc->stream.next_out != poc->cdata)
			putchunk(ctx, out, "IDAT", poc->cdata, poc->stream.next_out - poc->cdata);
	}
	while (poc->stream.avail_out == 0);
}

void
fz_write_png_trailer(fz_context *ctx, fz_output *out, fz_png_output_context *poc)
{
	unsigned char block[1];
	int err;

	if (!out || !poc)
		return;

	err = deflateEnd(&poc->stream);
	if (err != Z_OK)
		fz_throw(ctx, FZ_ERROR_GENERIC, "compression error %d", err);

	fz_free(ctx, poc->cdata);
	fz_free(ctx, poc->udata);
	fz_free(ctx, poc);

	putchunk(ctx, out, "IEND", block, 0);
}

/* We use an auxiliary function to do pixmap_as_png, as it can enable us to
 * drop pix early in the case where we have to convert, potentially saving
 * us having to have 2 copies of the pixmap and a buffer open at once. */
static fz_buffer *
png_from_pixmap(fz_context *ctx, fz_pixmap *pix, int drop)
{
	fz_buffer *buf = NULL;
	fz_output *out;
	fz_pixmap *pix2 = NULL;

	fz_var(buf);
	fz_var(out);
	fz_var(pix2);

	if (pix->w == 0 || pix->h == 0)
		return NULL;

	fz_try(ctx)
	{
		if (pix->colorspace && pix->colorspace != fz_device_gray(ctx) && pix->colorspace != fz_device_rgb(ctx))
		{
			pix2 = fz_new_pixmap(ctx, fz_device_rgb(ctx), pix->w, pix->h, pix->alpha);
			fz_convert_pixmap(ctx, pix2, pix);
			if (drop)
				fz_drop_pixmap(ctx, pix);
			pix = pix2;
		}
		buf = fz_new_buffer(ctx, 1024);
		out = fz_new_output_with_buffer(ctx, buf);
		fz_write_pixmap_as_png(ctx, out, pix);
	}
	fz_always(ctx)
	{
		fz_drop_pixmap(ctx, drop ? pix : pix2);
		fz_drop_output(ctx, out);
	}
	fz_catch(ctx)
	{
		fz_drop_buffer(ctx, buf);
		fz_rethrow(ctx);
	}
	return buf;
}

fz_buffer *
fz_new_buffer_from_image_as_png(fz_context *ctx, fz_image *image)
{
	return png_from_pixmap(ctx, fz_get_pixmap_from_image(ctx, image, NULL, NULL, NULL, NULL), 0);
}

fz_buffer *
fz_new_buffer_from_pixmap_as_png(fz_context *ctx, fz_pixmap *pix)
{
	return png_from_pixmap(ctx, pix, 0);
}

/* PNG output writer */

typedef struct fz_png_writer_s fz_png_writer;

struct fz_png_writer_s
{
	fz_document_writer super;
	fz_draw_options options;
	fz_pixmap *pixmap;
	int count;
	char *path;
};

const char *fz_png_write_options_usage = "";

static fz_device *
png_begin_page(fz_context *ctx, fz_document_writer *wri_, const fz_rect *mediabox)
{
	fz_png_writer *wri = (fz_png_writer*)wri_;
	return fz_new_draw_device_with_options(ctx, &wri->options, mediabox, &wri->pixmap);
}

static void
png_end_page(fz_context *ctx, fz_document_writer *wri_, fz_device *dev)
{
	fz_png_writer *wri = (fz_png_writer*)wri_;
	char path[PATH_MAX];

	fz_close_device(ctx, dev);
	fz_drop_device(ctx, dev);

	wri->count += 1;

	fz_format_output_path(ctx, path, sizeof path, wri->path, wri->count);
	fz_save_pixmap_as_png(ctx, wri->pixmap, path);
	fz_drop_pixmap(ctx, wri->pixmap);
	wri->pixmap = NULL;
}

static void
png_drop_writer(fz_context *ctx, fz_document_writer *wri_)
{
	fz_png_writer *wri = (fz_png_writer*)wri_;
	fz_drop_pixmap(ctx, wri->pixmap);
	fz_free(ctx, wri->path);
}

fz_document_writer *
fz_new_png_writer(fz_context *ctx, const char *path, const char *options)
{
	fz_png_writer *wri;

	wri = fz_malloc_struct(ctx, fz_png_writer);
	wri->super.begin_page = png_begin_page;
	wri->super.end_page = png_end_page;
	wri->super.drop_writer = png_drop_writer;

	fz_try(ctx)
	{
		fz_parse_draw_options(ctx, &wri->options, options);
		wri->path = fz_strdup(ctx, path ? path : "out-%04d.png");
	}
	fz_catch(ctx)
	{
		fz_free(ctx, wri);
		fz_rethrow(ctx);
	}

	return (fz_document_writer*)wri;
}
