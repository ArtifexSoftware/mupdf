#include "mupdf/fitz.h"

#include <zlib.h>

struct fz_ps_output_context_s
{
	z_stream stream;
	int input_size;
	unsigned char *input;
	int output_size;
	unsigned char *output;
};

void
fz_write_ps_file_header(fz_context *ctx, fz_output *out)
{
	fz_printf(ctx, out,
		"%%!PS-Adobe-3.0\n"
		//"%%%%BoundingBox: 0 0 612 792\n"
		//"%%%%HiResBoundingBox: 0 0 612 792\n"
		"%%%%Creator: MuPDF\n"
		"%%%%LanguageLevel: 2\n"
		"%%%%CreationDate: D:20160318101706Z00'00'\n"
		"%%%%DocumentData: Binary\n"
		"%%%%Pages: (atend)\n"
		"%%%%EndComments\n"
		"\n"
		"%%%%BeginProlog\n"
		"%%%%EndProlog\n"
		"\n"
		"%%%%BeginSetup\n"
		"%%%%EndSetup\n"
		"\n"
		);
}

void fz_write_ps_file_trailer(fz_context *ctx, fz_output *out, int pages)
{
	fz_printf(ctx, out, "%%%%Trailer\n%%%%Pages: %d\n%%%%EOF\n", pages);
}

fz_ps_output_context *fz_write_ps_header(fz_context *ctx, fz_output *out, int w, int h, int n, int xres, int yres, int pagenum)
{
	int w_points = (w * 72 + (xres>>1)) / xres;
	int h_points = (h * 72 + (yres>>1)) / yres;
	float sx = w/(float)w_points;
	float sy = h/(float)h_points;
	fz_ps_output_context *psoc;
	int err;

	psoc = fz_malloc_struct(ctx, fz_ps_output_context);
	err = deflateInit(&psoc->stream, Z_DEFAULT_COMPRESSION);
	if (err != Z_OK)
	{
		fz_free(ctx, psoc);
		fz_throw(ctx, FZ_ERROR_GENERIC, "compression error %d", err);
	}

	fz_printf(ctx, out, "%%%%Page: %d %d\n", pagenum, pagenum);
	fz_printf(ctx, out, "%%%%PageBoundingBox: 0 0 %d %d\n", w_points, h_points);
	fz_printf(ctx, out, "%%%%BeginPageSetup\n");
	fz_printf(ctx, out, "<</PageSize [%d %d]>> setpagedevice\n", w_points, h_points);
	fz_printf(ctx, out, "%%%%EndPageSetup\n\n");
	fz_printf(ctx, out, "/DataFile currentfile /FlateDecode filter def\n\n");
	switch(n)
	{
	case 2:
		fz_printf(ctx, out, "/DeviceGray setcolorspace\n");
		break;
	case 4:
		fz_printf(ctx, out, "/DeviceRGB setcolorspace\n");
		break;
	case 5:
		fz_printf(ctx, out, "/DeviceCMYK setcolorspace\n");
		break;
	default:
		fz_throw(ctx, FZ_ERROR_GENERIC, "Unexpected colorspace for ps output");
	}
	fz_printf(ctx, out,
		"<<\n"
		"/ImageType 1\n"
		"/Width %d\n"
		"/Height %d\n"
		"/ImageMatrix [ %f 0 0 -%f 0 %d ]\n"
		"/MultipleDataSources false\n"
		"/DataSource DataFile\n"
		"/BitsPerComponent 8\n"
		//"/Decode [0 1]\n"
		"/Interpolate false\n"
		">>\n"
		"image\n"
		, w, h, sx, sy, h);

	return psoc;
}

void fz_write_ps_trailer(fz_context *ctx, fz_output *out, fz_ps_output_context *psoc)
{
	if (psoc)
	{
		int err;

		psoc->stream.next_in = NULL;
		psoc->stream.avail_in = 0;
		psoc->stream.next_out = (Bytef*)psoc->output;
		psoc->stream.avail_out = (uInt)psoc->output_size;

		err = deflate(&psoc->stream, Z_FINISH);
		if (err != Z_STREAM_END)
			fz_throw(ctx, FZ_ERROR_GENERIC, "compression error %d", err);

		fz_write(ctx, out, psoc->output, psoc->output_size - psoc->stream.avail_out);
		fz_free(ctx, psoc->input);
		fz_free(ctx, psoc->output);
		fz_free(ctx, psoc);
	}
	fz_printf(ctx, out, "\nshowpage\n%%%%PageTrailer\n%%%%EndPageTrailer\n\n");

}

void fz_write_pixmap_as_ps(fz_context *ctx, fz_output *out, const fz_pixmap *pixmap)
{
	fz_ps_output_context *psoc;

	fz_write_ps_file_header(ctx, out);

	psoc = fz_write_ps_header(ctx, out, pixmap->w, pixmap->h, pixmap->n, pixmap->xres, pixmap->yres, 1);

	fz_try(ctx)
	{
		fz_write_ps_band(ctx, out, psoc, pixmap->w, pixmap->h, pixmap->n, pixmap->stride, 0, 0, pixmap->samples);
	}
	fz_always(ctx)
	{
		fz_write_ps_trailer(ctx, out, psoc);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	fz_write_ps_file_trailer(ctx, out, 1);
}

void fz_save_pixmap_as_ps(fz_context *ctx, fz_pixmap *pixmap, char *filename, int append)
{
	fz_output *out = fz_new_output_with_path(ctx, filename, append);
	fz_try(ctx)
		fz_write_pixmap_as_ps(ctx, out, pixmap);
	fz_always(ctx)
		fz_drop_output(ctx, out);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void fz_write_ps_band(fz_context *ctx, fz_output *out, fz_ps_output_context *psoc, int w, int h, int n, int stride, int band_start, int bandheight, unsigned char *samples)
{
	int x, y, i, err;
	int required_input;
	int required_output;
	unsigned char *o;

	if (band_start+bandheight >= h)
		bandheight = h - band_start;

	required_input = w*(n-1)*bandheight;
	required_output = (int)deflateBound(&psoc->stream, required_input);

	if (psoc->input == NULL || psoc->input_size < required_input)
	{
		fz_free(ctx, psoc->input);
		psoc->input = NULL;
		psoc->input = fz_malloc(ctx, required_input);
		psoc->input_size = required_input;
	}

	if (psoc->output == NULL || psoc->output_size < required_output)
	{
		fz_free(ctx, psoc->output);
		psoc->output = NULL;
		psoc->output = fz_malloc(ctx, required_output);
		psoc->output_size = required_output;
	}

	o = psoc->input;
	for (y = 0; y < bandheight; y++)
	{
		for (x = 0; x < w; x++)
		{
			for (i = n-1; i > 0; i--)
				*o++ = *samples++;
			samples++;
		}
		samples += stride - w*n;
	}

	psoc->stream.next_in = (Bytef*)psoc->input;
	psoc->stream.avail_in = required_input;
	psoc->stream.next_out = (Bytef*)psoc->output;
	psoc->stream.avail_out = (uInt)psoc->output_size;

	err = deflate(&psoc->stream, Z_NO_FLUSH);
	if (err != Z_OK)
		fz_throw(ctx, FZ_ERROR_GENERIC, "compression error %d", err);

	fz_write(ctx, out, psoc->output, psoc->output_size - psoc->stream.avail_out);
}
