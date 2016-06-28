#ifndef MUPDF_FITZ_OUTPUT_PNG_H
#define MUPDF_FITZ_OUTPUT_PNG_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/pixmap.h"
#include "mupdf/fitz/bitmap.h"

#include "mupdf/fitz/buffer.h"
#include "mupdf/fitz/image.h"

/*
	fz_save_pixmap_as_png: Save a pixmap as a PNG image file.
*/
void fz_save_pixmap_as_png(fz_context *ctx, fz_pixmap *pixmap, const char *filename);

/*
	Write a pixmap to an output stream in PNG format.
*/
void fz_write_pixmap_as_png(fz_context *ctx, fz_output *out, const fz_pixmap *pixmap);

typedef struct fz_png_output_context_s fz_png_output_context;

fz_png_output_context *fz_write_png_header(fz_context *ctx, fz_output *out, int w, int h, int n, int alpha);
void fz_write_png_band(fz_context *ctx, fz_output *out, fz_png_output_context *poc, int stride, int band_start, int bandheight, unsigned char *samples);
void fz_write_png_trailer(fz_context *ctx, fz_output *out, fz_png_output_context *poc);

/*
	Create a new buffer containing the image/pixmap in PNG format.
*/
fz_buffer *fz_new_buffer_from_image_as_png(fz_context *ctx, fz_image *image);
fz_buffer *fz_new_buffer_from_pixmap_as_png(fz_context *ctx, fz_pixmap *pixmap);

#endif
