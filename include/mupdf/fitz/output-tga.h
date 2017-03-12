#ifndef MUPDF_FITZ_OUTPUT_TGA_H
#define MUPDF_FITZ_OUTPUT_TGA_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/band-writer.h"
#include "mupdf/fitz/pixmap.h"

/*
	fz_save_pixmap_as_tga: Save a pixmap as a TGA image file.
	Can accept RGB, BGR or Grayscale pixmaps, with or without
	alpha.
*/
void fz_save_pixmap_as_tga(fz_context *ctx, fz_pixmap *pixmap, const char *filename);

/*
	Write a pixmap to an output stream in TGA format.
	Can accept RGB, BGR or Grayscale pixmaps, with or without
	alpha.
*/
void fz_write_pixmap_as_tga(fz_context *ctx, fz_output *out, fz_pixmap *pixmap);

/*
	fz_new_tga_band_writer: Generate a new band writer for TGA
	format images. Note that image must be generated vertically
	flipped for use with this writer!

	Can accept RGB, BGR or Grayscale pixmaps, with or without
	alpha.

	is_bgr: True, if the image is generated in bgr format.
*/
fz_band_writer *fz_new_tga_band_writer(fz_context *ctx, fz_output *out, int is_bgr);


#endif
