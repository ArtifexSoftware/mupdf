#ifndef MUPDF_FITZ_OUTPUT_PS_H
#define MUPDF_FITZ_OUTPUT_PS_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/band-writer.h"
#include "mupdf/fitz/pixmap.h"

/*
	PS (image) output
*/
void fz_write_pixmap_as_ps(fz_context *ctx, fz_output *out, const fz_pixmap *pixmap);

void fz_save_pixmap_as_ps(fz_context *ctx, fz_pixmap *pixmap, char *filename, int append);

void fz_write_ps_file_header(fz_context *ctx, fz_output *out);

fz_band_writer *fz_new_ps_band_writer(fz_context *ctx, fz_output *out);

void fz_write_ps_file_trailer(fz_context *ctx, fz_output *out, int pages);

#endif
