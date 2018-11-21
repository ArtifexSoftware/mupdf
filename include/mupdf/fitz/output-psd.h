#ifndef MUPDF_FITZ_OUTPUT_PSD_H
#define MUPDF_FITZ_OUTPUT_PSD_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/band-writer.h"
#include "mupdf/fitz/pixmap.h"
#include "mupdf/fitz/bitmap.h"

#include "mupdf/fitz/buffer.h"
#include "mupdf/fitz/image.h"

void fz_save_pixmap_as_psd(fz_context *ctx, fz_pixmap *pixmap, const char *filename);

void fz_write_pixmap_as_psd(fz_context *ctx, fz_output *out, const fz_pixmap *pixmap);

fz_band_writer *fz_new_psd_band_writer(fz_context *ctx, fz_output *out);

#endif
