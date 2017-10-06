#ifndef MUPDF_FITZ_OUTPUT_PCLM_H
#define MUPDF_FITZ_OUTPUT_PCLM_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/band-writer.h"
#include "mupdf/fitz/pixmap.h"
#include "mupdf/fitz/bitmap.h"

/*
	PCLm output
*/
typedef struct fz_pclm_options_s fz_pclm_options;

struct fz_pclm_options_s
{
	int compress;
	int strip_height;

	/* Updated as we move through the job */
	int page_count;
};

/*
	fz_parse_pclm_options: Parse PCLm options.

	Currently defined options and values are as follows:

		compression=none: No compression
		compression=flate: Flate compression
		strip-height=n: Strip height (default 16)
*/
fz_pclm_options *fz_parse_pclm_options(fz_context *ctx, fz_pclm_options *opts, const char *args);

fz_band_writer *fz_new_pclm_band_writer(fz_context *ctx, fz_output *out, const fz_pclm_options *options);
fz_document_writer *fz_new_pclm_writer(fz_context *ctx, const char *path, const char *options);
void fz_write_pixmap_as_pclm(fz_context *ctx, fz_output *out, const fz_pixmap *pixmap, const fz_pclm_options *options);
void fz_save_pixmap_as_pclm(fz_context *ctx, fz_pixmap *pixmap, char *filename, int append, const fz_pclm_options *options);

#endif
