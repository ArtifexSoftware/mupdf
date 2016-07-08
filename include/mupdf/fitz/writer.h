#ifndef MUPDF_FITZ_WRITER_H
#define MUPDF_FITZ_WRITER_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/document.h"
#include "mupdf/fitz/device.h"

typedef struct fz_document_writer_s fz_document_writer;

struct fz_document_writer_s
{
	fz_device *(*begin_page)(fz_context *ctx, fz_document_writer *wri, const fz_rect *mediabox);
	void (*end_page)(fz_context *ctx, fz_document_writer *wri, fz_device *dev);
	void (*close_writer)(fz_context *ctx, fz_document_writer *wri);
	void (*drop_writer)(fz_context *ctx, fz_document_writer *wri);
};

int fz_has_option(fz_context *ctx, const char *opts, const char *key, const char **val);

fz_document_writer *fz_new_document_writer(fz_context *ctx, const char *path, const char *format, const char *options);

fz_device *fz_begin_page(fz_context *ctx, fz_document_writer *wri, const fz_rect *mediabox);
void fz_end_page(fz_context *ctx, fz_document_writer *wri, fz_device *dev);
void fz_close_document_writer(fz_context *ctx, fz_document_writer *wri);
void fz_drop_document_writer(fz_context *ctx, fz_document_writer *wri);

fz_document_writer *fz_new_cbz_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_png_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_pdf_writer(fz_context *ctx, const char *path, const char *options);

extern const char *fz_cbz_write_options_usage;
extern const char *fz_png_write_options_usage;
extern const char *fz_pdf_write_options_usage;

#endif
