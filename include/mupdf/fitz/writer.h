#ifndef MUPDF_FITZ_WRITER_H
#define MUPDF_FITZ_WRITER_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/document.h"
#include "mupdf/fitz/device.h"

typedef struct fz_document_writer_s fz_document_writer;

/*
	fz_document_writer_begin_page_fn: Function type to start
	the process of writing a page to a document.

	mediabox: page size rectangle in points.

	Returns a fz_device to write page contents to.
*/
typedef fz_device *(fz_document_writer_begin_page_fn)(fz_context *ctx, fz_document_writer *wri, const fz_rect *mediabox);

/*
	fz_document_writer_end_page_fn: Function type to end the
	process of writing a page to a document.

	dev: The device created by the begin_page function.
*/
typedef void (fz_document_writer_end_page_fn)(fz_context *ctx, fz_document_writer *wri, fz_device *dev);

/*
	fz_document_writer_close_writer_fn: Function type to end
	the process of writing pages to a document.

	This writes any file level trailers required. After this
	completes successfully the file is up to date and complete.
*/
typedef void (fz_document_writer_close_writer_fn)(fz_context *ctx, fz_document_writer *wri);

/*
	fz_document_writer_drop_writer_fn: Function type to discard
	an fz_document_writer. This may be called at any time during
	the process to release all the resources owned by the writer.

	Calling drop without having previously called close may leave
	the file in an inconsistent state.
*/
typedef void (fz_document_writer_drop_writer_fn)(fz_context *ctx, fz_document_writer *wri);

/*
	Structure is public to allow other structures to
	be derived from it. Do not access members directly.
*/
struct fz_document_writer_s
{
	fz_document_writer_begin_page_fn *begin_page;
	fz_document_writer_end_page_fn *end_page;
	fz_document_writer_close_writer_fn *close_writer;
	fz_document_writer_drop_writer_fn *drop_writer;
	fz_device *dev;
};

/*
	fz_new_document_writer_of_size: Internal function to allocate a
	block for a derived document_writer structure, with the base
	structure's function pointers populated correctly, and the extra
	space zero initialised.
*/
fz_document_writer *fz_new_document_writer_of_size(fz_context *ctx, size_t size,
		fz_document_writer_begin_page_fn *begin_page,
		fz_document_writer_end_page_fn *end_page,
		fz_document_writer_close_writer_fn *close,
		fz_document_writer_drop_writer_fn *drop);

#define fz_new_derived_document_writer(CTX,TYPE,BEGIN_PAGE,END_PAGE,CLOSE,DROP) \
	((TYPE *)Memento_label(fz_new_document_writer_of_size(CTX,sizeof(TYPE),BEGIN_PAGE,END_PAGE,CLOSE,DROP),#TYPE))

int fz_has_option(fz_context *ctx, const char *opts, const char *key, const char **val);
int fz_option_eq(const char *a, const char *b);

/*
	fz_new_document_writer: Create a new fz_document_writer, for a
	file of the given type.

	path: The document name to write (or NULL for default)

	format: Which format to write (currently cbz, pdf, pam, pbm,
	pgm, pkm, png, ppm, pnm, svg, tga)

	options: NULL, or pointer to comma separated string to control
	file generation.
*/
fz_document_writer *fz_new_document_writer(fz_context *ctx, const char *path, const char *format, const char *options);

fz_document_writer *fz_new_cbz_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_pdf_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_svg_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_png_pixmap_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_tga_pixmap_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_pam_pixmap_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_pnm_pixmap_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_pgm_pixmap_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_ppm_pixmap_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_pbm_pixmap_writer(fz_context *ctx, const char *path, const char *options);
fz_document_writer *fz_new_pkm_pixmap_writer(fz_context *ctx, const char *path, const char *options);

/*
	fz_begin_page: Called to start the process of writing a page to
	a document.

	mediabox: page size rectangle in points.

	Returns a fz_device to write page contents to.
*/
fz_device *fz_begin_page(fz_context *ctx, fz_document_writer *wri, const fz_rect *mediabox);

/*
	fz_end_page: Called to end the process of writing a page to a
	document.
*/
void fz_end_page(fz_context *ctx, fz_document_writer *wri);

/*
	fz_close_document_writer: Called to end the process of writing
	pages to a document.

	This writes any file level trailers required. After this
	completes successfully the file is up to date and complete.
*/
void fz_close_document_writer(fz_context *ctx, fz_document_writer *wri);

/*
	fz_drop_document_writer: Called to discard a fz_document_writer.
	This may be called at any time during the process to release all
	the resources owned by the writer.

	Calling drop without having previously called close may leave
	the file in an inconsistent state.
*/
void fz_drop_document_writer(fz_context *ctx, fz_document_writer *wri);

fz_document_writer *fz_new_pixmap_writer(fz_context *ctx, const char *path, const char *options, const char *default_path, int n,
	void (*save)(fz_context *ctx, fz_pixmap *pix, const char *filename));

extern const char *fz_cbz_write_options_usage;
extern const char *fz_pdf_write_options_usage;
extern const char *fz_svg_write_options_usage;

#endif
