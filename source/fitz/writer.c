#include "mupdf/fitz.h"

fz_document_writer *
fz_new_document_writer(fz_context *ctx, const char *path, const char *format, const char *options)
{
	if (!format)
	{
		format = strrchr(path, '.');
		if (!format)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot detect document format");
		format += 1; /* skip the '.' */
	}

	if (!fz_strcasecmp(format, "cbz"))
		return fz_new_cbz_writer(ctx, path, options);

	fz_throw(ctx, FZ_ERROR_GENERIC, "unknown document format: %s", format);
}

void
fz_drop_document_writer(fz_context *ctx, fz_document_writer *wri)
{
	if (wri->drop_imp)
		wri->drop_imp(ctx, wri);
	fz_free(ctx, wri);
}

fz_device *
fz_begin_page(fz_context *ctx, fz_document_writer *wri, const fz_rect *mediabox, fz_matrix *ctm)
{
	return wri->begin_page(ctx, wri, mediabox, ctm);
}

void
fz_end_page(fz_context *ctx, fz_document_writer *wri, fz_device *dev)
{
	wri->end_page(ctx, wri, dev);
}
