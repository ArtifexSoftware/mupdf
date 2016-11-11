#ifndef MUPDF_PDF_IMP_H
#define MUPDF_PDF_IMP_H

#include "mupdf/pdf.h"

void pdf_read_ocg(fz_context *ctx, pdf_document *doc);
void pdf_drop_ocg(fz_context *ctx, pdf_document *doc);

int pdf_is_hidden_ocg(fz_context *ctx, pdf_ocg_descriptor *desc, pdf_obj *rdb, const char *usage, pdf_obj *ocg);

#endif
