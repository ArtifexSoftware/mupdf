#ifndef MUPDF_PDF_IMP_H
#define MUPDF_PDF_IMP_H

#include "mupdf/pdf.h"

void pdf_read_ocg(fz_context *ctx, pdf_document *doc);
void pdf_drop_ocg(fz_context *ctx, pdf_document *doc);

#endif
