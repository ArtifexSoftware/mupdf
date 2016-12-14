#ifndef MUPDF_PDF_IMP_H
#define MUPDF_PDF_IMP_H

#include "mupdf/pdf.h"

/* Private object functions. */

void pdf_dict_put_val_null(fz_context *ctx, pdf_obj *obj, int idx);

void pdf_forget_xref(fz_context *ctx, pdf_document *doc);

/* Private OCG functions. */

void pdf_read_ocg(fz_context *ctx, pdf_document *doc);
void pdf_drop_ocg(fz_context *ctx, pdf_document *doc);

int pdf_is_hidden_ocg(fz_context *ctx, pdf_ocg_descriptor *desc, pdf_obj *rdb, const char *usage, pdf_obj *ocg);

void pdf_drop_portfolio(fz_context *ctx, pdf_document *doc);

#endif
