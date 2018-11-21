#ifndef MUPDF_FITZ_ANNOTATION_H
#define MUPDF_FITZ_ANNOTATION_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/geometry.h"
#include "mupdf/fitz/document.h"

fz_annot *fz_new_annot_of_size(fz_context *ctx, int size);

#define fz_new_derived_annot(CTX, TYPE) \
	((TYPE *)Memento_label(fz_new_annot_of_size(CTX,sizeof(TYPE)),#TYPE))

fz_annot *fz_keep_annot(fz_context *ctx, fz_annot *annot);
void fz_drop_annot(fz_context *ctx, fz_annot *annot);
fz_annot *fz_first_annot(fz_context *ctx, fz_page *page);
fz_annot *fz_next_annot(fz_context *ctx, fz_annot *annot);
fz_rect fz_bound_annot(fz_context *ctx, fz_annot *annot);

#endif
