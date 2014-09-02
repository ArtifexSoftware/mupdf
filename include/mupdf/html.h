#ifndef MUPDF_HTML_H
#define MUPDF_HTML_H

#include "mupdf/fitz.h"

typedef struct html_document_s html_document;
typedef struct html_page_s html_page;

html_document *html_open_document(fz_context *ctx, const char *filename);
html_document *html_open_document_with_stream(fz_context *ctx, fz_stream *file);

#endif
