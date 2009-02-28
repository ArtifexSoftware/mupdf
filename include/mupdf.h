#ifndef _MUPDF_H_
#define _MUPDF_H_

#ifndef _FITZ_H_
#error "fitz.h must be included before mupdf.h"
#endif

void pdf_logxref(char *fmt, ...);
void pdf_logrsrc(char *fmt, ...);
void pdf_logfont(char *fmt, ...);
void pdf_logimage(char *fmt, ...);
void pdf_logshade(char *fmt, ...);
void pdf_logpage(char *fmt, ...);

#include "mupdf/syntax.h"
#include "mupdf/xref.h"
#include "mupdf/rsrc.h"
#include "mupdf/content.h"
#include "mupdf/annot.h"
#include "mupdf/page.h"

#endif
