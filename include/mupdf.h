#ifdef _MUPDF_H_
#error "mupdf.h must only be included once"
#endif
#define _MUPDF_H_

#ifndef _FITZ_H_
#error "fitz.h must be included before mupdf.h"
#endif

#include "mupdf/syntax.h"
#include "mupdf/xref.h"
#include "mupdf/rsrc.h"
#include "mupdf/content.h"
#include "mupdf/page.h"
#include "mupdf/function.h"
