#ifndef MUPDF_FITZ_IMP_H
#define MUPDF_FITZ_IMP_H

#include "mupdf/fitz.h"

struct fz_buffer_s
{
	int refs;
	unsigned char *data;
	size_t cap, len;
	int unused_bits;
	int shared;
};

#endif
