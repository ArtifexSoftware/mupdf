#include "fitz.h"
#include "muxps.h"

#include <jpeglib.h>
#include <setjmp.h>

int
xps_decode_jpeg(xps_context_t *ctx, byte *rbuf, int rlen, xps_image_t *image)
{
	return fz_throw("jpeg not available");
}
