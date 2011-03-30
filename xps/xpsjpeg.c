#include "fitz.h"
#include "muxps.h"

#include <jpeglib.h>
#include <setjmp.h>

int
xps_decode_jpeg(xps_context *ctx, byte *rbuf, int rlen, xps_image *image)
{
	return fz_throw("jpeg not available");
}
