/* JPEG-XR (formerly HD-Photo (formerly Windows Media Photo)) support */

#include "fitz.h"
#include "muxps.h"

int
xps_decode_jpegxr(xps_image **imagep, xps_context *ctx, byte *rbuf, int rlen)
{
	return fz_throw("JPEG-XR codec is not available");
}
