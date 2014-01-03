#include "mupdf/fitz.h"

/* TODO: implement JPEG-XR support */

fz_pixmap *
fz_load_jxr(fz_context *ctx, unsigned char *data, int size)
{
	fz_throw(ctx, FZ_ERROR_GENERIC, "JPEG-XR codec is not available");
}

void
fz_load_jxr_info(fz_context *ctx, unsigned char *data, int size, int *wp, int *hp, int *xresp, int *yresp, fz_colorspace **cspacep)
{
	fz_throw(ctx, FZ_ERROR_GENERIC, "JPEG-XR codec is not available");
}
