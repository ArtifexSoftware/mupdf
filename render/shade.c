#include <fitz.h>

fz_error *
fz_rendershade(fz_shade *shade, fz_matrix ctm, fz_colorspace *dsts, fz_pixmap *dstp, int over)
{
	if (!over)
		fz_clearpixmap(dstp);
	return nil;
}

