#include <fitz.h>

void fz_freeimage(fz_image *image)
{
	if (image->free)
		image->free(image);
	fz_free(image);
}

