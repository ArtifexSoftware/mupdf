#include <fitz.h>

void fz_dropimage(fz_image *image)
{
	if (image->drop)
		image->drop(image);
	fz_free(image);
}

