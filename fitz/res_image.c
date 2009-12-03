#include "fitz.h"

fz_image *
fz_keepimage(fz_image *image)
{
	image->refs ++;
	return image;
}

void
fz_dropimage(fz_image *image)
{
	if (image && --image->refs == 0)
	{
		if (image->freefunc)
			image->freefunc(image);
		if (image->cs)
			fz_dropcolorspace(image->cs);
		fz_free(image);
	}
}

