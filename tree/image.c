#include <fitz.h>

fz_image *
fz_keepimage(fz_image *image)
{
	image->refs ++;
	return image;
}

void
fz_dropimage(fz_image *image)
{
	if (--image->refs == 0)
	{
		if (image->drop)
			image->drop(image);
		fz_free(image);
	}
}

