#include <fitz.h>

fz_shade *
fz_keepshade(fz_shade *shade)
{
	shade->refs ++;
	return shade;
}

void
fz_dropshade(fz_shade *shade)
{
	if (--shade->refs == 0)
	{
		if (shade->colorspace)
			fz_dropcolorspace(shade->colorspace);
		fz_free(shade);
	}
}

fz_rect
fz_boundshade(fz_shade *shade, fz_matrix ctm)
{
	return fz_infiniterect;
}

