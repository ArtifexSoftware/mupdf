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
		if (shade->cs)
			fz_dropcolorspace(shade->cs);
		fz_free(shade);
	}
}

fz_rect
fz_boundshade(fz_shade *shade, fz_matrix ctm)
{
	return fz_infiniterect;
}

