#include <fitz.h>
#include <mupdf.h>

static fz_error *loadtile(fz_image *fzimg, fz_pixmap *tile)
{
	return nil;
}

fz_error *
pdf_loadimage(pdf_image **imgp, pdf_xref *xref, fz_obj *dict)
{
	fz_error *error;
	pdf_image *img;
	fz_colorspace *cs;
	int ismask;
	fz_obj *obj;

	img = fz_malloc(sizeof(pdf_image));
	if (!img)
		return fz_outofmem;

	img->super.loadtile = loadtile;
	img->super.free = nil;
	img->super.cs = nil;

	img->super.w = fz_toint(fz_dictgets(dict, "Width"));
	img->super.h = fz_toint(fz_dictgets(dict, "Height"));
	img->bpc = fz_toint(fz_dictgets(dict, "BitsPerComponent"));

	cs = nil;
	obj = fz_dictgets(dict, "ColorSpace");
	if (obj)
		error = pdf_loadcolorspace(&cs, xref, obj);

	ismask = fz_tobool(fz_dictgets(dict, "ImageMask"));

	if (!ismask)
	{
		img->super.cs = cs;
		img->super.n = cs->n;
		img->super.a = 0;
	}
	else
	{
		img->super.cs = nil;
		img->super.n = 0;
		img->super.a = 1;
	}

	*imgp = img;

	return nil;
}

