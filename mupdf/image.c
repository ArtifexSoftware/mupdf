#include <fitz.h>
#include <mupdf.h>

#define NEXTBYTE() \
	{ c = *srcline++; }
#define NEEDBITS(n) \
    { while (k<(n)) { NEXTBYTE(); b = (b << 8) | c; k += 8; } }
#define DUMPBITS(n) \
    { k -= (n); }
#define GETCOMP1 NEEDBITS(1);(cc)=((b>>(k-(1)))&0x0001);DUMPBITS(1)
#define GETCOMP2 NEEDBITS(2);(cc)=((b>>(k-(2)))&0x0003);DUMPBITS(2)
#define GETCOMP4 NEEDBITS(4);(cc)=((b>>(k-(4)))&0x000f);DUMPBITS(4)
#define GETCOMP8 NEXTBYTE();(cc)=c

static fz_error *loadtile(fz_image *fzimg, fz_pixmap *tile)
{
	pdf_image *img = (pdf_image*)fzimg;
	unsigned char *srcline;
	unsigned char *dstline;
	int x, y, z;
	int stride;
	unsigned cc, c, k, b;

	assert(fzimg->w == tile->w && fzimg->h == tile->h);
	assert(fzimg->n == tile->n);

	stride = ((fzimg->w * (fzimg->n + fzimg->a)) * img->bpc + 7) / 8;
	k = 0;
	b = 0;

	for (y = 0; y < fzimg->h; y++)
	{
		srcline = img->data->bp + y * stride;
		dstline = tile->samples + y * tile->stride;

		for (x = 0; x < fzimg->w; x++)
		{
			for (z = 0; z < fzimg->n + fzimg->a; z++)
			{
				switch (img->bpc)
				{
				case 1: GETCOMP1; *dstline++ = cc * 255; break;
				case 2: GETCOMP2; *dstline++ = cc * 85; break;
				case 4: GETCOMP4; *dstline++ = cc * 17; break;
				case 8: GETCOMP8; *dstline++ = cc; break;
				}
			}
			if (!fzimg->a && tile->a)
				*dstline++ = 0xff;
		}
	}

	return nil;
}

fz_error *
pdf_loadimage(pdf_image **imgp, pdf_xref *xref, fz_obj *dict, fz_obj *ref)
{
	fz_error *error;
	pdf_image *img;
	fz_colorspace *cs;
	int ismask;
	int stride;
	fz_obj *obj;
	int i;

	img = fz_malloc(sizeof(pdf_image));
	if (!img)
		return fz_outofmem;

	img->super.loadtile = loadtile;
	img->super.free = nil;
	img->super.cs = nil;

	img->super.w = fz_toint(fz_dictgets(dict, "Width"));
	img->super.h = fz_toint(fz_dictgets(dict, "Height"));
	img->bpc = fz_toint(fz_dictgets(dict, "BitsPerComponent"));

printf("load image %d x %d @ %d\n", img->super.w, img->super.h, img->bpc);

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

	obj = fz_dictgets(dict, "Decode");
	if (fz_isarray(obj))
		for (i = 0; i < (img->super.n + img->super.a) * 2; i++)
			img->decode[i] = fz_toreal(fz_arrayget(obj, i));
	else
		for (i = 0; i < (img->super.n + img->super.a) * 2; i++)
			img->decode[i] = i & 1;

printf("  cs %s\n", cs ? cs->name : "(null)");
printf("  mask %d\n", ismask);
printf("  decode [ ");
for (i = 0; i < (img->super.n + img->super.a) * 2; i++)
printf("%g ", img->decode[i]);
printf("]\n");

	error = pdf_loadstream(&img->data, xref, fz_tonum(ref), fz_togen(ref));
	if (error)
	{
		/* TODO: colorspace? */
		fz_free(img);
		return error;
	}

	stride = img->super.w * (img->super.n + img->super.a);
	stride = (stride * img->bpc + 7) / 8;
printf("  stride = %d -> %d bytes\n", stride, stride * img->super.h);
printf("  data = %d bytes\n", img->data->wp - img->data->bp);
	if (img->data->wp - img->data->bp != stride * img->super.h)
	{
		/* TODO: colorspace? */
		fz_freebuffer(img->data);
		fz_free(img);
		return fz_throw("syntaxerror: truncated image data");
	}

	*imgp = img;

	return nil;
}

