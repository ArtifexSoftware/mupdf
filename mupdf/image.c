#include <fitz.h>
#include <mupdf.h>

void pdf_dropimage(fz_image *fzimg)
{
	pdf_image *img = (pdf_image*)fzimg;
	fz_dropbuffer(img->samples);
	if (img->mask)
		fz_dropimage(img->mask);
}

static inline int getbit(const unsigned char *buf, int x)
{
	return ( buf[x >> 3] >> ( 7 - (x & 7) ) ) & 1;
}

static void loadtile1(pdf_image *src, fz_pixmap *dst, int n)
{
	int x, y, k;
	for (y = dst->y; y < dst->y + dst->h; y++)
	{
		unsigned char *s = src->samples->bp + y * src->stride;
		unsigned char *d = dst->samples + y * dst->w * dst->n;
		for (x = dst->x; x < dst->x + dst->w; x++)
		{
			for (k = 0; k < n; k++)
				d[x * n + k] = getbit(s, x * n + k);
		}
	}
}

static void loadtile1a(pdf_image *src, fz_pixmap *dst, int n)
{
	int x, y, k;
	for (y = dst->y; y < dst->y + dst->h; y++)
	{
		unsigned char *s = src->samples->bp + y * src->stride;
		unsigned char *d = dst->samples + y * dst->w * dst->n;
		for (x = dst->x; x < dst->x + dst->w; x++)
		{
			d[x * (n+1) + 0] = 255;
			for (k = 0; k < n; k++)
				d[x * (n+1) + k + 1] = getbit(s, x * n + k);
		}
	}
}

static void loadtile8(pdf_image *src, fz_pixmap *dst, int n)
{
	int x, y, k;
	for (y = dst->y; y < dst->y + dst->h; y++)
	{
		unsigned char *s = src->samples->bp + y * src->stride;
		unsigned char *d = dst->samples + y * dst->w * dst->n;
		for (x = dst->x; x < dst->x + dst->w; x++)
			for (k = 0; k < n; k++)
				*d++ = *s++;
	}
}

static void loadtile8a(pdf_image *src, fz_pixmap *dst, int n)
{
	int x, y, k;
	for (y = dst->y; y < dst->y + dst->h; y++)
	{
		unsigned char *s = src->samples->bp + y * src->stride;
		unsigned char *d = dst->samples + y * dst->w * dst->n;
		for (x = dst->x; x < dst->x + dst->w; x++)
		{
			*d++ = 255;
			for (k = 0; k < n; k++)
				*d++ = *s++;
		}
	}
}

static void
decodetile(fz_pixmap *pix, int bpc, int skip, float *decode)
{
	unsigned char table[32][256];
	float twon = (1 << bpc) - 1;
	int x, y, k, i;

printf("  decode bpc=%d skip=%d n=%d twon=%g\n", bpc, skip, pix->n, twon);

	for (k = skip; k < pix->n; k++)
	{
		float min = decode[(k - skip) * 2 + 0];
		float max = decode[(k - skip) * 2 + 1];
		printf("    k=%d min=%g max=%g\n", k, min, max);
	}

	for (i = 0; i < (1 << bpc); i++)
	{
		if (skip)
			table[0][i] = (i * 255) / twon;
		for (k = skip; k < pix->n; k++)
		{
			float min = decode[(k - skip) * 2 + 0];
			float max = decode[(k - skip) * 2 + 1];
			float f = min + i * (max - min) / twon;
			table[k][i] = f * 255;
		}
	}

	for (y = 0; y < pix->h; y++)
	{
		for (x = 0; x < pix->w; x++)
		{
			for (k = 0; k < pix->n; k++)
			{
				i = pix->samples[ (y * pix->w + x) * pix->n + k];
				pix->samples[ (y * pix->w + x) * pix->n + k] = table[k][i];
			}
		}
	}
}

static fz_error *
loadtile(fz_image *img, fz_pixmap *tile)
{
	pdf_image *src = (pdf_image*)img;
	fz_error *error;

	assert(tile->n == img->n + 1);
	assert(tile->x >= 0);
	assert(tile->y >= 0);
	assert(tile->x + tile->w <= img->w);
	assert(tile->y + tile->h <= img->h);

	if (src->indexed)
	{
		fz_pixmap *tmp;
		int x, y, k, i;

		error = fz_newpixmap(&tmp, tile->x, tile->y, tile->w, tile->h, 1);
		if (error)
			return error;

		switch (src->bpc)
		{
		case 1: loadtile1(src, tmp, 1); break;
	//	case 2: loadtile2(src, tmp, 1); break;
	//	case 4: loadtile4(src, tmp, 1); break;
		case 8: loadtile8(src, tmp, 1); break;
		default:
			return fz_throw("rangecheck: unsupported bit depth: %d", src->bpc);
		}

printf("  unpack n=%d\n", tile->n);
		for (y = 0; y < tile->h; y++)
		{
			for (x = 0; x < tile->w; x++)
			{
				tile->samples[(y * tile->w + x) * tile->n] = 255;
				i = tmp->samples[y * tile->w + x];
				i = CLAMP(i, 0, src->indexed->high);
				for (k = 0; k < src->indexed->base->n; k++)
				{
					tile->samples[(y * tile->w + x) * tile->n + k + 1] =
						src->indexed->lookup[i * src->indexed->base->n + k];
				}
			}
		}

		fz_droppixmap(tmp);
	}

	else
	{
		if (img->a)
		{
			switch (src->bpc)
			{
			case 1: loadtile1(src, tile, img->n + img->a); break;
		//	case 2: loadtile2(src, tile, img->n + img->a); break;
		//	case 4: loadtile4(src, tile, img->n + img->a); break;
			case 8: loadtile8(src, tile, img->n + img->a); break;
			default:
				return fz_throw("rangecheck: unsupported bit depth: %d", src->bpc);
			}
		}
		else
		{
			switch (src->bpc)
			{
			case 1: loadtile1a(src, tile, img->n); break;
		//	case 2: loadtile2a(src, tile, img->n); break;
		//	case 4: loadtile4a(src, tile, img->n); break;
			case 8: loadtile8a(src, tile, img->n); break;
			default:
				return fz_throw("rangecheck: unsupported bit depth: %d", src->bpc);
			}
		}

		decodetile(tile, src->bpc, !img->a, src->decode);
	}

	return nil;
}

fz_error *
pdf_loadinlineimage(pdf_image **imgp, pdf_xref *xref, fz_obj *dict, fz_file *file)
{
	fz_error *error;
	pdf_image *img;
	fz_filter *filter;
	fz_obj *cs;
	fz_obj *d;
	int ismask;
	int i;

	img = *imgp = fz_malloc(sizeof(pdf_image));
	if (!img)
		return fz_outofmem;

printf("inline image ");fz_debugobj(dict);printf("\n");

	img->super.loadtile = loadtile;
	img->super.drop = pdf_dropimage;
	img->super.n = 0;
	img->super.a = 0;
	img->indexed = nil;

	img->super.w = fz_toint(fz_dictgetsa(dict, "Width", "W"));
	img->super.h = fz_toint(fz_dictgetsa(dict, "Height", "H"));
	img->bpc = fz_toint(fz_dictgetsa(dict, "BitsPerComponent", "BPC"));
	ismask = fz_tobool(fz_dictgetsa(dict, "ImageMask", "IM"));
	d = fz_dictgetsa(dict, "Decode", "D");
	cs = fz_dictgetsa(dict, "ColorSpace", "CS");

	if (ismask)
	{
		img->super.n = 0;
		img->super.a = 1;
		img->bpc = 1;
	}

	if (cs)
	{
		error = pdf_loadcolorspace(&img->super.cs, xref, cs);
		if (error)
			return error;
		img->super.n = img->super.cs->n;
		img->super.a = 0;
		if (!strcmp(img->super.cs->name, "Indexed"))
		{
printf("  indexed!\n");
			img->indexed = (pdf_indexed*)img->super.cs;
			img->super.cs = img->indexed->base;
		}
	}

	if (fz_isarray(d))
	{
printf("  decode array!\n");
		if (img->indexed)
			for (i = 0; i < 2; i++)
				img->decode[i] = fz_toreal(fz_arrayget(d, i));
		else
			for (i = 0; i < (img->super.n + img->super.a) * 2; i++)
				img->decode[i] = fz_toreal(fz_arrayget(d, i));
	}
	else
	{
		if (img->indexed)
			for (i = 0; i < 2; i++)
				img->decode[i] = i & 1 ? (1 << img->bpc) - 1 : 0;
		else
			for (i = 0; i < (img->super.n + img->super.a) * 2; i++)
				img->decode[i] = i & 1;
	}

	if (img->indexed)
		img->stride = (img->super.w * img->bpc + 7) / 8;
	else
		img->stride = (img->super.w * (img->super.n + img->super.a) * img->bpc + 7) / 8;

	/* load image data */
	error = pdf_decodefilter(&filter, dict);
	if (error)
		return error;

	error = fz_pushfilter(file, filter);
	if (error)
		return error;

	error = fz_readfile(&img->samples, file);
	if (error)
		return error;

	fz_popfilter(file);

	/* 0 means opaque and 1 means transparent, so we invert to get alpha */
	if (ismask)
	{
		unsigned char *p;
		for (p = img->samples->bp; p < img->samples->ep; p++)
			*p = ~*p;
	}

	return nil;
}

/* TODO error cleanup */
fz_error *
pdf_loadimage(pdf_image **imgp, pdf_xref *xref, fz_obj *dict, fz_obj *ref)
{
	fz_error *error;
	pdf_image *img;
	pdf_image *mask;
	int ismask;
	fz_obj *obj;
	fz_obj *sub;
	int i;

	int w, h, bpc;
	int n = 0;
	int a = 0;
	fz_colorspace *cs = nil;
	pdf_indexed *indexed = nil;
	int stride;

printf("loading image "); fz_debugobj(dict); printf("\n");

	img = fz_malloc(sizeof(pdf_image));
	if (!img)
		return fz_outofmem;

	/*
	 * Dimensions, BPC and ColorSpace
	 */

	w = fz_toint(fz_dictgets(dict, "Width"));
	h = fz_toint(fz_dictgets(dict, "Height"));
	bpc = fz_toint(fz_dictgets(dict, "BitsPerComponent"));

printf("  geometry %d x %d @ %d\n", w, h, bpc);

	cs = nil;
	obj = fz_dictgets(dict, "ColorSpace");
	if (obj)
	{
		error = pdf_resolve(&obj, xref);
		if (error)
			return error;

		error = pdf_loadcolorspace(&cs, xref, obj);
		if (error)
			return error;

		if (!strcmp(cs->name, "Indexed"))
		{
printf("  indexed!\n");
			indexed = (pdf_indexed*)cs;
			cs = indexed->base;
		}
		n = cs->n;
		a = 0;

		fz_dropobj(obj);
	}

	/*
	 * ImageMask, Mask and SoftMask
	 */

	mask = nil;

	ismask = fz_tobool(fz_dictgets(dict, "ImageMask"));
	if (ismask)
	{
printf("  image mask!\n");
		bpc = 1;
		n = 0;
		a = 1;
	}

	obj = fz_dictgets(dict, "SMask");
	if (fz_isindirect(obj))
	{
		puts("  smask");
		error = pdf_loadindirect(&sub, xref, obj);
		if (error)
			return error;

		error = pdf_loadimage(&mask, xref, sub, obj);
		if (error)
			return error;

		if (mask->super.cs != pdf_devicegray)
			return fz_throw("syntaxerror: SMask must be DeviceGray");

		mask->super.cs = 0;
		mask->super.n = 0;
		mask->super.a = 1;

		fz_dropobj(sub);
	}

	obj = fz_dictgets(dict, "Mask");
	if (fz_isindirect(obj))
	{
		error = pdf_loadindirect(&sub, xref, obj);
		if (error)
			return error;
		if (fz_isarray(sub))
		{
			puts("  mask / color key");
		}
		else
		{
			puts("  mask");
			error = pdf_loadimage(&mask, xref, sub, obj);
			if (error)
				return error;
		}
		fz_dropobj(sub);
	}
	else if (fz_isarray(obj))
	{
		puts("  mask / color key");
	}

	/*
	 * Decode
	 */

	obj = fz_dictgets(dict, "Decode");
	if (fz_isarray(obj))
	{
printf("  decode array!\n");
		if (indexed)
			for (i = 0; i < 2; i++)
				img->decode[i] = fz_toreal(fz_arrayget(obj, i));
		else
			for (i = 0; i < (n + a) * 2; i++)
				img->decode[i] = fz_toreal(fz_arrayget(obj, i));
	}
	else
	{
		if (indexed)
			for (i = 0; i < 2; i++)
				img->decode[i] = i & 1 ? (1 << bpc) - 1 : 0;
		else
			for (i = 0; i < (n + a) * 2; i++)
				img->decode[i] = i & 1;
	}

	/*
	 * Load samples
	 */

	if (indexed)
		stride = (w * bpc + 7) / 8;
	else
		stride = (w * (n + a) * bpc + 7) / 8;

	error = pdf_loadstream(&img->samples, xref, fz_tonum(ref), fz_togen(ref));
	if (error)
	{
		/* TODO: colorspace? */
		fz_free(img);
		return error;
	}

	if (img->samples->wp - img->samples->bp < stride * h)
	{
		/* TODO: colorspace? */
		fz_dropbuffer(img->samples);
		fz_free(img);
		return fz_throw("syntaxerror: truncated image data");
	}

	/* 0 means opaque and 1 means transparent, so we invert to get alpha */
	if (ismask)
	{
		unsigned char *p;
		for (p = img->samples->bp; p < img->samples->ep; p++)
			*p = ~*p;
	}

if (indexed)
printf("  decode [ %g %g ]\n", img->decode[0], img->decode[1]);
else
{
printf("  decode [ ");
for (i = 0; i < (n + a) * 2; i++)
printf("%g ", img->decode[i]);
printf("]\n");
printf("\n");
}

	/*
	 * Create image object
	 */

	img->super.loadtile = loadtile;
	img->super.drop = pdf_dropimage;
	img->super.cs = cs;
	img->super.w = w;
	img->super.h = h;
	img->super.n = n;
	img->super.a = a;
	img->indexed = indexed;
	img->stride = stride;
	img->bpc = bpc;
	img->mask = (fz_image*)mask;

	*imgp = img;

	return nil;
}

