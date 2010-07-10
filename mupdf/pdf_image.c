#include "fitz.h"
#include "mupdf.h"

/* TODO: special case JPXDecode image loading */
/* TODO: store JPEG compressed samples */
/* TODO: store flate compressed samples */

pdf_image *
pdf_keepimage(pdf_image *image)
{
	image->refs ++;
	return image;
}

void
pdf_dropimage(pdf_image *img)
{
	if (img && --img->refs == 0)
	{
		if (img->colorspace)
			fz_dropcolorspace(img->colorspace);
		if (img->mask)
			pdf_dropimage(img->mask);
		if (img->samples)
			fz_dropbuffer(img->samples);
		fz_free(img);
	}
}

static fz_error
pdf_loadimageheader(pdf_image **imgp, pdf_xref *xref, fz_obj *rdb, fz_obj *dict)
{
	pdf_image *img;
	fz_error error;
	fz_obj *obj, *res;
	int i;

	img = fz_malloc(sizeof(pdf_image));
	memset(img, 0, sizeof(pdf_image));

	img->refs = 1;
	img->w = fz_toint(fz_dictgetsa(dict, "Width", "W"));
	img->h = fz_toint(fz_dictgetsa(dict, "Height", "H"));
	img->bpc = fz_toint(fz_dictgetsa(dict, "BitsPerComponent", "BPC"));
	img->imagemask = fz_tobool(fz_dictgetsa(dict, "ImageMask", "IM"));
	img->interpolate = fz_tobool(fz_dictgetsa(dict, "Interpolate", "I"));

	if (img->imagemask)
		img->bpc = 1;

	if (img->w == 0)
		fz_warn("image width is zero");
	if (img->h == 0)
		fz_warn("image height is zero");
	if (img->bpc == 0)
		fz_warn("image bit depth is zero"); /* okay for JPX */

	obj = fz_dictgetsa(dict, "ColorSpace", "CS");
	if (obj)
	{
		if (fz_isname(obj))
		{
			res = fz_dictget(fz_dictgets(rdb, "ColorSpace"), obj);
			if (res)
				obj = res;
		}

		error = pdf_loadcolorspace(&img->colorspace, xref, obj);
		if (error)
		{
			pdf_dropimage(img);
			return fz_rethrow(error, "cannot load image colorspace");
		}

		if (!strcmp(img->colorspace->name, "Indexed"))
			img->indexed = 1;

		img->n = img->colorspace->n;
	}
	else
	{
		img->colorspace = pdf_devicegray;
		img->n = 1;
	}

	obj = fz_dictgetsa(dict, "Decode", "D");
	if (obj)
	{
		for (i = 0; i < img->n * 2; i++)
			img->decode[i] = fz_toreal(fz_arrayget(obj, i));
	}
	else
	{
		for (i = 0; i < img->n * 2; i++)
			if (i & 1)
				img->decode[i] = 1;
			else
				img->decode[i] = 0;
	}

	obj = fz_dictgetsa(dict, "Mask", "SMask");
	if (pdf_isstream(xref, fz_tonum(obj), fz_togen(obj)))
	{
		error = pdf_loadimage(&img->mask, xref, rdb, obj);
		if (error)
		{
			pdf_dropimage(img);
			return fz_rethrow(error, "cannot load image mask/softmask");
		}
		img->mask->imagemask = 1;
	}
	else if (fz_isarray(obj))
	{
		img->usecolorkey = 1;
		for (i = 0; i < img->n * 2; i++)
			img->colorkey[i] = fz_toint(fz_arrayget(obj, i));
	}

	img->stride = (img->w * img->n * img->bpc + 7) / 8;

	pdf_logimage("size %dx%d n=%d bpc=%d (imagemask=%d)\n", img->w, img->h, img->n, img->bpc, img->imagemask);

	*imgp = img;
	return fz_okay;
}

fz_error
pdf_loadinlineimage(pdf_image **imgp, pdf_xref *xref,
	fz_obj *rdb, fz_obj *dict, fz_stream *file)
{
	fz_error error;
	pdf_image *img;
	fz_filter *filter;
	fz_stream *subfile;
	int n;

	pdf_logimage("load inline image {\n");

	error = pdf_loadimageheader(&img, xref, rdb, dict);
	if (error)
		return fz_rethrow(error, "cannot load inline image");

	filter = pdf_buildinlinefilter(xref, dict);
	subfile = fz_openfilter(filter, file);

	img->samples = fz_newbuffer(img->h * img->stride);
	error = fz_read(&n, file, img->samples->bp, img->h * img->stride);
	if (error)
	{
		pdf_dropimage(img);
		return fz_rethrow(error, "cannot load inline image data");
	}
	img->samples->wp += n;

	fz_dropstream(subfile);
	fz_dropfilter(filter);

	/* 0 means opaque and 1 means transparent, so we invert to get alpha */
	if (img->imagemask)
	{
		unsigned char *p;
		for (p = img->samples->bp; p < img->samples->ep; p++)
			*p = ~*p;
	}

	pdf_logimage("}\n");

	*imgp = img;
	return fz_okay;
}

fz_error
pdf_loadimage(pdf_image **imgp, pdf_xref *xref, fz_obj *rdb, fz_obj *dict)
{
	fz_error error;
	pdf_image *img;

	if ((*imgp = pdf_finditem(xref->store, PDF_KIMAGE, dict)))
	{
		pdf_keepimage(*imgp);
		return fz_okay;
	}

	pdf_logimage("load image (%d %d R) {\n", fz_tonum(dict), fz_togen(dict));

	error = pdf_loadimageheader(&img, xref, rdb, dict);
	if (error)
		return fz_rethrow(error, "cannot load image (%d %d R)", fz_tonum(dict), fz_togen(dict));

	error = pdf_loadstream(&img->samples, xref, fz_tonum(dict), fz_togen(dict));
	if (error)
	{
		pdf_dropimage(img);
		return fz_rethrow(error, "cannot load image data (%d %d R)", fz_tonum(dict), fz_togen(dict));
	}

	/* Pad truncated images */
	if (img->samples->wp - img->samples->bp < img->stride * img->h)
	{
		fz_warn("padding truncated image");
		fz_resizebuffer(img->samples, img->stride * img->h);
		memset(img->samples->wp, 0, img->samples->ep - img->samples->wp);
		img->samples->wp = img->samples->bp + img->stride * img->h;
	}

	/* 0 means opaque and 1 means transparent, so we invert to get alpha */
	if (img->imagemask)
	{
		unsigned char *p;
		for (p = img->samples->bp; p < img->samples->ep; p++)
			*p = ~*p;
	}

	pdf_logimage("}\n");

	pdf_storeitem(xref->store, PDF_KIMAGE, dict, img);

	*imgp = img;
	return fz_okay;
}

static void
pdf_maskcolorkey(fz_pixmap *pix, int n, int *colorkey, int scale)
{
	unsigned char *p = pix->samples;
	int i, k, t;
	for (i = 0; i < pix->w * pix->h; i++)
	{
		t = 1;
		for (k = 0; k < n; k++)
			if (p[k] < colorkey[k * 2] * scale || p[k] > colorkey[k * 2 + 1] * scale)
				t = 0;
		if (t)
			for (k = 0; k < pix->n; k++)
				p[k] = 0;
		p += pix->n;
	}
}

fz_error
pdf_loadtile(pdf_image *src, fz_pixmap *tile)
{
	void (*tilefunc)(unsigned char*restrict,int,unsigned char*restrict, int, int, int, int);

	assert(tile->x == 0); /* can't handle general tile yet, only y-banding */

	assert(tile->n == src->n + 1 - src->imagemask);
	assert(tile->x >= 0);
	assert(tile->y >= 0);
	assert(tile->x + tile->w <= src->w);
	assert(tile->y + tile->h <= src->h);

	switch (src->bpc)
	{
	case 1: tilefunc = fz_loadtile1; break;
	case 2: tilefunc = fz_loadtile2; break;
	case 4: tilefunc = fz_loadtile4; break;
	case 8: tilefunc = fz_loadtile8; break;
	case 16: tilefunc = fz_loadtile16; break;
	default:
		return fz_throw("rangecheck: unsupported bit depth: %d", src->bpc);
	}

	tilefunc(src->samples->rp + (tile->y * src->stride), src->stride,
		tile->samples, tile->w * tile->n,
		tile->w * src->n, tile->h, src->imagemask ? 0 : src->n);

	if (src->usecolorkey)
	{
		int scale = 1; /* tilefunc scaled image samples to 0..255 */
		if (!src->indexed)
		{
			switch (src->bpc)
			{
			case 1: scale = 255; break;
			case 2: scale = 85; break;
			case 4: scale = 17; break;
			case 8: scale = 1; break;
			case 16:
				fz_warn("color-key masked 16-bpc images are not supported");
				break;
			}
		}
		pdf_maskcolorkey(tile, src->n, src->colorkey, scale);
	}

	fz_decodetile(tile, !src->imagemask, src->decode);

	return fz_okay;
}
