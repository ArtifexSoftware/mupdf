#include <fitz.h>
#include <mupdf.h>

void pdf_dropimage(fz_image *fzimg)
{
	pdf_image *img = (pdf_image*)fzimg;
	fz_dropbuffer(img->samples);
	if (img->mask)
		fz_dropimage(img->mask);
}

fz_error *
pdf_loadinlineimage(pdf_image **imgp, pdf_xref *xref, fz_obj *rdb, fz_obj *dict, fz_file *file)
{
	fz_error *error;
	pdf_image *img;
	fz_filter *filter;
	fz_obj *f;
	fz_obj *cs;
	fz_obj *d;
	int ismask;
	int i;

	img = *imgp = fz_malloc(sizeof(pdf_image));
	if (!img)
		return fz_outofmem;

	img->super.loadtile = pdf_loadtile;
	img->super.drop = pdf_dropimage;
	img->super.n = 0;
	img->super.a = 0;
	img->indexed = nil;
	img->mask = nil;

	img->super.w = fz_toint(fz_dictgetsa(dict, "Width", "W"));
	img->super.h = fz_toint(fz_dictgetsa(dict, "Height", "H"));
	img->bpc = fz_toint(fz_dictgetsa(dict, "BitsPerComponent", "BPC"));
	ismask = fz_tobool(fz_dictgetsa(dict, "ImageMask", "IM"));
	d = fz_dictgetsa(dict, "Decode", "D");
	cs = fz_dictgetsa(dict, "ColorSpace", "CS");

	if (ismask)
	{
		img->super.cs = nil;
		img->super.n = 0;
		img->super.a = 1;
		img->bpc = 1;
	}

	if (cs)
	{
		img->super.cs = nil;

		if (fz_isname(cs))
		{
			fz_obj *csd = fz_dictgets(rdb, "ColorSpace");
			if (csd)
			{
				fz_obj *cso = fz_dictget(csd, cs);
				img->super.cs = pdf_findresource(xref->rcolorspace, cso);
			}
		}

		if (!img->super.cs)
		{
			error = pdf_loadcolorspace(&img->super.cs, xref, cs);
			if (error)
				return error;
		}

		if (!strcmp(img->super.cs->name, "Indexed"))
		{
			img->indexed = (pdf_indexed*)img->super.cs;
			img->super.cs = img->indexed->base;
		}

		img->super.n = img->super.cs->n;
		img->super.a = 0;
	}

	if (fz_isarray(d))
	{
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

	f = fz_dictgetsa(dict, "Filter", "F");
	if (f)
	{
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
	}
	else
	{
		error = fz_newbuffer(&img->samples, img->super.h * img->stride);
		if (error)
			return error;

		i = fz_read(file, img->samples->bp, img->super.h * img->stride);
		error = fz_ferror(file);
		if (error)
			return error;

		img->samples->wp += img->super.h * img->stride;
	}

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

	img = fz_malloc(sizeof(pdf_image));
	if (!img)
		return fz_outofmem;

	/*
	 * Dimensions, BPC and ColorSpace
	 */

	w = fz_toint(fz_dictgets(dict, "Width"));
	h = fz_toint(fz_dictgets(dict, "Height"));
	bpc = fz_toint(fz_dictgets(dict, "BitsPerComponent"));

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

	/*
	 * Create image object
	 */

	img->super.loadtile = pdf_loadtile;
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

