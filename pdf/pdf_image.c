#include "fitz.h"
#include "mupdf.h"

/* TODO: store JPEG compressed samples */
/* TODO: store flate compressed samples */

static fz_pixmap *pdf_load_jpx_image(pdf_xref *xref, fz_obj *dict);

static void
pdf_mask_color_key(fz_pixmap *pix, int n, int *colorkey)
{
	unsigned char *p = pix->samples;
	int len = pix->w * pix->h;
	int k, t;
	while (len--)
	{
		t = 1;
		for (k = 0; k < n; k++)
			if (p[k] < colorkey[k * 2] || p[k] > colorkey[k * 2 + 1])
				t = 0;
		if (t)
			for (k = 0; k < pix->n; k++)
				p[k] = 0;
		p += pix->n;
	}
}

static fz_pixmap *
pdf_load_image_imp(pdf_xref *xref, fz_obj *rdb, fz_obj *dict, fz_stream *cstm, int forcemask)
{
	fz_stream * volatile stm = NULL;
	fz_pixmap * volatile tile = NULL;
	fz_obj *obj, *res;

	int w, h, bpc, n;
	int imagemask;
	int interpolate;
	int indexed;
	fz_colorspace * volatile colorspace = NULL;
	fz_pixmap * volatile mask = NULL; /* explicit mask/softmask image */
	int usecolorkey;
	int colorkey[FZ_MAX_COLORS * 2];
	float decode[FZ_MAX_COLORS * 2];

	int stride;
	unsigned char * volatile samples = NULL;
	int i, len;
	fz_context *ctx = xref->ctx;

	fz_try(ctx)
	{
		/* special case for JPEG2000 images */
		if (pdf_is_jpx_image(ctx, dict))
		{
			tile = pdf_load_jpx_image(xref, dict);
			/* RJW: "cannot load jpx image" */
			if (forcemask)
			{
				if (tile->n != 2)
					fz_throw(ctx, "softmask must be grayscale");
				mask = fz_alpha_from_gray(ctx, tile, 1);
				fz_drop_pixmap(ctx, tile);
				tile = mask;
				mask = NULL;
			}
			break; /* Out of fz_try */
		}

		w = fz_to_int(fz_dict_getsa(dict, "Width", "W"));
		h = fz_to_int(fz_dict_getsa(dict, "Height", "H"));
		bpc = fz_to_int(fz_dict_getsa(dict, "BitsPerComponent", "BPC"));
		imagemask = fz_to_bool(fz_dict_getsa(dict, "ImageMask", "IM"));
		interpolate = fz_to_bool(fz_dict_getsa(dict, "Interpolate", "I"));

		indexed = 0;
		usecolorkey = 0;
		mask = NULL;

		if (imagemask)
			bpc = 1;

		if (w == 0)
			fz_throw(ctx, "image width is zero");
		if (h == 0)
			fz_throw(ctx, "image height is zero");
		if (bpc == 0)
			fz_throw(ctx, "image depth is zero");
		if (bpc > 16)
			fz_throw(ctx, "image depth is too large: %d", bpc);
		if (w > (1 << 16))
			fz_throw(ctx, "image is too wide");
		if (h > (1 << 16))
			fz_throw(ctx, "image is too high");

		obj = fz_dict_getsa(dict, "ColorSpace", "CS");
		if (obj && !imagemask && !forcemask)
		{
			/* colorspace resource lookup is only done for inline images */
			if (fz_is_name(obj))
			{
				res = fz_dict_get(fz_dict_gets(rdb, "ColorSpace"), obj);
				if (res)
					obj = res;
			}

			colorspace = pdf_load_colorspace(xref, obj);
			/* RJW: "cannot load image colorspace" */

			if (!strcmp(colorspace->name, "Indexed"))
				indexed = 1;

			n = colorspace->n;
		}
		else
		{
			n = 1;
		}

		obj = fz_dict_getsa(dict, "Decode", "D");
		if (obj)
		{
			for (i = 0; i < n * 2; i++)
				decode[i] = fz_to_real(fz_array_get(obj, i));
		}
		else
		{
			float maxval = indexed ? (1 << bpc) - 1 : 1;
			for (i = 0; i < n * 2; i++)
				decode[i] = i & 1 ? maxval : 0;
		}

		obj = fz_dict_getsa(dict, "SMask", "Mask");
		if (fz_is_dict(obj))
		{
			/* Not allowed for inline images */
			if (!cstm)
			{
				mask = pdf_load_image_imp(xref, rdb, obj, NULL, 1);
				/* RJW: "cannot load image mask/softmask" */
			}
		}
		else if (fz_is_array(obj))
		{
			usecolorkey = 1;
			for (i = 0; i < n * 2; i++)
				colorkey[i] = fz_to_int(fz_array_get(obj, i));
		}

		/* Allocate now, to fail early if we run out of memory */
		tile = fz_new_pixmap_with_limit(ctx, colorspace, w, h);
		if (!tile)
		{
			fz_throw(ctx, "out of memory");
		}

		if (colorspace)
		{
			fz_drop_colorspace(ctx, colorspace);
			colorspace = NULL;
		}

		tile->mask = mask;
		mask = NULL;
		tile->interpolate = interpolate;

		stride = (w * n * bpc + 7) / 8;

		if (cstm)
		{
			stm = pdf_open_inline_stream(cstm, xref, dict, stride * h);
		}
		else
		{
			stm = pdf_open_stream(xref, fz_to_num(dict), fz_to_gen(dict));
			/* RJW: "cannot open image data stream (%d 0 R)", fz_to_num(dict) */
		}

		samples = fz_malloc_array(ctx, h, stride);

		len = fz_read(stm, samples, h * stride);
		if (len < 0)
		{
			fz_throw(ctx, "cannot read image data");
		}

		/* Make sure we read the EOF marker (for inline images only) */
		if (cstm)
		{
			unsigned char tbuf[512];
			int tlen = fz_read(stm, tbuf, sizeof tbuf);
			if (tlen < 0)
				fz_error_handle(tlen, "ignoring error at end of image");
			if (tlen > 0)
				fz_warn(ctx, "ignoring garbage at end of image");
		}

		fz_close(stm);
		stm = NULL;

		/* Pad truncated images */
		if (len < stride * h)
		{
			fz_warn(ctx, "padding truncated image (%d 0 R)", fz_to_num(dict));
			memset(samples + len, 0, stride * h - len);
		}

		/* Invert 1-bit image masks */
		if (imagemask)
		{
			/* 0=opaque and 1=transparent so we need to invert */
			unsigned char *p = samples;
			len = h * stride;
			for (i = 0; i < len; i++)
				p[i] = ~p[i];
		}

		fz_unpack_tile(tile, samples, n, bpc, stride, indexed);

		fz_free(ctx, samples);
		samples = NULL;

		if (usecolorkey)
			pdf_mask_color_key(tile, n, colorkey);

		if (indexed)
		{
			fz_pixmap *conv;
			fz_decode_indexed_tile(tile, decode, (1 << bpc) - 1);
			conv = pdf_expand_indexed_pixmap(ctx, tile);
			fz_drop_pixmap(ctx, tile);
			tile = conv;
		}
		else
		{
			fz_decode_tile(tile, decode);
		}
	}
	fz_catch(ctx)
	{
		if (colorspace)
			fz_drop_colorspace(ctx, colorspace);
		if (mask)
			fz_drop_pixmap(ctx, mask);
		if (tile)
			fz_drop_pixmap(ctx, tile);
		fz_close(stm);
		fz_free(ctx, samples);

		fz_rethrow(ctx);
	}

	return tile;
}

fz_pixmap *
pdf_load_inline_image(pdf_xref *xref, fz_obj *rdb, fz_obj *dict, fz_stream *file)
{
	return pdf_load_image_imp(xref, rdb, dict, file, 0);
	/* RJW: "cannot load inline image" */
}

int
pdf_is_jpx_image(fz_context *ctx, fz_obj *dict)
{
	fz_obj *filter;
	int i, n;

	filter = fz_dict_gets(dict, "Filter");
	if (!strcmp(fz_to_name(filter), "JPXDecode"))
		return 1;
	n = fz_array_len(filter);
	for (i = 0; i < n; i++)
		if (!strcmp(fz_to_name(fz_array_get(filter, i)), "JPXDecode"))
			return 1;
	return 0;
}

static fz_pixmap *
pdf_load_jpx_image(pdf_xref *xref, fz_obj *dict)
{
	fz_buffer * volatile buf = NULL;
	fz_colorspace * volatile colorspace = NULL;
	fz_pixmap *img;
	fz_obj *obj;
	fz_context *ctx = xref->ctx;

	buf = pdf_load_stream(xref, fz_to_num(dict), fz_to_gen(dict));
	/* RJW: "cannot load jpx image data" */

	fz_try(ctx)
	{
		obj = fz_dict_gets(dict, "ColorSpace");
		if (obj)
		{
			colorspace = pdf_load_colorspace(xref, obj);
			/* RJW: "cannot load image colorspace" */
		}

		img = fz_load_jpx_image(ctx, buf->data, buf->len, colorspace);
		/* RJW: "cannot load jpx image" */

		if (colorspace)
			fz_drop_colorspace(ctx, colorspace);
		fz_drop_buffer(ctx, buf);

		obj = fz_dict_getsa(dict, "SMask", "Mask");
		if (fz_is_dict(obj))
		{
			img->mask = pdf_load_image_imp(xref, NULL, obj, NULL, 1);
			/* RJW: "cannot load image mask/softmask" */
		}
	}
	fz_catch(ctx)
	{
		if (colorspace)
			fz_drop_colorspace(ctx, colorspace);
		fz_drop_buffer(ctx, buf);
		fz_drop_pixmap(ctx, img);
	}
	return img;
}

fz_pixmap *
pdf_load_image(pdf_xref *xref, fz_obj *dict)
{
	fz_context *ctx = xref->ctx;
	fz_pixmap *pix;

	if ((pix = pdf_find_item(ctx, xref->store, (pdf_store_drop_fn *)fz_drop_pixmap, dict)))
	{
		return fz_keep_pixmap(pix);
	}

	pix = pdf_load_image_imp(xref, NULL, dict, NULL, 0);
	/* RJW: "cannot load image (%d 0 R)", fz_to_num(dict) */

	pdf_store_item(ctx, xref->store, (pdf_store_keep_fn *)fz_keep_pixmap, (pdf_store_drop_fn *)fz_drop_pixmap, dict, pix);

	return pix;
}
