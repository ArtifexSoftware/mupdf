#include "mupdf/pdf.h"

static fz_image *pdf_load_jpx(fz_context *ctx, pdf_document *doc, pdf_obj *dict, int forcemask);

static fz_image *
pdf_load_image_imp(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, pdf_obj *dict, fz_stream *cstm, int forcemask)
{
	fz_stream *stm = NULL;
	fz_image *image = NULL;
	pdf_obj *obj, *res;

	int w, h, bpc, n;
	int imagemask;
	int interpolate;
	int indexed;
	fz_image *mask = NULL; /* explicit mask/soft mask image */
	int usecolorkey = 0;
	fz_colorspace *colorspace = NULL;
	float decode[FZ_MAX_COLORS * 2];
	int colorkey[FZ_MAX_COLORS * 2];
	int stride;

	int i;
	fz_compressed_buffer *buffer;

	fz_var(stm);
	fz_var(mask);
	fz_var(image);
	fz_var(colorspace);

	fz_try(ctx)
	{
		/* special case for JPEG2000 images */
		if (pdf_is_jpx_image(ctx, dict))
		{
			image = pdf_load_jpx(ctx, doc, dict, forcemask);

			if (forcemask)
			{
				fz_pixmap *mask_pixmap;
				if (image->n != 2)
				{
					fz_pixmap *gray;
					fz_irect bbox;
					fz_warn(ctx, "soft mask should be grayscale");
					gray = fz_new_pixmap_with_bbox(ctx, fz_device_gray(ctx), fz_pixmap_bbox(ctx, image->tile, &bbox));
					fz_convert_pixmap(ctx, gray, image->tile);
					fz_drop_pixmap(ctx, image->tile);
					image->tile = gray;
				}
				mask_pixmap = fz_alpha_from_gray(ctx, image->tile, 1);
				fz_drop_pixmap(ctx, image->tile);
				image->tile = mask_pixmap;
			}
			break; /* Out of fz_try */
		}

		w = pdf_to_int(ctx, pdf_dict_geta(ctx, dict, PDF_NAME_Width, PDF_NAME_W));
		h = pdf_to_int(ctx, pdf_dict_geta(ctx, dict, PDF_NAME_Height, PDF_NAME_H));
		bpc = pdf_to_int(ctx, pdf_dict_geta(ctx, dict, PDF_NAME_BitsPerComponent, PDF_NAME_BPC));
		if (bpc == 0)
			bpc = 8;
		imagemask = pdf_to_bool(ctx, pdf_dict_geta(ctx, dict, PDF_NAME_ImageMask, PDF_NAME_IM));
		interpolate = pdf_to_bool(ctx, pdf_dict_geta(ctx, dict, PDF_NAME_Interpolate, PDF_NAME_I));

		indexed = 0;
		usecolorkey = 0;

		if (imagemask)
			bpc = 1;

		if (w <= 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "image width is zero (or less)");
		if (h <= 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "image height is zero (or less)");
		if (bpc <= 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "image depth is zero (or less)");
		if (bpc > 16)
			fz_throw(ctx, FZ_ERROR_GENERIC, "image depth is too large: %d", bpc);
		if (w > (1 << 16))
			fz_throw(ctx, FZ_ERROR_GENERIC, "image is too wide");
		if (h > (1 << 16))
			fz_throw(ctx, FZ_ERROR_GENERIC, "image is too high");

		obj = pdf_dict_geta(ctx, dict, PDF_NAME_ColorSpace, PDF_NAME_CS);
		if (obj && !imagemask && !forcemask)
		{
			/* colorspace resource lookup is only done for inline images */
			if (pdf_is_name(ctx, obj))
			{
				res = pdf_dict_get(ctx, pdf_dict_get(ctx, rdb, PDF_NAME_ColorSpace), obj);
				if (res)
					obj = res;
			}

			colorspace = pdf_load_colorspace(ctx, doc, obj);
			indexed = fz_colorspace_is_indexed(ctx, colorspace);

			n = colorspace->n;
		}
		else
		{
			n = 1;
		}

		obj = pdf_dict_geta(ctx, dict, PDF_NAME_Decode, PDF_NAME_D);
		if (obj)
		{
			for (i = 0; i < n * 2; i++)
				decode[i] = pdf_to_real(ctx, pdf_array_get(ctx, obj, i));
		}
		else
		{
			float maxval = indexed ? (1 << bpc) - 1 : 1;
			for (i = 0; i < n * 2; i++)
				decode[i] = i & 1 ? maxval : 0;
		}

		obj = pdf_dict_geta(ctx, dict, PDF_NAME_SMask, PDF_NAME_Mask);
		if (pdf_is_dict(ctx, obj))
		{
			/* Not allowed for inline images or soft masks */
			if (cstm)
				fz_warn(ctx, "Ignoring invalid inline image soft mask");
			else if (forcemask)
				fz_warn(ctx, "Ignoring recursive image soft mask");
			else
			{
				mask = pdf_load_image_imp(ctx, doc, rdb, obj, NULL, 1);
				obj = pdf_dict_get(ctx, obj, PDF_NAME_Matte);
				if (pdf_is_array(ctx, obj))
				{
					usecolorkey = 1;
					for (i = 0; i < n; i++)
						colorkey[i] = pdf_to_real(ctx, pdf_array_get(ctx, obj, i)) * 255;
				}
			}
		}
		else if (pdf_is_array(ctx, obj))
		{
			usecolorkey = 1;
			for (i = 0; i < n * 2; i++)
			{
				if (!pdf_is_int(ctx, pdf_array_get(ctx, obj, i)))
				{
					fz_warn(ctx, "invalid value in color key mask");
					usecolorkey = 0;
				}
				colorkey[i] = pdf_to_int(ctx, pdf_array_get(ctx, obj, i));
			}
		}

		/* Do we load from a ref, or do we load an inline stream? */
		if (cstm == NULL)
		{
			/* Just load the compressed image data now and we can
			 * decode it on demand. */
			int num = pdf_to_num(ctx, dict);
			int gen = pdf_to_gen(ctx, dict);
			buffer = pdf_load_compressed_stream(ctx, doc, num, gen);
			image = fz_new_image(ctx, w, h, bpc, colorspace, 96, 96, interpolate, imagemask, decode, usecolorkey ? colorkey : NULL, buffer, mask);
		}
		else
		{
			/* Inline stream */
			stride = (w * n * bpc + 7) / 8;
			image = fz_new_image(ctx, w, h, bpc, colorspace, 96, 96, interpolate, imagemask, decode, usecolorkey ? colorkey : NULL, NULL, mask);
			pdf_load_compressed_inline_image(ctx, doc, dict, stride * h, cstm, indexed, image);
		}

	}
	fz_catch(ctx)
	{
		fz_drop_colorspace(ctx, colorspace);
		fz_drop_image(ctx, mask);
		fz_drop_image(ctx, image);
		fz_rethrow(ctx);
	}
	return image;
}

fz_image *
pdf_load_inline_image(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, pdf_obj *dict, fz_stream *file)
{
	return pdf_load_image_imp(ctx, doc, rdb, dict, file, 0);
}

int
pdf_is_jpx_image(fz_context *ctx, pdf_obj *dict)
{
	pdf_obj *filter;
	int i, n;

	filter = pdf_dict_get(ctx, dict, PDF_NAME_Filter);
	if (pdf_name_eq(ctx, filter, PDF_NAME_JPXDecode))
		return 1;
	n = pdf_array_len(ctx, filter);
	for (i = 0; i < n; i++)
		if (pdf_name_eq(ctx, pdf_array_get(ctx, filter, i), PDF_NAME_JPXDecode))
			return 1;
	return 0;
}

static fz_image *
pdf_load_jpx(fz_context *ctx, pdf_document *doc, pdf_obj *dict, int forcemask)
{
	fz_buffer *buf = NULL;
	fz_colorspace *colorspace = NULL;
	fz_pixmap *pix = NULL;
	pdf_obj *obj;
	int indexed = 0;
	fz_image *mask = NULL;
	fz_image *img = NULL;

	fz_var(pix);
	fz_var(buf);
	fz_var(colorspace);
	fz_var(mask);

	buf = pdf_load_stream(ctx, doc, pdf_to_num(ctx, dict), pdf_to_gen(ctx, dict));

	/* FIXME: We can't handle decode arrays for indexed images currently */
	fz_try(ctx)
	{
		obj = pdf_dict_get(ctx, dict, PDF_NAME_ColorSpace);
		if (obj)
		{
			colorspace = pdf_load_colorspace(ctx, doc, obj);
			indexed = fz_colorspace_is_indexed(ctx, colorspace);
		}

		pix = fz_load_jpx(ctx, buf->data, buf->len, colorspace, indexed);

		obj = pdf_dict_geta(ctx, dict, PDF_NAME_SMask, PDF_NAME_Mask);
		if (pdf_is_dict(ctx, obj))
		{
			if (forcemask)
				fz_warn(ctx, "Ignoring recursive JPX soft mask");
			else
				mask = pdf_load_image_imp(ctx, doc, NULL, obj, NULL, 1);
		}

		obj = pdf_dict_geta(ctx, dict, PDF_NAME_Decode, PDF_NAME_D);
		if (obj && !indexed)
		{
			float decode[FZ_MAX_COLORS * 2];
			int i;

			for (i = 0; i < pix->n * 2; i++)
				decode[i] = pdf_to_real(ctx, pdf_array_get(ctx, obj, i));

			fz_decode_tile(ctx, pix, decode);
		}

		img = fz_new_image_from_pixmap(ctx, pix, mask);
	}
	fz_always(ctx)
	{
		fz_drop_colorspace(ctx, colorspace);
		fz_drop_buffer(ctx, buf);
		fz_drop_pixmap(ctx, pix);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return img;
}

static int
fz_image_size(fz_context *ctx, fz_image *im)
{
	if (im == NULL)
		return 0;
	return sizeof(*im) + fz_pixmap_size(ctx, im->tile) + (im->buffer && im->buffer->buffer ? im->buffer->buffer->cap : 0);
}

fz_image *
pdf_load_image(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	fz_image *image;

	if ((image = pdf_find_item(ctx, fz_drop_image_imp, dict)) != NULL)
	{
		return (fz_image *)image;
	}

	image = pdf_load_image_imp(ctx, doc, NULL, dict, NULL, 0);

	pdf_store_item(ctx, dict, image, fz_image_size(ctx, image));

	return (fz_image *)image;
}
