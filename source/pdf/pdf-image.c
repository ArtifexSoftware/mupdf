#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>

static fz_image *pdf_load_jpx(fz_context *ctx, pdf_document *doc, pdf_obj *dict, int forcemask);

static fz_image *
pdf_load_jpx_imp(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, pdf_obj *dict, fz_stream *cstm, int forcemask)
{
	fz_image *image = pdf_load_jpx(ctx, doc, dict, forcemask);

	if (forcemask)
	{
		fz_pixmap_image *cimg = (fz_pixmap_image *)image;
		fz_pixmap *mask_pixmap;
		fz_pixmap *tile = fz_pixmap_image_tile(ctx, cimg);

		if (tile->n != 1)
		{
			fz_pixmap *gray = fz_convert_pixmap(ctx, tile, fz_device_gray(ctx), 0);
			fz_drop_pixmap(ctx, tile);
			tile = gray;
		}

		mask_pixmap = fz_alpha_from_gray(ctx, tile);
		fz_drop_pixmap(ctx, tile);
		fz_set_pixmap_image_tile(ctx, cimg, mask_pixmap);
	}

	return image;
}

static fz_image *
pdf_load_image_imp(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, pdf_obj *dict, fz_stream *cstm, int forcemask)
{
	fz_image *image = NULL;
	pdf_obj *obj, *res;

	int w, h, bpc, n;
	int imagemask;
	int interpolate;
	int indexed;
	fz_image *mask = NULL; /* explicit mask/soft mask image */
	int use_colorkey = 0;
	fz_colorspace *colorspace = NULL;
	float decode[FZ_MAX_COLORS * 2];
	int colorkey[FZ_MAX_COLORS * 2];
	int stride;

	int i;
	fz_compressed_buffer *buffer;

	/* special case for JPEG2000 images */
	if (pdf_is_jpx_image(ctx, dict))
		return pdf_load_jpx_imp(ctx, doc, rdb, dict, cstm, forcemask);

	w = pdf_to_int(ctx, pdf_dict_geta(ctx, dict, PDF_NAME_Width, PDF_NAME_W));
	h = pdf_to_int(ctx, pdf_dict_geta(ctx, dict, PDF_NAME_Height, PDF_NAME_H));
	bpc = pdf_to_int(ctx, pdf_dict_geta(ctx, dict, PDF_NAME_BitsPerComponent, PDF_NAME_BPC));
	if (bpc == 0)
		bpc = 8;
	imagemask = pdf_to_bool(ctx, pdf_dict_geta(ctx, dict, PDF_NAME_ImageMask, PDF_NAME_IM));
	interpolate = pdf_to_bool(ctx, pdf_dict_geta(ctx, dict, PDF_NAME_Interpolate, PDF_NAME_I));

	indexed = 0;
	use_colorkey = 0;

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

	fz_var(mask);
	fz_var(image);
	fz_var(colorspace);

	fz_try(ctx)
	{
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

			n = fz_colorspace_n(ctx, colorspace);
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
					use_colorkey = 1;
					for (i = 0; i < n; i++)
						colorkey[i] = pdf_to_real(ctx, pdf_array_get(ctx, obj, i)) * 255;
				}
			}
		}
		else if (pdf_is_array(ctx, obj))
		{
			use_colorkey = 1;
			for (i = 0; i < n * 2; i++)
			{
				if (!pdf_is_int(ctx, pdf_array_get(ctx, obj, i)))
				{
					fz_warn(ctx, "invalid value in color key mask");
					use_colorkey = 0;
				}
				colorkey[i] = pdf_to_int(ctx, pdf_array_get(ctx, obj, i));
			}
		}

		/* Do we load from a ref, or do we load an inline stream? */
		if (cstm == NULL)
		{
			/* Just load the compressed image data now and we can decode it on demand. */
			buffer = pdf_load_compressed_stream(ctx, doc, pdf_to_num(ctx, dict));
			image = fz_new_image_from_compressed_buffer(ctx, w, h, bpc, colorspace, 96, 96, interpolate, imagemask, decode, use_colorkey ? colorkey : NULL, buffer, mask);
			image->invert_cmyk_jpeg = 0;
		}
		else
		{
			/* Inline stream */
			stride = (w * n * bpc + 7) / 8;
			image = fz_new_image_from_compressed_buffer(ctx, w, h, bpc, colorspace, 96, 96, interpolate, imagemask, decode, use_colorkey ? colorkey : NULL, NULL, mask);
			image->invert_cmyk_jpeg = 0;
			pdf_load_compressed_inline_image(ctx, doc, dict, stride * h, cstm, indexed, (fz_compressed_image *)image);
		}
	}
	fz_always(ctx)
	{
		fz_drop_colorspace(ctx, colorspace);
		fz_drop_image(ctx, mask);
	}
	fz_catch(ctx)
	{
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
	fz_image *mask = NULL;
	fz_image *img = NULL;

	fz_var(pix);
	fz_var(buf);
	fz_var(colorspace);
	fz_var(mask);

	buf = pdf_load_stream(ctx, dict);

	/* FIXME: We can't handle decode arrays for indexed images currently */
	fz_try(ctx)
	{
		unsigned char *data;
		size_t len;

		obj = pdf_dict_get(ctx, dict, PDF_NAME_ColorSpace);
		if (obj)
			colorspace = pdf_load_colorspace(ctx, doc, obj);

		len = fz_buffer_storage(ctx, buf, &data);
		pix = fz_load_jpx(ctx, data, len, colorspace);

		obj = pdf_dict_geta(ctx, dict, PDF_NAME_SMask, PDF_NAME_Mask);
		if (pdf_is_dict(ctx, obj))
		{
			if (forcemask)
				fz_warn(ctx, "Ignoring recursive JPX soft mask");
			else
				mask = pdf_load_image_imp(ctx, doc, NULL, obj, NULL, 1);
		}

		obj = pdf_dict_geta(ctx, dict, PDF_NAME_Decode, PDF_NAME_D);
		if (obj && !fz_colorspace_is_indexed(ctx, colorspace))
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
		fz_drop_image(ctx, mask);
		fz_drop_pixmap(ctx, pix);
		fz_drop_colorspace(ctx, colorspace);
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return img;
}

fz_image *
pdf_load_image(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	fz_image *image;

	if ((image = pdf_find_item(ctx, fz_drop_image_imp, dict)) != NULL)
		return image;

	image = pdf_load_image_imp(ctx, doc, NULL, dict, NULL, 0);
	pdf_store_item(ctx, dict, image, fz_image_size(ctx, image));
	return image;
}

pdf_obj *
pdf_add_image(fz_context *ctx, pdf_document *doc, fz_image *image, int mask)
{
	fz_pixmap *pixmap = NULL;
	pdf_obj *imobj = NULL;
	fz_buffer *buffer = NULL;
	pdf_obj *imref = NULL;
	fz_compressed_buffer *cbuffer;
	unsigned char digest[16];
	int n;

	/* If we can maintain compression, do so */
	cbuffer = fz_compressed_image_buffer(ctx, image);

	fz_var(pixmap);
	fz_var(buffer);
	fz_var(imobj);
	fz_var(imref);

	/* Check if the same image already exists in this doc. */
	imref = pdf_find_image_resource(ctx, doc, image, digest);
	if (imref)
		return imref;

	fz_try(ctx)
	{
		imobj = pdf_new_dict(ctx, doc, 3);
		pdf_dict_put_drop(ctx, imobj, PDF_NAME_Type, PDF_NAME_XObject);
		pdf_dict_put_drop(ctx, imobj, PDF_NAME_Subtype, PDF_NAME_Image);

		if (cbuffer)
		{
			fz_compression_params *cp = &cbuffer->params;
			switch (cp ? cp->type : FZ_IMAGE_UNKNOWN)
			{
			default:
				goto raw_or_unknown_compression;
			case FZ_IMAGE_JPEG:
				if (cp->u.jpeg.color_transform != -1)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_ColorTransform, pdf_new_int(ctx, doc, cp->u.jpeg.color_transform));
				pdf_dict_put_drop(ctx, imobj, PDF_NAME_Filter, PDF_NAME_DCTDecode);
				break;
			case FZ_IMAGE_JPX:
				if (cp->u.jpx.smask_in_data)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_SMaskInData, pdf_new_int(ctx, doc, cp->u.jpx.smask_in_data));
				pdf_dict_put_drop(ctx, imobj, PDF_NAME_Filter, PDF_NAME_JPXDecode);
				break;
			case FZ_IMAGE_FAX:
				if (cp->u.fax.columns)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_Columns, pdf_new_int(ctx, doc, cp->u.fax.columns));
				if (cp->u.fax.rows)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_Rows, pdf_new_int(ctx, doc, cp->u.fax.rows));
				if (cp->u.fax.k)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_K, pdf_new_int(ctx, doc, cp->u.fax.k));
				if (cp->u.fax.end_of_line)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_EndOfLine, pdf_new_int(ctx, doc, cp->u.fax.end_of_line));
				if (cp->u.fax.encoded_byte_align)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_EncodedByteAlign, pdf_new_int(ctx, doc, cp->u.fax.encoded_byte_align));
				if (cp->u.fax.end_of_block)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_EndOfBlock, pdf_new_int(ctx, doc, cp->u.fax.end_of_block));
				if (cp->u.fax.black_is_1)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_BlackIs1, pdf_new_int(ctx, doc, cp->u.fax.black_is_1));
				if (cp->u.fax.damaged_rows_before_error)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_DamagedRowsBeforeError, pdf_new_int(ctx, doc, cp->u.fax.damaged_rows_before_error));
				pdf_dict_put_drop(ctx, imobj, PDF_NAME_Filter, PDF_NAME_CCITTFaxDecode);
				break;
			case FZ_IMAGE_FLATE:
				if (cp->u.flate.columns)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_Columns, pdf_new_int(ctx, doc, cp->u.flate.columns));
				if (cp->u.flate.colors)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_Colors, pdf_new_int(ctx, doc, cp->u.flate.colors));
				if (cp->u.flate.predictor)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_Predictor, pdf_new_int(ctx, doc, cp->u.flate.predictor));
				pdf_dict_put_drop(ctx, imobj, PDF_NAME_Filter, PDF_NAME_FlateDecode);
				pdf_dict_put_drop(ctx, imobj, PDF_NAME_BitsPerComponent, pdf_new_int(ctx, doc, image->bpc));
				break;
			case FZ_IMAGE_LZW:
				if (cp->u.lzw.columns)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_Columns, pdf_new_int(ctx, doc, cp->u.lzw.columns));
				if (cp->u.lzw.colors)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_Colors, pdf_new_int(ctx, doc, cp->u.lzw.colors));
				if (cp->u.lzw.predictor)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_Predictor, pdf_new_int(ctx, doc, cp->u.lzw.predictor));
				if (cp->u.lzw.early_change)
					pdf_dict_put_drop(ctx, imobj, PDF_NAME_EarlyChange, pdf_new_int(ctx, doc, cp->u.lzw.early_change));
				pdf_dict_put_drop(ctx, imobj, PDF_NAME_Filter, PDF_NAME_LZWDecode);
				break;
			case FZ_IMAGE_RLD:
				pdf_dict_put_drop(ctx, imobj, PDF_NAME_Filter, PDF_NAME_RunLengthDecode);
				break;
			}
			buffer = fz_keep_buffer(ctx, cbuffer->buffer);
		}
		else
		{
			unsigned int size;
			int n, h;
			unsigned char *d, *s;

raw_or_unknown_compression:
			/* Currently, set to maintain resolution; should we consider
			 * subsampling here according to desired output res? */
			pixmap = fz_get_pixmap_from_image(ctx, image, NULL, NULL, NULL, NULL);
			n = (pixmap->n == 1 ? 1 : pixmap->n - pixmap->alpha);
			s = pixmap->samples;
			h = image->h;
			size = image->w * n;
			d = fz_malloc(ctx, size * h);
			buffer = fz_new_buffer_from_data(ctx, d, size * h);
			if (pixmap->alpha == 0 || n == 1)
			{
				while (h--)
				{
					memcpy(d, s, size);
					d += size;
					s += pixmap->stride;
				}
			}
			else
			{
				/* Need to remove the alpha plane */
				/* TODO: extract alpha plane to a soft mask */
				int pad = pixmap->stride - pixmap->w * pixmap->n;
				while (h--)
				{
					unsigned int size2 = size;
					int mod = n;
					while (size2--)
					{
						*d++ = *s++;
						mod--;
						if (mod == 0)
							s++, mod = n;
					}
					s += pad;
				}
			}
		}

		pdf_dict_put_drop(ctx, imobj, PDF_NAME_Width, pdf_new_int(ctx, doc, pixmap ? pixmap->w : image->w));
		pdf_dict_put_drop(ctx, imobj, PDF_NAME_Height, pdf_new_int(ctx, doc, pixmap ? pixmap->h : image->h));

		if (mask)
		{
			pdf_dict_put_drop(ctx, imobj, PDF_NAME_ImageMask, pdf_new_bool(ctx, doc, 1));
		}
		else
		{
			pdf_dict_put_drop(ctx, imobj, PDF_NAME_BitsPerComponent, pdf_new_int(ctx, doc, image->bpc));

			n = fz_colorspace_n(ctx, pixmap ? pixmap->colorspace : image->colorspace);
			if (n <= 1)
				pdf_dict_put_drop(ctx, imobj, PDF_NAME_ColorSpace, PDF_NAME_DeviceGray);
			else if (n == 3)
				// TODO: Lab colorspace?
				pdf_dict_put_drop(ctx, imobj, PDF_NAME_ColorSpace, PDF_NAME_DeviceRGB);
			else if (n == 4)
				pdf_dict_put_drop(ctx, imobj, PDF_NAME_ColorSpace, PDF_NAME_DeviceCMYK);
			else
				// TODO: convert to RGB!
				fz_throw(ctx, FZ_ERROR_GENERIC, "only Gray, RGB, and CMYK colorspaces supported");
		}

		if (image->mask)
		{
			pdf_dict_put_drop(ctx, imobj, PDF_NAME_SMask, pdf_add_image(ctx, doc, image->mask, 0));
		}

		imref = pdf_add_object(ctx, doc, imobj);
		pdf_update_stream(ctx, doc, imref, buffer, 1);

		/* Add ref to our image resource hash table. */
		imref = pdf_insert_image_resource(ctx, doc, digest, imref);
	}
	fz_always(ctx)
	{
		fz_drop_pixmap(ctx, pixmap);
		fz_drop_buffer(ctx, buffer);
		pdf_drop_obj(ctx, imobj);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, imref);
		fz_rethrow(ctx);
	}
	return imref;
}
