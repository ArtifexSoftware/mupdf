#include "mupdf/fitz.h"

#ifdef HAVE_LURATECH

#include <lwf_jp2.h>

typedef struct fz_jpxd_s fz_jpxd;

struct fz_jpxd_s
{
	JP2_Decomp_Handle doc;
	fz_context *ctx;
	fz_pixmap *pix;
	JP2_Palette_Params *palette;
	JP2_Colorspace colorspace;
	unsigned char *data;
	int size;
	JP2_Property_Value width;
	JP2_Property_Value height;
	fz_colorspace *cs;
	int expand_indexed;
	unsigned long xres;
	unsigned long yres;

	JP2_Property_Value nchans;
	JP2_Property_Value *widths;
	JP2_Property_Value *heights;
	JP2_Property_Value *hstep;
	JP2_Property_Value *vstep;
	JP2_Property_Value *bpss;
	JP2_Property_Value *signs;
};

static void * JP2_Callback_Conv
jpx_alloc(long size, JP2_Callback_Param param)
{
	fz_jpxd *state = (fz_jpxd *) param;
	return fz_malloc(state->ctx, size);
}

static JP2_Error JP2_Callback_Conv
jpx_free(void *ptr, JP2_Callback_Param param)
{
	fz_jpxd *state = (fz_jpxd *) param;
	fz_free(state->ctx, ptr);
	return cJP2_Error_OK;
}

static unsigned long JP2_Callback_Conv
jpx_read(unsigned char *pucData,
		unsigned long ulPos, unsigned long ulSize,
		JP2_Callback_Param param)
{
	fz_jpxd *state = (fz_jpxd *) param;

	if (ulPos >= state->size)
		return 0;

	ulSize = fz_mini(ulSize, state->size - ulPos);
	memcpy(pucData, &state->data[ulPos], ulSize);
	return ulSize;
}

static JP2_Error JP2_Callback_Conv
jpx_write(unsigned char * pucData, short sComponent, unsigned long ulRow,
		unsigned long ulStart, unsigned long ulNum, JP2_Callback_Param param)
{
	fz_jpxd *state = (fz_jpxd *) param;
	JP2_Property_Value hstep, vstep;
	unsigned char *row;
	int x, y, i;

	if (ulRow >= state->pix->h || ulStart >= state->pix->w || sComponent >= state->pix->n)
		return cJP2_Error_OK;

	ulNum = fz_mini(ulNum, state->pix->w - ulStart);
	hstep = state->hstep[sComponent];
	vstep = state->vstep[sComponent];

	if (state->palette)
	{

		row = state->pix->samples +
			state->pix->stride * ulRow * vstep +
			state->pix->n * ulStart * hstep +
			sComponent;

		for (y = 0; ulRow * vstep + y < state->pix->h && y < vstep; y++)
		{
			unsigned char *p = row;

			for (i = 0; i < ulNum; i++)
			{
				for (x = 0; (ulStart + i) * hstep + x < state->pix->w && x < hstep; x++)
				{
					unsigned char v = fz_clampi(pucData[i], 0, state->palette->ulEntries);

					if (state->expand_indexed)
					{
						int k;
						for (k = 0; k < state->pix->n; k++)
							p[k] = state->palette->ppulPalette[k][v];
						p += state->pix->n;
					}
					else
					{
						*p = v;
						p++;
					}
				}
			}

			row += state->pix->stride;
		}
	}
	else
	{
		unsigned int signedoffset;

		if (state->signs[sComponent])
			signedoffset = 1 << (state->bpss[sComponent] - 1);
		else
			signedoffset = 0;

		row = &state->pix->samples[state->pix->stride * ulRow * vstep +
			state->pix->n * ulStart * hstep +
			sComponent];

		if (state->bpss[sComponent] > 8)
		{
			for (y = 0; ulRow * vstep + y < state->pix->h && y < vstep; y++)
			{
				unsigned char *p = row;

				for (i = 0; i < ulNum; i++)
				{
					for (x = 0; (ulStart + i) * hstep + x < state->pix->w && x < hstep; x++)
					{
						unsigned int v = (pucData[2 * i + 1] << 8) | pucData[2 * i + 0];
						v &= (1 << state->bpss[sComponent]) - 1;
						v -= signedoffset;
						*p = v >> (state->bpss[sComponent] - 8);
						p += state->pix->n;
					}
				}

				row += state->pix->stride;
			}
		}
		else if (state->bpss[sComponent] == 8)
		{
			for (y = 0; ulRow * vstep + y < state->pix->h && y < vstep; y++)
			{
				unsigned char *p = row;

				for (i = 0; i < ulNum; i++)
				{
					for (x = 0; (ulStart + i) * hstep + x < state->pix->w && x < hstep; x++)
					{
						unsigned int v = pucData[i];
						v &= (1 << state->bpss[sComponent]) - 1;
						v -= signedoffset;
						*p = v;
						p += state->pix->n;
					}
				}

				row += state->pix->stride;
			}
		}
		else
		{
			for (y = 0; ulRow * vstep + y < state->pix->h && y < vstep; y++)
			{
				unsigned char *p = row;

				for (i = 0; i < ulNum; i++)
				{
					for (x = 0; (ulStart + i) * hstep + x < state->pix->w && x < hstep; x++)
					{
						unsigned int v = pucData[i];
						v &= (1 << state->bpss[sComponent]) - 1;
						v -= signedoffset;
						*p = v << (8 - state->bpss[sComponent]);
						p += state->pix->n;
					}
				}

				row += state->pix->stride;
			}
		}
	}

	return cJP2_Error_OK;
}

static void
jpx_ycc_to_rgb(fz_context *ctx, fz_jpxd *state)
{
	int x, y;

	for (y = 0; y < state->height; y++)
	{
		unsigned char * row = &state->pix->samples[state->pix->stride * y];
		for (x = 0; x < state->width; x++)
		{
			int ycc[3];
			ycc[0] = row[x * 3 + 0];
			ycc[1] = row[x * 3 + 1];
			ycc[2] = row[x * 3 + 2];

			/* conciously skip Y */
			if (!state->signs[1])
				ycc[1] -= 128;
			if (!state->signs[2])
				ycc[2] -= 128;

			row[x * 3 + 0] = fz_clampi((double)ycc[0] + 1.402 * ycc[2], 0, 255);
			row[x * 3 + 1] = fz_clampi((double)ycc[0] - 0.34413 * ycc[1] - 0.71414 * ycc[2], 0, 255);
			row[x * 3 + 2] = fz_clampi((double)ycc[0] + 1.772 * ycc[1], 0, 255);
		}
	}

}

struct indexed
{
	fz_colorspace *base;
	int high;
	unsigned char *lookup;
};

static fz_pixmap *
jpx_read_image(fz_context *ctx, fz_jpxd *state, unsigned char *data, size_t size, fz_colorspace *defcs, int indexed, int onlymeta)
{
	JP2_Channel_Def_Params *chans = NULL;
	JP2_Error err;
	int k, colors, alphas, prealphas;

	memset(state, 0x00, sizeof (fz_jpxd));
	state->ctx = ctx;
	state->data = data;
	state->size = size;

	fz_try(ctx)
	{
		err = JP2_Decompress_Start(&state->doc,
				jpx_alloc, (JP2_Callback_Param) state,
				jpx_free, (JP2_Callback_Param) state,
				jpx_read, (JP2_Callback_Param) state);
		if (err != cJP2_Error_OK)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open image: %d", (int) err);

#if defined(JP2_LICENSE_NUM_1) && defined(JP2_LICENSE_NUM_2)
		err = JP2_Document_SetLicense(state->doc, JP2_LICENSE_NUM_1, JP2_LICENSE_NUM_2);
		if (err != cJP2_Error_OK)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot set license: %d", (int) err);
#endif

		err = JP2_Decompress_GetProp(state->doc, cJP2_Prop_Extern_Colorspace, (unsigned long *) &state->colorspace, -1, -1);
		if (err != cJP2_Error_OK)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot get colorspace: %d", (int) err);

		if (state->colorspace == cJP2_Colorspace_Palette_Gray ||
				state->colorspace == cJP2_Colorspace_Palette_RGBa ||
				state->colorspace == cJP2_Colorspace_Palette_RGB_YCCa ||
				state->colorspace == cJP2_Colorspace_Palette_CIE_LABa ||
				state->colorspace == cJP2_Colorspace_Palette_ICCa ||
				state->colorspace == cJP2_Colorspace_Palette_CMYKa)
		{
			err = JP2_Decompress_GetPalette(state->doc, &state->palette);
			if (err != cJP2_Error_OK)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot get indexed palette: %d", (int) err);

			/* no available sample file */
			for (k = 0; k < state->palette->ulChannels; k++)
				if (state->palette->pucSignedSample[k])
					fz_throw(ctx, FZ_ERROR_GENERIC, "signed palette compoments not yet supported");
		}

		err = JP2_Decompress_GetChannelDefs(state->doc, &chans, &state->nchans);
		if (err != cJP2_Error_OK)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot get channel definitions: %d", (int) err);

		colors = 0;
		alphas = 0;
		prealphas = 0;
		for (k = 0; k < state->nchans; k++)
		{
			switch (chans[k].ulType)
			{
			case cJP2_Channel_Type_Color: colors++; break;
			case cJP2_Channel_Type_Opacity: alphas++; break;
			case cJP2_Channel_Type_Opacity_Pre: prealphas++; break;
			}
		}

		if (prealphas> 0)
			alphas = prealphas;
		colors = fz_clampi(colors, 0, 4);
		alphas = fz_clampi(alphas, 0, 1);

		state->nchans = colors + alphas;

		state->widths = fz_malloc(ctx, state->nchans * sizeof (JP2_Property_Value));
		state->heights = fz_malloc(ctx, state->nchans * sizeof (JP2_Property_Value));
		state->hstep = fz_malloc(ctx, state->nchans * sizeof (JP2_Property_Value));
		state->vstep = fz_malloc(ctx, state->nchans * sizeof (JP2_Property_Value));
		state->bpss = fz_malloc(ctx, state->nchans * sizeof (JP2_Property_Value));
		state->signs = fz_malloc(ctx, state->nchans * sizeof (JP2_Property_Value));

		if (state->palette)
		{
			err = JP2_Decompress_GetProp(state->doc, cJP2_Prop_Width, &state->width, -1, 0);
			if (err != cJP2_Error_OK)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot get width for palette indicies: %d", (int) err);
			err = JP2_Decompress_GetProp(state->doc, cJP2_Prop_Height, &state->height, -1, 0);
			if (err != cJP2_Error_OK)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot get height for palette indicies: %d", (int) err);

			for (k = 0; k < state->nchans; k++)
			{
				state->widths[k] = state->width;
				state->heights[k] = state->height;
				state->bpss[k] = state->palette->pucBitsPerSample[k];
				state->signs[k] = state->palette->pucSignedSample[k];
			}
		}
		else
		{
			for (k = 0; k < state->nchans; k++)
			{
				err = JP2_Decompress_GetProp(state->doc, cJP2_Prop_Width, &state->widths[k], -1, k);
				if (err != cJP2_Error_OK)
					fz_throw(ctx, FZ_ERROR_GENERIC, "cannot get width for compoment %d: %d", k, (int) err);
				err = JP2_Decompress_GetProp(state->doc, cJP2_Prop_Height, &state->heights[k], -1, k);
				if (err != cJP2_Error_OK)
					fz_throw(ctx, FZ_ERROR_GENERIC, "cannot get height for compomment %d: %d", k, (int) err);
				err = JP2_Decompress_GetProp(state->doc, cJP2_Prop_Bits_Per_Sample, &state->bpss[k], -1, k);
				if (err != cJP2_Error_OK)
					fz_throw(ctx, FZ_ERROR_GENERIC, "cannot get bits per sample for compomment %d: %d", k, (int) err);
				err = JP2_Decompress_GetProp(state->doc, cJP2_Prop_Signed_Samples, &state->signs[k], -1, k);
				if (err != cJP2_Error_OK)
					fz_throw(ctx, FZ_ERROR_GENERIC, "cannot get signed for compomment %d: %d", k, (int) err);

				state->width = fz_maxi(state->width, state->widths[k]);
				state->height = fz_maxi(state->height, state->heights[k]);
			}
		}

		for (k = 0; k < state->nchans; k++)
		{
			state->hstep[k] = (state->width + (state->widths[k] - 1)) / state->widths[k];
			state->vstep[k] = (state->height + (state->heights[k] - 1)) / state->heights[k];
		}

		err = JP2_Decompress_GetResolution(state->doc, &state->yres, &state->xres, NULL,
				cJP2_Resolution_Dots_Per_Inch, cJP2_Resolution_Capture);
		if (err != cJP2_Error_OK)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot get resolution: %d", (int) err);

		if (state->xres == 0 || state->yres == 0)
			state->xres = state->yres = 72;

		if (defcs)
		{
			if (defcs->n == state->nchans)
			{
				state->cs = defcs;
			}
			else
			{
				fz_warn(ctx, "jpx file (%lu) and dict colorspace (%d, %s) do not match", state->nchans, defcs->n, defcs->name);
				defcs = NULL;
			}
		}

		if (!defcs)
		{
			switch (colors)
			{
			case 4: state->cs = fz_device_cmyk(ctx); break;
			case 3: if (state->colorspace == cJP2_Colorspace_CIE_LABa)
					state->cs = fz_device_lab(ctx);
				else
					state->cs = fz_device_rgb(ctx);
				break;
			case 1: state->cs = fz_device_gray(ctx); break;
			case 0: if (alphas == 1)
				{
					/* alpha only images are rendered as grayscale */
					state->cs = fz_device_gray(ctx);
					colors = 1;
					alphas = 0;
					break;
				}
				/* fallthrough */
			default: fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported number of components: %lu", state->nchans);
			}
		}

		if (state->palette && !fz_colorspace_is_indexed(ctx, state->cs))
			state->expand_indexed = 1;

		if (!onlymeta)
		{
			state->pix = fz_new_pixmap(ctx, state->cs, state->width, state->height, alphas);
			fz_clear_pixmap_with_value(ctx, state->pix, 0);

			err = JP2_Decompress_SetProp(state->doc, cJP2_Prop_Output_Parameter, (JP2_Property_Value) state);
			if (err != cJP2_Error_OK)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot set write callback userdata: %d", (int) err);
			err = JP2_Decompress_SetProp(state->doc, cJP2_Prop_Output_Function, (JP2_Property_Value) jpx_write);
			if (err != cJP2_Error_OK)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot set write callback: %d", (int) err);

			err = JP2_Decompress_Image(state->doc);
			if (err != cJP2_Error_OK)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot decode image: %d", (int) err);

			if (state->colorspace == cJP2_Colorspace_RGB_YCCa)
				jpx_ycc_to_rgb(ctx, state);

			if (state->pix->alpha && ! (state->palette && !state->expand_indexed))
			{
				if (state->pix->n == 5)
				{
					fz_pixmap *tmp = fz_new_pixmap(ctx, fz_device_rgb(ctx), state->pix->w, state->pix->h, 1);
					fz_convert_pixmap(ctx, tmp, state->pix);
					fz_drop_pixmap(ctx, state->pix);
					state->pix = tmp;
				}

				if (alphas > 0 && prealphas == 0)
					fz_premultiply_pixmap(ctx, state->pix);
			}

		}
	}
	fz_always(ctx)
	{
		JP2_Decompress_End(state->doc);
		fz_free(ctx, state->signs);
		fz_free(ctx, state->widths);
		fz_free(ctx, state->heights);
		fz_free(ctx, state->hstep);
		fz_free(ctx, state->vstep);
		fz_free(ctx, state->bpss);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return state->pix;
}

fz_pixmap *
fz_load_jpx(fz_context *ctx, unsigned char *data, size_t size, fz_colorspace *defcs, int indexed)
{
	fz_jpxd state = { 0 };

	return jpx_read_image(ctx, &state, data, size, defcs, indexed, 0);
}

void
fz_load_jpx_info(fz_context *ctx, unsigned char *data, size_t size, int *wp, int *hp, int *xresp, int *yresp, fz_colorspace **cspacep)
{
	fz_jpxd state = { 0 };

	jpx_read_image(ctx, &state, data, size, NULL, 0, 1);

	*cspacep = state.cs;
	*wp = state.width;
	*hp = state.height;
	*xresp = state.xres;
	*yresp = state.yres;
}

#else /* HAVE_LURATECH */

/* Without the definition of OPJ_STATIC, compilation fails on windows
 * due to the use of __stdcall. We believe it is required on some
 * linux toolchains too. */
#define OPJ_STATIC
#ifndef _MSC_VER
#define OPJ_HAVE_STDINT_H
#endif

#include <openjpeg.h>

static void fz_opj_error_callback(const char *msg, void *client_data)
{
	fz_context *ctx = (fz_context *)client_data;
	fz_warn(ctx, "openjpeg error: %s", msg);
}

static void fz_opj_warning_callback(const char *msg, void *client_data)
{
	fz_context *ctx = (fz_context *)client_data;
	fz_warn(ctx, "openjpeg warning: %s", msg);
}

static void fz_opj_info_callback(const char *msg, void *client_data)
{
	/* fz_warn("openjpeg info: %s", msg); */
}

typedef struct stream_block_s
{
	unsigned char *data;
	OPJ_SIZE_T size;
	OPJ_SIZE_T pos;
} stream_block;

static OPJ_SIZE_T fz_opj_stream_read(void * p_buffer, OPJ_SIZE_T p_nb_bytes, void * p_user_data)
{
	stream_block *sb = (stream_block *)p_user_data;
	OPJ_SIZE_T len;

	len = sb->size - sb->pos;
	if (len == 0)
		return (OPJ_SIZE_T)-1; /* End of file! */
	if (len > p_nb_bytes)
		len = p_nb_bytes;
	memcpy(p_buffer, sb->data + sb->pos, len);
	sb->pos += len;
	return len;
}

static OPJ_OFF_T fz_opj_stream_skip(OPJ_OFF_T skip, void * p_user_data)
{
	stream_block *sb = (stream_block *)p_user_data;

	if (skip > (OPJ_OFF_T)(sb->size - sb->pos))
		skip = (OPJ_OFF_T)(sb->size - sb->pos);
	sb->pos += skip;
	return sb->pos;
}

static OPJ_BOOL fz_opj_stream_seek(OPJ_OFF_T seek_pos, void * p_user_data)
{
	stream_block *sb = (stream_block *)p_user_data;

	if (seek_pos > (OPJ_OFF_T)sb->size)
		return OPJ_FALSE;
	sb->pos = seek_pos;
	return OPJ_TRUE;
}

static fz_pixmap *
jpx_read_image(fz_context *ctx, unsigned char *data, size_t size, fz_colorspace *defcs, int indexed, int onlymeta)
{
	fz_pixmap *img;
	opj_dparameters_t params;
	opj_codec_t *codec;
	opj_image_t *jpx;
	opj_stream_t *stream;
	fz_colorspace *colorspace;
	unsigned char *p;
	OPJ_CODEC_FORMAT format;
	int a, n, w, h, depth, sgnd;
	int x, y, k, v, stride;
	stream_block sb;

	if (size < 2)
		fz_throw(ctx, FZ_ERROR_GENERIC, "not enough data to determine image format");

	/* Check for SOC marker -- if found we have a bare J2K stream */
	if (data[0] == 0xFF && data[1] == 0x4F)
		format = OPJ_CODEC_J2K;
	else
		format = OPJ_CODEC_JP2;

	opj_set_default_decoder_parameters(&params);
	if (indexed)
		params.flags |= OPJ_DPARAMETERS_IGNORE_PCLR_CMAP_CDEF_FLAG;

	codec = opj_create_decompress(format);
	opj_set_info_handler(codec, fz_opj_info_callback, ctx);
	opj_set_warning_handler(codec, fz_opj_warning_callback, ctx);
	opj_set_error_handler(codec, fz_opj_error_callback, ctx);
	if (!opj_setup_decoder(codec, &params))
	{
		opj_destroy_codec(codec);
		fz_throw(ctx, FZ_ERROR_GENERIC, "j2k decode failed");
	}

	stream = opj_stream_default_create(OPJ_TRUE);
	sb.data = data;
	sb.pos = 0;
	sb.size = size;

	opj_stream_set_read_function(stream, fz_opj_stream_read);
	opj_stream_set_skip_function(stream, fz_opj_stream_skip);
	opj_stream_set_seek_function(stream, fz_opj_stream_seek);
	opj_stream_set_user_data(stream, &sb, NULL);
	/* Set the length to avoid an assert */
	opj_stream_set_user_data_length(stream, size);

	if (!opj_read_header(stream, codec, &jpx))
	{
		opj_stream_destroy(stream);
		opj_destroy_codec(codec);
		fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to read JPX header");
	}

	if (!opj_decode(codec, stream, jpx))
	{
		opj_stream_destroy(stream);
		opj_destroy_codec(codec);
		opj_image_destroy(jpx);
		fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to decode JPX image");
	}

	opj_stream_destroy(stream);
	opj_destroy_codec(codec);

	/* jpx should never be NULL here, but check anyway */
	if (!jpx)
		fz_throw(ctx, FZ_ERROR_GENERIC, "opj_decode failed");

	for (k = 1; k < (int)jpx->numcomps; k++)
	{
		if (!jpx->comps[k].data)
		{
			opj_image_destroy(jpx);
			fz_throw(ctx, FZ_ERROR_GENERIC, "image components are missing data");
		}
		if (jpx->comps[k].w != jpx->comps[0].w)
		{
			opj_image_destroy(jpx);
			fz_throw(ctx, FZ_ERROR_GENERIC, "image components have different width");
		}
		if (jpx->comps[k].h != jpx->comps[0].h)
		{
			opj_image_destroy(jpx);
			fz_throw(ctx, FZ_ERROR_GENERIC, "image components have different height");
		}
		if (jpx->comps[k].prec != jpx->comps[0].prec)
		{
			opj_image_destroy(jpx);
			fz_throw(ctx, FZ_ERROR_GENERIC, "image components have different precision");
		}
	}

	n = jpx->numcomps;
	w = jpx->comps[0].w;
	h = jpx->comps[0].h;
	depth = jpx->comps[0].prec;
	sgnd = jpx->comps[0].sgnd;

	if (jpx->color_space == OPJ_CLRSPC_SRGB && n == 4) { n = 3; a = 1; }
	else if (jpx->color_space == OPJ_CLRSPC_SYCC && n == 4) { n = 3; a = 1; }
	else if (n == 2) { n = 1; a = 1; }
	else if (n > 4) { n = 4; a = 1; }
	else { a = 0; }

	if (defcs)
	{
		if (defcs->n == n)
		{
			colorspace = defcs;
		}
		else
		{
			fz_warn(ctx, "jpx file and dict colorspace do not match");
			defcs = NULL;
		}
	}

	if (!defcs)
	{
		switch (n)
		{
		case 1: colorspace = fz_device_gray(ctx); break;
		case 3: colorspace = fz_device_rgb(ctx); break;
		case 4: colorspace = fz_device_cmyk(ctx); break;
		default: fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported number of components: %d", n);
		}
	}

	fz_try(ctx)
	{
		img = fz_new_pixmap(ctx, colorspace, w, h, a);
	}
	fz_catch(ctx)
	{
		opj_image_destroy(jpx);
		fz_rethrow(ctx);
	}

	if (!onlymeta)
	{
		p = img->samples;
		stride = img->stride - w * (n + a);
		for (y = 0; y < h; y++)
		{
			for (x = 0; x < w; x++)
			{
				for (k = 0; k < n + a; k++)
				{
					v = jpx->comps[k].data[y * w + x];
					if (sgnd)
						v = v + (1 << (depth - 1));
					if (depth > 8)
						v = v >> (depth - 8);
					else if (depth < 8)
						v = v << (8 - depth);
					*p++ = v;
				}
			}
			p += stride;
		}

		if (a)
		{
			if (n == 4)
			{
				fz_pixmap *tmp = fz_new_pixmap(ctx, fz_device_rgb(ctx), w, h, 1);
				fz_convert_pixmap(ctx, tmp, img);
				fz_drop_pixmap(ctx, img);
				img = tmp;
			}
			fz_premultiply_pixmap(ctx, img);
		}
	}

	opj_image_destroy(jpx);

	return img;
}

fz_pixmap *
fz_load_jpx(fz_context *ctx, unsigned char *data, size_t size, fz_colorspace *defcs, int indexed)
{
	return jpx_read_image(ctx, data, size, defcs, indexed, 0);
}

void
fz_load_jpx_info(fz_context *ctx, unsigned char *data, size_t size, int *wp, int *hp, int *xresp, int *yresp, fz_colorspace **cspacep)
{
	fz_pixmap *img = jpx_read_image(ctx, data, size, NULL, 0, 1);

	*cspacep = fz_keep_colorspace(ctx, img->colorspace);
	*wp = img->w;
	*hp = img->h;
	*xresp = 72; /* openjpeg does not read the JPEG 2000 resc box */
	*yresp = 72; /* openjpeg does not read the JPEG 2000 resc box */
}

#endif /* HAVE_LURATECH */
