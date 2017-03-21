#include "mupdf/fitz.h"
#include "lcms2.h"
#include "lcms2_plugin.h"
#include "colorspace-imp.h"
#include "mupdf/fitz/color-lcms.h"

#define LCMS_BYTES_MASK 0x7

static void
fz_cmm_error(cmsContext id, cmsUInt32Number error_code, const char *error_text)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	fz_warn(ctx, "lcms error: %s", error_text);
}

static void
*fz_cmm_malloc(cmsContext id, unsigned int size)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	return fz_malloc_no_throw(ctx, size);
}

static void
fz_cmm_free(cmsContext id, void *ptr)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	fz_free(ctx, ptr);
}

static void*
fz_cmm_realloc(cmsContext id, void *ptr, unsigned int size)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);

	if (ptr == 0)
		return fz_cmm_malloc(id, size);
	if (size == 0)
	{
		fz_cmm_free(id, ptr);
		return NULL;
	}
	return fz_resize_array_no_throw(ctx, ptr, size, 1);
}

static cmsPluginMemHandler fz_cmm_memhandler =
{
	{
		cmsPluginMagicNumber,
		2000,
		cmsPluginMemHandlerSig,
		NULL
	},
	fz_cmm_malloc,
	fz_cmm_free,
	fz_cmm_realloc,
	NULL,
	NULL,
	NULL,
};

static int
fz_cmm_num_devcomps(fz_iccprofile *profile)
{
	return cmsChannelsOf(cmsGetColorSpace(profile->cmm_handle));
}

int
fz_cmm_avoid_white_fix_flag()
{
	return cmsFLAGS_NOWHITEONWHITEFIXUP;
}

/* Transform an entire buffer */
void
fz_cmm_transform_color_buffer(fz_context *ctx, fz_icclink *link, fz_color_bufferdesc *in_desc, fz_color_bufferdesc *out_desc, void *input, void *output)
{
	cmsHTRANSFORM hTransform = (cmsHTRANSFORM) link->cmm_handle;
	cmsUInt32Number dwInputFormat = 0;
	cmsUInt32Number dwOutputFormat = 0;
	int cmm_num_src, cmm_num_des;
	unsigned char *inputpos, *outputpos;

	/* Set up the cmm format descriptions */
	/* Color space the same */
	dwInputFormat = COLORSPACE_SH(T_COLORSPACE(cmsGetTransformInputFormat(hTransform)));
	dwOutputFormat = COLORSPACE_SH(T_COLORSPACE(cmsGetTransformOutputFormat(hTransform)));

	/* planar */
	dwInputFormat = dwInputFormat | PLANAR_SH(in_desc->planar);
	dwOutputFormat = dwOutputFormat | PLANAR_SH(out_desc->planar);

	/* byte depths */
	dwInputFormat = dwInputFormat | BYTES_SH(in_desc->bytes);
	dwOutputFormat = dwOutputFormat | BYTES_SH(out_desc->bytes);

	/* endian */
	dwInputFormat = dwInputFormat | ENDIAN16_SH(!in_desc->endian);
	dwOutputFormat = dwOutputFormat | ENDIAN16_SH(!out_desc->endian);

	/* check the channels. */
	cmm_num_src = T_CHANNELS(cmsGetTransformInputFormat(hTransform));
	cmm_num_des = T_CHANNELS(cmsGetTransformOutputFormat(hTransform));
	if (cmm_num_src != in_desc->num_chan || cmm_num_des != out_desc->num_chan)
		return;
	dwInputFormat = dwInputFormat | CHANNELS_SH(cmm_num_src);
	dwOutputFormat = dwOutputFormat | CHANNELS_SH(cmm_num_des);

	/* alpha, if input has it so will the output */
	dwInputFormat = dwInputFormat | EXTRA_SH(in_desc->alpha);
	dwOutputFormat = dwOutputFormat | EXTRA_SH(in_desc->alpha);

	/* Change the formatters */
	cmsChangeBuffersFormat(hTransform, dwInputFormat, dwOutputFormat);

	/* Do the transform */
	inputpos = (unsigned char*) input;
	outputpos = (unsigned char*) output;

	if (in_desc->planar)
	{
		/* Check if full plane */
		if (in_desc->num_rows * in_desc->pixels_per_row == in_desc->plane_stride  &&
			out_desc->num_rows * out_desc->pixels_per_row == out_desc->plane_stride)
			cmsDoTransform(hTransform, inputpos, outputpos, in_desc->plane_stride);
		else
		{
			/* Subsection so do row by row */
			unsigned char *temp_des = NULL, *temp_src;
			int source_size = in_desc->bytes * in_desc->pixels_per_row;
			int des_size = out_desc->bytes * out_desc->pixels_per_row;
			int y, i;

			temp_src = (unsigned char*) fz_malloc(ctx, source_size * in_desc->num_chan);

			fz_var(temp_des);

			fz_try(ctx)
			{
				temp_des = (unsigned char*) fz_malloc(ctx, des_size * out_desc->num_chan);

				for (y = 0; y < in_desc->num_rows; y++)
				{
					unsigned char *src_cm = temp_src;
					unsigned char *src_buff = inputpos;
					unsigned char *des_cm = temp_des;
					unsigned char *des_buff = outputpos;

					/* Put into planar temp buffer */
					for (i = 0; i < in_desc->num_chan; i++)
					{
						memcpy(src_cm, src_buff, source_size);
						src_cm += source_size;
						src_buff += in_desc->plane_stride;
					}

					/* Transform */
					cmsDoTransform(hTransform, temp_src, temp_des, in_desc->pixels_per_row);

					/* Get out of temp planar buffer */
					for (i = 0; i < out_desc->num_chan; i++)
					{
						memcpy(des_buff, des_cm, des_size);
						des_cm += des_size;
						des_buff += out_desc->plane_stride;
					}
					inputpos += in_desc->row_stride;
					outputpos += out_desc->row_stride;
				}
			}
			fz_always(ctx)
			{
				fz_free(ctx, temp_src);
				fz_free(ctx, temp_des);
			}
			fz_catch(ctx)
			{
				fz_rethrow(ctx);
			}
		}
	}
	else
	{
		int k;

		/* non-planar. Do row by row. */
		for (k = 0; k < in_desc->num_rows; k++)
		{
			cmsDoTransform(hTransform, inputpos, outputpos, in_desc->pixels_per_row);
			inputpos += in_desc->row_stride;
			outputpos += out_desc->row_stride;
		}
	}
}

/* Transform a single color. */
void
fz_cmm_transform_color(fz_icclink *link, void *inputcolor, void *outputcolor, int num_bytes)
{
	cmsHTRANSFORM hTransform = (cmsHTRANSFORM) link->cmm_handle;
	cmsUInt32Number dwInputFormat, dwOutputFormat;

	dwInputFormat = cmsGetTransformInputFormat(hTransform);
	dwOutputFormat = cmsGetTransformOutputFormat(hTransform);
	dwInputFormat = (dwInputFormat & (~LCMS_BYTES_MASK)) | BYTES_SH(num_bytes);
	dwOutputFormat = (dwOutputFormat & (~LCMS_BYTES_MASK)) | BYTES_SH(num_bytes);

	/* Change the formatters */
	cmsChangeBuffersFormat(hTransform, dwInputFormat, dwOutputFormat);

	/* Do the conversion */
	cmsDoTransform(hTransform, inputcolor, outputcolor, 1);
}

void
fz_cmm_new_link(fz_context *ctx, fz_icclink *link, fz_iccprofile *src, fz_iccprofile *des, fz_rendering_param *rend, int cmm_flags)
{
	cmsUInt32Number src_data_type, des_data_type;
	cmsColorSpaceSignature src_cs, des_cs;
	int src_num_chan, des_num_chan;
	int lcms_src_cs, lcms_des_cs;
	unsigned int flag = cmsFLAGS_HIGHRESPRECALC | cmm_flags;
	cmsContext cmm_ctx = fz_get_cmm_ctx(ctx);

	/* src */
	src_cs = cmsGetColorSpace(src->cmm_handle);
	lcms_src_cs = _cmsLCMScolorSpace(src_cs);
	if (lcms_src_cs < 0)
		lcms_src_cs = 0;
	src_num_chan = cmsChannelsOf(src_cs);
	src_data_type = (COLORSPACE_SH(lcms_src_cs) | CHANNELS_SH(src_num_chan) | BYTES_SH(2));

	/* des */
	des_cs = cmsGetColorSpace(des->cmm_handle);
	lcms_des_cs = _cmsLCMScolorSpace(des_cs);
	if (lcms_des_cs < 0)
		lcms_des_cs = 0;
	des_num_chan = cmsChannelsOf(des_cs);
	des_data_type = (COLORSPACE_SH(lcms_des_cs) | CHANNELS_SH(des_num_chan) | BYTES_SH(2));

	/* flags */
	if (rend->black_point)
		flag |= cmsFLAGS_BLACKPOINTCOMPENSATION;

	/* create */
	link->cmm_handle = cmsCreateTransformTHR(cmm_ctx, src->cmm_handle, src_data_type, des->cmm_handle, des_data_type, rend->rendering_intent, flag);
}

void
fz_cmm_free_link(fz_icclink *link)
{
	if (link->cmm_handle != NULL)
		cmsDeleteTransform(link->cmm_handle);
	link->cmm_handle = NULL;
}

void *
fz_cmm_new_ctx(fz_context *ctx)
{
	cmsContext cmm_ctx;

	cmm_ctx = cmsCreateContext((void *)&fz_cmm_memhandler, ctx);
	if (cmm_ctx == NULL)
		return NULL;
	cmsSetLogErrorHandlerTHR(cmm_ctx, fz_cmm_error);
	return cmm_ctx;
}

void
fz_cmm_free_ctx(void *ctx)
{
	if (ctx == NULL)
		return;
	cmsDeleteContext(ctx);
}

void
fz_cmm_new_profile(fz_context *ctx, fz_iccprofile *profile)
{
	cmsContext cmm_ctx = fz_get_cmm_ctx(ctx);
	size_t size;
	unsigned char *data;

	cmsSetLogErrorHandlerTHR(cmm_ctx, fz_cmm_error);
	if (profile->buffer != NULL)
	{
		size = fz_buffer_storage(ctx, profile->buffer, &data);
		profile->cmm_handle = cmsOpenProfileFromMemTHR(cmm_ctx, data, size);
	}
	else
		profile->cmm_handle = cmsOpenProfileFromMemTHR(cmm_ctx, profile->res_buffer, profile->res_size);
	if (profile->cmm_handle != NULL)
		profile->num_devcomp = fz_cmm_num_devcomps(profile);
	else
		profile->num_devcomp = 0;

}

void
fz_cmm_free_profile(fz_iccprofile *profile)
{
	if (profile->cmm_handle != NULL)
		cmsCloseProfile(profile->cmm_handle);
	profile->cmm_handle = NULL;
}
