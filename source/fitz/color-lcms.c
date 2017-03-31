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

/* Transform pixmap */
void
fz_cmm_transform_pixmap(fz_context *ctx, fz_icclink *link, fz_pixmap *dst, fz_pixmap *src)
{
	cmsHTRANSFORM hTransform = (cmsHTRANSFORM) link->cmm_handle;
	cmsUInt32Number dwInputFormat = 0;
	cmsUInt32Number dwOutputFormat = 0;
	int cmm_num_src, cmm_num_des;
	unsigned char *inputpos, *outputpos;
	int k;

	/* check the channels. */
	cmm_num_src = T_CHANNELS(cmsGetTransformInputFormat(hTransform));
	cmm_num_des = T_CHANNELS(cmsGetTransformOutputFormat(hTransform));
	if (cmm_num_src != src->n || cmm_num_des != dst->n)
		return;

	/* Set up the cmm format descriptions */
	dwInputFormat = COLORSPACE_SH(T_COLORSPACE(cmsGetTransformInputFormat(hTransform)));
	dwOutputFormat = COLORSPACE_SH(T_COLORSPACE(cmsGetTransformOutputFormat(hTransform)));
	dwInputFormat = dwInputFormat | BYTES_SH(1);
	dwOutputFormat = dwOutputFormat | BYTES_SH(1);
	dwInputFormat = dwInputFormat | CHANNELS_SH(cmm_num_src);
	dwOutputFormat = dwOutputFormat | CHANNELS_SH(cmm_num_des);
	dwInputFormat = dwInputFormat | EXTRA_SH(src->alpha);
	dwOutputFormat = dwOutputFormat | EXTRA_SH(dst->alpha);
	cmsChangeBuffersFormat(hTransform, dwInputFormat, dwOutputFormat);

	/* Transform */
	inputpos = src->samples;
	outputpos = dst->samples;
	for (k = 0; k < src->h; k++)
	{
		cmsDoTransform(hTransform, inputpos, outputpos, src->w);
		inputpos += src->stride;
		outputpos += dst->stride;
	}
}

/* Transform a single color. */
void
fz_cmm_transform_color(fz_icclink *link, int num_bytes, void *dst, const void *src)
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
	cmsDoTransform(hTransform, src, dst, 1);
}

void
fz_cmm_new_link(fz_context *ctx, fz_icclink *link, fz_color_params *rend, int cmm_flags, fz_iccprofile *dst, fz_iccprofile *src)
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

	/* dst */
	des_cs = cmsGetColorSpace(dst->cmm_handle);
	lcms_des_cs = _cmsLCMScolorSpace(des_cs);
	if (lcms_des_cs < 0)
		lcms_des_cs = 0;
	des_num_chan = cmsChannelsOf(des_cs);
	des_data_type = (COLORSPACE_SH(lcms_des_cs) | CHANNELS_SH(des_num_chan) | BYTES_SH(2));

	/* flags */
	if (rend->bp)
		flag |= cmsFLAGS_BLACKPOINTCOMPENSATION;

	/* create */
	link->cmm_handle = cmsCreateTransformTHR(cmm_ctx, src->cmm_handle, src_data_type, dst->cmm_handle, des_data_type, rend->ri, flag);
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
