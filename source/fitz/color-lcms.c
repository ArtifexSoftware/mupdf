#include "mupdf/fitz.h"
#include "lcms2.h"
#include "lcms2_plugin.h"
#include "colorspace-imp.h"
#include "mupdf/fitz/color-lcms.h"

#define LCMS_BYTES_MASK 0x7
/* #define DEBUG_LCMS_MEM(A) do { printf A; fflush(stdout); } while (0) */
#define DEBUG_LCMS_MEM(A) do { } while (0)

static void
fz_cmm_error(cmsContext id, cmsUInt32Number error_code, const char *error_text)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	fz_warn(ctx, "lcms error: %s", error_text);
}

static void
*fz_cmm_malloc(cmsContext id, unsigned int size)
{
	void *result;
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	result = fz_malloc_no_throw(ctx, size);
	DEBUG_LCMS_MEM(("Allocation::  mupdf ctx = %p lcms ctx = %p allocation = %p \n", (void*) ctx, (void*) id, (void*) result));
	return result;
}

static void
fz_cmm_free(cmsContext id, void *ptr)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	DEBUG_LCMS_MEM(("Free:: mupdf ctx = %p lcms ctx = %p allocation = %p \n", (void*) ctx, (void*) id, (void*) ptr));
	fz_free(ctx, ptr);
}

static void*
fz_cmm_realloc(cmsContext id, void *ptr, unsigned int size)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	DEBUG_LCMS_MEM(("Realloc:: mupdf ctx = %p lcms ctx = %p allocation = %p \n", (void*) ctx, (void*) id, (void*) ptr));
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
fz_cmm_num_devcomps(fz_context *ctx, fz_iccprofile *profile)
{
	cmsContext cmm_ctx = fz_get_cmm_ctx(ctx);

	return cmsChannelsOf(cmm_ctx, cmsGetColorSpace(cmm_ctx, profile->cmm_handle));
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
	cmsContext cmm_ctx = fz_get_cmm_ctx(ctx);
	cmsHTRANSFORM hTransform = (cmsHTRANSFORM) link->cmm_handle;
	int cmm_num_src, cmm_num_des;
	unsigned char *inputpos, *outputpos;
	int k;
	DEBUG_LCMS_MEM(("@@@@@@@ Transform Pixmap Start:: mupdf ctx = %p lcms ctx = %p link = %p \n", (void*)ctx, (void*)cmm_ctx, (void*)link->cmm_handle));

	/* check the channels. */
	cmm_num_src = T_CHANNELS(cmsGetTransformInputFormat(cmm_ctx, hTransform));
	cmm_num_des = T_CHANNELS(cmsGetTransformOutputFormat(cmm_ctx, hTransform));
	if (cmm_num_src != src->n || cmm_num_des != dst->n)
		return;

	/* Transform */
	inputpos = src->samples;
	outputpos = dst->samples;
	for (k = 0; k < src->h; k++)
	{
		cmsDoTransform(cmm_ctx, hTransform, inputpos, outputpos, src->w);
		inputpos += src->stride;
		outputpos += dst->stride;
	}
	DEBUG_LCMS_MEM(("@@@@@@@ Transform Pixmap End:: mupdf ctx = %p lcms ctx = %p link = %p \n", (void*)ctx, (void*)cmm_ctx, (void*)link->cmm_handle));
}

/* Transform a single color. */
void
fz_cmm_transform_color(fz_context *ctx, fz_icclink *link, int num_bytes, void *dst, const void *src)
{
	cmsContext cmm_ctx = fz_get_cmm_ctx(ctx);
	cmsHTRANSFORM hTransform = (cmsHTRANSFORM) link->cmm_handle;

	/* Do the conversion */
	cmsDoTransform(cmm_ctx, hTransform, src, dst, 1);
}

void
fz_cmm_new_link(fz_context *ctx, fz_icclink *link, const fz_color_params *rend, int cmm_flags, int num_bytes, int alpha, const fz_iccprofile *dst, const fz_iccprofile *src)
{
	cmsUInt32Number src_data_type, des_data_type;
	cmsColorSpaceSignature src_cs, des_cs;
	int src_num_chan, des_num_chan;
	int lcms_src_cs, lcms_des_cs;
	unsigned int flag = cmsFLAGS_LOWRESPRECALC | cmm_flags;
	cmsContext cmm_ctx = fz_get_cmm_ctx(ctx);

	DEBUG_LCMS_MEM(("@@@@@@@ Create Link Start:: mupdf ctx = %p lcms ctx = %p src = %p des = %p \n", (void*)ctx, (void*)cmm_ctx, (void*)src->cmm_handle, (void*)dst->cmm_handle));
	/* src */
	src_cs = cmsGetColorSpace(cmm_ctx, src->cmm_handle);
	lcms_src_cs = _cmsLCMScolorSpace(cmm_ctx, src_cs);
	if (lcms_src_cs < 0)
		lcms_src_cs = 0;
	src_num_chan = cmsChannelsOf(cmm_ctx, src_cs);
	src_data_type = (COLORSPACE_SH(lcms_src_cs) | CHANNELS_SH(src_num_chan) | BYTES_SH(num_bytes));
	src_data_type = src_data_type | EXTRA_SH(alpha);

	/* dst */
	des_cs = cmsGetColorSpace(cmm_ctx, dst->cmm_handle);
	lcms_des_cs = _cmsLCMScolorSpace(cmm_ctx, des_cs);
	if (lcms_des_cs < 0)
		lcms_des_cs = 0;
	des_num_chan = cmsChannelsOf(cmm_ctx, des_cs);
	des_data_type = (COLORSPACE_SH(lcms_des_cs) | CHANNELS_SH(des_num_chan) | BYTES_SH(num_bytes));
	des_data_type = des_data_type | EXTRA_SH(alpha);

	/* flags */
	if (rend->bp)
		flag |= cmsFLAGS_BLACKPOINTCOMPENSATION;

	link->depth = num_bytes;
	link->alpha = alpha;

	/* create */
	link->cmm_handle = cmsCreateTransformTHR(cmm_ctx, src->cmm_handle, src_data_type, dst->cmm_handle, des_data_type, rend->ri, flag);
	DEBUG_LCMS_MEM(("@@@@@@@ Create Link End:: mupdf ctx = %p lcms ctx = %p link = %p link_cmm = %p src = %p des = %p \n", (void*)ctx, (void*)cmm_ctx, (void*) link, (void*) link->cmm_handle, (void*)src->cmm_handle, (void*)dst->cmm_handle));
}

void
fz_cmm_free_link(fz_context *ctx, fz_icclink *link)
{
	cmsContext cmm_ctx = fz_get_cmm_ctx(ctx);

	if (link->cmm_handle != NULL)
	{
		DEBUG_LCMS_MEM(("Free Link:: link = %p \n", (void*)link->cmm_handle));
		cmsDeleteTransform(cmm_ctx, link->cmm_handle);
	}
	link->cmm_handle = NULL;
}

void *
fz_cmm_new_ctx(fz_context *ctx)
{
	cmsContext cmm_ctx;

	cmm_ctx = cmsCreateContext((void *)&fz_cmm_memhandler, ctx);
	if (cmm_ctx == NULL)
		return NULL;
	DEBUG_LCMS_MEM(("Context Creation:: mupdf ctx = %p lcms ctx = %p \n", (void*) ctx, (void*) cmm_ctx));
	cmsSetLogErrorHandlerTHR(cmm_ctx, fz_cmm_error);
	return cmm_ctx;
}

void
fz_cmm_free_ctx(void *ctx)
{
	DEBUG_LCMS_MEM(("Context Destruction:: lcms ctx = %p \n", (void*) ctx));
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

	DEBUG_LCMS_MEM(("@@@@@@@ Create Profile Start:: mupdf ctx = %p lcms ctx = %p \n", (void*)ctx, (void*)cmm_ctx));
	cmsSetLogErrorHandlerTHR(cmm_ctx, fz_cmm_error);
	size = fz_buffer_storage(ctx, profile->buffer, &data);
	profile->cmm_handle = cmsOpenProfileFromMemTHR(cmm_ctx, data, size);
	if (profile->cmm_handle != NULL)
		profile->num_devcomp = fz_cmm_num_devcomps(ctx, profile);
	else
		profile->num_devcomp = 0;
	DEBUG_LCMS_MEM(("@@@@@@@ Create Profile End:: mupdf ctx = %p lcms ctx = %p profile = %p profile_cmm = %p \n", (void*)ctx, (void*)cmm_ctx, (void*)profile, (void*)profile->cmm_handle));
}

void
fz_cmm_free_profile(fz_context *ctx, fz_iccprofile *profile)
{
	cmsContext cmm_ctx = fz_get_cmm_ctx(ctx);

	if (profile->cmm_handle != NULL)
	{
		DEBUG_LCMS_MEM(("Free Profile:: profile = %p \n", (void*) profile->cmm_handle));
		cmsCloseProfile(cmm_ctx, profile->cmm_handle);
	}
	profile->cmm_handle = NULL;
}
