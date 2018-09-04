#include "mupdf/fitz.h"

#ifndef NO_ICC
#include "lcms2art.h"
#include "lcms2art_plugin.h"
#include "colorspace-imp.h"

#define LCMS_BYTES_MASK 0x7
/* #define DEBUG_LCMS_MEM(A) do { printf A; fflush(stdout); } while (0) */
#define DEBUG_LCMS_MEM(A) do { } while (0)

static void
fz_lcms_log_error(cmsContext id, cmsUInt32Number error_code, const char *error_text)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	fz_warn(ctx, "lcms error: %s", error_text);
}

static void
*fz_lcms_malloc(cmsContext id, unsigned int size)
{
	void *result;
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	result = fz_malloc_no_throw(ctx, size);
	DEBUG_LCMS_MEM(("Allocation::  mupdf ctx = %p lcms ctx = %p allocation = %p \n", (void*) ctx, (void*) id, (void*) result));
	return result;
}

static void
fz_lcms_free(cmsContext id, void *ptr)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	DEBUG_LCMS_MEM(("Free:: mupdf ctx = %p lcms ctx = %p allocation = %p \n", (void*) ctx, (void*) id, (void*) ptr));
	fz_free(ctx, ptr);
}

static void*
fz_lcms_realloc(cmsContext id, void *ptr, unsigned int size)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(id);
	DEBUG_LCMS_MEM(("Realloc:: mupdf ctx = %p lcms ctx = %p allocation = %p \n", (void*) ctx, (void*) id, (void*) ptr));
	if (ptr == 0)
		return fz_lcms_malloc(id, size);
	if (size == 0)
	{
		fz_lcms_free(id, ptr);
		return NULL;
	}
	return fz_resize_array_no_throw(ctx, ptr, size, 1);
}

static cmsPluginMemHandler fz_lcms_memhandler =
{
	{
		cmsPluginMagicNumber,
		LCMS_VERSION,
		cmsPluginMemHandlerSig,
		NULL
	},
	fz_lcms_malloc,
	fz_lcms_free,
	fz_lcms_realloc,
	NULL,
	NULL,
	NULL,
};

static int
fz_lcms_num_devcomps(cmsContext cmm_ctx, fz_iccprofile *profile)
{
	return cmsChannelsOf(cmm_ctx, cmsGetColorSpace(cmm_ctx, profile->cmm_handle));
}

static char *
fz_lcms_description(cmsContext cmm_ctx, fz_iccprofile *profile)
{
	fz_context *ctx = (fz_context *)cmsGetContextUserData(cmm_ctx);
	cmsMLU *descMLU;
	char *desc;
	size_t size;

	descMLU = cmsReadTag(cmm_ctx, profile->cmm_handle, cmsSigProfileDescriptionTag);
	size = cmsMLUgetASCII(cmm_ctx, descMLU, "en", "US", NULL, 0);
	desc = fz_malloc(ctx, size);
	cmsMLUgetASCII(cmm_ctx, descMLU, "en", "US", desc, size);
	return desc;
}

static void
fz_lcms_premultiply_row(fz_context *ctx, int n, int c, int w, unsigned char *s)
{
	unsigned char a;
	int k;
	int n1 = n-1;

	for (; w > 0; w--)
	{
		a = s[n1];
		for (k = 0; k < c; k++)
			s[k] = fz_mul255(s[k], a);
		s += n;
	}
}

static void
fz_lcms_unmultiply_row(fz_context *ctx, int n, int c, int w, unsigned char *s, const unsigned char *in)
{
	int a, inva;
	int k;
	int n1 = n-1;

	for (; w > 0; w--)
	{
		a = in[n1];
		inva = a ? 255 * 256 / a : 0;
		for (k = 0; k < c; k++)
			s[k] = (in[k] * inva) >> 8;
		for (;k < n1; k++)
			s[k] = in[k];
		s[n1] = a;
		s += n;
		in += n;
	}
}

/* Transform pixmap */
void
fz_lcms_transform_pixmap(fz_cmm_instance *instance, fz_icclink *link, fz_pixmap *dst, fz_pixmap *src)
{
	cmsContext cmm_ctx = (cmsContext)instance;
	fz_context *ctx = (fz_context *)cmsGetContextUserData(cmm_ctx);
	cmsHTRANSFORM hTransform = (cmsHTRANSFORM)link->cmm_handle;
	int cmm_num_src, cmm_num_des, cmm_extras;
	unsigned char *inputpos, *outputpos, *buffer;
	int ss = src->stride;
	int ds = dst->stride;
	int sw = src->w;
	int dw = dst->w;
	int sn = src->n;
	int dn = dst->n;
	int sa = src->alpha;
	int da = dst->alpha;
	int ssp = src->s;
	int dsp = dst->s;
	int sc = sn - ssp - sa;
	int dc = dn - dsp - da;
	int h = src->h;
	cmsUInt32Number src_format, dst_format;
	DEBUG_LCMS_MEM(("@@@@@@@ Transform Pixmap Start:: mupdf ctx = %p lcms ctx = %p link = %p \n", (void*)ctx, (void*)cmm_ctx, (void*)link->cmm_handle));

	/* check the channels. */
	src_format = cmsGetTransformInputFormat(cmm_ctx, hTransform);
	dst_format = cmsGetTransformOutputFormat(cmm_ctx, hTransform);
	cmm_num_src = T_CHANNELS(src_format);
	cmm_num_des = T_CHANNELS(dst_format);
	cmm_extras = T_EXTRA(src_format);
	if (cmm_num_src != sc || cmm_num_des != dc || cmm_extras != ssp+sa || sa != da || (link->copy_spots && ssp != dsp))
		fz_throw(ctx, FZ_ERROR_GENERIC, "Mismatching color setup in cmm pixmap transformation: src: %d vs %d+%d+%d, dst: %d vs %d+%d+%d", cmm_num_src, sc, ssp, sa, cmm_num_des, dc, dsp, da);

	/* Transform */
	inputpos = src->samples;
	outputpos = dst->samples;
	if (sa)
	{
		/* Allow for premultiplied alpha */
		buffer = fz_malloc(ctx, ss);
		for (; h > 0; h--)
		{
			fz_lcms_unmultiply_row(ctx, sn, sc, sw, buffer, inputpos);
			cmsDoTransform(cmm_ctx, hTransform, buffer, outputpos, sw);
			fz_lcms_premultiply_row(ctx, dn, dc, dw, outputpos);
			inputpos += ss;
			outputpos += ds;
		}
		fz_free(ctx, buffer);
	}
	else
	{
		for (; h > 0; h--)
		{
			cmsDoTransform(cmm_ctx, hTransform, inputpos, outputpos, sw);
			inputpos += ss;
			outputpos += ds;
		}
	}
	DEBUG_LCMS_MEM(("@@@@@@@ Transform Pixmap End:: mupdf ctx = %p lcms ctx = %p link = %p \n", (void*)ctx, (void*)cmm_ctx, (void*)link->cmm_handle));
}

/* Transform a single color. */
void
fz_lcms_transform_color(fz_cmm_instance *instance, fz_icclink *link, unsigned short *dst, const unsigned short *src)
{
	cmsContext cmm_ctx = (cmsContext)instance;
	cmsHTRANSFORM hTransform = (cmsHTRANSFORM) link->cmm_handle;

	cmsDoTransform(cmm_ctx, hTransform, src, dst, 1);
}

void
fz_lcms_init_link(fz_cmm_instance *instance, fz_icclink *link, const fz_iccprofile *dst, int dst_extras, const fz_iccprofile *src, int src_extras, const fz_iccprofile *prf, const fz_color_params *rend, int cmm_flags, int num_bytes, int copy_spots)
{
	cmsContext cmm_ctx = (cmsContext)instance;
	fz_context *ctx = (fz_context *)cmsGetContextUserData(cmm_ctx);

	cmsUInt32Number src_data_type, des_data_type;
	cmsColorSpaceSignature src_cs, des_cs;
	int src_num_chan, des_num_chan;
	int lcms_src_cs, lcms_des_cs;
	unsigned int flag = cmsFLAGS_LOWRESPRECALC | cmm_flags;

	DEBUG_LCMS_MEM(("@@@@@@@ Create Link Start:: mupdf ctx = %p lcms ctx = %p src = %p des = %p \n", (void*)ctx, (void*)cmm_ctx, (void*)src->cmm_handle, (void*)dst->cmm_handle));

	/* src */
	src_cs = cmsGetColorSpace(cmm_ctx, src->cmm_handle);
	lcms_src_cs = _cmsLCMScolorSpace(cmm_ctx, src_cs);
	if (lcms_src_cs < 0)
		lcms_src_cs = 0;
	src_num_chan = cmsChannelsOf(cmm_ctx, src_cs);
	src_data_type = (COLORSPACE_SH(lcms_src_cs) | CHANNELS_SH(src_num_chan) | DOSWAP_SH(src->bgr) | SWAPFIRST_SH(src->bgr && (src_extras != 0)) | BYTES_SH(num_bytes) | EXTRA_SH(src_extras));

	/* dst */
	des_cs = cmsGetColorSpace(cmm_ctx, dst->cmm_handle);
	lcms_des_cs = _cmsLCMScolorSpace(cmm_ctx, des_cs);
	if (lcms_des_cs < 0)
		lcms_des_cs = 0;
	des_num_chan = cmsChannelsOf(cmm_ctx, des_cs);
	des_data_type = (COLORSPACE_SH(lcms_des_cs) | CHANNELS_SH(des_num_chan) | DOSWAP_SH(dst->bgr) | SWAPFIRST_SH(dst->bgr && (dst_extras != 0)) | BYTES_SH(num_bytes) | EXTRA_SH(dst_extras));

	/* flags */
	if (rend->bp)
		flag |= cmsFLAGS_BLACKPOINTCOMPENSATION;

	if (copy_spots)
		flag |= cmsFLAGS_COPY_ALPHA;

	link->depth = num_bytes;
	link->src_extras = src_extras;
	link->dst_extras = dst_extras;
	link->copy_spots = copy_spots;

	if (prf == NULL)
	{
		link->cmm_handle = cmsCreateTransformTHR(cmm_ctx, src->cmm_handle, src_data_type, dst->cmm_handle, des_data_type, rend->ri, flag);
		if (!link->cmm_handle)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cmsCreateTransform failed");
	}
	else
	{
		/* littleCMS proof creation links don't work properly with the Ghent
		 * test files. Handle this in a brutish manner.
		 */
		if (src == prf)
		{
			link->cmm_handle = cmsCreateTransformTHR(cmm_ctx, src->cmm_handle, src_data_type, dst->cmm_handle, des_data_type, INTENT_RELATIVE_COLORIMETRIC, flag);
			if (!link->cmm_handle)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cmsCreateTransform failed");
		}
		else if (prf == dst)
		{
			link->cmm_handle = cmsCreateTransformTHR(cmm_ctx, src->cmm_handle, src_data_type, prf->cmm_handle, des_data_type, rend->ri, flag);
			if (!link->cmm_handle)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cmsCreateTransform failed");
		}
		else
		{
			cmsHPROFILE src_to_prf_profile;
			cmsHTRANSFORM src_to_prf_link;
			cmsColorSpaceSignature prf_cs;
			int prf_num_chan;
			int lcms_prf_cs;
			cmsUInt32Number prf_data_type;
			cmsHPROFILE hProfiles[3];

			prf_cs = cmsGetColorSpace(cmm_ctx, prf->cmm_handle);
			lcms_prf_cs = _cmsLCMScolorSpace(cmm_ctx, prf_cs);
			if (lcms_prf_cs < 0)
				lcms_prf_cs = 0;
			prf_num_chan = cmsChannelsOf(cmm_ctx, prf_cs);
			prf_data_type = (COLORSPACE_SH(lcms_prf_cs) | CHANNELS_SH(prf_num_chan) | BYTES_SH(num_bytes));
			src_to_prf_link = cmsCreateTransformTHR(cmm_ctx, src->cmm_handle, src_data_type, prf->cmm_handle, prf_data_type, rend->ri, flag);
			if (!src_to_prf_link)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cmsCreateTransform failed");
			src_to_prf_profile = cmsTransform2DeviceLink(cmm_ctx, src_to_prf_link, 3.4, flag);
			cmsDeleteTransform(cmm_ctx, src_to_prf_link);
			if (!src_to_prf_profile)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cmsTransform2DeviceLink failed");

			hProfiles[0] = src_to_prf_profile;
			hProfiles[1] = prf->cmm_handle;
			hProfiles[2] = dst->cmm_handle;
			link->cmm_handle = cmsCreateMultiprofileTransformTHR(cmm_ctx, hProfiles, 3, src_data_type, des_data_type, INTENT_RELATIVE_COLORIMETRIC, flag);
			cmsCloseProfile(cmm_ctx, src_to_prf_profile);
			if (!link->cmm_handle)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cmsCreateMultiprofileTransform failed");
		}
	}

	DEBUG_LCMS_MEM(("@@@@@@@ Create Link End:: mupdf ctx = %p lcms ctx = %p link = %p link_cmm = %p src = %p des = %p \n", (void*)ctx, (void*)cmm_ctx, (void*)link, (void*)link->cmm_handle, (void*)src->cmm_handle, (void*)dst->cmm_handle));
}

void
fz_lcms_fin_link(fz_cmm_instance *instance, fz_icclink *link)
{
	cmsContext cmm_ctx = (cmsContext)instance;
	DEBUG_LCMS_MEM(("Free Link:: link = %p \n", (void*)link->cmm_handle));
	if (link->cmm_handle != NULL)
		cmsDeleteTransform(cmm_ctx, link->cmm_handle);
	link->cmm_handle = NULL;
}

static fz_cmm_instance *
fz_lcms_new_instance(fz_context *ctx)
{
	cmsContext cmm_ctx;

	cmm_ctx = cmsCreateContext(&fz_lcms_memhandler, ctx);
	DEBUG_LCMS_MEM(("Context Creation:: mupdf ctx = %p lcms ctx = %p \n", (void*) ctx, (void*) cmm_ctx));
	if (cmm_ctx == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cmsCreateContext failed");
	cmsSetLogErrorHandlerTHR(cmm_ctx, fz_lcms_log_error);
	return (fz_cmm_instance *)cmm_ctx;
}

static void
fz_lcms_drop_instance(fz_cmm_instance *instance)
{
	DEBUG_LCMS_MEM(("Context Destruction:: lcms ctx = %p \n", (void*)instance));
	if (instance == NULL)
		return;
	cmsDeleteContext((cmsContext)instance);
}

static void
fz_lcms_init_profile(fz_cmm_instance *instance, fz_iccprofile *profile)
{
	cmsContext cmm_ctx = (cmsContext)instance;
	fz_context *ctx = (fz_context *)cmsGetContextUserData(cmm_ctx);
	size_t size;
	unsigned char *data;

	DEBUG_LCMS_MEM(("@@@@@@@ Create Profile Start:: mupdf ctx = %p lcms ctx = %p \n", (void*)ctx, (void*)cmm_ctx));

	size = fz_buffer_storage(ctx, profile->buffer, &data);
	profile->cmm_handle = cmsOpenProfileFromMemTHR(cmm_ctx, data, (cmsUInt32Number)size);
	if (profile->cmm_handle == NULL)
	{
		profile->num_devcomp = 0;
		fz_throw(ctx, FZ_ERROR_GENERIC, "cmsOpenProfileFromMem failed");
	}
	profile->num_devcomp = fz_lcms_num_devcomps(cmm_ctx, profile);
	profile->desc = fz_lcms_description(cmm_ctx, profile);

	DEBUG_LCMS_MEM(("@@@@@@@ Create Profile End:: mupdf ctx = %p lcms ctx = %p profile = %p profile_cmm = %p \n", (void*)ctx, (void*)cmm_ctx, (void*)profile, (void*)profile->cmm_handle));
}

static void
fz_lcms_fin_profile(fz_cmm_instance *instance, fz_iccprofile *profile)
{
	cmsContext cmm_ctx = (cmsContext)instance;
	fz_context *ctx = (fz_context *)cmsGetContextUserData(cmm_ctx);
	DEBUG_LCMS_MEM(("Free Profile:: profile = %p \n", (void*) profile->cmm_handle));
	if (profile->cmm_handle != NULL)
		cmsCloseProfile(cmm_ctx, profile->cmm_handle);
	fz_free(ctx, profile->desc);
	profile->cmm_handle = NULL;
}

fz_cmm_engine fz_cmm_engine_lcms = {
	fz_lcms_new_instance,
	fz_lcms_drop_instance,
	fz_lcms_transform_pixmap,
	fz_lcms_transform_color,
	fz_lcms_init_link,
	fz_lcms_fin_link,
	fz_lcms_init_profile,
	fz_lcms_fin_profile,
};
#endif
