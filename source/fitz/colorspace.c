#include "mupdf/fitz.h"

#include "colorspace-imp.h"
#include "fitz-imp.h"

#include <assert.h>
#include <math.h>
#include <string.h>

/* Colorspace feature tests */

int fz_colorspace_is_gray(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && cs->type == FZ_COLORSPACE_GRAY;
}

int fz_colorspace_is_rgb(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && cs->type == FZ_COLORSPACE_RGB;
}

int fz_colorspace_is_bgr(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && cs->type == FZ_COLORSPACE_BGR;
}

int fz_colorspace_is_cmyk(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && cs->type == FZ_COLORSPACE_CMYK;
}

int fz_colorspace_is_lab(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && cs->type == FZ_COLORSPACE_LAB;
}

int fz_colorspace_is_indexed(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && (cs->type == FZ_COLORSPACE_INDEXED);
}

int fz_colorspace_is_device_n(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && (cs->type == FZ_COLORSPACE_SEPARATION);
}

int fz_colorspace_is_subtractive(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && (cs->type == FZ_COLORSPACE_CMYK || cs->type == FZ_COLORSPACE_SEPARATION);
}

int fz_colorspace_is_device(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && (cs->flags & FZ_COLORSPACE_IS_DEVICE);
}

int fz_colorspace_is_icc(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && (cs->flags & FZ_COLORSPACE_IS_ICC);
}

int fz_colorspace_is_cal(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && (cs->flags & FZ_COLORSPACE_IS_CAL);
}

int fz_colorspace_is_lab_icc(fz_context *ctx, const fz_colorspace *cs)
{
	return fz_colorspace_is_lab(ctx, cs) && fz_colorspace_is_icc(ctx, cs);
}

int fz_colorspace_is_device_gray(fz_context *ctx, const fz_colorspace *cs)
{
	return fz_colorspace_is_device(ctx, cs) && fz_colorspace_is_gray(ctx, cs);
}

int fz_colorspace_is_device_cmyk(fz_context *ctx, const fz_colorspace *cs)
{
	return fz_colorspace_is_device(ctx, cs) && fz_colorspace_is_cmyk(ctx, cs);
}

int fz_colorspace_device_n_has_only_cmyk(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && ((cs->flags & FZ_CS_HAS_CMYK_AND_SPOTS) == FZ_CS_HAS_CMYK);
}

int fz_colorspace_device_n_has_cmyk(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && (cs->flags & FZ_CS_HAS_CMYK);
}

/* CMM module */

void
fz_cmm_transform_pixmap(fz_context *ctx, fz_icclink *link, fz_pixmap *dst, fz_pixmap *src)
{
	if (ctx && ctx->colorspace && ctx->colorspace->cmm && ctx->cmm_instance)
		ctx->colorspace->cmm->transform_pixmap(ctx->cmm_instance, link, dst, src);
}

void
fz_cmm_transform_color(fz_context *ctx, fz_icclink *link, unsigned short *dst, const unsigned short *src)
{
	if (ctx && ctx->colorspace && ctx->colorspace->cmm && ctx->cmm_instance)
		ctx->colorspace->cmm->transform_color(ctx->cmm_instance, link, dst, src);
}

void
fz_cmm_init_link(fz_context *ctx, fz_icclink *link, const fz_iccprofile *dst, int dst_extras, const fz_iccprofile *src, int src_extras, const fz_iccprofile *prf, const fz_color_params *rend, int cmm_flags, int num_bytes, int copy_spots)
{
	if (ctx && ctx->colorspace && ctx->colorspace->cmm && ctx->cmm_instance)
		ctx->colorspace->cmm->init_link(ctx->cmm_instance, link, dst, dst_extras, src, src_extras, prf, rend, cmm_flags, num_bytes, copy_spots);
}

void
fz_cmm_fin_link(fz_context *ctx, fz_icclink *link)
{
	if (ctx && ctx->colorspace && ctx->colorspace->cmm && ctx->cmm_instance)
		ctx->colorspace->cmm->fin_link(ctx->cmm_instance, link);
}

fz_cmm_instance *fz_cmm_new_instance(fz_context *ctx)
{
	if (ctx && ctx->colorspace && ctx->colorspace->cmm)
		return ctx->colorspace->cmm->new_instance(ctx);
	return NULL;
}

void fz_cmm_drop_instance(fz_context *ctx)
{
	if (ctx && ctx->colorspace && ctx->colorspace->cmm && ctx->cmm_instance)
		ctx->colorspace->cmm->drop_instance(ctx->cmm_instance);
}

void fz_cmm_init_profile(fz_context *ctx, fz_iccprofile *profile)
{
	if (ctx && ctx->colorspace && ctx->colorspace->cmm && ctx->cmm_instance)
		ctx->colorspace->cmm->init_profile(ctx->cmm_instance, profile);
}

void fz_cmm_fin_profile(fz_context *ctx, fz_iccprofile *profile)
{
	if (ctx && ctx->colorspace && ctx->colorspace->cmm && ctx->cmm_instance)
		if (profile && profile->cmm_handle != NULL)
			ctx->colorspace->cmm->fin_profile(ctx->cmm_instance, profile);
}

void fz_premultiply_row(fz_context *ctx, int n, int c, int w, unsigned char *s)
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

void fz_unmultiply_row(fz_context *ctx, int n, int c, int w, unsigned char *s, const unsigned char *in)
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

#if FZ_ENABLE_ICC

#include "icc/gray.icc.h"
#include "icc/rgb.icc.h"
#include "icc/cmyk.icc.h"
#include "icc/lab.icc.h"

const unsigned char *
fz_lookup_icc(fz_context *ctx, enum fz_colorspace_type type, size_t *size)
{
	if (fz_get_cmm_engine(ctx) == NULL)
		return *size = 0, NULL;
	if (type == FZ_COLORSPACE_GRAY) {
		*size = resources_icc_gray_icc_len;
		return resources_icc_gray_icc;
	}
	if (type == FZ_COLORSPACE_RGB || type == FZ_COLORSPACE_BGR) {
		*size = resources_icc_rgb_icc_len;
		return resources_icc_rgb_icc;
	}
	if (type == FZ_COLORSPACE_CMYK) {
		*size = resources_icc_cmyk_icc_len;
		return resources_icc_cmyk_icc;
	}
	if (type == FZ_COLORSPACE_LAB) {
		*size = resources_icc_lab_icc_len;
		return resources_icc_lab_icc;
	}
	return *size = 0, NULL;
}

#else

const unsigned char *
fz_lookup_icc(fz_context *ctx, enum fz_colorspace_type type, size_t *size)
{
	return *size = 0, NULL;
}

#endif

/* Same order as needed by lcms */
static const char *fz_intent_names[] =
{
	"Perceptual",
	"RelativeColorimetric",
	"Saturation",
	"AbsoluteColorimetric",
};

int
fz_lookup_rendering_intent(const char *name)
{
	int i;
	for (i = 0; i < nelem(fz_intent_names); i++)
		if (!strcmp(name, fz_intent_names[i]))
			return i;
	return FZ_RI_RELATIVE_COLORIMETRIC;
}

char *
fz_rendering_intent_name(int ri)
{
	if (ri >= 0 && ri < nelem(fz_intent_names))
		return (char*)fz_intent_names[ri];
	return "RelativeColorimetric";
}

void
fz_drop_colorspace_imp(fz_context *ctx, fz_storable *cs_)
{
	fz_colorspace *cs = (fz_colorspace *)cs_;
	int i;

	if (cs->free_data && cs->data)
		cs->free_data(ctx, cs);
	for (i = 0; i < FZ_MAX_COLORS; i++)
		fz_free(ctx, cs->colorant[i]);
	fz_free(ctx, cs->name);
	fz_free(ctx, cs);
}

static void
clamp_default(const fz_colorspace *cs, const float *src, float *dst)
{
	int i;

	for (i = 0; i < cs->n; i++)
		dst[i] = fz_clamp(src[i], 0, 1);
}

fz_colorspace *
fz_new_colorspace(fz_context *ctx,
		const char *name,
		enum fz_colorspace_type type, int flags, int n,
		fz_colorspace_convert_fn *to_ccs,
		fz_colorspace_convert_fn *from_ccs,
		fz_colorspace_base_fn *base,
		fz_colorspace_clamp_fn *clamp,
		fz_colorspace_destruct_fn *destruct,
		void *data, size_t size)
{
	fz_colorspace *cs = fz_malloc_struct(ctx, fz_colorspace);
	FZ_INIT_KEY_STORABLE(cs, 1, fz_drop_colorspace_imp);
	cs->size = sizeof(fz_colorspace) + size;
	fz_try(ctx)
		cs->name = fz_strdup(ctx, name ? name : "UNKNOWN");
	fz_catch(ctx)
	{
		fz_free(ctx, cs);
		fz_rethrow(ctx);
	}
	cs->type = type;
	cs->flags = flags;
	cs->n = n;
	cs->to_ccs = to_ccs;
	cs->from_ccs = from_ccs;
	cs->get_base = base;

	if (clamp != NULL)
		cs->clamp = clamp;
	else
		cs->clamp = clamp_default;

	cs->free_data = destruct;
	cs->data = data;
	return cs;
}

fz_colorspace *
fz_keep_colorspace(fz_context *ctx, fz_colorspace *cs)
{
	return fz_keep_key_storable(ctx, &cs->key_storable);
}

void
fz_drop_colorspace(fz_context *ctx, fz_colorspace *cs)
{
	fz_drop_key_storable(ctx, &cs->key_storable);
}

fz_colorspace *
fz_keep_colorspace_store_key(fz_context *ctx, fz_colorspace *cs)
{
	return fz_keep_key_storable_key(ctx, &cs->key_storable);
}

void
fz_drop_colorspace_store_key(fz_context *ctx, fz_colorspace *cs)
{
	fz_drop_key_storable_key(ctx, &cs->key_storable);
}

enum fz_colorspace_type
fz_colorspace_type(fz_context *ctx, fz_colorspace *cs)
{
	return cs ? cs->type : FZ_COLORSPACE_NONE;
}

/* icc links */

typedef struct fz_link_key_s fz_link_key;

struct fz_link_key_s {
	int refs;
	unsigned char src_md5[16];
	unsigned char dst_md5[16];
	fz_color_params rend;
	int src_extras;
	int dst_extras;
	int copy_spots;
	int depth;
	int proof;
};

static void *
fz_keep_link_key(fz_context *ctx, void *key_)
{
	fz_link_key *key = (fz_link_key *)key_;
	return fz_keep_imp(ctx, key, &key->refs);
}

static void
fz_drop_link_key(fz_context *ctx, void *key_)
{
	fz_link_key *key = (fz_link_key *)key_;
	if (fz_drop_imp(ctx, key, &key->refs))
		fz_free(ctx, key);
}

static int
fz_cmp_link_key(fz_context *ctx, void *k0_, void *k1_)
{
	fz_link_key *k0 = (fz_link_key *)k0_;
	fz_link_key *k1 = (fz_link_key *)k1_;
	return k0->proof == k1->proof &&
		k0->src_extras == k1->src_extras &&
		k0->dst_extras == k1->dst_extras &&
		k0->copy_spots == k1->copy_spots &&
		k0->depth == k1->depth &&
		k0->rend.bp == k1->rend.bp &&
		k0->rend.ri == k1->rend.ri &&
		memcmp(k0->dst_md5, k1->dst_md5, 16) == 0 &&
		memcmp(k0->src_md5, k1->src_md5, 16);
}

static void
fz_format_link_key(fz_context *ctx, char *s, int n, void *key_)
{
	static const char *hex = "0123456789abcdef";
	fz_link_key *key = (fz_link_key *)key_;
	char sm[33], dm[33];
	int i;
	for (i = 0; i < 16; ++i)
	{
		sm[i*2+0] = hex[key->src_md5[i]>>4];
		sm[i*2+1] = hex[key->src_md5[i]&15];
		dm[i*2+0] = hex[key->dst_md5[i]>>4];
		dm[i*2+1] = hex[key->dst_md5[i]&15];
	}
	sm[32] = 0;
	dm[32] = 0;
	fz_snprintf(s, n, "(link src_md5=%s dst_md5=%s)", sm, dm);
}

static int
fz_make_hash_link_key(fz_context *ctx, fz_store_hash *hash, void *key_)
{
	fz_link_key *key = (fz_link_key *)key_;
	memcpy(hash->u.link.dst_md5, key->dst_md5, 16);
	memcpy(hash->u.link.src_md5, key->src_md5, 16);
	hash->u.link.ri = key->rend.ri;
	hash->u.link.bp = key->rend.bp;
	hash->u.link.src_extras = key->src_extras;
	hash->u.link.dst_extras = key->dst_extras;
	hash->u.link.bpp16 = key->depth == 2;
	hash->u.link.proof = key->proof;
	hash->u.link.copy_spots = key->copy_spots;
	return 1;
}

static fz_store_type fz_link_store_type =
{
	fz_make_hash_link_key,
	fz_keep_link_key,
	fz_drop_link_key,
	fz_cmp_link_key,
	fz_format_link_key,
	NULL
};

static void
fz_drop_link_imp(fz_context *ctx, fz_storable *storable)
{
	fz_icclink *link = (fz_icclink *)storable;
	fz_cmm_fin_link(ctx, link);
	fz_free(ctx, link);
}

static void
fz_drop_icclink(fz_context *ctx, fz_icclink *link)
{
	fz_drop_storable(ctx, &link->storable);
}

static fz_iccprofile *
get_base_icc_profile(fz_context *ctx, const fz_colorspace *cs)
{
	fz_colorspace *base;
	fz_cal_colorspace *cal;
	fz_iccprofile *cal_icc;

	if (!cs || !cs->get_base)
		return NULL;

	base = cs->get_base(cs);
	if (base == NULL)
		return NULL;

	if (fz_colorspace_is_icc(ctx, base))
		return base->data;
	if (!fz_colorspace_is_cal(ctx, base))
		return get_base_icc_profile(ctx, base);

	cal = base->data;
	cal_icc = cal->profile;
	if (cal_icc && cal_icc->cmm_handle == NULL)
		fz_cmm_init_profile(ctx, cal_icc);

	return cal_icc;
}

static fz_icclink *
fz_new_icc_link(fz_context *ctx, fz_iccprofile *dst, int dst_extras, fz_iccprofile *src, int src_extras, fz_iccprofile *prf, const fz_color_params *rend, int num_bytes, int copy_extras)
{
	fz_icclink *link = fz_malloc_struct(ctx, fz_icclink);
	FZ_INIT_STORABLE(link, 1, fz_drop_link_imp);

	if (memcmp(src->md5, dst->md5, 16) == 0 && prf == NULL)
	{
		link->is_identity = 1;
		return link;
	}

	fz_try(ctx)
		fz_cmm_init_link(ctx, link, dst, dst_extras, src, src_extras, prf, rend, 0, num_bytes, copy_extras);
	fz_catch(ctx)
	{
		fz_free(ctx, link);
		fz_rethrow(ctx);
	}

	return link;
}

static void
fz_md5_icc(fz_context *ctx, fz_iccprofile *profile)
{
	if (profile)
		fz_md5_buffer(ctx, profile->buffer, profile->md5);
}

/* Create icc profile from calrgb, calgray values */
static fz_iccprofile *
fz_icc_from_cal(fz_context *ctx, const fz_colorspace *cs)
{
	fz_cal_colorspace *cal_data = cs->data;
	fz_iccprofile *profile;

	if (cal_data->profile != NULL)
		return cal_data->profile;
	profile = fz_malloc_struct(ctx, fz_iccprofile);

	fz_try(ctx)
	{
		profile->buffer = fz_new_icc_data_from_cal_colorspace(ctx, cal_data);
		fz_md5_icc(ctx, profile);
		cal_data->profile = profile;
	}
	fz_catch(ctx)
	{
		fz_free(ctx, profile);
		fz_rethrow(ctx);
	}

	return profile;
}

static fz_iccprofile *
fz_get_icc_from_cal(fz_context *ctx, const fz_colorspace *cs)
{
	fz_cal_colorspace *cal;
	fz_iccprofile *icc = NULL;

	cal = cs->data;
	icc = cal->profile;
	/* Check if we have any work to do. */
	if (icc == NULL)
		icc = fz_icc_from_cal(ctx, cs);
	if (icc->cmm_handle == NULL)
	{
		fz_cmm_init_profile(ctx, icc);

		/* The CMM failed to make a profile. Use the default. */
		if (icc->cmm_handle == NULL)
		{
			switch (cs->n)
			{
			case 1:
				icc = fz_device_gray(ctx)->data;
				break;
			case 3:
				icc = fz_device_rgb(ctx)->data;
				break;
			case 4:
				icc = fz_device_cmyk(ctx)->data;
				break;
			default:
				fz_throw(ctx, FZ_ERROR_GENERIC, "Poorly formed Cal color space");
			}
			/* To avoid repeated failures building the pdf-cal color space,
			* assign the default profile. */
			fz_cmm_fin_profile(ctx, icc);
			cal->profile = icc;
		}
	}
	return icc;
}

static fz_icclink *
fz_get_icc_link(fz_context *ctx, const fz_colorspace *dst, int dst_extras, const fz_colorspace *src, int src_extras, const fz_colorspace *prf, const fz_color_params *rend, int num_bytes, int copy_spots, int *src_n)
{
	fz_icclink *link = NULL;
	fz_iccprofile *src_icc = NULL;
	fz_iccprofile *dst_icc = NULL;
	fz_iccprofile *prf_icc = NULL;
	fz_link_key *key = NULL;
	fz_icclink *new_link;

	assert(!copy_spots || src_extras == dst_extras);

	if (prf != NULL)
		prf_icc = prf->data;

	if (fz_colorspace_is_icc(ctx, src))
		src_icc = src->data;
	else if (fz_colorspace_is_cal(ctx, src))
		src_icc = fz_get_icc_from_cal(ctx, src);
	else
		src_icc = get_base_icc_profile(ctx, src);

	if (fz_colorspace_is_icc(ctx, dst))
		dst_icc = dst->data;
	else if (fz_colorspace_is_cal(ctx, dst))
		dst_icc = fz_get_icc_from_cal(ctx, dst);
	else
		dst_icc = get_base_icc_profile(ctx, dst);

	if (dst_icc == NULL || src_icc == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Profile missing during link creation");

	*src_n = src_icc->num_devcomp;

	fz_var(link);
	fz_var(key);

	if (rend == NULL)
		rend = fz_default_color_params(ctx);

	fz_try(ctx)
	{
		/* Check the storable to see if we have a copy. */
		key = fz_malloc_struct(ctx, fz_link_key);
		key->refs = 1;
		memcpy(&key->dst_md5, dst_icc->md5, 16);
		memcpy(&key->src_md5, src_icc->md5, 16);
		key->rend.ri = rend->ri;
		key->rend.bp = rend->bp;
		key->src_extras = src_extras;
		key->dst_extras = dst_extras;
		key->depth = num_bytes;
		key->proof = (prf_icc != NULL);
		key->copy_spots = copy_spots;
		link = fz_find_item(ctx, fz_drop_link_imp, key, &fz_link_store_type);

		/* Not found.  Make new one add to store. */
		if (link == NULL)
		{
			link = fz_new_icc_link(ctx, dst_icc, dst_extras, src_icc, src_extras, prf_icc, rend, num_bytes, copy_spots);
			new_link = fz_store_item(ctx, key, link, sizeof(fz_icclink), &fz_link_store_type);
			if (new_link != NULL)
			{
				/* Found one while adding! Perhaps from another thread? */
				fz_drop_icclink(ctx, link);
				link = new_link;
			}
		}
	}
	fz_always(ctx)
	{
		fz_drop_link_key(ctx, key);
	}
	fz_catch(ctx)
	{
		/* Ignore any error that came just from the enstoring. */
		if (link == NULL)
			fz_rethrow(ctx);
	}
	return link;
}

/* Device colorspace definitions */
static void gray_to_rgb(fz_context *ctx, const fz_colorspace *cs, const float *gray, float *rgb)
{
	rgb[0] = gray[0];
	rgb[1] = gray[0];
	rgb[2] = gray[0];
}

static void rgb_to_gray(fz_context *ctx, const fz_colorspace *cs, const float *rgb, float *gray)
{
	float r = rgb[0];
	float g = rgb[1];
	float b = rgb[2];
	gray[0] = r * 0.3f + g * 0.59f + b * 0.11f;
}

static void rgb_to_rgb(fz_context *ctx, const fz_colorspace *cs, const float *rgb, float *xyz)
{
	xyz[0] = rgb[0];
	xyz[1] = rgb[1];
	xyz[2] = rgb[2];
}

static void bgr_to_rgb(fz_context *ctx, const fz_colorspace *cs, const float *bgr, float *rgb)
{
	rgb[0] = bgr[2];
	rgb[1] = bgr[1];
	rgb[2] = bgr[0];
}

static void rgb_to_bgr(fz_context *ctx, const fz_colorspace *cs, const float *rgb, float *bgr)
{
	bgr[0] = rgb[2];
	bgr[1] = rgb[1];
	bgr[2] = rgb[0];
}

static void cmyk_to_rgb(fz_context *ctx, const fz_colorspace *cs, const float *cmyk, float *rgb)
{
	rgb[0] = 1 - fz_min(1, cmyk[0] + cmyk[3]);
	rgb[1] = 1 - fz_min(1, cmyk[1] + cmyk[3]);
	rgb[2] = 1 - fz_min(1, cmyk[2] + cmyk[3]);
}

static void rgb_to_cmyk(fz_context *ctx, const fz_colorspace *cs, const float *rgb, float *cmyk)
{
	float c, m, y, k;
	c = 1 - rgb[0];
	m = 1 - rgb[1];
	y = 1 - rgb[2];
	k = fz_min(c, fz_min(m, y));
	cmyk[0] = c - k;
	cmyk[1] = m - k;
	cmyk[2] = y - k;
	cmyk[3] = k;
}

static inline float fung(float x)
{
	if (x >= 6.0f / 29.0f)
		return x * x * x;
	return (108.0f / 841.0f) * (x - (4.0f / 29.0f));
}

static void
lab_to_rgb(fz_context *ctx, const fz_colorspace *cs, const float *lab, float *rgb)
{
	/* input is in range (0..100, -128..127, -128..127) not (0..1, 0..1, 0..1) */
	float lstar, astar, bstar, l, m, n, x, y, z, r, g, b;
	lstar = lab[0];
	astar = lab[1];
	bstar = lab[2];
	m = (lstar + 16) / 116;
	l = m + astar / 500;
	n = m - bstar / 200;
	x = fung(l);
	y = fung(m);
	z = fung(n);
	r = (3.240449f * x + -1.537136f * y + -0.498531f * z) * 0.830026f;
	g = (-0.969265f * x + 1.876011f * y + 0.041556f * z) * 1.05452f;
	b = (0.055643f * x + -0.204026f * y + 1.057229f * z) * 1.1003f;
	rgb[0] = sqrtf(fz_clamp(r, 0, 1));
	rgb[1] = sqrtf(fz_clamp(g, 0, 1));
	rgb[2] = sqrtf(fz_clamp(b, 0, 1));
}

static void
rgb_to_lab(fz_context *ctx, const fz_colorspace *cs, const float *rgb, float *lab)
{
	fz_warn(ctx, "cannot convert into L*a*b colorspace");
	lab[0] = rgb[0];
	lab[1] = rgb[1];
	lab[2] = rgb[2];
}

/* This could be different for a, b */
static void
clamp_lab(const fz_colorspace *cs, const float *src, float *dst)
{
	int i;

	for (i = 0; i < 3; i++)
		dst[i] = fz_clamp(src[i], i ? -128 : 0, i ? 127 : 100);
}

static fz_colorspace k_default_gray = { { {-1, fz_drop_colorspace_imp}, 0 }, 0, "DeviceGray", FZ_COLORSPACE_GRAY, FZ_COLORSPACE_IS_DEVICE, 1, gray_to_rgb, rgb_to_gray, clamp_default, NULL, NULL, NULL, { "Gray" } };
static fz_colorspace k_default_rgb = { { {-1, fz_drop_colorspace_imp}, 0 }, 0, "DeviceRGB", FZ_COLORSPACE_RGB, FZ_COLORSPACE_IS_DEVICE, 3, rgb_to_rgb, rgb_to_rgb, clamp_default, NULL, NULL, NULL, { "Red", "Green", "Blue" } };
static fz_colorspace k_default_bgr = { { {-1, fz_drop_colorspace_imp}, 0 }, 0, "DeviceBGR", FZ_COLORSPACE_BGR, FZ_COLORSPACE_IS_DEVICE, 3, bgr_to_rgb, rgb_to_bgr, clamp_default, NULL, NULL, NULL, { "Blue", "Green", "Red" }  };
static fz_colorspace k_default_cmyk = { { {-1, fz_drop_colorspace_imp}, 0 }, 0, "DeviceCMYK", FZ_COLORSPACE_CMYK, FZ_COLORSPACE_IS_DEVICE, 4, cmyk_to_rgb, rgb_to_cmyk, clamp_default, NULL, NULL, NULL, { "Cyan", "Magenta", "Yellow", "Black" } };
static fz_colorspace k_default_lab = { { {-1, fz_drop_colorspace_imp}, 0 }, 0, "Lab", FZ_COLORSPACE_LAB, 0, 3, lab_to_rgb, rgb_to_lab, clamp_lab, NULL, NULL, NULL, { "L*", "a*", "b*" } };

static fz_color_params k_default_color_params = { FZ_RI_RELATIVE_COLORIMETRIC, 1, 0, 0 };

static fz_colorspace *default_gray = &k_default_gray;
static fz_colorspace *default_rgb = &k_default_rgb;
static fz_colorspace *default_bgr = &k_default_bgr;
static fz_colorspace *default_cmyk = &k_default_cmyk;
static fz_colorspace *default_lab = &k_default_lab;
static fz_color_params *default_color_params = &k_default_color_params;

const fz_cmm_engine *fz_get_cmm_engine(fz_context *ctx)
{
	return ctx->colorspace ? ctx->colorspace->cmm : NULL;
}

static void
set_no_icc(fz_colorspace_context *cct)
{
	cct->gray = default_gray;
	cct->rgb = default_rgb;
	cct->bgr = default_bgr;
	cct->cmyk = default_cmyk;
	cct->lab = default_lab;
}

void fz_set_cmm_engine(fz_context *ctx, const fz_cmm_engine *engine)
{
	fz_colorspace_context *cct;

	if (!ctx)
		return;
	cct = ctx->colorspace;
	if (!cct)
		return;

#if FZ_ENABLE_ICC
	if (cct->cmm == engine)
		return;

	fz_drop_colorspace(ctx, cct->gray);
	fz_drop_colorspace(ctx, cct->rgb);
	fz_drop_colorspace(ctx, cct->bgr);
	fz_drop_colorspace(ctx, cct->cmyk);
	fz_drop_colorspace(ctx, cct->lab);
	cct->gray = NULL;
	cct->rgb = NULL;
	cct->bgr = NULL;
	cct->cmyk = NULL;
	cct->lab = NULL;

	fz_drop_cmm_context(ctx);

	cct->cmm = engine;

	fz_new_cmm_context(ctx);

	if (engine)
	{
		fz_try(ctx)
		{
			cct->gray = fz_new_icc_colorspace(ctx, FZ_COLORSPACE_GRAY, NULL);
			cct->rgb = fz_new_icc_colorspace(ctx, FZ_COLORSPACE_RGB, NULL);
			cct->bgr = fz_new_icc_colorspace(ctx, FZ_COLORSPACE_BGR, NULL);
			cct->cmyk = fz_new_icc_colorspace(ctx, FZ_COLORSPACE_CMYK, NULL);
			cct->lab = fz_new_icc_colorspace(ctx, FZ_COLORSPACE_LAB, NULL);
		}
		fz_catch(ctx)
		{
			fz_drop_colorspace(ctx, cct->gray);
			fz_drop_colorspace(ctx, cct->rgb);
			fz_drop_colorspace(ctx, cct->bgr);
			fz_drop_colorspace(ctx, cct->cmyk);
			fz_drop_colorspace(ctx, cct->lab);
			fz_drop_cmm_context(ctx);
			cct->cmm = NULL;
			fz_new_cmm_context(ctx);
			set_no_icc(cct);
			fz_rethrow(ctx);
		}
	}
	else
		set_no_icc(cct);
#else
	if (engine)
		fz_throw(ctx, FZ_ERROR_GENERIC, "ICC workflow not supported in FZ_ENABLE_ICC=0 build");
#endif
}

void fz_new_colorspace_context(fz_context *ctx)
{
	ctx->colorspace = fz_malloc_struct(ctx, fz_colorspace_context);
	ctx->colorspace->ctx_refs = 1;
	set_no_icc(ctx->colorspace);
#if FZ_ENABLE_ICC
	fz_set_cmm_engine(ctx, &fz_cmm_engine_lcms);
#else
	fz_set_cmm_engine(ctx, NULL);
#endif
}

void
fz_new_cmm_context(fz_context *ctx)
{
	ctx->cmm_instance = fz_cmm_new_instance(ctx);
}

void
fz_drop_cmm_context(fz_context *ctx)
{
	fz_cmm_drop_instance(ctx);
	ctx->cmm_instance = NULL;
}

fz_colorspace_context *
fz_keep_colorspace_context(fz_context *ctx)
{
	if (!ctx)
		return NULL;
	return fz_keep_imp(ctx, ctx->colorspace, &ctx->colorspace->ctx_refs);
}

void fz_drop_colorspace_context(fz_context *ctx)
{
	if (!ctx)
		return;
	if (fz_drop_imp(ctx, ctx->colorspace, &ctx->colorspace->ctx_refs))
	{
		fz_drop_colorspace(ctx, ctx->colorspace->gray);
		fz_drop_colorspace(ctx, ctx->colorspace->rgb);
		fz_drop_colorspace(ctx, ctx->colorspace->bgr);
		fz_drop_colorspace(ctx, ctx->colorspace->cmyk);
		fz_drop_colorspace(ctx, ctx->colorspace->lab);
		fz_drop_cmm_context(ctx);
		fz_free(ctx, ctx->colorspace);
		ctx->colorspace = NULL;
	}
}

fz_colorspace *
fz_device_gray(fz_context *ctx)
{
	return ctx->colorspace->gray;
}

fz_colorspace *
fz_device_rgb(fz_context *ctx)
{
	return ctx->colorspace->rgb;
}

fz_colorspace *
fz_device_bgr(fz_context *ctx)
{
	return ctx->colorspace->bgr;
}

fz_colorspace *
fz_device_cmyk(fz_context *ctx)
{
	return ctx->colorspace->cmyk;
}

fz_colorspace *
fz_device_lab(fz_context *ctx)
{
	return ctx->colorspace->lab;
}

const fz_color_params *
fz_default_color_params(fz_context *ctx)
{
	return default_color_params;
}

/* Fast pixmap color conversions */

static void fast_gray_to_rgb(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;
	size_t w = src->w;
	int h = src->h;
	int sn = src->n;
	int ss = src->s;
	int sa = src->alpha;
	int dn = dst->n;
	int ds = dst->s;
	int da = dst->alpha;
	ptrdiff_t d_line_inc = dst->stride - w * dn;
	ptrdiff_t s_line_inc = src->stride - w * sn;

	/* If copying spots, they must match, and we can never drop alpha (but we can invent it) */
	if (copy_spots && ss != ds)
		fz_throw(ctx, FZ_ERROR_GENERIC, "incompatible number of spots when converting pixmap");
	if (!da && sa)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot drop alpha when converting pixmap");

	if ((int)w < 0 || h < 0)
		return;

	if (d_line_inc == 0 && s_line_inc == 0)
	{
		w *= h;
		h = 1;
	}

	if (ss == 0 && ds == 0)
	{
		/* Common, no spots case */
		if (da)
		{
			if (sa)
			{
				while (h--)
				{
					size_t ww = w;
					while (ww--)
					{
						d[0] = s[0];
						d[1] = s[0];
						d[2] = s[0];
						d[3] = s[1];
						s += 2;
						d += 4;
					}
					d += d_line_inc;
					s += s_line_inc;
				}
			}
			else
			{
				while (h--)
				{
					size_t ww = w;
					while (ww--)
					{
						d[0] = s[0];
						d[1] = s[0];
						d[2] = s[0];
						d[3] = 255;
						s++;
						d += 4;
					}
					d += d_line_inc;
					s += s_line_inc;
				}
			}
		}
		else
		{
			while (h--)
			{
				size_t ww = w;
				while (ww--)
				{
					d[0] = s[0];
					d[1] = s[0];
					d[2] = s[0];
					s++;
					d += 3;
				}
				d += d_line_inc;
				s += s_line_inc;
			}
		}
	}
	else if (copy_spots)
	{
		/* Slower, spots capable version */
		int i;
		while (h--)
		{
			size_t ww = w;
			while (ww--)
			{
				d[0] = s[0];
				d[1] = s[0];
				d[2] = s[0];
				s += 1;
				d += 3;
				for (i=ss; i > 0; i--)
					*d++ = *s++;
				if (da)
					*d++ = sa ? *s++ : 255;
			}
			d += d_line_inc;
			s += s_line_inc;
		}
	}
	else
	{
		while (h--)
		{
			size_t ww = w;
			while (ww--)
			{
				d[0] = s[0];
				d[1] = s[0];
				d[2] = s[0];
				s += sn;
				d += dn;
				if (da)
					d[-1] = sa ? s[-1] : 255;
			}
			d += d_line_inc;
			s += s_line_inc;
		}
	}
}

static void fast_gray_to_cmyk(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;
	size_t w = src->w;
	int h = src->h;
	int sn = src->n;
	int ss = src->s;
	int sa = src->alpha;
	int dn = dst->n;
	int ds = dst->s;
	int da = dst->alpha;
	ptrdiff_t d_line_inc = dst->stride - w * dn;
	ptrdiff_t s_line_inc = src->stride - w * sn;
	int k, g;
	int a = 255;
	int i;

	if (copy_spots && ss != ds)
		fz_throw(ctx, FZ_ERROR_GENERIC, "incompatible number of spots when converting pixmap");

	if ((int)w < 0 || h < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "integer overflow");

	while (h--)
	{
		size_t ww = w;
		while (ww--)
		{
			g = s[0];

			if (sa)
			{
				a = s[1+ss];
				g = fz_div255(g, a);
			}

			k = 255 - g;

			if (da)
			{
				*d++ = 0;
				*d++ = 0;
				*d++ = 0;
				*d++ = fz_mul255(k, a);
			}
			else
			{
				*d++ = 0;
				*d++ = 0;
				*d++ = 0;
				*d++ = k;
			}

			if (copy_spots)
			{
				s += 1;
				for (i=ss; i > 0; --i)
					*d++ = *s++;
				s += sa;
			}
			else
			{
				s += 1 + ss + sa;
				d += ds;
			}

			if (da)
			{
				*d++ = a;
			}
		}
		d += d_line_inc;
		s += s_line_inc;
	}
}

static void fast_rgb_to_gray(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;
	size_t w = src->w;
	int h = src->h;
	int sn = src->n;
	int ss = src->s;
	int sa = src->alpha;
	int dn = dst->n;
	int ds = dst->s;
	int da = dst->alpha;
	ptrdiff_t d_line_inc = dst->stride - w * dn;
	ptrdiff_t s_line_inc = src->stride - w * sn;

	/* If copying spots, they must match, and we can never drop alpha (but we can invent it) */
	if (copy_spots && ss != ds)
		fz_throw(ctx, FZ_ERROR_GENERIC, "incompatible number of spots when converting pixmap");
	if (!da && sa)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot drop alpha when converting pixmap");

	if ((int)w < 0 || h < 0)
		return;

	if (d_line_inc == 0 && s_line_inc == 0)
	{
		w *= h;
		h = 1;
	}

	if (ss == 0 && ds == 0)
	{
		/* Common, no spots case */
		if (da)
		{
			if (sa)
			{
				while (h--)
				{
					size_t ww = w;
					while (ww--)
					{
						d[0] = ((s[0]+1) * 77 + (s[1]+1) * 150 + (s[2]+1) * 28) >> 8;
						d[1] = s[3];
						s += 4;
						d += 2;
					}
					d += d_line_inc;
					s += s_line_inc;
				}
			}
			else
			{
				while (h--)
				{
					size_t ww = w;
					while (ww--)
					{
						d[0] = ((s[0]+1) * 77 + (s[1]+1) * 150 + (s[2]+1) * 28) >> 8;
						d[1] = 255;
						s += 3;
						d += 2;
					}
					d += d_line_inc;
					s += s_line_inc;
				}
			}
		}
		else
		{
			while (h--)
			{
				size_t ww = w;
				while (ww--)
				{
					d[0] = ((s[0]+1) * 77 + (s[1]+1) * 150 + (s[2]+1) * 28) >> 8;
					s += 3;
					d++;
				}
				d += d_line_inc;
				s += s_line_inc;
			}
		}
	}
	else if (copy_spots)
	{
		/* Slower, spots capable version */
		int i;
		while (h--)
		{
			size_t ww = w;
			while (ww--)
			{
				d[0] = ((s[0]+1) * 77 + (s[1]+1) * 150 + (s[2]+1) * 28) >> 8;
				s += 3;
				d++;
				for (i=ss; i > 0; i--)
					*d++ = *s++;
				if (da)
					*d++ = sa ? *s++ : 255;
			}
			d += d_line_inc;
			s += s_line_inc;
		}
	}
	else
	{
		while (h--)
		{
			size_t ww = w;
			while (ww--)
			{
				d[0] = ((s[0]+1) * 77 + (s[1]+1) * 150 + (s[2]+1) * 28) >> 8;
				s += sn;
				d += dn;
				if (da)
					d[-1] = sa ? s[-1] : 255;
			}
			d += d_line_inc;
			s += s_line_inc;
		}
	}
}

static void fast_bgr_to_gray(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;
	size_t w = src->w;
	int h = src->h;
	int sn = src->n;
	int ss = src->s;
	int sa = src->alpha;
	int dn = dst->n;
	int ds = dst->s;
	int da = dst->alpha;
	ptrdiff_t d_line_inc = dst->stride - w * dn;
	ptrdiff_t s_line_inc = src->stride - w * sn;

	/* If copying spots, they must match, and we can never drop alpha (but we can invent it) */
	if (copy_spots && ss != ds)
		fz_throw(ctx, FZ_ERROR_GENERIC, "incompatible number of spots when converting pixmap");
	if (!da && sa)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot drop alpha when converting pixmap");

	if ((int)w < 0 || h < 0)
		return;

	if (d_line_inc == 0 && s_line_inc == 0)
	{
		w *= h;
		h = 1;
	}

	if (ss == 0 && ds == 0)
	{
		/* Common, no spots case */
		if (da)
		{
			if (sa)
			{
				while (h--)
				{
					size_t ww = w;
					while (ww--)
					{
						d[0] = ((s[0]+1) * 28 + (s[1]+1) * 150 + (s[2]+1) * 77) >> 8;
						d[1] = s[3];
						s += 4;
						d += 2;
					}
					d += d_line_inc;
					s += s_line_inc;
				}
			}
			else
			{
				while (h--)
				{
					size_t ww = w;
					while (ww--)
					{
						d[0] = ((s[0]+1) * 28 + (s[1]+1) * 150 + (s[2]+1) * 77) >> 8;
						d[1] = 255;
						s += 3;
						d += 2;
					}
					d += d_line_inc;
					s += s_line_inc;
				}
			}
		}
		else
		{
			int si = 3 + src->alpha;

			while (h--)
			{
				size_t ww = w;
				while (ww--)
				{
					d[0] = ((s[0]+1) * 28 + (s[1]+1) * 150 + (s[2]+1) * 77) >> 8;
					s += si;
					d++;
				}
				d += d_line_inc;
				s += s_line_inc;
			}
		}
	}
	else if (copy_spots)
	{
		/* Slower, spots capable version */
		while (h--)
		{
			int i;
			size_t ww = w;
			while (ww--)
			{
				d[0] = ((s[0]+1) * 28 + (s[1]+1) * 150 + (s[2]+1) * 77) >> 8;
				s += 3;
				d++;
				for (i=ss; i > 0; i--)
					*d++ = *s++;
				if (da)
					*d++ = sa ? *s++ : 255;
			}
			d += d_line_inc;
			s += s_line_inc;
		}
	}
	else
	{
		/* Slower, spots capable version */
		while (h--)
		{
			size_t ww = w;
			while (ww--)
			{
				d[0] = ((s[0]+1) * 28 + (s[1]+1) * 150 + (s[2]+1) * 77) >> 8;
				s += sn;
				d += dn;
				if (da)
					d[-1] = sa ? s[-1] : 255;
			}
			d += d_line_inc;
			s += s_line_inc;
		}
	}
}

static void fast_rgb_to_cmyk(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;
	size_t w = src->w;
	int h = src->h;
	int sn = src->n;
	int ss = src->s;
	int sa = src->alpha;
	int dn = dst->n;
	int ds = dst->s;
	int da = dst->alpha;
	ptrdiff_t d_line_inc = dst->stride - w * dn;
	ptrdiff_t s_line_inc = src->stride - w * sn;
	int c, m, y, k, r, g, b;
	int a = 255;
	int i;

	if (copy_spots && ss != ds)
		fz_throw(ctx, FZ_ERROR_GENERIC, "incompatible number of spots when converting pixmap");

	if ((int)w < 0 || h < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "integer overflow");

	while (h--)
	{
		size_t ww = w;
		while (ww--)
		{
			r = s[0];
			g = s[1];
			b = s[2];

			if (sa)
			{
				a = s[3+ss];
				r = fz_div255(r, a);
				g = fz_div255(g, a);
				b = fz_div255(b, a);
			}

			c = 255 - r;
			m = 255 - g;
			y = 255 - b;
			k = fz_mini(c, fz_mini(m, y));
			c = c - k;
			m = m - k;
			y = y - k;

			if (da)
			{
				*d++ = fz_mul255(c, a);
				*d++ = fz_mul255(m, a);
				*d++ = fz_mul255(y, a);
				*d++ = fz_mul255(k, a);
			}
			else
			{
				*d++ = c;
				*d++ = m;
				*d++ = y;
				*d++ = k;
			}

			if (copy_spots)
			{
				s += 3;
				for (i=ss; i > 0; --i)
					*d++ = *s++;
				s += sa;
			}
			else
			{
				s += 3 + ss + sa;
				d += ds;
			}

			if (da)
			{
				*d++ = a;
			}
		}
		d += d_line_inc;
		s += s_line_inc;
	}
}

static void fast_bgr_to_cmyk(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;
	size_t w = src->w;
	int h = src->h;
	int sn = src->n;
	int ss = src->s;
	int sa = src->alpha;
	int dn = dst->n;
	int ds = dst->s;
	int da = dst->alpha;
	ptrdiff_t d_line_inc = dst->stride - w * dn;
	ptrdiff_t s_line_inc = src->stride - w * sn;
	int c, m, y, k, r, g, b;
	int a = 255;
	int i;

	if (copy_spots && ss != ds)
		fz_throw(ctx, FZ_ERROR_GENERIC, "incompatible number of spots when converting pixmap");

	if ((int)w < 0 || h < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "integer overflow");

	while (h--)
	{
		size_t ww = w;
		while (ww--)
		{
			b = s[0];
			g = s[1];
			r = s[2];

			if (sa)
			{
				a = s[3+ss];
				r = fz_div255(r, a);
				g = fz_div255(g, a);
				b = fz_div255(b, a);
			}

			c = 255 - r;
			m = 255 - g;
			y = 255 - b;
			k = fz_mini(c, fz_mini(m, y));
			c = c - k;
			m = m - k;
			y = y - k;

			if (da)
			{
				*d++ = fz_mul255(c, a);
				*d++ = fz_mul255(m, a);
				*d++ = fz_mul255(y, a);
				*d++ = fz_mul255(k, a);
			}
			else
			{
				*d++ = c;
				*d++ = m;
				*d++ = y;
				*d++ = k;
			}

			if (copy_spots)
			{
				s += 3;
				for (i=ss; i > 0; --i)
					*d++ = *s++;
				s += sa;
			}
			else
			{
				s += 3 + ss + sa;
				d += ds;
			}

			if (da)
			{
				*d++ = a;
			}
		}
		d += d_line_inc;
		s += s_line_inc;
	}
}

static void fast_cmyk_to_gray(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;
	size_t w = src->w;
	int h = src->h;
	int sn = src->n;
	int ss = src->s;
	int sa = src->alpha;
	int dn = dst->n;
	int ds = dst->s;
	int da = dst->alpha;
	ptrdiff_t d_line_inc = dst->stride - w * dn;
	ptrdiff_t s_line_inc = src->stride - w * sn;
	int c, m, y, k, g;
	int a = 255;
	int i;

	if (copy_spots && ss != ds)
		fz_throw(ctx, FZ_ERROR_GENERIC, "incompatible number of spots when converting pixmap");

	if ((int)w < 0 || h < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "integer overflow");

	while (h--)
	{
		size_t ww = w;
		while (ww--)
		{
			c = s[0];
			m = s[1];
			y = s[2];
			k = s[3];

			if (sa)
			{
				a = s[4+ss];
				c = fz_div255(c, a);
				m = fz_div255(m, a);
				y = fz_div255(y, a);
				k = fz_div255(k, a);
			}

			g = 255 - fz_mini(c + m + y + k, 255);

			if (da)
			{
				*d++ = fz_mul255(g, a);
			}
			else
			{
				*d++ = g;
			}

			if (copy_spots)
			{
				s += 4;
				for (i=ss; i > 0; --i)
					*d++ = *s++;
				s += sa;
			}
			else
			{
				s += 4 + ss + sa;
				d += ds;
			}

			if (da)
			{
				*d++ = a;
			}
		}
		d += d_line_inc;
		s += s_line_inc;
	}
}

static void fast_cmyk_to_rgb(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;
	size_t w = src->w;
	int h = src->h;
	int sn = src->n;
	int ss = src->s;
	int sa = src->alpha;
	int dn = dst->n;
	int ds = dst->s;
	int da = dst->alpha;
	ptrdiff_t d_line_inc = dst->stride - w * dn;
	ptrdiff_t s_line_inc = src->stride - w * sn;
	int c, m, y, k, r, g, b;
	int a = 255;
	int i;

	if (copy_spots && ss != ds)
		fz_throw(ctx, FZ_ERROR_GENERIC, "incompatible number of spots when converting pixmap");

	if ((int)w < 0 || h < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "integer overflow");

	while (h--)
	{
		size_t ww = w;
		while (ww--)
		{
			c = s[0];
			m = s[1];
			y = s[2];
			k = s[3];

			if (sa)
			{
				a = s[4+ss];
				c = fz_div255(c, a);
				m = fz_div255(m, a);
				y = fz_div255(y, a);
				k = fz_div255(k, a);
			}

			r = 255 - fz_mini(c + k, 255);
			g = 255 - fz_mini(m + k, 255);
			b = 255 - fz_mini(y + k, 255);

			if (da)
			{
				*d++ = fz_mul255(r, a);
				*d++ = fz_mul255(g, a);
				*d++ = fz_mul255(b, a);
			}
			else
			{
				*d++ = r;
				*d++ = g;
				*d++ = b;
			}

			if (copy_spots)
			{
				s += 4;
				for (i=ss; i > 0; --i)
					*d++ = *s++;
				s += sa;
			}
			else
			{
				s += 4 + ss + sa;
				d += ds;
			}

			if (da)
			{
				*d++ = a;
			}
		}
		d += d_line_inc;
		s += s_line_inc;
	}
}

static void fast_cmyk_to_bgr(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;
	size_t w = src->w;
	int h = src->h;
	int sn = src->n;
	int ss = src->s;
	int sa = src->alpha;
	int dn = dst->n;
	int ds = dst->s;
	int da = dst->alpha;
	ptrdiff_t d_line_inc = dst->stride - w * dn;
	ptrdiff_t s_line_inc = src->stride - w * sn;
	int c, m, y, k, r, g, b;
	int a = 255;
	int i;

	if (copy_spots && ss != ds)
		fz_throw(ctx, FZ_ERROR_GENERIC, "incompatible number of spots when converting pixmap");

	if ((int)w < 0 || h < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "integer overflow");

	while (h--)
	{
		size_t ww = w;
		while (ww--)
		{
			c = s[0];
			m = s[1];
			y = s[2];
			k = s[3];

			if (sa)
			{
				a = s[4+ss];
				c = fz_div255(c, a);
				m = fz_div255(m, a);
				y = fz_div255(y, a);
				k = fz_div255(k, a);
			}

			r = 255 - fz_mini(c + k, 255);
			g = 255 - fz_mini(m + k, 255);
			b = 255 - fz_mini(y + k, 255);

			if (da)
			{
				*d++ = fz_mul255(b, a);
				*d++ = fz_mul255(g, a);
				*d++ = fz_mul255(r, a);
			}
			else
			{
				*d++ = b;
				*d++ = g;
				*d++ = r;
			}

			if (copy_spots)
			{
				s += 4;
				for (i=ss; i > 0; --i)
					*d++ = *s++;
				s += sa;
			}
			else
			{
				s += 4 + ss + sa;
				d += ds;
			}

			if (da)
			{
				*d++ = a;
			}
		}
		d += d_line_inc;
		s += s_line_inc;
	}
}

static void fast_rgb_to_bgr(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;
	size_t w = src->w;
	int h = src->h;
	int sn = src->n;
	int ss = src->s;
	int sa = src->alpha;
	int dn = dst->n;
	int ds = dst->s;
	int da = dst->alpha;
	ptrdiff_t d_line_inc = dst->stride - w * dn;
	ptrdiff_t s_line_inc = src->stride - w * sn;

	/* If copying spots, they must match, and we can never drop alpha (but we can invent it) */
	if (copy_spots && ss != ds)
		fz_throw(ctx, FZ_ERROR_GENERIC, "incompatible number of spots when converting pixmap");
	if (!da && sa)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot drop alpha when converting pixmap");

	if ((int)w < 0 || h < 0)
		return;

	if (d_line_inc == 0 && s_line_inc == 0)
	{
		w *= h;
		h = 1;
	}

	if (ss == 0 && ds == 0)
	{
		/* Common, no spots case */
		if (da)
		{
			if (sa)
			{
				while (h--)
				{
					size_t ww = w;
					while (ww--)
					{
						d[0] = s[2];
						d[1] = s[1];
						d[2] = s[0];
						d[3] = s[3];
						s += 4;
						d += 4;
					}
				}
			}
			else
			{
				while (h--)
				{
					size_t ww = w;
					while (ww--)
					{
						d[0] = s[2];
						d[1] = s[1];
						d[2] = s[0];
						d[3] = 255;
						s += 3;
						d += 4;
					}
				}
			}
		}
		else
		{
			while (h--)
			{
				size_t ww = w;
				while (ww--)
				{
					d[0] = s[2];
					d[1] = s[1];
					d[2] = s[0];
					s += 3;
					d += 3;
				}
			}
		}
	}
	else if (copy_spots)
	{
		/* Slower, spots capable version */
		while (h--)
		{
			int i;
			size_t ww = w;
			while (ww--)
			{
				d[0] = s[2];
				d[1] = s[1];
				d[2] = s[0];
				s += 3;
				d += 3;
				for (i=ss; i > 0; i--)
					*d++ = *s++;
				if (da)
					*d++ = sa ? *s++ : 255;
			}
			d += d_line_inc;
			s += s_line_inc;
		}
	}
	else
	{
		while (h--)
		{
			size_t ww = w;
			while (ww--)
			{
				d[0] = s[2];
				d[1] = s[1];
				d[2] = s[0];
				s += sn;
				d += dn;
				if (da)
					d[-1] = sa ? s[-1] : 255;
			}
			d += d_line_inc;
			s += s_line_inc;
		}
	}
}

static void
icc_conv_pixmap(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_extras)
{
	fz_colorspace *srcs = src->colorspace;
	fz_colorspace *dsts = dst->colorspace;
	fz_icclink *link;
	int i;
	unsigned char *inputpos, *outputpos;
	int src_n;

	/* Handle DeviceGray to CMYK as K only. See note in Section 6.3 of PDF spec 1.7. */
	if (fz_colorspace_is_device_gray(ctx, srcs) && fz_colorspace_is_cmyk(ctx, dsts))
	{
		fast_gray_to_cmyk(ctx, dst, src, prf, default_cs, color_params, copy_extras);
		return;
	}

	/* Check if we have to do a color space default substitution */
	if (default_cs)
	{
		switch (fz_colorspace_type(ctx, src->colorspace))
		{
		case FZ_COLORSPACE_GRAY:
			if (src->colorspace == fz_device_gray(ctx))
				srcs = fz_default_gray(ctx, default_cs);
			break;
		case FZ_COLORSPACE_RGB:
			if (src->colorspace == fz_device_rgb(ctx))
				srcs = fz_default_rgb(ctx, default_cs);
			break;
		case FZ_COLORSPACE_CMYK:
			if (src->colorspace == fz_device_cmyk(ctx))
				srcs = fz_default_cmyk(ctx, default_cs);
			break;
		default:
			break;
		}
	}

	inputpos = src->samples;
	outputpos = dst->samples;

	/* If we have alpha channels, set copy_extras so that the LCMS transform also copies the alpha channels. */
	if (src->alpha || dst->alpha)
		copy_extras = 1;

	link = fz_get_icc_link(ctx, dsts, dst->s + dst->alpha, srcs, src->s + src->alpha, prf, color_params, 1, copy_extras, &src_n);

	if (link->is_identity)
	{
		for (i = 0; i < src->h; i++)
		{
			memcpy(outputpos, inputpos, src->stride);
			inputpos = inputpos + src->stride;
			outputpos = outputpos + dst->stride;
		}
	}
	else
		fz_cmm_transform_pixmap(ctx, link, dst, src);

	fz_drop_icclink(ctx, link);
}

/* Drill down through the base spaces until we get the either a pdf-cal or
 * an ICC base space.  This is where we want our pixmap to be decoded prior
 * to application of the link transform */
static fz_colorspace*
get_base_icc_space(fz_context *ctx, fz_colorspace *srcs)
{
	while (1)
	{
		srcs = srcs->get_base(srcs);
		if (srcs == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Final color space should be icc or pdf-cal or lab");

		if (fz_colorspace_is_icc(ctx, srcs) || fz_colorspace_is_cal(ctx, srcs) || fz_colorspace_is_lab(ctx, srcs))
			return srcs;
	}
}

/* Cope with cases where we have to convert through multiple base spaces before
 * getting to the final cm color space */
static void
convert_to_icc_base(fz_context *ctx, fz_colorspace *srcs, float *src_f, float *des_f)
{
	float temp_f[FZ_MAX_COLORS];
	fz_colorspace *base_cs = srcs->get_base(srcs);

	if (fz_colorspace_is_icc(ctx, base_cs) || fz_colorspace_is_cal(ctx, base_cs) || fz_colorspace_is_lab(ctx, base_cs))
		srcs->to_ccs(ctx, srcs, src_f, des_f);
	else
	{
		srcs->to_ccs(ctx, srcs, src_f, temp_f);
		convert_to_icc_base(ctx, base_cs, temp_f, des_f);
	}
}

/* For DeviceN and Separation CS, where we require an alternate tint tranform
 * prior to the application of an icc profile. Also, indexed images have to
 * be handled.  Realize those can map from index->devn->pdf-cal->icc for
 * example. */
static void
icc_base_conv_pixmap(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	fz_colorspace *srcs = src->colorspace;
	fz_colorspace *base_cs = get_base_icc_space(ctx, srcs);
	int i, j;
	unsigned char *inputpos, *outputpos;
	fz_pixmap *base;
	int h, len;
	float src_f[FZ_MAX_COLORS], des_f[FZ_MAX_COLORS];
	int sn = src->n;
	int sc = sn - src->alpha - src->s;
	int stride_src = src->stride - src->w * sn;
	int stride_base;
	int bn, bc;

	base = fz_new_pixmap_with_bbox(ctx, base_cs, fz_pixmap_bbox(ctx, src), src->seps, src->alpha);
	bn = base->n;
	bc = base->n - base->alpha - base->s;
	stride_base = base->stride - base->w * bn;

	inputpos = src->samples;
	outputpos = base->samples;

	h = src->h;
	while (h--)
	{
		len = src->w;
		while (len--)
		{
			/* Convert the actual colors */
			for (i = 0; i < sc; i++)
				src_f[i] = (float) inputpos[i] / 255.0f;

			convert_to_icc_base(ctx, srcs, src_f, des_f);
			base_cs->clamp(base_cs, des_f, des_f);

			for (j = 0; j < bc; j++)
				outputpos[j] = des_f[j] * 255.0f;
			/* Copy spots and alphas unchanged */
			for (; i < sn; i++, j++)
				outputpos[j] = inputpos[i];

			outputpos += bn;
			inputpos += sn;
		}
		outputpos += stride_base;
		inputpos += stride_src;
	}

	fz_try(ctx)
		icc_conv_pixmap(ctx, dst, base, prf, default_cs, color_params, copy_spots);
	fz_always(ctx)
		fz_drop_pixmap(ctx, base);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void
std_conv_pixmap(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	float srcv[FZ_MAX_COLORS];
	float dstv[FZ_MAX_COLORS];
	int srcn, dstn;
	int k, i;
	size_t w = src->w;
	int h = src->h;
	ptrdiff_t d_line_inc = dst->stride - w * dst->n;
	ptrdiff_t s_line_inc = src->stride - w * src->n;
	int da = dst->alpha;
	int sa = src->alpha;
	int alpha = 255;

	fz_colorspace *ss = src->colorspace;
	fz_colorspace *ds = dst->colorspace;

	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;

	if ((int)w < 0 || h < 0)
		return;

	if (color_params == NULL)
		color_params = fz_default_color_params(ctx);

	srcn = ss->n;
	dstn = ds->n;

	/* No spot colors allowed here! */
	assert(src->s == 0);
	assert(dst->s == 0);

	assert(src->w == dst->w && src->h == dst->h);
	assert(src->n == srcn + sa);
	assert(dst->n == dstn + da);

	if (d_line_inc == 0 && s_line_inc == 0)
	{
		w *= h;
		h = 1;
	}

	/* Special case for Lab colorspace (scaling of components to float) */
	if ((fz_colorspace_is_lab(ctx, ss) || fz_colorspace_is_lab_icc(ctx, ss)) && srcn == 3)
	{
		fz_color_converter cc;

		fz_find_color_converter(ctx, &cc, NULL, ds, ss, color_params);
		while (h--)
		{
			size_t ww = w;
			while (ww--)
			{
				if (sa)
				{
					alpha = s[4];
					srcv[0] = fz_div255(s[0], alpha) / 255.0f * 100;
					srcv[1] = fz_div255(s[1], alpha) - 128;
					srcv[2] = fz_div255(s[2], alpha) - 128;
					s += 4;
				}
				else
				{
					srcv[0] = s[0] / 255.0f * 100;
					srcv[1] = s[1] - 128;
					srcv[2] = s[2] - 128;
					s += 3;
				}

				cc.convert(ctx, &cc, dstv, srcv);

				if (da)
				{
					for (k = 0; k < dstn; k++)
						*d++ = fz_mul255(dstv[k] * 255, alpha);
					*d++ = alpha;
				}
				else
				{
					for (k = 0; k < dstn; k++)
						*d++ = dstv[k] * 255;
				}
			}
			d += d_line_inc;
			s += s_line_inc;
		}
		fz_drop_color_converter(ctx, &cc);
	}

	/* Brute-force for small images */
	else if (w*h < 256)
	{
		fz_color_converter cc;

		fz_find_color_converter(ctx, &cc, NULL, ds, ss, color_params);
		while (h--)
		{
			size_t ww = w;
			while (ww--)
			{
				if (sa)
				{
					alpha = s[srcn];
					for (k = 0; k < srcn; k++)
						srcv[k] = fz_div255(s[k], alpha) / 255.0f;
					s += srcn + 1;
				}
				else
				{
					for (k = 0; k < srcn; k++)
						srcv[k] = s[k] / 255.0f;
					s += srcn;
				}

				cc.convert(ctx, &cc, dstv, srcv);

				if (da)
				{
					for (k = 0; k < dstn; k++)
						*d++ = fz_mul255(dstv[k] * 255, alpha);
					*d++ = alpha;
				}
				else
				{
					for (k = 0; k < dstn; k++)
						*d++ = dstv[k] * 255;
				}
			}
			d += d_line_inc;
			s += s_line_inc;
		}
		fz_drop_color_converter(ctx, &cc);
	}

	/* 1-d lookup table for separation and similar colorspaces */
	else if (srcn == 1)
	{
		unsigned char lookup[FZ_MAX_COLORS * 256];
		fz_color_converter cc;

		fz_find_color_converter(ctx, &cc, NULL, ds, ss, color_params);
		for (i = 0; i < 256; i++)
		{
			srcv[0] = i / 255.0f;
			cc.convert(ctx, &cc, dstv, srcv);
			for (k = 0; k < dstn; k++)
				lookup[i * dstn + k] = dstv[k] * 255;
		}
		fz_drop_color_converter(ctx, &cc);

		while (h--)
		{
			size_t ww = w;
			while (ww--)
			{
				if (sa)
				{
					alpha = s[1];
					i = fz_div255(s[0], alpha);
					s += 2;
				}
				else
				{
					i = *s++;
				}

				if (da)
				{
					for (k = 0; k < dstn; k++)
						*d++ = fz_mul255(lookup[i * dstn + k], alpha);
					*d++ = alpha;
				}
				else
				{
					for (k = 0; k < dstn; k++)
						*d++ = lookup[i * dstn + k];
				}
			}
			d += d_line_inc;
			s += s_line_inc;
		}
	}

	/* Memoize colors using a hash table for the general case */
	else
	{
		fz_hash_table *lookup;
		unsigned char *color;
		unsigned char dummy = s[0] ^ 255;
		unsigned char *sold = &dummy;
		unsigned char *dold;
		fz_color_converter cc;

		lookup = fz_new_hash_table(ctx, 509, srcn+sa, -1, NULL);
		fz_find_color_converter(ctx, &cc, NULL, ds, ss, color_params);

		fz_try(ctx)
		{
			while (h--)
			{
				size_t ww = w;
				while (ww--)
				{
					if (*s == *sold && memcmp(sold,s,srcn+sa) == 0)
					{
						sold = s;
						memcpy(d, dold, dstn+da);
					}
					else
					{
						sold = s;
						dold = d;
						color = fz_hash_find(ctx, lookup, s);
						if (color)
						{
							memcpy(d, color, dstn+da);
						}
						else
						{
							if (sa)
							{
								alpha = s[srcn];
								for (k = 0; k < srcn; k++)
									srcv[k] = fz_div255(s[k], alpha) / 255.0f;
							}
							else
							{
								for (k = 0; k < srcn; k++)
									srcv[k] = s[k] / 255.0f;
							}

							cc.convert(ctx, &cc, dstv, srcv);

							if (da)
							{
								for (k = 0; k < dstn; k++)
									d[k] = fz_mul255(dstv[k] * 255, alpha);
								d[k] = alpha;
							}
							else
							{
								for (k = 0; k < dstn; k++)
									d[k] = dstv[k] * 255;
							}

							fz_hash_insert(ctx, lookup, s, d);
						}
					}
					s += srcn + sa;
					d += dstn + da;
				}
				d += d_line_inc;
				s += s_line_inc;
			}
		}
		fz_always(ctx)
		{
			fz_drop_color_converter(ctx, &cc);
			fz_drop_hash_table(ctx, lookup);
		}
		fz_catch(ctx)
			fz_rethrow(ctx);

	}
}

static void fast_any_to_alpha(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, const fz_default_colorspaces *default_cs, const fz_color_params *color_params, int copy_spots)
{
	assert(copy_spots && dst->s == 0 && src->s == 0);

	if (!src->alpha)
		fz_clear_pixmap_with_value(ctx, dst, 255);
	else
	{
		unsigned char *s = src->samples;
		unsigned char *d = dst->samples;
		size_t w = src->w;
		int h = src->h;
		int n = src->n;
		ptrdiff_t d_line_inc = dst->stride - w * dst->n;
		ptrdiff_t s_line_inc = src->stride - w * src->n;

		if ((int)w < 0 || h < 0)
			return;

		assert(dst->alpha && src->alpha && dst->n == 1);

		if (d_line_inc == 0 && s_line_inc == 0)
		{
			w *= h;
			h = 1;
		}

		s += n-1;
		while (h--)
		{
			size_t ww = w;
			while (ww--)
			{
				*d++ = *s;
				s += n;
			}
			d += d_line_inc;
			s += s_line_inc;
		}
	}
}

/* Used for testing all color managed color spaces.  If it is icc, cal or
 * has a base space that is managed */
static const fz_colorspace *
fz_colorspace_cm(fz_context *ctx, const fz_colorspace *cs)
{
	while (cs)
	{
		if (fz_colorspace_is_icc(ctx, cs))
			return cs;
		if (fz_colorspace_is_cal(ctx, cs))
			return cs;
		cs = fz_colorspace_base(ctx, cs);
	}
	return NULL;
}

fz_pixmap_converter *fz_lookup_pixmap_converter(fz_context *ctx, fz_colorspace *ds, fz_colorspace *ss)
{
	if (ds == NULL)
		return fast_any_to_alpha;

	if (ss == default_gray)
	{
		if (ds == default_rgb) return fast_gray_to_rgb;
		else if (ds == default_bgr) return fast_gray_to_rgb; /* bgr == rgb here */
		else if (ds == default_cmyk) return fast_gray_to_cmyk;
		else return std_conv_pixmap;
	}

	else if (ss == default_rgb)
	{
		if (ds == default_gray) return fast_rgb_to_gray;
		else if (ds == default_bgr) return fast_rgb_to_bgr;
		else if (ds == default_cmyk) return fast_rgb_to_cmyk;
		else return std_conv_pixmap;
	}

	else if (ss == default_bgr)
	{
		if (ds == default_gray) return fast_bgr_to_gray;
		else if (ds == default_rgb) return fast_rgb_to_bgr; /* bgr = rgb here */
		else if (ds == default_cmyk) return fast_bgr_to_cmyk;
		else return std_conv_pixmap;
	}

	else if (ss == default_cmyk)
	{
		if (ds == default_gray) return fast_cmyk_to_gray;
		else if (ds == default_bgr) return fast_cmyk_to_bgr;
		else if (ds == default_rgb) return fast_cmyk_to_rgb;
		else return std_conv_pixmap;
	}
	else if ((ss == fz_device_rgb(ctx) && ds == fz_device_bgr(ctx)) ||
		(ds == fz_device_rgb(ctx) && ss == fz_device_bgr(ctx)))
	{
		return fast_rgb_to_bgr;
	}
	else
	{
		const fz_colorspace *ss_base = fz_colorspace_cm(ctx, ss);
		if (ss_base != NULL && fz_colorspace_cm(ctx, ds))
		{
			if (ss_base == ss)
				return icc_conv_pixmap;
			else
				return icc_base_conv_pixmap;
		}
		else return std_conv_pixmap;
	}
}

/* Single color conversion with ICC profiles. ToDo: Check if it makes sense
 * to use lcms float link here or to do the conversion to short and back.
 */
static void
icc_conv_color(fz_context *ctx, fz_color_converter *cc, float *dstv, const float *srcv)
{
	const fz_colorspace *dsts = cc->ds;
	int src_n = cc->n;
	int dst_n = dsts->n;

	fz_icclink *link = (fz_icclink *)cc->link;
	int i;
	unsigned short dstv_s[FZ_MAX_COLORS];
	unsigned short srcv_s[FZ_MAX_COLORS];

	/* Special case.  Link is NULL if we are doing DeviceGray to CMYK */
	if (link == NULL)
	{
		dstv[0] = 0;
		dstv[1] = 0;
		dstv[2] = 0;
		dstv[3] = 1 - srcv[0];
	}
	else if (link->is_identity)
	{
		for (i = 0; i < src_n; i++)
			dstv[i] = srcv[i];
	}
	else
	{
		for (i = 0; i < src_n; i++)
			srcv_s[i] = srcv[i] * 65535;
		fz_cmm_transform_color(ctx, link, dstv_s, srcv_s);
		for (i = 0; i < dst_n; i++)
			dstv[i] = fz_clamp((float) dstv_s[i] / 65535.0f, 0, 1);
	}
}

/* Single ICC color conversion but for DeviceN, Sep and Indexed spaces.
 * Does premapping to get to ICC */
static void
icc_base_conv_color(fz_context *ctx, fz_color_converter *cc, float *dstv, const float *srcv)
{
	const fz_colorspace *srcs = cc->ss;

	float local_src_map[FZ_MAX_COLORS];
	float local_src_map2[FZ_MAX_COLORS];
	float *src_map = local_src_map;

	do
	{
		srcs->to_ccs(ctx, srcs, srcv, src_map);
		srcs = srcs->get_base(srcs);
		srcs->clamp(srcs, src_map, src_map);
		srcv = src_map;
		src_map = (src_map == local_src_map ? local_src_map2 : local_src_map);
	}
	while (!fz_colorspace_is_icc(ctx, srcs) && !fz_colorspace_is_cal(ctx, srcs));

	icc_conv_color(ctx, cc, dstv, srcv);
}

/* Convert a single color */
static void
std_conv_color(fz_context *ctx, fz_color_converter *cc, float *dstv, const float *srcv)
{
	float rgb[3];
	int i;
	const fz_colorspace *srcs = cc->ss;
	const fz_colorspace *dsts = cc->ds;

	if (srcs == NULL)
		srcs = fz_device_rgb(ctx);
	if (dsts == NULL)
		dsts = fz_device_rgb(ctx);

	if (srcs != dsts)
	{
		assert(srcs->to_ccs && dsts->from_ccs);
		srcs->to_ccs(ctx, srcs, srcv, rgb);
		dsts->from_ccs(ctx, dsts, rgb, dstv);
		for (i = 0; i < dsts->n; i++)
			dstv[i] = fz_clamp(dstv[i], 0, 1);
	}
	else
	{
		for (i = 0; i < srcs->n; i++)
			dstv[i] = srcv[i];
	}
}

static void
g2rgb(fz_context *ctx, fz_color_converter *cc, float *dv, const float *sv)
{
	dv[0] = sv[0];
	dv[1] = sv[0];
	dv[2] = sv[0];
}

static void
g2cmyk(fz_context *ctx, fz_color_converter *cc, float *dv, const float *sv)
{
	dv[0] = 0;
	dv[1] = 0;
	dv[2] = 0;
	dv[3] = 1 - sv[0];
}

static void
rgb2g(fz_context *ctx, fz_color_converter *cc, float *dv, const float *sv)
{
	dv[0] = sv[0] * 0.3f + sv[1] * 0.59f + sv[2] * 0.11f;
}

static void
rgb2bgr(fz_context *ctx, fz_color_converter *cc, float *dv, const float *sv)
{
	dv[0] = sv[2];
	dv[1] = sv[1];
	dv[2] = sv[0];
}

static void
rgb2cmyk(fz_context *ctx, fz_color_converter *cc, float *dv, const float *sv)
{
	float c = 1 - sv[0];
	float m = 1 - sv[1];
	float y = 1 - sv[2];
	float k = fz_min(c, fz_min(m, y));
	dv[0] = c - k;
	dv[1] = m - k;
	dv[2] = y - k;
	dv[3] = k;
}

static void
bgr2g(fz_context *ctx, fz_color_converter *cc, float *dv, const float *sv)
{
	dv[0] = sv[0] * 0.11f + sv[1] * 0.59f + sv[2] * 0.3f;
}

static void
bgr2cmyk(fz_context *ctx, fz_color_converter *cc, float *dv, const float *sv)
{
	float c = 1 - sv[2];
	float m = 1 - sv[1];
	float y = 1 - sv[0];
	float k = fz_min(c, fz_min(m, y));
	dv[0] = c - k;
	dv[1] = m - k;
	dv[2] = y - k;
	dv[3] = k;
}

static void
cmyk2g(fz_context *ctx, fz_color_converter *cc, float *dv, const float *sv)
{
	float c = sv[0] * 0.3f;
	float m = sv[1] * 0.59f;
	float y = sv[2] * 0.11f;
	dv[0] = 1 - fz_min(c + m + y + sv[3], 1);
}

static void
cmyk2rgb(fz_context *ctx, fz_color_converter *cc, float *dv, const float *sv)
{
	dv[0] = 1 - fz_min(sv[0] + sv[3], 1);
	dv[1] = 1 - fz_min(sv[1] + sv[3], 1);
	dv[2] = 1 - fz_min(sv[2] + sv[3], 1);
}

static void
cmyk2bgr(fz_context *ctx, fz_color_converter *cc, float *dv, const float *sv)
{
	dv[0] = 1 - fz_min(sv[2] + sv[3], 1);
	dv[1] = 1 - fz_min(sv[1] + sv[3], 1);
	dv[2] = 1 - fz_min(sv[0] + sv[3], 1);
}

void fz_find_color_converter(fz_context *ctx, fz_color_converter *cc, const fz_colorspace *is, const fz_colorspace *ds, const fz_colorspace *ss, const fz_color_params *params)
{
	if (ds == NULL)
		ds = fz_device_gray(ctx);
	if (ss == NULL)
		ss = fz_device_gray(ctx);
	cc->ds = ds;
	cc->ss = ss;
	cc->is = is;
	cc->link = NULL;
	if (ss == default_gray)
	{
		if ((ds == default_rgb) || (ds == default_bgr))
			cc->convert = g2rgb;
		else if (ds == default_cmyk)
			cc->convert = g2cmyk;
		else
			cc->convert = std_conv_color;
	}

	else if (ss == default_rgb)
	{
		if (ds == default_gray)
			cc->convert = rgb2g;
		else if (ds == default_bgr)
			cc->convert = rgb2bgr;
		else if (ds == default_cmyk)
			cc->convert = rgb2cmyk;
		else
			cc->convert = std_conv_color;
	}

	else if (ss == default_bgr)
	{
		if (ds == default_gray)
			cc->convert = bgr2g;
		else if (ds == default_rgb)
			cc->convert = rgb2bgr;
		else if (ds == default_cmyk)
			cc->convert = bgr2cmyk;
		else
			cc->convert = std_conv_color;
	}

	else if (ss == default_cmyk)
	{
		if (ds == default_gray)
			cc->convert = cmyk2g;
		else if (ds == default_rgb)
			cc->convert = cmyk2rgb;
		else if (ds == default_bgr)
			cc->convert = cmyk2bgr;
		else
			cc->convert = std_conv_color;
	}
	else if ((ss == fz_device_rgb(ctx) && ds == fz_device_bgr(ctx)) ||
		(ss == fz_device_bgr(ctx) && ds == fz_device_rgb(ctx)))
	{
		cc->convert = rgb2bgr;
	}
	else
	{
		const fz_colorspace *ss_base = fz_colorspace_cm(ctx, ss);
		if (ss_base != NULL && fz_colorspace_cm(ctx, ds))
		{
			if (ss_base == ss)
				cc->convert = icc_conv_color;
			else
				cc->convert = icc_base_conv_color;

			/* Special case: Do not set link if we are doing DeviceGray to CMYK. */
			/* Handle DeviceGray to CMYK as K only. See note in Section 6.3 of PDF spec 1.7. */
			if (!(fz_colorspace_is_device_gray(ctx, ss_base) && fz_colorspace_is_cmyk(ctx, ds)))
				cc->link = fz_get_icc_link(ctx, ds, 0, ss_base, 0, is, params, 2, 0, &cc->n);
		}
		else
			cc->convert = std_conv_color;
	}
}

void
fz_drop_color_converter(fz_context *ctx, fz_color_converter *cc)
{
	fz_icclink *link = (fz_icclink *)cc->link;
	if (link)
		fz_drop_icclink(ctx, link);
	cc->link = NULL;
}

void
fz_convert_color(fz_context *ctx, const fz_color_params *params, const fz_colorspace *is, const fz_colorspace *ds, float *dv, const fz_colorspace *ss, const float *sv)
{
	fz_color_converter cc;
	fz_find_color_converter(ctx, &cc, is, ds, ss, params);
	cc.convert(ctx, &cc, dv, sv);
	fz_drop_color_converter(ctx, &cc);
}

/* Indexed */

struct indexed
{
	fz_colorspace *base;
	int high;
	unsigned char *lookup;
};

static void
indexed_to_alt(fz_context *ctx, const fz_colorspace *cs, const float *color, float *alt)
{
	struct indexed *idx = cs->data;
	int i, k;
	int n = idx->base->n;

	i = color[0] * 255;
	i = fz_clampi(i, 0, idx->high);
	for (k = 0; k < n; k++)
		alt[k] = idx->lookup[i * n + k] / 255.0f;
}

static void
indexed_to_rgb(fz_context *ctx, const fz_colorspace *cs, const float *color, float *rgb)
{
	float alt[FZ_MAX_COLORS];
	struct indexed *idx = cs->data;

	indexed_to_alt(ctx, cs, color, alt);
	idx->base->to_ccs(ctx, idx->base, alt, rgb);
}

static void
free_indexed(fz_context *ctx, fz_colorspace *cs)
{
	struct indexed *idx = cs->data;
	fz_drop_colorspace(ctx, idx->base);
	fz_free(ctx, idx->lookup);
	fz_free(ctx, idx);
}

static fz_colorspace *
base_indexed(const fz_colorspace *cs)
{
	struct indexed *idx = cs->data;

	return idx->base;
}

static void
clamp_indexed(const fz_colorspace *cs, const float *in, float *out)
{
	struct indexed *idx = cs->data;

	*out = fz_clamp(*in, 0, idx->high) / 255.0f; /* To do, avoid 255 divide */
}

fz_colorspace *
fz_new_indexed_colorspace(fz_context *ctx, fz_colorspace *base, int high, unsigned char *lookup)
{
	fz_colorspace *cs = NULL;
	struct indexed *idx;

	idx = fz_malloc_struct(ctx, struct indexed);
	idx->lookup = lookup;
	idx->base = fz_keep_colorspace(ctx, base);
	idx->high = high;

	fz_try(ctx)
		cs = fz_new_colorspace(ctx, "Indexed", FZ_COLORSPACE_INDEXED, 0, 1, fz_colorspace_is_icc(ctx, fz_device_rgb(ctx)) ? indexed_to_alt : indexed_to_rgb, NULL, base_indexed, clamp_indexed, free_indexed, idx, sizeof(*idx) + (base->n * (idx->high + 1)) + base->size);
	fz_catch(ctx)
	{
		fz_free(ctx, idx);
		fz_rethrow(ctx);
	}
	return cs;
}

unsigned char *
fz_indexed_colorspace_palette(fz_context *ctx, fz_colorspace *cs, int *high)
{
	struct indexed *idx = cs->data;
	if (!fz_colorspace_is_indexed(ctx, cs))
		fz_throw(ctx, FZ_ERROR_GENERIC, "colorspace not indexed");
	*high = idx->high;
	return idx->lookup;
}

fz_pixmap *
fz_expand_indexed_pixmap(fz_context *ctx, const fz_pixmap *src, int alpha)
{
	struct indexed *idx;
	fz_pixmap *dst;
	const unsigned char *s;
	unsigned char *d;
	int y, x, k, n, high;
	unsigned char *lookup;
	int s_line_inc, d_line_inc;

	assert(src->colorspace->to_ccs == indexed_to_rgb || src->colorspace->to_ccs == indexed_to_alt);
	assert(src->n == 1 + alpha);

	idx = src->colorspace->data;
	high = idx->high;
	lookup = idx->lookup;
	n = idx->base->n;

	dst = fz_new_pixmap_with_bbox(ctx, idx->base, fz_pixmap_bbox(ctx, src), src->seps, alpha);
	s = src->samples;
	d = dst->samples;
	s_line_inc = src->stride - src->w * src->n;
	d_line_inc = dst->stride - dst->w * dst->n;

	if (alpha)
	{
		for (y = 0; y < src->h; y++)
		{
			for (x = 0; x < src->w; x++)
			{
				int v = *s++;
				int a = *s++;
				int aa = a + (a>>7);
				v = fz_mini(v, high);
				for (k = 0; k < n; k++)
					*d++ = (aa * lookup[v * n + k] + 128)>>8;
				*d++ = a;
			}
			s += s_line_inc;
			d += d_line_inc;
		}
	}
	else
	{
		for (y = 0; y < src->h; y++)
		{
			for (x = 0; x < src->w; x++)
			{
				int v = *s++;
				v = fz_mini(v, high);
				for (k = 0; k < n; k++)
					*d++ = lookup[v * n + k];
			}
			s += s_line_inc;
			d += d_line_inc;
		}
	}

	if (src->flags & FZ_PIXMAP_FLAG_INTERPOLATE)
		dst->flags |= FZ_PIXMAP_FLAG_INTERPOLATE;
	else
		dst->flags &= ~FZ_PIXMAP_FLAG_INTERPOLATE;

	return dst;
}

typedef struct fz_cached_color_converter
{
	fz_color_converter base;
	fz_hash_table *hash;
} fz_cached_color_converter;

static void fz_cached_color_convert(fz_context *ctx, fz_color_converter *cc_, float *ds, const float *ss)
{
	fz_cached_color_converter *cc = cc_->opaque;
	void *val = fz_hash_find(ctx, cc->hash, ss);
	int n = cc->base.ds->n * sizeof(float);
	fz_color_converter *base_cc = &cc->base;

	if (val)
	{
		memcpy(ds, val, n);
		return;
	}

	base_cc->convert(ctx, base_cc, ds, ss);
	val = fz_malloc(ctx, n);
	memcpy(val, ds, n);
	fz_try(ctx)
	{
		fz_hash_insert(ctx, cc->hash, ss, val);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, val);
	}
}

void fz_init_cached_color_converter(fz_context *ctx, fz_color_converter *cc, fz_colorspace *is, fz_colorspace *ds, fz_colorspace *ss, const fz_color_params *params)
{
	int n = ss->n;
	fz_cached_color_converter *cached = fz_malloc_struct(ctx, fz_cached_color_converter);

	cc->opaque = cached;
	cc->convert = fz_cached_color_convert;
	cc->ds = ds ? ds : fz_device_gray(ctx);
	cc->ss = ss;
	cc->is = is;

	fz_try(ctx)
	{
		fz_find_color_converter(ctx, &cached->base, is, cc->ds, ss, params);
		cached->hash = fz_new_hash_table(ctx, 256, n * sizeof(float), -1, fz_free);
	}
	fz_catch(ctx)
	{
		fz_drop_color_converter(ctx, &cached->base);
		fz_drop_hash_table(ctx, cached->hash);
		fz_free(ctx, cached);
		cc->opaque = NULL;
		fz_rethrow(ctx);
	}
}

void fz_fin_cached_color_converter(fz_context *ctx, fz_color_converter *cc_)
{
	fz_cached_color_converter *cc;
	if (cc_ == NULL)
		return;
	cc = cc_->opaque;
	if (cc == NULL)
		return;
	cc_->opaque = NULL;
	fz_drop_hash_table(ctx, cc->hash);
	fz_drop_color_converter(ctx, &cc->base);
	fz_free(ctx, cc);
}

fz_colorspace *fz_colorspace_base(fz_context *ctx, const fz_colorspace *cs)
{
	return cs && cs->get_base ? cs->get_base(cs) : NULL;
}

int fz_colorspace_n(fz_context *ctx, const fz_colorspace *cs)
{
	return cs ? cs->n : 0;
}

const char *fz_colorspace_name(fz_context *ctx, const fz_colorspace *cs)
{
	return cs ? cs->name : "";
}

#if FZ_ENABLE_ICC
static void
free_icc(fz_context *ctx, fz_colorspace *cs)
{
	fz_iccprofile *profile = cs->data;
	fz_drop_buffer(ctx, profile->buffer);
	fz_cmm_fin_profile(ctx, profile);
	fz_free(ctx, profile);
}

/* This could be different for a* b* */
static void
clamp_lab_icc(const fz_colorspace *cs, const float *src, float *dst)
{
	dst[0] = (fz_clamp(src[0], 0, 100)) / 100.0f;
	dst[1] = (fz_clamp(src[1], -128, 127) + 128.0f) / 256;
	dst[2] = (fz_clamp(src[2], -128, 127) + 128.0f) / 256;
}

/* Embedded icc profiles could have different range */
static void
clamp_default_icc(const fz_colorspace *cs, const float *src, float *dst)
{
	int i;
	fz_iccprofile *profile = cs->data;

	for (i = 0; i < profile->num_devcomp; i++)
		dst[i] = fz_clamp(src[i], 0, 1);
}

static const char *colorspace_name_from_type(int type)
{
	switch (type) {
	default: return "Unknown";
	case FZ_COLORSPACE_GRAY: return "Gray";
	case FZ_COLORSPACE_RGB: return "RGB";
	case FZ_COLORSPACE_BGR: return "BGR";
	case FZ_COLORSPACE_CMYK: return "CMYK";
	case FZ_COLORSPACE_LAB: return "Lab";
	}
}
#endif

fz_colorspace *
fz_new_icc_colorspace(fz_context *ctx, enum fz_colorspace_type type, fz_buffer *buf)
{
#if FZ_ENABLE_ICC
	fz_colorspace *cs = NULL;
	fz_iccprofile *profile;
	int flags = FZ_COLORSPACE_IS_ICC;
	const char *name;
	int num;

	profile = fz_malloc_struct(ctx, fz_iccprofile);
	fz_try(ctx)
	{
		if (buf == NULL)
		{
			size_t size;
			const unsigned char *data;
			data = fz_lookup_icc(ctx, type, &size);
			profile->buffer = fz_new_buffer_from_shared_data(ctx, data, size);
			flags |= FZ_COLORSPACE_IS_DEVICE;
		}
		else
		{
			profile->buffer = fz_keep_buffer(ctx, buf);
		}

		fz_cmm_init_profile(ctx, profile);

		if (type == FZ_COLORSPACE_NONE)
		{
			switch (profile->num_devcomp)
			{
			default: type = FZ_COLORSPACE_SEPARATION; break;
			case 1: type = FZ_COLORSPACE_GRAY; break;
			case 3: type = FZ_COLORSPACE_RGB; break;
			case 4: type = FZ_COLORSPACE_CMYK; break;
			}
		}

		profile->bgr = (type == FZ_COLORSPACE_BGR);

		switch (type)
		{
		default: num = profile->num_devcomp; break;
		case FZ_COLORSPACE_GRAY: num = 1; break;
		case FZ_COLORSPACE_RGB: num = 3; break;
		case FZ_COLORSPACE_BGR: num = 3; break;
		case FZ_COLORSPACE_LAB: num = 3; break;
		case FZ_COLORSPACE_CMYK: num = 4; break;
		}

		/* Check if correct type, if a particular type was expected */
		if (num != profile->num_devcomp)
			fz_throw(ctx, FZ_ERROR_GENERIC, "ICC profile did not match expected colorspace type");

		fz_md5_icc(ctx, profile);

		if (profile->desc)
			name = profile->desc;
		else
			name = colorspace_name_from_type(type);

		cs = fz_new_colorspace(ctx, name, type, flags, profile->num_devcomp,
			NULL,
			NULL,
			NULL,
			(type == FZ_COLORSPACE_LAB) ? clamp_lab_icc : clamp_default_icc,
			free_icc,
			profile, sizeof(*profile));

		switch (type)
		{
		default:
			break;
		case FZ_COLORSPACE_GRAY:
			fz_colorspace_name_colorant(ctx, cs, 0, "Gray");
			break;
		case FZ_COLORSPACE_LAB:
			fz_colorspace_name_colorant(ctx, cs, 0, "L*");
			fz_colorspace_name_colorant(ctx, cs, 1, "a*");
			fz_colorspace_name_colorant(ctx, cs, 2, "b*");
			break;
		case FZ_COLORSPACE_RGB:
			fz_colorspace_name_colorant(ctx, cs, 0, "Red");
			fz_colorspace_name_colorant(ctx, cs, 1, "Green");
			fz_colorspace_name_colorant(ctx, cs, 2, "Blue");
			break;
		case FZ_COLORSPACE_BGR:
			fz_colorspace_name_colorant(ctx, cs, 2, "Red");
			fz_colorspace_name_colorant(ctx, cs, 1, "Green");
			fz_colorspace_name_colorant(ctx, cs, 0, "Blue");
			break;
		case FZ_COLORSPACE_CMYK:
			fz_colorspace_name_colorant(ctx, cs, 0, "Cyan");
			fz_colorspace_name_colorant(ctx, cs, 1, "Magenta");
			fz_colorspace_name_colorant(ctx, cs, 2, "Yellow");
			fz_colorspace_name_colorant(ctx, cs, 3, "Black");
			break;
		}
	}
	fz_catch(ctx)
	{
		fz_drop_buffer(ctx, profile->buffer);
		fz_cmm_fin_profile(ctx, profile);
		fz_free(ctx, profile);
		fz_rethrow(ctx);
	}
	return cs;
#else
	fz_throw(ctx, FZ_ERROR_GENERIC, "ICC Profiles not supported in FZ_ENABLE_ICC=0 build");
#endif
}

fz_colorspace *fz_new_icc_colorspace_from_file(fz_context *ctx, enum fz_colorspace_type type, const char *path)
{
	fz_colorspace *cs = NULL;
	fz_buffer *buffer = fz_read_file(ctx, path);
	fz_try(ctx)
		cs = fz_new_icc_colorspace(ctx, type, buffer);
	fz_always(ctx)
		fz_drop_buffer(ctx, buffer);
	fz_catch(ctx)
		fz_rethrow(ctx);
	return cs;
}

fz_colorspace *fz_new_icc_colorspace_from_stream(fz_context *ctx, enum fz_colorspace_type type, fz_stream *in)
{
	fz_colorspace *cs = NULL;
	fz_buffer *buffer = fz_read_all(ctx, in, 1024);
	fz_try(ctx)
		cs = fz_new_icc_colorspace(ctx, type, buffer);
	fz_always(ctx)
		fz_drop_buffer(ctx, buffer);
	fz_catch(ctx)
		fz_rethrow(ctx);
	return cs;
}

/* Gets the icc data from a color space. Used in the writing out of the icc
 * data for output formats.
 */
fz_buffer *
fz_icc_data_from_icc_colorspace(fz_context *ctx, const fz_colorspace *cs)
{
	fz_iccprofile *profile;

	if (cs == NULL || !fz_colorspace_is_icc(ctx, cs))
		return NULL;
	profile = cs->data;
	if (!profile)
		return NULL;
	return profile->buffer;
}

static void
free_cal(fz_context *ctx, fz_colorspace *cs)
{
	fz_cal_colorspace *cal_data = cs->data;
	if (cal_data->profile != NULL)
	{
		fz_drop_buffer(ctx, cal_data->profile->buffer);
		fz_cmm_fin_profile(ctx, cal_data->profile);
		fz_free(ctx, cal_data->profile);
	}
	fz_free(ctx, cal_data);
}

/* Profile created if needed during draw command. */
fz_colorspace *
fz_new_cal_colorspace(fz_context *ctx, const char *name, float *wp, float *bp, float *gamma, float *matrix)
{
	fz_colorspace *cs = NULL;
	enum fz_colorspace_type type;
	int num;
	fz_cal_colorspace *cal_data;

	if (matrix)
	{
		type = FZ_COLORSPACE_RGB;
		num = 3;
	}
	else
	{
		type = FZ_COLORSPACE_GRAY;
		num = 1;
	}

	cal_data = fz_malloc_struct(ctx, fz_cal_colorspace);
	memcpy(&cal_data->bp, bp, sizeof(float) * 3);
	memcpy(&cal_data->wp, wp, sizeof(float) * 3);
	memcpy(&cal_data->gamma, gamma, sizeof(float) * num);
	if (matrix != NULL)
		memcpy(&cal_data->matrix, matrix, sizeof(float) * 9);
	cal_data->n = num;

	fz_try(ctx)
		cs = fz_new_colorspace(ctx, name, type, FZ_COLORSPACE_IS_CAL, num, NULL, NULL, NULL, NULL, free_cal, cal_data, sizeof(*cal_data));
	fz_catch(ctx)
	{
		fz_free(ctx, cal_data);
		fz_rethrow(ctx);
	}
	return cs;
}

void
fz_clamp_color(fz_context *ctx, const fz_colorspace *cs, const float *in, float *out)
{
	cs->clamp(cs, in, out);
}

/* Default CS. To handle the page specific default settings that PDF can do in
 * its page resource dictionary as well as the output intent.  Both need to
 * to be accessible by the device on the other side of the display list.
 * Same with the output intent. */
void
fz_set_default_gray(fz_context *ctx, fz_default_colorspaces *default_cs, fz_colorspace *cs)
{
	if (cs->n == 1)
	{
		fz_drop_colorspace(ctx, default_cs->gray);
		default_cs->gray = fz_keep_colorspace(ctx, cs);
	}
}

void
fz_set_default_rgb(fz_context *ctx, fz_default_colorspaces *default_cs, fz_colorspace *cs)
{
	if (cs->n == 3)
	{
		fz_drop_colorspace(ctx, default_cs->rgb);
		default_cs->rgb = fz_keep_colorspace(ctx, cs);
	}
}

void
fz_set_default_cmyk(fz_context *ctx, fz_default_colorspaces *default_cs, fz_colorspace *cs)
{
	if (cs->n == 4)
	{
		fz_drop_colorspace(ctx, default_cs->cmyk);
		default_cs->cmyk = fz_keep_colorspace(ctx, cs);
	}
}

void
fz_set_default_output_intent(fz_context *ctx, fz_default_colorspaces *default_cs, fz_colorspace *cs)
{
	fz_drop_colorspace(ctx, default_cs->oi);
	default_cs->oi = fz_keep_colorspace(ctx, cs);

	switch (cs->n)
	{
	case 1:
		if (default_cs->gray == fz_device_gray(ctx))
		{
			fz_drop_colorspace(ctx, default_cs->gray);
			default_cs->gray = fz_keep_colorspace(ctx, cs);
		}
		break;
	case 3:
		if (default_cs->rgb == fz_device_rgb(ctx))
		{
			fz_drop_colorspace(ctx, default_cs->rgb);
			default_cs->rgb = fz_keep_colorspace(ctx, cs);
		}
		break;
	case 4:
		if (default_cs->cmyk == fz_device_cmyk(ctx))
		{
			fz_drop_colorspace(ctx, default_cs->cmyk);
			default_cs->cmyk = fz_keep_colorspace(ctx, cs);
		}
		break;
	}
}

fz_colorspace *
fz_default_gray(fz_context *ctx, const fz_default_colorspaces *default_cs)
{
	if (default_cs)
		return default_cs->gray;
	else
		return fz_device_gray(ctx);
}

fz_colorspace *
fz_default_rgb(fz_context *ctx, const fz_default_colorspaces *default_cs)
{
	if (default_cs)
		return default_cs->rgb;
	else
		return fz_device_rgb(ctx);
}

fz_colorspace *
fz_default_cmyk(fz_context *ctx, const fz_default_colorspaces *default_cs)
{
	if (default_cs)
		return default_cs->cmyk;
	else
		return fz_device_cmyk(ctx);
}

fz_colorspace *
fz_default_output_intent(fz_context *ctx, const fz_default_colorspaces *default_cs)
{
	if (default_cs)
		return default_cs->oi;
	else
		return NULL;
}

fz_default_colorspaces *
fz_new_default_colorspaces(fz_context *ctx)
{
	fz_default_colorspaces *default_cs = fz_malloc_struct(ctx, fz_default_colorspaces);
	default_cs->refs = 1;
	default_cs->gray = fz_keep_colorspace(ctx, fz_device_gray(ctx));
	default_cs->rgb = fz_keep_colorspace(ctx, fz_device_rgb(ctx));
	default_cs->cmyk = fz_keep_colorspace(ctx, fz_device_cmyk(ctx));
	default_cs->oi = NULL;
	return default_cs;
}

fz_default_colorspaces *
fz_clone_default_colorspaces(fz_context *ctx, fz_default_colorspaces *base)
{
	fz_default_colorspaces *default_cs = fz_malloc_struct(ctx, fz_default_colorspaces);
	default_cs->refs = 1;
	if (base)
	{
		default_cs->gray = fz_keep_colorspace(ctx, base->gray);
		default_cs->rgb = fz_keep_colorspace(ctx, base->rgb);
		default_cs->cmyk = fz_keep_colorspace(ctx, base->cmyk);
		default_cs->oi = fz_keep_colorspace(ctx, base->oi);
	}
	return default_cs;
}

fz_default_colorspaces *
fz_keep_default_colorspaces(fz_context *ctx, fz_default_colorspaces *default_cs)
{
	return fz_keep_imp(ctx, default_cs, &default_cs->refs);
}

void
fz_drop_default_colorspaces(fz_context *ctx, fz_default_colorspaces *default_cs)
{
	if (fz_drop_imp(ctx, default_cs, &default_cs->refs))
	{
		fz_drop_colorspace(ctx, default_cs->gray);
		fz_drop_colorspace(ctx, default_cs->rgb);
		fz_drop_colorspace(ctx, default_cs->cmyk);
		fz_drop_colorspace(ctx, default_cs->oi);
		fz_free(ctx, default_cs);
	}
}

void fz_colorspace_name_colorant(fz_context *ctx, fz_colorspace *cs, int i, const char *name)
{
	if (!cs)
		return;

	if (i < 0 || i >= cs->n)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Attempt to name out of range colorant");

	fz_free(ctx, cs->colorant[i]);
	cs->colorant[i] = NULL;
	if (name)
	{
		cs->colorant[i] = fz_strdup(ctx, name);

		if (cs->type == FZ_COLORSPACE_SEPARATION)
		{
			if (i == 0)
			{
				if (strcmp(name, "Cyan") == 0 ||
					strcmp(name, "Magenta") == 0 ||
					strcmp(name, "Yellow") == 0 ||
					strcmp(name, "Black") == 0)
				{
					cs->flags |= FZ_CS_HAS_CMYK;
				}
			}
			else
			{
				if ((cs->flags & FZ_CS_HAS_CMYK_AND_SPOTS) != FZ_CS_HAS_CMYK_AND_SPOTS)
				{
					if (strcmp(name, "Cyan") == 0 ||
						strcmp(name, "Magenta") == 0 ||
						strcmp(name, "Yellow") == 0 ||
						strcmp(name, "Black") == 0)
						cs->flags |= FZ_CS_HAS_CMYK;
					else
						cs->flags |= FZ_CS_HAS_SPOTS;
				}
			}
		}
	}
}

const char *fz_colorspace_colorant(fz_context *ctx, const fz_colorspace *cs, int i)
{
	if (!cs || i < 0 || i >= cs->n)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Colorant out of range");

	return cs->colorant[i];
}
