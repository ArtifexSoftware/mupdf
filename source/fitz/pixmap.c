#include "mupdf/fitz.h"

#include <assert.h>
#include <limits.h>
#include <string.h>
#include <math.h>

fz_pixmap *
fz_keep_pixmap(fz_context *ctx, fz_pixmap *pix)
{
	return fz_keep_storable(ctx, &pix->storable);
}

void
fz_drop_pixmap(fz_context *ctx, fz_pixmap *pix)
{
	fz_drop_storable(ctx, &pix->storable);
}

void
fz_drop_pixmap_imp(fz_context *ctx, fz_storable *pix_)
{
	fz_pixmap *pix = (fz_pixmap *)pix_;

	fz_drop_colorspace(ctx, pix->colorspace);
	if (pix->free_samples)
		fz_free(ctx, pix->samples);
	fz_free(ctx, pix);
}

fz_pixmap *
fz_new_pixmap_with_data(fz_context *ctx, fz_colorspace *colorspace, int w, int h, int alpha, int stride, unsigned char *samples)
{
	fz_pixmap *pix;
	int n;

	if (w < 0 || h < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Illegal dimensions for pixmap %d %d", w, h);

	n = alpha + fz_colorspace_n(ctx, colorspace);
	if (stride < n*w && stride > -n*w)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Illegal stride for pixmap (n=%d w=%d, stride=%d)", n, w, stride);
	if (samples == NULL && stride < n*w)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Illegal -ve stride for pixmap without data");

	pix = fz_malloc_struct(ctx, fz_pixmap);
	FZ_INIT_STORABLE(pix, 1, fz_drop_pixmap_imp);
	pix->x = 0;
	pix->y = 0;
	pix->w = w;
	pix->h = h;
	pix->alpha = alpha = !!alpha;
	pix->interpolate = 1;
	pix->xres = 96;
	pix->yres = 96;
	pix->colorspace = NULL;
	pix->n = n;
	pix->stride = stride;

	if (colorspace)
	{
		pix->colorspace = fz_keep_colorspace(ctx, colorspace);
	}
	else
	{
		assert(alpha);
	}

	pix->samples = samples;
	if (samples)
	{
		pix->free_samples = 0;
	}
	else
	{
		fz_try(ctx)
		{
			if (pix->stride - 1 > INT_MAX / pix->n)
				fz_throw(ctx, FZ_ERROR_GENERIC, "overly wide image");
			pix->samples = fz_malloc_array(ctx, pix->h, pix->stride);
		}
		fz_catch(ctx)
		{
			fz_drop_colorspace(ctx, colorspace);
			fz_free(ctx, pix);
			fz_rethrow(ctx);
		}
		pix->free_samples = 1;
	}

	return pix;
}

fz_pixmap *
fz_new_pixmap(fz_context *ctx, fz_colorspace *colorspace, int w, int h, int alpha)
{
	int stride;
	if (!colorspace) alpha = 1;
	stride = (fz_colorspace_n(ctx, colorspace) + alpha) * w;
	return fz_new_pixmap_with_data(ctx, colorspace, w, h, alpha, stride, NULL);
}

fz_pixmap *
fz_new_pixmap_with_bbox(fz_context *ctx, fz_colorspace *colorspace, const fz_irect *r, int alpha)
{
	fz_pixmap *pixmap;
	pixmap = fz_new_pixmap(ctx, colorspace, r->x1 - r->x0, r->y1 - r->y0, alpha);
	pixmap->x = r->x0;
	pixmap->y = r->y0;
	return pixmap;
}

fz_pixmap *
fz_new_pixmap_with_bbox_and_data(fz_context *ctx, fz_colorspace *colorspace, const fz_irect *r, int alpha, unsigned char *samples)
{
	int w = r->x1 - r->x0;
	int stride;
	fz_pixmap *pixmap;
	if (!colorspace) alpha = 1;
	stride = (fz_colorspace_n(ctx, colorspace) + alpha) * w;
	pixmap = fz_new_pixmap_with_data(ctx, colorspace, w, r->y1 - r->y0, alpha, stride, samples);
	pixmap->x = r->x0;
	pixmap->y = r->y0;
	return pixmap;
}

fz_irect *
fz_pixmap_bbox(fz_context *ctx, const fz_pixmap *pix, fz_irect *bbox)
{
	bbox->x0 = pix->x;
	bbox->y0 = pix->y;
	bbox->x1 = pix->x + pix->w;
	bbox->y1 = pix->y + pix->h;
	return bbox;
}

fz_irect *
fz_pixmap_bbox_no_ctx(const fz_pixmap *pix, fz_irect *bbox)
{
	bbox->x0 = pix->x;
	bbox->y0 = pix->y;
	bbox->x1 = pix->x + pix->w;
	bbox->y1 = pix->y + pix->h;
	return bbox;
}

fz_colorspace *
fz_pixmap_colorspace(fz_context *ctx, fz_pixmap *pix)
{
	if (!pix)
		return NULL;
	return pix->colorspace;
}

int
fz_pixmap_x(fz_context *ctx, fz_pixmap *pix)
{
	return pix->x;
}

int
fz_pixmap_y(fz_context *ctx, fz_pixmap *pix)
{
	return pix->y;
}

int
fz_pixmap_width(fz_context *ctx, fz_pixmap *pix)
{
	return pix->w;
}

int
fz_pixmap_height(fz_context *ctx, fz_pixmap *pix)
{
	return pix->h;
}

int
fz_pixmap_components(fz_context *ctx, fz_pixmap *pix)
{
	return pix->n;
}

int
fz_pixmap_colorants(fz_context *ctx, fz_pixmap *pix)
{
	return pix->n - pix->alpha;
}

int
fz_pixmap_stride(fz_context *ctx, fz_pixmap *pix)
{
	return pix->stride;
}

unsigned char *
fz_pixmap_samples(fz_context *ctx, fz_pixmap *pix)
{
	if (!pix)
		return NULL;
	return pix->samples;
}

/*
	The slowest routine in most CMYK rendering profiles.
	We therefore spend some effort to improve it. Rather than
	writing bytes, we write uint32_t's.
*/
#ifdef ARCH_ARM
static void
clear_cmyka_bitmap_ARM(uint32_t *samples, int c, int value)
__attribute__((naked));

static void
clear_cmyka_bitmap_ARM(uint32_t *samples, int c, int value)
{
	asm volatile(
	ENTER_ARM
	"stmfd	r13!,{r4-r6,r14}					\n"
	"@ r0 = samples							\n"
	"@ r1 = c							\n"
	"@ r2 = value							\n"
	"mov	r3, #255						\n"
	"mov	r12,#0			@ r12= 0			\n"
	"subs	r1, r1, #3						\n"
	"ble	2f							\n"
	"str	r12,[r13,#-20]!						\n"
	"str	r12,[r13,#4]						\n"
	"str	r12,[r13,#8]						\n"
	"str	r12,[r13,#12]						\n"
	"str	r12,[r13,#16]						\n"
	"strb	r2, [r13,#3]						\n"
	"strb	r3, [r13,#4]						\n"
	"strb	r2, [r13,#8]						\n"
	"strb	r3, [r13,#9]						\n"
	"strb	r2, [r13,#13]						\n"
	"strb	r3, [r13,#14]						\n"
	"strb	r2, [r13,#18]						\n"
	"strb	r3, [r13,#19]						\n"
	"ldmfd	r13!,{r4,r5,r6,r12,r14}					\n"
	"1:								\n"
	"stmia	r0!,{r4,r5,r6,r12,r14}					\n"
	"subs	r1, r1, #4						\n"
	"bgt	1b							\n"
	"2:								\n"
	"adds	r1, r1, #3						\n"
	"ble	4f							\n"
	"3:								\n"
	"strb	r12,[r0], #1						\n"
	"strb	r12,[r0], #1						\n"
	"strb	r12,[r0], #1						\n"
	"strb	r2, [r0], #1						\n"
	"strb	r3, [r0], #1						\n"
	"subs	r1, r1, #1						\n"
	"bgt	3b							\n"
	"4:								\n"
	"ldmfd	r13!,{r4-r6,PC}						\n"
	ENTER_THUMB
	);
}
#endif

static void
clear_cmyk_bitmap(unsigned char *samples, int w, int h, int stride, int value, int alpha)
{
	uint32_t *s = (uint32_t *)(void *)samples;
	uint8_t *t;

	if (w < 0 || h < 0)
		return;

	if (alpha)
	{
		int c = w;
		stride -= w*5;
		if (stride == 0)
		{
#ifdef ARCH_ARM
			clear_cmyka_bitmap_ARM(s, c, alpha);
			return;
#else
			/* We can do it all fast (except for maybe a few stragglers) */
			union
			{
				uint8_t bytes[20];
				uint32_t words[5];
			} d;

			c *= h;
			h = 1;

			d.words[0] = 0;
			d.words[1] = 0;
			d.words[2] = 0;
			d.words[3] = 0;
			d.words[4] = 0;
			d.bytes[3] = value;
			d.bytes[4] = 255;
			d.bytes[8] = value;
			d.bytes[9] = 255;
			d.bytes[13] = value;
			d.bytes[14] = 255;
			d.bytes[18] = value;
			d.bytes[19] = 255;

			c -= 3;
			{
				const uint32_t a0 = d.words[0];
				const uint32_t a1 = d.words[1];
				const uint32_t a2 = d.words[2];
				const uint32_t a3 = d.words[3];
				const uint32_t a4 = d.words[4];
				while (c > 0)
				{
					*s++ = a0;
					*s++ = a1;
					*s++ = a2;
					*s++ = a3;
					*s++ = a4;
					c -= 4;
				}
			}
			c += 3;
#endif
		}
		t = (unsigned char *)s;
		w = c;
		while (h--)
		{
			c = w;
			while (c > 0)
			{
				*t++ = 0;
				*t++ = 0;
				*t++ = 0;
				*t++ = value;
				*t++ = 255;
				c--;
			}
			t += stride;
		}
	}
	else
	{
		stride -= w*4;
		if ((stride & 3) == 0)
		{
			size_t W = w;
			if (stride == 0)
			{
				W *= h;
				h = 1;
			}
			W *= 4;
			if (value == 0)
			{
				while (h--)
				{
					memset(s, 0, W);
					s += (stride>>2);
				}
			}
			else
			{
				/* We can do it all fast */
				union
				{
					uint8_t bytes[4];
					uint32_t word;
				} d;

				d.word = 0;
				d.bytes[3] = value;
				{
					const uint32_t a0 = d.word;
					while (h--)
					{
						size_t WW = W >> 2;
						while (WW--)
						{
							*s++ = a0;
						}
						s += (stride>>2);
					}
				}
			}
		}
		else
		{
			t = (unsigned char *)s;
			while (h--)
			{
				int c = w;
				while (c > 0)
				{
					*t++ = 0;
					*t++ = 0;
					*t++ = 0;
					*t++ = value;
					c--;
				}
				t += stride;
			}
		}
	}
}

void
fz_clear_pixmap(fz_context *ctx, fz_pixmap *pix)
{
	int stride = pix->w * pix->n;
	int h = pix->h;
	unsigned char *s = pix->samples;
	if (stride == pix->stride)
	{
		stride *= h;
		h = 1;
	}
	if (pix->alpha)
	{
		while (h--)
		{
			memset(s, 0, (unsigned int)stride);
			s += pix->stride;
		}
	}
	else
	{
		/* FIXME: Not right for CMYK or other subtractive spaces */
		while (h--)
		{
			memset(s, 0xff, (unsigned int)stride);
			s += pix->stride;
		}
	}
}

void
fz_clear_pixmap_with_value(fz_context *ctx, fz_pixmap *pix, int value)
{
	unsigned char *s;
	int w, h, n, stride, len;
	int alpha = pix->alpha;

	w = pix->w;
	h = pix->h;
	if (w < 0 || h < 0)
		return;

	/* CMYK needs special handling (and potentially any other subtractive colorspaces) */
	if (fz_colorspace_n(ctx, pix->colorspace) == 4)
	{
		clear_cmyk_bitmap(pix->samples, w, h, pix->stride, 255-value, pix->alpha);
		return;
	}

	n = pix->n;
	stride = pix->stride;
	len = w * n;

	s = pix->samples;
	if (value == 255 || !alpha)
	{
		if (stride == len)
		{
			len *= h;
			h = 1;
		}
		while (h--)
		{
			memset(s, value, (unsigned int)len);
			s += stride;
		}
	}
	else
	{
		int k, x, y;
		stride -= len;
		for (y = 0; y < pix->h; y++)
		{
			for (x = 0; x < pix->w; x++)
			{
				for (k = 0; k < pix->n - 1; k++)
					*s++ = value;
				if (alpha)
					*s++ = 255;
			}
			s += stride;
		}
	}
}

void
fz_copy_pixmap_rect(fz_context *ctx, fz_pixmap *dest, fz_pixmap *src, const fz_irect *b)
{
	const unsigned char *srcp;
	unsigned char *destp;
	int x, y, w, destspan, srcspan;
	fz_irect local_b, bb;

	local_b = *b;
	fz_intersect_irect(&local_b, fz_pixmap_bbox(ctx, dest, &bb));
	fz_intersect_irect(&local_b, fz_pixmap_bbox(ctx, src, &bb));
	w = local_b.x1 - local_b.x0;
	y = local_b.y1 - local_b.y0;
	if (w <= 0 || y <= 0)
		return;

	srcspan = src->stride;
	srcp = src->samples + (unsigned int)(srcspan * (local_b.y0 - src->y) + src->n * (local_b.x0 - src->x));
	destspan = dest->stride;
	destp = dest->samples + (unsigned int)(destspan * (local_b.y0 - dest->y) + dest->n * (local_b.x0 - dest->x));

	if (src->n == dest->n)
	{
		w *= src->n;
		do
		{
			memcpy(destp, srcp, w);
			srcp += srcspan;
			destp += destspan;
		}
		while (--y);
	}
	else if (src->n == 2 && dest->n == 4)
	{
		/* Copy, and convert from grey+alpha to rgb+alpha */
		srcspan -= w*2;
		destspan -= w*4;
		do
		{
			for (x = w; x > 0; x--)
			{
				unsigned char v = *srcp++;
				unsigned char a = *srcp++;
				*destp++ = v;
				*destp++ = v;
				*destp++ = v;
				*destp++ = a;
			}
			srcp += srcspan;
			destp += destspan;
		}
		while (--y);
	}
	else if (src->n == 1 + src->alpha && dest->n == 3 + dest->alpha)
	{
		assert("FIXME" == NULL);
	}
	else if (src->n == 4 && dest->n == 2)
	{
		/* Copy, and convert from rgb+alpha to grey+alpha */
		srcspan -= w*4;
		destspan -= w*2;
		do
		{
			for (x = w; x > 0; x--)
			{
				int v;
				v = *srcp++;
				v += *srcp++;
				v += *srcp++;
				*destp++ = (unsigned char)((v+1)/3);
				*destp++ = *srcp++;
			}
			srcp += srcspan;
			destp += destspan;
		}
		while (--y);
	}
	else if (src->n == 3 + src->alpha && dest->n == 1 + dest->alpha)
	{
		assert("FIXME" == NULL);
	}
	else
	{
		/* FIXME: Crap conversion */
		int z;
		int sn = src->n-1;
		int dn = dest->n-1;

		srcspan -= w*src->n;
		destspan -= w*dest->n;
		do
		{
			for (x = w; x > 0; x--)
			{
				int v = 0;
				for (z = sn; z > 0; z--)
					v += *srcp++;
				v = (v * dn + (sn>>1)) / sn;
				for (z = dn; z > 0; z--)
					*destp++ = (unsigned char)v;
				*destp++ = *srcp++;
			}
			srcp += srcspan;
			destp += destspan;
		}
		while (--y);
	}
}

void
fz_clear_pixmap_rect_with_value(fz_context *ctx, fz_pixmap *dest, int value, const fz_irect *b)
{
	unsigned char *destp;
	int x, y, w, k, destspan;
	fz_irect bb;
	fz_irect local_b = *b;

	fz_intersect_irect(&local_b, fz_pixmap_bbox(ctx, dest, &bb));
	w = local_b.x1 - local_b.x0;
	y = local_b.y1 - local_b.y0;
	if (w <= 0 || y <= 0)
		return;

	destspan = dest->stride;
	destp = dest->samples + (unsigned int)(destspan * (local_b.y0 - dest->y) + dest->n * (local_b.x0 - dest->x));

	/* CMYK needs special handling (and potentially any other subtractive colorspaces) */
	if (fz_colorspace_n(ctx, dest->colorspace) == 4)
	{
		value = 255 - value;
		do
		{
			unsigned char *s = destp;
			for (x = 0; x < w; x++)
			{
				*s++ = 0;
				*s++ = 0;
				*s++ = 0;
				*s++ = value;
				*s++ = 255;
			}
			destp += destspan;
		}
		while (--y);
		return;
	}

	if (value == 255)
	{
		do
		{
			memset(destp, 255, (unsigned int)(w * dest->n));
			destp += destspan;
		}
		while (--y);
	}
	else
	{
		do
		{
			unsigned char *s = destp;
			for (x = 0; x < w; x++)
			{
				for (k = 0; k < dest->n - 1; k++)
					*s++ = value;
				*s++ = 255;
			}
			destp += destspan;
		}
		while (--y);
	}
}

void
fz_premultiply_pixmap(fz_context *ctx, fz_pixmap *pix)
{
	unsigned char *s = pix->samples;
	unsigned char a;
	int k, x, y;
	int stride = pix->stride - pix->w * pix->n;

	if (!pix->alpha)
		return;

	if (fz_colorspace_is_subtractive(ctx, pix->colorspace))
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot pre-multiply subtractive colors");

	for (y = 0; y < pix->h; y++)
	{
		for (x = 0; x < pix->w; x++)
		{
			a = s[pix->n - 1];
			for (k = 0; k < pix->n - 1; k++)
				s[k] = fz_mul255(s[k], a);
			s += pix->n;
		}
		s += stride;
	}
}

void
fz_unmultiply_pixmap(fz_context *ctx, fz_pixmap *pix)
{
	unsigned char *s = pix->samples;
	int a, inva;
	int k, x, y;
	int stride = pix->stride - pix->w * pix->n;

	if (!pix->alpha)
		return;

	for (y = 0; y < pix->h; y++)
	{
		for (x = 0; x < pix->w; x++)
		{
			a = s[pix->n - 1];
			inva = a ? 255 * 256 / a : 0;
			for (k = 0; k < pix->n - 1; k++)
				s[k] = (s[k] * inva) >> 8;
			s += pix->n;
		}
		s += stride;
	}
}

fz_pixmap *
fz_ensure_pixmap_is_additive(fz_context *ctx, fz_pixmap *pix)
{
	if (fz_colorspace_is_subtractive(ctx, pix->colorspace))
	{
		fz_pixmap *rgb = fz_convert_pixmap(ctx, pix, fz_device_rgb(ctx), 1);
		fz_drop_pixmap(ctx, pix);
		return rgb;
	}
	return pix;
}

fz_pixmap *
fz_alpha_from_gray(fz_context *ctx, fz_pixmap *gray)
{
	fz_pixmap *alpha;
	unsigned char *sp, *dp;
	int w, h, sstride, dstride;
	fz_irect bbox;

	assert(gray->n == 1);

	alpha = fz_new_pixmap_with_bbox(ctx, NULL, fz_pixmap_bbox(ctx, gray, &bbox), 1);
	dp = alpha->samples;
	dstride = alpha->stride;
	sp = gray->samples;
	sstride = gray->stride;

	h = gray->h;
	w = gray->w;
	while (h--)
	{
		memcpy(dp, sp, w);
		sp += sstride;
		dp += dstride;
	}

	return alpha;
}

void
fz_tint_pixmap(fz_context *ctx, fz_pixmap *pix, int r, int g, int b)
{
	unsigned char *s = pix->samples;
	int x, y;

	if (pix->colorspace == fz_device_bgr(ctx))
	{
		int save = r;
		r = b;
		b = save;
	}
	else if (pix->colorspace == fz_device_gray(ctx))
	{
		g = (r + g + b) / 3;
	}
	else if (pix->colorspace != fz_device_rgb(ctx))
	{
		fz_throw(ctx, FZ_ERROR_GENERIC, "can only tint RGB, BGR and Gray pixmaps");
	}

	if (pix->n == 4)
	{
		assert(pix->alpha);
		for (y = 0; y < pix->h; y++)
		{
			for (x = 0; x < pix->w; x++)
			{
				s[0] = fz_mul255(s[0], r);
				s[1] = fz_mul255(s[1], g);
				s[2] = fz_mul255(s[2], b);
				s += 4;
			}
			s += pix->stride - pix->w * 4;
		}
	}
	else if (pix->n == 2)
	{
		assert(pix->alpha);
		for (y = 0; y < pix->h; y++)
		{
			for (x = 0; x < pix->w; x++)
			{
				*s = fz_mul255(*s, g);
				s += 2;
			}
			s += pix->stride - pix->w * 2;
		}
	}
}

void
fz_invert_pixmap(fz_context *ctx, fz_pixmap *pix)
{
	unsigned char *s = pix->samples;
	int k, x, y;
	int n1 = pix->n - pix->alpha;
	int n = pix->n;

	for (y = 0; y < pix->h; y++)
	{
		for (x = 0; x < pix->w; x++)
		{
			for (k = 0; k < n1; k++)
				s[k] = 255 - s[k];
			s += n;
		}
		s += pix->stride - pix->w * n;
	}
}

void fz_invert_pixmap_rect(fz_context *ctx, fz_pixmap *image, const fz_irect *rect)
{
	unsigned char *p;
	int x, y, n;

	int x0 = fz_clampi(rect->x0 - image->x, 0, image->w);
	int x1 = fz_clampi(rect->x1 - image->x, 0, image->w);
	int y0 = fz_clampi(rect->y0 - image->y, 0, image->h);
	int y1 = fz_clampi(rect->y1 - image->y, 0, image->h);

	for (y = y0; y < y1; y++)
	{
		p = image->samples + (unsigned int)((y * image->stride) + (x0 * image->n));
		for (x = x0; x < x1; x++)
		{
			for (n = image->n; n > 1; n--, p++)
				*p = 255 - *p;
			p++;
		}
	}
}

void
fz_gamma_pixmap(fz_context *ctx, fz_pixmap *pix, float gamma)
{
	unsigned char gamma_map[256];
	unsigned char *s = pix->samples;
	int k, x, y;

	for (k = 0; k < 256; k++)
		gamma_map[k] = pow(k / 255.0f, gamma) * 255;

	for (y = 0; y < pix->h; y++)
	{
		for (x = 0; x < pix->w; x++)
		{
			for (k = 0; k < pix->n - 1; k++)
				s[k] = gamma_map[s[k]];
			s += pix->n;
		}
		s += pix->stride - pix->w * pix->n;
	}
}

size_t
fz_pixmap_size(fz_context *ctx, fz_pixmap * pix)
{
	if (pix == NULL)
		return 0;
	return sizeof(*pix) + pix->n * pix->w * pix->h;
}

fz_pixmap *
fz_convert_pixmap(fz_context *ctx, fz_pixmap *pix, fz_colorspace *ds, int keep_alpha)
{
	fz_pixmap *cvt;

	if (!ds && !keep_alpha)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot both throw away and keep alpha");

	cvt = fz_new_pixmap(ctx, ds, pix->w, pix->h, keep_alpha && pix->alpha);

	cvt->xres = pix->xres;
	cvt->yres = pix->yres;
	cvt->x = pix->x;
	cvt->y = pix->y;
	cvt->interpolate = pix->interpolate;

	fz_try(ctx)
	{
		fz_pixmap_converter *pc = fz_lookup_pixmap_converter(ctx, ds, pix->colorspace);
		pc(ctx, cvt, pix);
	}
	fz_catch(ctx)
	{
		fz_drop_pixmap(ctx, cvt);
		fz_rethrow(ctx);
	}

	return cvt;
}

fz_pixmap *
fz_new_pixmap_from_8bpp_data(fz_context *ctx, int x, int y, int w, int h, unsigned char *sp, int span)
{
	fz_pixmap *pixmap = fz_new_pixmap(ctx, NULL, w, h, 1);
	int stride = pixmap->stride;
	unsigned char *s = pixmap->samples;
	pixmap->x = x;
	pixmap->y = y;

	for (y = 0; y < h; y++)
	{
		memcpy(s, sp + y * span, w);
		s += stride;
	}

	return pixmap;
}

fz_pixmap *
fz_new_pixmap_from_1bpp_data(fz_context *ctx, int x, int y, int w, int h, unsigned char *sp, int span)
{
	fz_pixmap *pixmap = fz_new_pixmap(ctx, NULL, w, h, 1);
	int stride = pixmap->stride - pixmap->w;
	pixmap->x = x;
	pixmap->y = y;

	for (y = 0; y < h; y++)
	{
		unsigned char *out = pixmap->samples + y * w;
		unsigned char *in = sp + y * span;
		unsigned char bit = 0x80;
		int ww = w;
		while (ww--)
		{
			*out++ = (*in & bit) ? 255 : 0;
			bit >>= 1;
			if (bit == 0)
				bit = 0x80, in++;
		}
		out += stride;
	}

	return pixmap;
}

#ifdef ARCH_ARM
static void
fz_subsample_pixmap_ARM(unsigned char *ptr, int w, int h, int f, int factor,
			int n, int fwd, int back, int back2, int fwd2,
			int divX, int back4, int fwd4, int fwd3,
			int divY, int back5, int divXY)
__attribute__((naked));

static void
fz_subsample_pixmap_ARM(unsigned char *ptr, int w, int h, int f, int factor,
			int n, int fwd, int back, int back2, int fwd2,
			int divX, int back4, int fwd4, int fwd3,
			int divY, int back5, int divXY)
{
	asm volatile(
	ENTER_ARM
	"stmfd	r13!,{r1,r4-r11,r14}					\n"
	"@STACK:r1,<9>,factor,n,fwd,back,back2,fwd2,divX,back4,fwd4,fwd3,divY,back5,divXY\n"
	"@ r0 = src = ptr						\n"
	"@ r1 = w							\n"
	"@ r2 = h							\n"
	"@ r3 = f							\n"
	"mov	r9, r0			@ r9 = dst = ptr		\n"
	"ldr	r6, [r13,#4*12]		@ r6 = fwd			\n"
	"ldr	r7, [r13,#4*13]		@ r7 = back			\n"
	"subs	r2, r2, r3		@ r2 = h -= f			\n"
	"blt	11f			@ Skip if less than a full row	\n"
	"1:				@ for (y = h; y > 0; y--) {	\n"
	"ldr	r1, [r13]		@ r1 = w			\n"
	"subs	r1, r1, r3		@ r1 = w -= f			\n"
	"blt	6f			@ Skip if less than a full col	\n"
	"ldr	r4, [r13,#4*10]		@ r4 = factor			\n"
	"ldr	r8, [r13,#4*14]		@ r8 = back2			\n"
	"ldr	r12,[r13,#4*15]		@ r12= fwd2			\n"
	"2:				@ for (x = w; x > 0; x--) {	\n"
	"ldr	r5, [r13,#4*11]		@ for (nn = n; nn > 0; n--) {	\n"
	"3:				@				\n"
	"mov	r14,#0			@ r14= v = 0			\n"
	"sub	r5, r5, r3, LSL #8	@ for (xx = f; xx > 0; x--) {	\n"
	"4:				@				\n"
	"add	r5, r5, r3, LSL #16	@ for (yy = f; yy > 0; y--) {	\n"
	"5:				@				\n"
	"ldrb	r11,[r0], r6		@ r11= *src	src += fwd	\n"
	"subs	r5, r5, #1<<16		@ xx--				\n"
	"add	r14,r14,r11		@ v += r11			\n"
	"bgt	5b			@ }				\n"
	"sub	r0, r0, r7		@ src -= back			\n"
	"adds	r5, r5, #1<<8		@ yy--				\n"
	"blt	4b			@ }				\n"
	"mov	r14,r14,LSR r4		@ r14 = v >>= factor		\n"
	"strb	r14,[r9], #1		@ *d++ = r14			\n"
	"sub	r0, r0, r8		@ s -= back2			\n"
	"subs	r5, r5, #1		@ n--				\n"
	"bgt	3b			@ }				\n"
	"add	r0, r0, r12		@ s += fwd2			\n"
	"subs	r1, r1, r3		@ x -= f			\n"
	"bge	2b			@ }				\n"
	"6:				@ Less than a full column left	\n"
	"adds	r1, r1, r3		@ x += f			\n"
	"beq	11f			@ if (x == 0) next row		\n"
	"@ r0 = src							\n"
	"@ r1 = x							\n"
	"@ r2 = y							\n"
	"@ r3 = f							\n"
	"@ r4 = factor							\n"
	"@ r6 = fwd							\n"
	"@ r7 = back							\n"
	"@STACK:r1,<9>,factor,n,fwd,back,back2,fwd2,divX,back4,fwd4,fwd3,divY,back5,divXY\n"
	"ldr	r5, [r13,#4*11]		@ for (nn = n; nn > 0; n--) {	\n"
	"ldr	r4, [r13,#4*16]		@ r4 = divX			\n"
	"ldr	r8, [r13,#4*17]		@ r8 = back4			\n"
	"ldr	r12,[r13,#4*18]		@ r12= fwd4			\n"
	"8:				@				\n"
	"mov	r14,#0			@ r14= v = 0			\n"
	"sub	r5, r5, r1, LSL #8	@ for (xx = x; xx > 0; x--) {	\n"
	"9:				@				\n"
	"add	r5, r5, r3, LSL #16	@ for (yy = f; yy > 0; y--) {	\n"
	"10:				@				\n"
	"ldrb	r11,[r0], r6		@ r11= *src	src += fwd	\n"
	"subs	r5, r5, #1<<16		@ xx--				\n"
	"add	r14,r14,r11		@ v += r11			\n"
	"bgt	10b			@ }				\n"
	"sub	r0, r0, r7		@ src -= back			\n"
	"adds	r5, r5, #1<<8		@ yy--				\n"
	"blt	9b			@ }				\n"
	"mul	r14,r4, r14		@ r14= v *= divX		\n"
	"mov	r14,r14,LSR #16		@ r14= v >>= 16			\n"
	"strb	r14,[r9], #1		@ *d++ = r14			\n"
	"sub	r0, r0, r8		@ s -= back4			\n"
	"subs	r5, r5, #1		@ n--				\n"
	"bgt	8b			@ }				\n"
	"add	r0, r0, r12		@ s += fwd4			\n"
	"11:				@				\n"
	"ldr	r14,[r13,#4*19]		@ r14 = fwd3			\n"
	"subs	r2, r2, r3		@ h -= f			\n"
	"add	r0, r0, r14		@ s += fwd3			\n"
	"bge	1b			@ }				\n"
	"adds	r2, r2, r3		@ h += f			\n"
	"beq	21f			@ if no stray row, end		\n"
	"@ So doing one last (partial) row				\n"
	"@STACK:r1,<9>,factor,n,fwd,back,back2,fwd2,divX,back4,fwd4,fwd3,divY,back5,divXY\n"
	"@ r0 = src = ptr						\n"
	"@ r1 = w							\n"
	"@ r2 = h							\n"
	"@ r3 = f							\n"
	"@ r4 = factor							\n"
	"@ r5 = n							\n"
	"@ r6 = fwd							\n"
	"12:				@ for (y = h; y > 0; y--) {	\n"
	"ldr	r1, [r13]		@ r1 = w			\n"
	"ldr	r7, [r13,#4*21]		@ r7 = back5			\n"
	"ldr	r8, [r13,#4*14]		@ r8 = back2			\n"
	"subs	r1, r1, r3		@ r1 = w -= f			\n"
	"blt	17f			@ Skip if less than a full col	\n"
	"ldr	r4, [r13,#4*20]		@ r4 = divY			\n"
	"ldr	r12,[r13,#4*15]		@ r12= fwd2			\n"
	"13:				@ for (x = w; x > 0; x--) {	\n"
	"ldr	r5, [r13,#4*11]		@ for (nn = n; nn > 0; n--) {	\n"
	"14:				@				\n"
	"mov	r14,#0			@ r14= v = 0			\n"
	"sub	r5, r5, r3, LSL #8	@ for (xx = f; xx > 0; x--) {	\n"
	"15:				@				\n"
	"add	r5, r5, r2, LSL #16	@ for (yy = y; yy > 0; y--) {	\n"
	"16:				@				\n"
	"ldrb	r11,[r0], r6		@ r11= *src	src += fwd	\n"
	"subs	r5, r5, #1<<16		@ xx--				\n"
	"add	r14,r14,r11		@ v += r11			\n"
	"bgt	16b			@ }				\n"
	"sub	r0, r0, r7		@ src -= back5			\n"
	"adds	r5, r5, #1<<8		@ yy--				\n"
	"blt	15b			@ }				\n"
	"mul	r14,r4, r14		@ r14 = x *= divY		\n"
	"mov	r14,r14,LSR #16		@ r14 = v >>= 16		\n"
	"strb	r14,[r9], #1		@ *d++ = r14			\n"
	"sub	r0, r0, r8		@ s -= back2			\n"
	"subs	r5, r5, #1		@ n--				\n"
	"bgt	14b			@ }				\n"
	"add	r0, r0, r12		@ s += fwd2			\n"
	"subs	r1, r1, r3		@ x -= f			\n"
	"bge	13b			@ }				\n"
	"17:				@ Less than a full column left	\n"
	"adds	r1, r1, r3		@ x += f			\n"
	"beq	21f			@ if (x == 0) end		\n"
	"@ r0 = src							\n"
	"@ r1 = x							\n"
	"@ r2 = y							\n"
	"@ r3 = f							\n"
	"@ r4 = factor							\n"
	"@ r6 = fwd							\n"
	"@ r7 = back5							\n"
	"@ r8 = back2							\n"
	"@STACK:r1,<9>,factor,n,fwd,back,back2,fwd2,divX,back4,fwd4,fwd3,divY,back5,divXY\n"
	"ldr	r4, [r13,#4*22]		@ r4 = divXY			\n"
	"ldr	r5, [r13,#4*11]		@ for (nn = n; nn > 0; n--) {	\n"
	"ldr	r8, [r13,#4*17]		@ r8 = back4			\n"
	"18:				@				\n"
	"mov	r14,#0			@ r14= v = 0			\n"
	"sub	r5, r5, r1, LSL #8	@ for (xx = x; xx > 0; x--) {	\n"
	"19:				@				\n"
	"add	r5, r5, r2, LSL #16	@ for (yy = y; yy > 0; y--) {	\n"
	"20:				@				\n"
	"ldrb	r11,[r0],r6		@ r11= *src	src += fwd	\n"
	"subs	r5, r5, #1<<16		@ xx--				\n"
	"add	r14,r14,r11		@ v += r11			\n"
	"bgt	20b			@ }				\n"
	"sub	r0, r0, r7		@ src -= back5			\n"
	"adds	r5, r5, #1<<8		@ yy--				\n"
	"blt	19b			@ }				\n"
	"mul	r14,r4, r14		@ r14= v *= divX		\n"
	"mov	r14,r14,LSR #16		@ r14= v >>= 16			\n"
	"strb	r14,[r9], #1		@ *d++ = r14			\n"
	"sub	r0, r0, r8		@ s -= back4			\n"
	"subs	r5, r5, #1		@ n--				\n"
	"bgt	18b			@ }				\n"
	"21:				@				\n"
	"ldmfd	r13!,{r1,r4-r11,PC}	@ pop, return to thumb		\n"
	ENTER_THUMB
	);
}

#endif

void
fz_subsample_pixmap(fz_context *ctx, fz_pixmap *tile, int factor)
{
	int dst_w, dst_h, w, h, fwd, fwd2, fwd3, back, back2, n, f;
	unsigned char *s, *d;
#ifndef ARCH_ARM
	int x, y, xx, yy, nn;
#endif

	if (!tile)
		return;

	assert(tile->stride >= tile->w * tile->n);

	s = d = tile->samples;
	f = 1<<factor;
	w = tile->w;
	h = tile->h;
	n = tile->n;
	dst_w = (w + f-1)>>factor;
	dst_h = (h + f-1)>>factor;
	fwd = tile->stride;
	back = f*fwd-n;
	back2 = f*n-1;
	fwd2 = (f-1)*n;
	fwd3 = (f-1)*fwd + tile->stride - w * n;
	factor *= 2;
#ifdef ARCH_ARM
	{
		int strayX = w%f;
		int divX = (strayX ? 65536/(strayX*f) : 0);
		int fwd4 = (strayX-1) * n;
		int back4 = strayX*n-1;
		int strayY = h%f;
		int divY = (strayY ? 65536/(strayY*f) : 0);
		int back5 = fwd * strayY - n;
		int divXY = (strayY*strayX ? 65536/(strayX*strayY) : 0);
		fz_subsample_pixmap_ARM(s, w, h, f, factor, n, fwd, back,
					back2, fwd2, divX, back4, fwd4, fwd3,
					divY, back5, divXY);
	}
#else
	for (y = h - f; y >= 0; y -= f)
	{
		for (x = w - f; x >= 0; x -= f)
		{
			for (nn = n; nn > 0; nn--)
			{
				int v = 0;
				for (xx = f; xx > 0; xx--)
				{
					for (yy = f; yy > 0; yy--)
					{
						v += *s;
						s += fwd;
					}
					s -= back;
				}
				*d++ = v >> factor;
				s -= back2;
			}
			s += fwd2;
		}
		/* Do any strays */
		x += f;
		if (x > 0)
		{
			int div = x * f;
			int fwd4 = (x-1) * n;
			int back4 = x*n-1;
			for (nn = n; nn > 0; nn--)
			{
				int v = 0;
				for (xx = x; xx > 0; xx--)
				{
					for (yy = f; yy > 0; yy--)
					{
						v += *s;
						s += fwd;
					}
					s -= back;
				}
				*d++ = v / div;
				s -= back4;
			}
			s += fwd4;
		}
		s += fwd3;
	}
	/* Do any stray line */
	y += f;
	if (y > 0)
	{
		int div = y * f;
		int back5 = fwd * y - n;
		for (x = w - f; x >= 0; x -= f)
		{
			for (nn = n; nn > 0; nn--)
			{
				int v = 0;
				for (xx = f; xx > 0; xx--)
				{
					for (yy = y; yy > 0; yy--)
					{
						v += *s;
						s += fwd;
					}
					s -= back5;
				}
				*d++ = v / div;
				s -= back2;
			}
			s += fwd2;
		}
		/* Do any stray at the end of the stray line */
		x += f;
		if (x > 0)
		{
			int back4 = x * n - 1;
			div = x * y;
			for (nn = n; nn > 0; nn--)
			{
				int v = 0;
				for (xx = x; xx > 0; xx--)
				{
					for (yy = y; yy > 0; yy--)
					{
						v += *s;
						s += fwd;
					}
					s -= back5;
				}
				*d++ = v / div;
				s -= back4;
			}
		}
	}
#endif
	tile->w = dst_w;
	tile->h = dst_h;
	tile->stride = dst_w * n;
	tile->samples = fz_resize_array(ctx, tile->samples, dst_w * n, dst_h);
}

void
fz_set_pixmap_resolution(fz_context *ctx, fz_pixmap *pix, int xres, int yres)
{
	pix->xres = xres;
	pix->yres = yres;
}

void
fz_md5_pixmap(fz_context *ctx, fz_pixmap *pix, unsigned char digest[16])
{
	fz_md5 md5;

	fz_md5_init(&md5);
	if (pix)
	{
		unsigned char *s = pix->samples;
		int h = pix->h;
		int ss = pix->stride;
		int len = pix->w * pix->n;
		while (h--)
		{
			fz_md5_update(&md5, s, len);
			s += ss;
		}
	}
	fz_md5_final(&md5, digest);
}

#ifdef HAVE_VALGRIND
int fz_valgrind_pixmap(const fz_pixmap *pix)
{
	int w, h, n, total;
	int ww, hh, nn;
	int stride;
	const unsigned char *p = pix->samples;

	if (pix == NULL)
		return 0;

	total = 0;
	ww = pix->w;
	hh = pix->h;
	nn = pix->n;
	stride = pix->stride - ww*nn;
	for (h = 0; h < hh; h++)
	{
		for (w = 0; w < ww; w++)
			for (n = 0; n < nn; n++)
				if (*p++) total ++;
		p += stride;
	}
	return total;
}
#endif /* HAVE_VALGRIND */
