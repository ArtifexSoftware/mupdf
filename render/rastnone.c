#include <fitz.h>

typedef unsigned char byte;

/*
 * Mask -- blit one span (clipped and adjusted)
 *
 *	mask_g
 *	mask_i1
 *	mask_o1
 *	mask_i1o1
 *	mask_o4w3
 *	mask_i1o4w3
 */

static void mask_g(int n, byte *src, byte *pix)
{
	memcpy(pix, src, n);
}

static void mask_i1(int n, byte *src, byte *dst)
{
	while (n--)
	{
		dst[0] = fz_mul255(src[0], dst[0]);
		src++;
		dst++;
	}
}

static void mask_o1(int n, byte *src, byte *dst)
{
	while (n--)
	{
		dst[0] = src[0] + fz_mul255(dst[0], 255 - src[0]);
		src++;
		dst++;
	}
}

static void mask_i1o1(int n, byte *src, byte *msk, byte *dst)
{
	while (n--)
	{
		byte sa = fz_mul255(src[0], msk[0]);
		dst[0] = sa + fz_mul255(dst[0], 255 - sa);
		src++;
		msk++;
		dst++;
	}
}

static void mask_o4w3(int n, byte *src, byte *dst, byte *rgb)
{
	byte sa, ssa;
	while (n--)
	{
		sa = src[0];
		ssa = 255 - sa;
		dst[0] = sa + fz_mul255(dst[0], ssa);
		dst[1] = rgb[0] + fz_mul255((short)dst[1] - rgb[0], ssa);
		dst[2] = rgb[1] + fz_mul255((short)dst[2] - rgb[1], ssa);
		dst[3] = rgb[2] + fz_mul255((short)dst[3] - rgb[2], ssa);
		src ++;
		dst += 4;
	}
}

static void mask_i1o4w3(int n, byte *src, byte *msk, byte *dst, byte *rgb)
{
	byte sa, ssa;
	while (n--)
	{
		sa = fz_mul255(src[0], msk[0]);
		ssa = 255 - sa;
		dst[0] = sa + fz_mul255(dst[0], ssa);
		dst[1] = rgb[0] + fz_mul255((short)dst[1] - rgb[0], ssa);
		dst[2] = rgb[1] + fz_mul255((short)dst[2] - rgb[1], ssa);
		dst[3] = rgb[2] + fz_mul255((short)dst[3] - rgb[2], ssa);
		src ++;
		msk ++;
		dst += 4;
	}
}

/*
 * Image -- blit entire image
 *
 *	img1_g
 *	img1_i1
 *	img1_o1
 *	img1_i1o1
 *	img1_o4w3
 *	img1_i1o4w3
 *
 *	img4_g
 *	img4_o4
 *	img4_i1o4
 */

#define lerpmsk(a,b,t) (a + (((b - a) * t) >> 16))

static inline byte getmsk(byte *s, int w, int h, int u, int v)
{
	if (u < 0 || u >= w) return 0;
	if (v < 0 || v >= h) return 0;
	return s[w * v + u];
}

static inline int samplemsk(byte *s, int w, int h, int u, int v)
{
	int ui = u >> 16;
	int vi = v >> 16;
	int ud = u & 0xFF;
	int vd = v & 0xFF;
	int a = getmsk(s, w, h, ui, vi);
	int b = getmsk(s, w, h, ui+1, vi);
	int c = getmsk(s, w, h, ui, vi+1);
	int d = getmsk(s, w, h, ui+1, vi+1);
	int ab = lerpmsk(a, b, ud);
	int cd = lerpmsk(c, d, ud);
	return lerpmsk(ab, cd, vd);
}

static inline void lerpargb(byte *dst, byte *a, byte *b, int t)
{
	dst[0] = lerpmsk(a[0], b[0], t);
	dst[1] = lerpmsk(a[1], b[1], t);
	dst[2] = lerpmsk(a[2], b[2], t);
	dst[3] = lerpmsk(a[3], b[3], t);
}

static inline byte *getargb(byte *s, int w, int h, int u, int v)
{
	static byte zero[4] = { 0, 0, 0, 0 };
	if (u < 0 || u >= w) return zero;
	if (v < 0 || v >= h) return zero;
	return s + ((w * v + u) << 2);
}

static inline void sampleargb(byte *s, int w, int h, int u, int v, byte *abcd)
{
	byte ab[4];
	byte cd[4];
	int ui = u >> 16;
	int vi = v >> 16;
	int ud = u & 0xFF;
	int vd = v & 0xFF;
	byte *a = getargb(s, w, h, ui, vi);
	byte *b = getargb(s, w, h, ui+1, vi);
	byte *c = getargb(s, w, h, ui, vi+1);
	byte *d = getargb(s, w, h, ui+1, vi+1);
	lerpargb(ab, a, b, ud);
	lerpargb(cd, c, d, ud);
	lerpargb(abcd, ab, cd, vd);
}

#define PSRC byte *src, int w, int h, int nx0, int ny
#define PDST byte *dst0, int dstw
#define PMSK byte *msk0, int mskw
#define PCTM int u0, int v0, int fa, int fb, int fc, int fd

#if 0
static void example(PSRC, PDST, PMSK, PCTM)
{
	while (ny--)
	{
		byte *dst = dst0;
		byte *msk = msk0;
		int u = u0;
		int v = v0;
		int nx = nx0;
		while (nx--)
		{
			// dst[0] = ... msk[0] ... sample(s, w, h, u, v);
			dst ++;
			msk ++;
			u += fa;
			v += fb;
		}
		u0 += fc;
		v0 += fd;
		dst0 += dstw;
		msk0 += mskw;
	}
}
#endif

#define BLOOP \
	while (ny--) \
	{ \
		byte *dst = dst0; \
		int u = u0; \
		int v = v0; \
		int nx = nx0; \
		while (nx--)

#define ELOOP \
		u0 += fc; \
		v0 += fd; \
		dst0 += dstw; \
	}

#define BLOOPM \
	while (ny--) \
	{ \
		byte *dst = dst0; \
		byte *msk = msk0; \
		int u = u0; \
		int v = v0; \
		int nx = nx0; \
		while (nx--)

#define ELOOPM \
		u0 += fc; \
		v0 += fd; \
		dst0 += dstw; \
		msk0 += mskw; \
	}

static void img1_g(PSRC, PDST, PCTM)
{
	BLOOP
	{
		dst[0] = samplemsk(src, w, h, u, v);
		dst ++;
		u += fa;
		v += fb;
	}
	ELOOP
}

static void img1_i1(PSRC, PDST, PCTM)
{
	BLOOP
	{
		dst[0] = fz_mul255(dst[0], samplemsk(src, w, h, u, v));
		dst ++;
		u += fa;
		v += fb;
	}
	ELOOP
}

static void img1_o1(PSRC, PDST, PCTM)
{
	BLOOP
	{
		byte sa = samplemsk(src, w, h, u, v);
		dst[0] = sa + fz_mul255(dst[0], 255 - sa);
		dst ++;
		u += fa;
		v += fb;
	}
	ELOOP
}

static void img1_i1o1(PSRC, PDST, PMSK, PCTM)
{
	BLOOPM
	{
		byte sa = fz_mul255(msk[0], samplemsk(src, w, h, u, v));
		dst[0] = sa + fz_mul255(dst[0], 255 - sa);
		dst ++;
		msk ++;
		u += fa;
		v += fb;
	}
	ELOOPM
}

static void img1_o4w3(PSRC, PDST, PCTM, byte *rgb)
{
	BLOOP
	{
		byte sa = samplemsk(src, w, h, u, v);
		byte ssa = 255 - sa;
		dst[0] = sa + fz_mul255(dst[0], ssa);
		dst[1] = rgb[0] + fz_mul255((short)dst[1] - rgb[0], ssa);
		dst[2] = rgb[1] + fz_mul255((short)dst[2] - rgb[1], ssa);
		dst[3] = rgb[2] + fz_mul255((short)dst[3] - rgb[2], ssa);
		dst += 4;
		u += fa;
		v += fb;
	}
	ELOOP
}

static void img1_i1o4w3(PSRC, PDST, PMSK, PCTM, byte *rgb)
{
	BLOOPM
	{
		byte sa = fz_mul255(msk[0], samplemsk(src, w, h, u, v));
		byte ssa = 255 - sa;
		dst[0] = sa + fz_mul255(dst[0], ssa);
		dst[1] = rgb[0] + fz_mul255((short)dst[1] - rgb[0], ssa);
		dst[2] = rgb[1] + fz_mul255((short)dst[2] - rgb[1], ssa);
		dst[3] = rgb[2] + fz_mul255((short)dst[3] - rgb[2], ssa);
		dst += 4;
		msk ++;
		u += fa;
		v += fb;
	}
	ELOOPM
}

static void img4_g(PSRC, PDST, PCTM)
{
	BLOOP
	{
		sampleargb(src, w, h, u, v, dst);
		dst += 4;
		u += fa;
		v += fb;
	}
	ELOOP
}

static void img4_o4(PSRC, PDST, PCTM)
{
	byte argb[4];
	BLOOP
	{
		sampleargb(src, w, h, u, v, argb);
		byte ssa = 255 - argb[0];
		dst[0] = argb[0] + fz_mul255(dst[0], ssa);
		dst[1] = argb[1] + fz_mul255((short)dst[1] - argb[1], ssa);
		dst[2] = argb[2] + fz_mul255((short)dst[2] - argb[2], ssa);
		dst[3] = argb[3] + fz_mul255((short)dst[3] - argb[3], ssa);
		dst += 4;
		u += fa;
		v += fb;
	}
	ELOOP
}

static void img4_i1o4(PSRC, PDST, PMSK, PCTM)
{
	byte argb[4];
	BLOOPM
	{
		sampleargb(src, w, h, u, v, argb);
		byte sa = fz_mul255(msk[0], argb[0]);
		byte ssa = 255 - sa;
		dst[0] = argb[0] + fz_mul255(dst[0], ssa);
		dst[1] = argb[1] + fz_mul255((short)dst[1] - argb[1], ssa);
		dst[2] = argb[2] + fz_mul255((short)dst[2] - argb[2], ssa);
		dst[3] = argb[3] + fz_mul255((short)dst[3] - argb[3], ssa);
		dst += 4;
		msk ++;
		u += fa;
		v += fb;
	}
	ELOOPM
}

/*
 *
 */

void
fz_defaultrastfuncs(fz_rastfuncs *tab)
{
	tab->mask_g = mask_g;
	tab->mask_i1 = mask_i1;
	tab->mask_o1 = mask_o1;
	tab->mask_i1o1 = mask_i1o1;
	tab->mask_o4w3 = mask_o4w3;
	tab->mask_i1o4w3 = mask_i1o4w3;

	tab->img1_g = img1_g;
	tab->img1_i1 = img1_i1;
	tab->img1_o1 = img1_o1;
	tab->img1_i1o1 = img1_i1o1;
	tab->img1_o4w3 = img1_o4w3;
	tab->img1_i1o4w3 = img1_i1o4w3;

	tab->img4_g = img4_g;
	tab->img4_o4 = img4_o4;
	tab->img4_i1o4 = img4_i1o4;
}

