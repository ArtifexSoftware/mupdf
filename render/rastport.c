#include <fitz.h>

typedef unsigned char byte;

/*
 * General Porter-Duff compositing -- blit image regions
 *
 * duff_NoN
 * duff_NiM
 * duff_NiMoN
 */

/* dst = src over dst */
static void
duff_NoN(byte *sp0, int sw, int sn, byte *dp0, int dw, int w0, int h)
{
	int k;
	while (h--)
	{
		byte *sp = sp0;
		byte *dp = dp0;
		int w = w0;
		while (w--)
		{
			byte sa = sp[0];
			byte ssa = 255 - sa;
			for (k = 0; k < sn; k++)
			{
				dp[k] = sp[k] + fz_mul255(dp[k], ssa);
			}
			sp += sn;
			dp += sn;
		}
		sp0 += sw;
		dp0 += dw;
	}
}

/* dst = src in msk */
static void
duff_NiMcN(byte *sp0, int sw, int sn, byte *mp0, int mw, int mn, byte *dp0, int dw, int w0, int h)
{
	int k;
	while (h--)
	{
		byte *sp = sp0;
		byte *mp = mp0;
		byte *dp = dp0;
		int w = w0;
		while (w--)
		{
			byte ma = mp[0];
			for (k = 0; k < sn; k++)
				dp[k] = fz_mul255(sp[k], ma);
			sp += sn;
			mp += mn;
			dp += sn;
		}
		sp0 += sw;
		mp0 += mw;
		dp0 += dw;
	}
}

/* dst = src in msk over dst */
static void
duff_NiMoN(byte *sp0, int sw, int sn, byte *mp0, int mw, int mn, byte *dp0, int dw, int w0, int h)
{
	int k;
	while (h--)
	{
		byte *sp = sp0;
		byte *mp = mp0;
		byte *dp = dp0;
		int w = w0;
		while (w--)
		{
			/* TODO: validate this */
			byte ma = mp[0];
			byte sa = fz_mul255(sp[0], ma);
			byte ssa = 255 - sa;
			for (k = 0; k < sn; k++)
			{
				dp[k] = fz_mul255(sp[k], ma) + fz_mul255(dp[k], ssa);
			}
			sp += sn;
			mp += mn;
			dp += sn;
		}
		sp0 += sw;
		mp0 += mw;
		dp0 += dw;
	}
}

static void duff_1o1(byte *sp0, int sw, byte *dp0, int dw, int w0, int h)
{
	/* duff_NoN(sp0, sw, 1, dp0, dw, w0, h); */
	while (h--)
	{
		byte *sp = sp0;
		byte *dp = dp0;
		int w = w0;
		while (w--)
		{
			dp[0] = sp[0] + fz_mul255(dp[0], 255 - sp[0]);
			sp ++;
			dp ++;
		}
		sp0 += sw;
		dp0 += dw;
	}
}

static void duff_4o4(byte *sp0, int sw, byte *dp0, int dw, int w0, int h)
{
	/* duff_NoN(sp0, sw, 4, dp0, dw, w0, h); */
	while (h--)
	{
		byte *sp = sp0;
		byte *dp = dp0;
		int w = w0;
		while (w--)
		{
			byte ssa = 255 - sp[0];
			dp[0] = sp[0] + fz_mul255(dp[0], ssa);
			dp[1] = sp[1] + fz_mul255(dp[1], ssa);
			dp[2] = sp[2] + fz_mul255(dp[2], ssa);
			dp[3] = sp[3] + fz_mul255(dp[3], ssa);
			sp += 4;
			dp += 4;
		}
		sp0 += sw;
		dp0 += dw;
	}
}

static void duff_1i1c1(byte *sp0, int sw, byte *mp0, int mw, byte *dp0, int dw, int w0, int h)
{
	/* duff_NiMcN(sp0, sw, 1, mp0, mw, 1, dp0, dw, w0, h); */
	while (h--)
	{
		byte *sp = sp0;
		byte *mp = mp0;
		byte *dp = dp0;
		int w = w0;
		while (w--)
		{
			dp[0] = fz_mul255(sp[0], mp[0]);
			sp ++;
			mp ++;
			dp ++;
		}
		sp0 += sw;
		mp0 += mw;
		dp0 += dw;
	}
}

static void duff_4i1c4(byte *sp0, int sw, byte *mp0, int mw, byte *dp0, int dw, int w0, int h)
{
	/* duff_NiMcN(sp0, sw, 4, mp0, mw, 1, dp0, dw, w0, h); */
	while (h--)
	{
		byte *sp = sp0;
		byte *mp = mp0;
		byte *dp = dp0;
		int w = w0;
		while (w--)
		{
			byte ma = mp[0];
			dp[0] = fz_mul255(sp[0], ma);
			dp[1] = fz_mul255(sp[1], ma);
			dp[2] = fz_mul255(sp[2], ma);
			dp[3] = fz_mul255(sp[3], ma);
			sp += 4;
			mp += 1;
			dp += 4;
		}
		sp0 += sw;
		mp0 += mw;
		dp0 += dw;
	}
}

static void duff_1i1o1(byte *sp0, int sw, byte *mp0, int mw, byte *dp0, int dw, int w0, int h)
{
	/* duff_NiMoN(sp0, sw, 1, mp0, mw, 1, dp0, dw, w0, h); */
	while (h--)
	{
		byte *sp = sp0;
		byte *mp = mp0;
		byte *dp = dp0;
		int w = w0;
		while (w--)
		{
			byte ma = mp[0];
			byte sa = fz_mul255(sp[0], ma);
			byte ssa = 255 - sa;
			dp[0] = fz_mul255(sp[0], ma) + fz_mul255(dp[0], ssa);
			sp ++;
			mp ++;
			dp ++;
		}
		sp0 += sw;
		mp0 += mw;
		dp0 += dw;
	}
}

static void duff_4i1o4(byte *sp0, int sw, byte *mp0, int mw, byte *dp0, int dw, int w0, int h)
{
	/* duff_NiMoN(sp0, sw, 4, mp0, mw, 1, dp0, dw, w0, h); */
	while (h--)
	{
		byte *sp = sp0;
		byte *mp = mp0;
		byte *dp = dp0;
		int w = w0;
		while (w--)
		{
			byte ma = mp[0];
			byte sa = fz_mul255(sp[0], ma);
			byte ssa = 255 - sa;
			dp[0] = fz_mul255(sp[0], ma) + fz_mul255(dp[0], ssa);
			dp[1] = fz_mul255(sp[1], ma) + fz_mul255(dp[1], ssa);
			dp[2] = fz_mul255(sp[2], ma) + fz_mul255(dp[2], ssa);
			dp[3] = fz_mul255(sp[3], ma) + fz_mul255(dp[3], ssa);
			sp += 4;
			mp += 1;
			dp += 4;
		}
		sp0 += sw;
		mp0 += mw;
		dp0 += dw;
	}
}

/*
 * Mask -- blit one scanline of mask
 *
 *	msk_1c1
 *	msk_1o1
 *	msk_1i1c1
 *	msk_1i1o1
 *	msk_w3i1o4
 *	msk_w3i1i1o4
 */

static void msk_1c1(byte *src, byte *dst, int w)
{
	memcpy(dst, src, w);
}

static void msk_1o1(byte *src, byte *dst, int w)
{
	while (w--)
	{
		dst[0] = src[0] + fz_mul255(dst[0], 255 - src[0]);
		src++;
		dst++;
	}
}

static void msk_w3i1o4(byte *rgb, byte *src, byte *dst, int n)
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

/*
 * Image -- draw transformed image
 *
 */

#define lerp(a,b,t) (a + (((b - a) * t) >> 16))

static inline byte getcomp(byte *s, int w, int h, int u, int v, int n, int k)
{
	if (u < 0 || u >= w) return 0;
	if (v < 0 || v >= h) return 0;
	return s[(w * v + u) * n + k];
}

static inline int samplecomp(byte *s, int w, int h, int u, int v, int n, int k)
{
	int ui = u >> 16;
	int vi = v >> 16;
	int ud = u & 0xFFFF;
	int vd = v & 0xFFFF;
	int a = getcomp(s, w, h, ui, vi, n, k);
	int b = getcomp(s, w, h, ui+1, vi, n, k);
	int c = getcomp(s, w, h, ui, vi+1, n, k);
	int d = getcomp(s, w, h, ui+1, vi+1, n, k);
	int ab = lerp(a, b, ud);
	int cd = lerp(c, d, ud);
	return lerp(ab, cd, vd);
}

static inline byte getmask(byte *s, int w, int h, int u, int v)
{
	if (u < 0 || u >= w) return 0;
	if (v < 0 || v >= h) return 0;
	return s[w * v + u];
}

static inline int samplemask(byte *s, int w, int h, int u, int v)
{
	int ui = u >> 16;
	int vi = v >> 16;
	int ud = u & 0xFFFF;
	int vd = v & 0xFFFF;
	int a = getmask(s, w, h, ui, vi);
	int b = getmask(s, w, h, ui+1, vi);
	int c = getmask(s, w, h, ui, vi+1);
	int d = getmask(s, w, h, ui+1, vi+1);
	int ab = lerp(a, b, ud);
	int cd = lerp(c, d, ud);
	return lerp(ab, cd, vd);
}

static inline void lerpargb(byte *dst, byte *a, byte *b, int t)
{
	dst[0] = lerp(a[0], b[0], t);
	dst[1] = lerp(a[1], b[1], t);
	dst[2] = lerp(a[2], b[2], t);
	dst[3] = lerp(a[3], b[3], t);
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
	int ud = u & 0xFFFF;
	int vd = v & 0xFFFF;
	byte *a = getargb(s, w, h, ui, vi);
	byte *b = getargb(s, w, h, ui+1, vi);
	byte *c = getargb(s, w, h, ui, vi+1);
	byte *d = getargb(s, w, h, ui+1, vi+1);
	lerpargb(ab, a, b, ud);
	lerpargb(cd, c, d, ud);
	lerpargb(abcd, ab, cd, vd);
}

/*
 * img_NcN
 * img_1c1
 * img_4c4
 * img_1o1
 * img_4o4
 * img_1i1c1
 * img_1i1o1
 * img_4i1c4
 * img_4i1o4
 * img_w3i1o4
 * img_w3i1i1o4
 */

static void img_NcN(FZ_PSRC, int srcn, FZ_PDST, FZ_PCTM)
{
	int k;
	while (h--)
	{
		byte *dstp = dst0;
		int u = u0;
		int v = v0;
		int w = w0;
		while (w--)
		{
			for (k = 0; k < srcn; k++)
			{
				dstp[k] = samplecomp(src, srcw, srch, u, v, srcn, k);
				dstp += srcn;
				u += fa;
				v += fb;
			}
		}
		dst0 += dstw;
		u0 += fc;
		v0 += fd;
	}
}

static void img_1c1(FZ_PSRC, FZ_PDST, FZ_PCTM)
{
	while (h--)
	{
		byte *dstp = dst0;
		int u = u0;
		int v = v0;
		int w = w0;
		while (w--)
		{
			dstp[0] = samplemask(src, srcw, srch, u, v);
			dstp ++;
			u += fa;
			v += fb;
		}
		dst0 += dstw;
		u0 += fc;
		v0 += fd;
	}
}

static void img_4c4(FZ_PSRC, FZ_PDST, FZ_PCTM)
{
	while (h--)
	{
		byte *dstp = dst0;
		int u = u0;
		int v = v0;
		int w = w0;
		while (w--)
		{
			sampleargb(src, srcw, srch, u, v, dstp);
			dstp += 4;
			u += fa;
			v += fb;
		}
		dst0 += dstw;
		u0 += fc;
		v0 += fd;
	}
}

static void img_1o1(FZ_PSRC, FZ_PDST, FZ_PCTM)
{
	byte srca;
	while (h--)
	{
		byte *dstp = dst0;
		int u = u0;
		int v = v0;
		int w = w0;
		while (w--)
		{
			srca = samplemask(src, srcw, srch, u, v);
			dstp[0] = srca + fz_mul255(dstp[0], 255 - srca);
			dstp ++;
			u += fa;
			v += fb;
		}
		dst0 += dstw;
		u0 += fc;
		v0 += fd;
	}
}

static void img_4o4(FZ_PSRC, FZ_PDST, FZ_PCTM)
{
	byte argb[4];
	byte ssa;
	while (h--)
	{
		byte *dstp = dst0;
		int u = u0;
		int v = v0;
		int w = w0;
		while (w--)
		{
			sampleargb(src, srcw, srch, u, v, argb);
			ssa = 255 - argb[0];
			dstp[0] = argb[0] + fz_mul255(dstp[0], ssa);
			dstp[1] = argb[1] + fz_mul255(dstp[1], ssa);
			dstp[2] = argb[2] + fz_mul255(dstp[2], ssa);
			dstp[3] = argb[3] + fz_mul255(dstp[3], ssa);
			dstp += 4;
			u += fa;
			v += fb;
		}
		dst0 += dstw;
		u0 += fc;
		v0 += fd;
	}
}

static void img_w3i1o4(byte *rgb, FZ_PSRC, FZ_PDST, FZ_PCTM)
{
	byte sa, ssa;
	while (h--)
	{
		byte *dstp = dst0;
		int u = u0;
		int v = v0;
		int w = w0;
		while (w--)
		{
			sa = samplemask(src, srcw, srch, u, v);
			ssa = 255 - sa;
			dstp[0] = sa + fz_mul255(dstp[0], ssa);
			dstp[1] = rgb[0] + fz_mul255((short)dstp[1] - rgb[0], ssa);
			dstp[2] = rgb[1] + fz_mul255((short)dstp[2] - rgb[1], ssa);
			dstp[3] = rgb[2] + fz_mul255((short)dstp[3] - rgb[2], ssa);
			dstp += 4;
			u += fa;
			v += fb;
		}
		dst0 += dstw;
		u0 += fc;
		v0 += fd;
	}
}

/*
 * Fill in the big fat vtable
 */

static fz_rastfuncs deftab =
{
	duff_NoN,
	duff_NiMcN,
	duff_NiMoN,
	duff_1o1,
	duff_4o4,
	duff_1i1c1,
	duff_4i1c4,
	duff_1i1o1,
	duff_4i1o4,

	msk_1c1,
	msk_1o1,
	msk_w3i1o4,

	nil,
	nil,
	nil,

	img_NcN,
	img_1c1,
	img_4c4,
	img_1o1,
	img_4o4,
	img_w3i1o4
};

void
fz_loadrastfuncs(fz_rastfuncs *tab)
{
	*tab = deftab;
#ifdef HAVE_CPUDEP
	fz_accelrastfuncs(tab);
#endif
}

