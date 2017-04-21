#include "mupdf/fitz.h"
#include "draw-imp.h"

#include <math.h>
#include <float.h>
#include <assert.h>

typedef unsigned char byte;

typedef void (paintfn_t)(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp);

static inline int lerp(int a, int b, int t)
{
	return a + (((b - a) * t) >> 16);
}

static inline int bilerp(int a, int b, int c, int d, int u, int v)
{
	return lerp(lerp(a, b, u), lerp(c, d, u), v);
}

static inline const byte *sample_nearest(const byte *s, int w, int h, int str, int n, int u, int v)
{
	if (u < 0) u = 0;
	if (v < 0) v = 0;
	if (u >= (w>>16)) u = (w>>16) - 1;
	if (v >= (h>>16)) v = (h>>16) - 1;
	return s + v * str + u * n;
}

/* Blend premultiplied source image in constant alpha over destination */

static inline void
template_affine_alpha_N_lerp(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, byte * restrict hp)
{
	int k;

	do
	{
		if (u + 32768 >= 0 && u < sw && v + 32768 >= 0 && v < sh)
		{
			int ui = u >> 16;
			int vi = v >> 16;
			int uf = u & 0xffff;
			int vf = v & 0xffff;
			const byte *a = sample_nearest(sp, sw, sh, ss, n1+sa, ui, vi);
			const byte *b = sample_nearest(sp, sw, sh, ss, n1+sa, ui+1, vi);
			const byte *c = sample_nearest(sp, sw, sh, ss, n1+sa, ui, vi+1);
			const byte *d = sample_nearest(sp, sw, sh, ss, n1+sa, ui+1, vi+1);
			int xa = sa ? fz_mul255(bilerp(a[n1], b[n1], c[n1], d[n1], uf, vf), alpha) : alpha;
			if (xa != 0)
			{
				int t = 255 - xa;
				for (k = 0; k < n1; k++)
				{
					int x = bilerp(a[k], b[k], c[k], d[k], uf, vf);
					dp[k] = fz_mul255(x, alpha) + fz_mul255(dp[k], t);
				}
				if (da)
					dp[n1] = xa + fz_mul255(dp[n1], t);
				if (hp)
					hp[0] = xa + fz_mul255(hp[0], t);
			}
		}
		dp += n1+da;
		if (hp)
			hp++;
		u += fa;
		v += fb;
	}
	while (--w);
}

/* Special case code for gray -> rgb */
static inline void
template_affine_alpha_g2rgb_lerp(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int alpha, byte * restrict hp)
{
	do
	{
		if (u + 32768 >= 0 && u < sw && v + 32768 >= 0 && v < sh)
		{
			int ui = u >> 16;
			int vi = v >> 16;
			int uf = u & 0xffff;
			int vf = v & 0xffff;
			const byte *a = sample_nearest(sp, sw, sh, ss, 1+sa, ui, vi);
			const byte *b = sample_nearest(sp, sw, sh, ss, 1+sa, ui+1, vi);
			const byte *c = sample_nearest(sp, sw, sh, ss, 1+sa, ui, vi+1);
			const byte *d = sample_nearest(sp, sw, sh, ss, 1+sa, ui+1, vi+1);
			int y = (sa ? fz_mul255(bilerp(a[1], b[1], c[1], d[1], uf, vf), alpha) : alpha);
			if (y != 0)
			{
				int x = bilerp(a[0], b[0], c[0], d[0], uf, vf);
				int t = 255 - y;
				x = fz_mul255(x, alpha);
				dp[0] = x + fz_mul255(dp[0], t);
				dp[1] = x + fz_mul255(dp[1], t);
				dp[2] = x + fz_mul255(dp[2], t);
				if (da)
					dp[3] = y + fz_mul255(dp[3], t);
				if (hp)
					hp[0] = y + fz_mul255(hp[0], t);
			}
		}
		dp += 4;
		if (hp)
			hp++;
		u += fa;
		v += fb;
	}
	while (--w);
}

static inline void
template_affine_alpha_N_near_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, byte * restrict hp)
{
	int k;
	int ui = u >> 16;
	TRACK_FN();
	if (ui < 0 || ui >= sw)
		return;
	sp += ui * (n1+sa);
	do
	{
		int vi = v >> 16;
		if (vi >= 0 && vi < sh)
		{
			const byte *sample = sp + (vi * ss);
			int a = (sa ? fz_mul255(sample[n1], alpha) : alpha);
			if (a != 0)
			{
				int t = 255 - a;
				for (k = 0; k < n1; k++)
					dp[k] = fz_mul255(sample[k], alpha) + fz_mul255(dp[k], t);
				if (da)
					dp[n1] = a + fz_mul255(dp[n1], t);
				if (hp)
					hp[0] = a + fz_mul255(hp[0], t);
			}
		}
		dp += n1+da;
		if (hp)
			hp++;
		v += fb;
	}
	while (--w);
}

static inline void
template_affine_alpha_N_near_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, byte * restrict hp)
{
	int k;
	int vi = v >> 16;
	if (vi < 0 || vi >= sh)
		return;
	sp += vi * ss;
	do
	{
		int ui = u >> 16;
		if (ui >= 0 && ui < sw)
		{
			const byte *sample = sp + (ui * (n1+sa));
			int a = (sa ? fz_mul255(sample[n1], alpha) : alpha);
			if (a != 0)
			{
				int t = 255 - a;
				for (k = 0; k < n1; k++)
					dp[k] = fz_mul255(sample[k], alpha) + fz_mul255(dp[k], t);
				if (da)
					dp[n1] = a + fz_mul255(dp[n1], t);
				if (hp)
					hp[0] = a + fz_mul255(hp[0], t);
			}
		}
		dp += n1+da;
		if (hp)
			hp++;
		u += fa;
	}
	while (--w);
}

static inline void
template_affine_alpha_N_near(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, byte * restrict hp)
{
	int k;

	do
	{
		int ui = u >> 16;
		int vi = v >> 16;
		if (ui >= 0 && ui < sw && vi >= 0 && vi < sh)
		{
			const byte *sample = sp + (vi * ss) + (ui * (n1+sa));
			int a = (sa ? fz_mul255(sample[n1], alpha) : alpha);
			if (a != 0)
			{
				int t = 255 - a;
				for (k = 0; k < n1; k++)
					dp[k] = fz_mul255(sample[k], alpha) + fz_mul255(dp[k], t);
				if (da)
					dp[n1] = a + fz_mul255(dp[n1], t);
				if (hp)
					hp[0] = a + fz_mul255(hp[0], t);
			}
		}
		dp += n1+da;
		if (hp)
			hp++;
		u += fa;
		v += fb;
	}
	while (--w);
}

static inline void
template_affine_alpha_g2rgb_near_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int alpha, byte * restrict hp)
{
	int ui = u >> 16;
	if (ui < 0 || ui >= sw)
		return;
	sp += ui * (1+sa);
	do
	{
		int vi = v >> 16;
		if (vi >= 0 && vi < sh)
		{
			const byte *sample = sp + (vi * ss);
			int x = fz_mul255(sample[0], alpha);
			int a = (sa ? fz_mul255(sample[1], alpha) : alpha);
			if (a != 0)
			{
				int t = 255 - a;
				dp[0] = x + fz_mul255(dp[0], t);
				dp[1] = x + fz_mul255(dp[1], t);
				dp[2] = x + fz_mul255(dp[2], t);
				if (da)
					dp[3] = a + fz_mul255(dp[3], t);
				if (hp)
					hp[0] = a + fz_mul255(hp[0], t);
			}
		}
		dp += 3 + da;
		if (hp)
			hp++;
		v += fb;
	}
	while (--w);
}

static inline void
template_affine_alpha_g2rgb_near_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int alpha, byte * restrict hp)
{
	int vi = v >> 16;
	if (vi < 0 || vi >= sh)
		return;
	sp += vi * ss;
	do
	{
		int ui = u >> 16;
		if (ui >= 0 && ui < sw)
		{
			const byte *sample = sp + (ui * (1+sa));
			int x = fz_mul255(sample[0], alpha);
			int a = (sa ? fz_mul255(sample[1], alpha) : alpha);
			if (a != 0)
			{
				int t = 255 - a;
				dp[0] = x + fz_mul255(dp[0], t);
				dp[1] = x + fz_mul255(dp[1], t);
				dp[2] = x + fz_mul255(dp[2], t);
				if (da)
					dp[3] = a + fz_mul255(dp[3], t);
				if (hp)
					hp[0] = a + fz_mul255(hp[0], t);
			}
		}
		dp += 3 + da;
		if (hp)
			hp++;
		u += fa;
	}
	while (--w);
}

static inline void
template_affine_alpha_g2rgb_near(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int alpha, byte * restrict hp)
{
	do
	{
		int ui = u >> 16;
		int vi = v >> 16;
		if (ui >= 0 && ui < sw && vi >= 0 && vi < sh)
		{
			const byte *sample = sp + (vi * ss) + (ui * (1+sa));
			int x = fz_mul255(sample[0], alpha);
			int a = (sa ? fz_mul255(sample[1], alpha): alpha);
			if (a != 0)
			{
				int t = 255 - a;
				dp[0] = x + fz_mul255(dp[0], t);
				dp[1] = x + fz_mul255(dp[1], t);
				dp[2] = x + fz_mul255(dp[2], t);
				if (da)
					dp[3] = a + fz_mul255(dp[3], t);
				if (hp)
					hp[0] = a + fz_mul255(hp[0], t);
			}
		}
		dp += 3 + da;
		if (hp)
			hp++;
		u += fa;
		v += fb;
	}
	while (--w);
}

/* Blend premultiplied source image over destination */
static inline void
template_affine_N_lerp(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, byte * restrict hp)
{
	int k;

	do
	{
		if (u + 32768 >= 0 && u < sw && v + 32768 >= 0 && v < sh)
		{
			int ui = u >> 16;
			int vi = v >> 16;
			int uf = u & 0xffff;
			int vf = v & 0xffff;
			const byte *a = sample_nearest(sp, sw, sh, ss, n1+sa, ui, vi);
			const byte *b = sample_nearest(sp, sw, sh, ss, n1+sa, ui+1, vi);
			const byte *c = sample_nearest(sp, sw, sh, ss, n1+sa, ui, vi+1);
			const byte *d = sample_nearest(sp, sw, sh, ss, n1+sa, ui+1, vi+1);
			int y = sa ? bilerp(a[n1], b[n1], c[n1], d[n1], uf, vf) : 255;
			if (y != 0)
			{
				int t = 255 - y;
				for (k = 0; k < n1; k++)
				{
					int x = bilerp(a[k], b[k], c[k], d[k], uf, vf);
					dp[k] = x + fz_mul255(dp[k], t);
				}
				if (da)
					dp[n1] = y + fz_mul255(dp[n1], t);
				if (hp)
					hp[0] = y + fz_mul255(hp[0], t);
			}
		}
		dp += n1 + da;
		if (hp)
			hp++;
		u += fa;
		v += fb;
	}
	while (--w);
}

static inline void
template_affine_solid_g2rgb_lerp(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, byte * restrict hp)
{
	do
	{
		if (u + 32768 >= 0 && u < sw && v + 32768 >= 0 && v < sh)
		{
			int ui = u >> 16;
			int vi = v >> 16;
			int uf = u & 0xffff;
			int vf = v & 0xffff;
			const byte *a = sample_nearest(sp, sw, sh, ss, 1+sa, ui, vi);
			const byte *b = sample_nearest(sp, sw, sh, ss, 1+sa, ui+1, vi);
			const byte *c = sample_nearest(sp, sw, sh, ss, 1+sa, ui, vi+1);
			const byte *d = sample_nearest(sp, sw, sh, ss, 1+sa, ui+1, vi+1);
			int y = (sa ? bilerp(a[1], b[1], c[1], d[1], uf, vf) : 255);
			if (y != 0)
			{
				int t = 255 - y;
				int x = bilerp(a[0], b[0], c[0], d[0], uf, vf);
				dp[0] = x + fz_mul255(dp[0], t);
				dp[1] = x + fz_mul255(dp[1], t);
				dp[2] = x + fz_mul255(dp[2], t);
				if (da)
					dp[3] = y + fz_mul255(dp[3], t);
				if (hp)
					hp[0] = y + fz_mul255(hp[0], t);
			}
		}
		dp += 3 + da;
		if (hp)
			hp++;
		u += fa;
		v += fb;
	}
	while (--w);
}

static inline void
template_affine_N_near_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, byte * restrict hp)
{
	int k;
	int ui = u >> 16;
	if (ui < 0 || ui >= sw)
		return;
	sp += ui*(n1+sa);
	do
	{
		int vi = v >> 16;
		if (vi >= 0 && vi < sh)
		{
			const byte *sample = sp + (vi * ss);
			int a = (sa ? sample[n1] : 255);
			/* If a is 0, then sample[k] = 0 for all k, as premultiplied */
			if (a != 0)
			{
				int t = 255 - a;
				if (t == 0)
				{
					if (n1+da == 4 && n1+sa == 4)
					{
						*(int32_t *)dp = *(int32_t *)sample;
					}
					else
					{
						dp[0] = sample[0];
						if (n1 > 1)
							dp[1] = sample[1];
						if (n1 > 2)
							dp[2] = sample[2];
						for (k = 3; k < n1; k++)
							dp[k] = sample[k];
						if (da)
							dp[n1] = a;
					}
					if (hp)
						hp[0] = a;
				}
				else
				{
					for (k = 0; k < n1; k++)
						dp[k] = sample[k] + fz_mul255(dp[k], t);
					if (da)
						dp[n1] = a + fz_mul255(dp[n1], t);
					if (hp)
						hp[0] = a + fz_mul255(hp[0], t);
				}
			}
		}
		dp += n1+da;
		if (hp)
			hp++;
		v += fb;
	}
	while (--w);
}

static inline void
template_affine_N_near_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, byte * restrict hp)
{
	int k;
	int vi = v >> 16;
	if (vi < 0 || vi >= sh)
		return;
	sp += vi * ss;
	do
	{
		int ui = u >> 16;
		if (ui >= 0 && ui < sw)
		{
			const byte *sample = sp + (ui * (n1+sa));
			int a = sa ? sample[n1] : 255;
			/* If a is 0, then sample[k] = 0 for all k, as premultiplied */
			if (a != 0)
			{
				int t = 255 - a;
				if (t == 0)
				{
					if (n1+da == 4 && n1+sa == 4)
					{
						*(int32_t *)dp = *(int32_t *)sample;
					}
					else
					{
						dp[0] = sample[0];
						if (n1 > 1)
							dp[1] = sample[1];
						if (n1 > 2)
							dp[2] = sample[2];
						for (k = 3; k < n1; k++)
							dp[k] = sample[k];
						if (da)
							dp[n1] = a;
					}
					if (hp)
						hp[0] = a;
				}
				else
				{
					for (k = 0; k < n1; k++)
						dp[k] = sample[k] + fz_mul255(dp[k], t);
					if(da)
						dp[n1] = a + fz_mul255(dp[n1], t);
					if (hp)
						hp[0] = a + fz_mul255(hp[0], t);
				}
			}
		}
		dp += n1+da;
		if (hp)
			hp++;
		u += fa;
	}
	while (--w);
}

static inline void
template_affine_N_near(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, byte * restrict hp)
{
	int k;
	do
	{
		int ui = u >> 16;
		int vi = v >> 16;
		if (ui >= 0 && ui < sw && vi >= 0 && vi < sh)
		{
			const byte *sample = sp + (vi * ss) + (ui * (n1+sa));
			int a = sa ? sample[n1] : 255;
			/* If a is 0, then sample[k] = 0 for all k, as premultiplied */
			if (a != 0)
			{
				int t = 255 - a;
				if (t == 0)
				{
					if (n1+da == 4 && n1+sa == 4)
					{
						*(int32_t *)dp = *(int32_t *)sample;
					}
					else
					{
						dp[0] = sample[0];
						if (n1 > 1)
							dp[1] = sample[1];
						if (n1 > 2)
							dp[2] = sample[2];
						for (k = 3; k < n1; k++)
							dp[k] = sample[k];
						if (da)
							dp[n1] = a;
					}
					if (hp)
						hp[0] = a;
				}
				else
				{
					for (k = 0; k < n1; k++)
						dp[k] = sample[k] + fz_mul255(dp[k], t);
					if (da)
						dp[n1] = a + fz_mul255(dp[n1], t);
					if (hp)
						hp[0] = a + fz_mul255(hp[0], t);
				}
			}
		}
		dp += n1+da;
		if (hp)
			hp++;
		u += fa;
		v += fb;
	}
	while (--w);
}

static inline void
template_affine_solid_g2rgb_near_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, byte * restrict hp)
{
	int ui = u >> 16;
	if (ui < 0 || ui >= sw)
		return;
	sp += ui * (1+sa);
	do
	{
		int vi = v >> 16;
		if (vi >= 0 && vi < sh)
		{
			const byte *sample = sp + (vi * ss);
			int a = (sa ? sample[1] : 255);
			if (a != 0)
			{
				int x = sample[0];
				int t = 255 - a;
				if (t == 0)
				{
					dp[0] = x;
					dp[1] = x;
					dp[2] = x;
					if (da)
						dp[3] = a;
					if (hp)
						hp[0] = a;
				}
				else
				{
					dp[0] = x + fz_mul255(dp[0], t);
					dp[1] = x + fz_mul255(dp[1], t);
					dp[2] = x + fz_mul255(dp[2], t);
					if (da)
						dp[3] = a + fz_mul255(dp[3], t);
					if (hp)
						hp[0] = a + fz_mul255(hp[0], t);
				}
			}
		}
		dp += 3 + da;
		if (hp)
			hp++;
		v += fb;
	}
	while (--w);
}

static inline void
template_affine_solid_g2rgb_near_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, byte * restrict hp)
{
	int vi = v >> 16;
	if (vi < 0 || vi >= sh)
		return;
	sp += vi * ss;
	do
	{
		int ui = u >> 16;
		if (ui >= 0 && ui < sw)
		{
			const byte *sample = sp + (ui * (1+sa));
			int a = (sa ? sample[1] : 255);
			if (a != 0)
			{
				int x = sample[0];
				int t = 255 - a;
				if (t == 0)
				{
					dp[0] = x;
					dp[1] = x;
					dp[2] = x;
					if (da)
						dp[3] = a;
					if (hp)
						hp[0] = a;
				}
				else
				{
					dp[0] = x + fz_mul255(dp[0], t);
					dp[1] = x + fz_mul255(dp[1], t);
					dp[2] = x + fz_mul255(dp[2], t);
					if (da)
						dp[3] = a + fz_mul255(dp[3], t);
					if (hp)
						hp[0] = a + fz_mul255(hp[0], t);
				}
			}
		}
		dp += 3 + da;
		if (hp)
			hp++;
		u += fa;
	}
	while (--w);
}

static inline void
template_affine_solid_g2rgb_near(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, byte * restrict hp)
{
	do
	{
		int ui = u >> 16;
		int vi = v >> 16;
		if (ui >= 0 && ui < sw && vi >= 0 && vi < sh)
		{
			const byte *sample = sp + (vi * ss) + (ui * (1+sa));
			int a = sa ? sample[1] : 255;
			if (a != 0)
			{
				int x = sample[0];
				int t = 255 - a;
				if (t == 0)
				{
					dp[0] = x;
					dp[1] = x;
					dp[2] = x;
					if (da)
						dp[3] = a;
					if (hp)
						hp[0] = a;
				}
				else
				{
					dp[0] = x + fz_mul255(dp[0], t);
					dp[1] = x + fz_mul255(dp[1], t);
					dp[2] = x + fz_mul255(dp[2], t);
					if (da)
						dp[3] = a + fz_mul255(dp[3], t);
					if (hp)
						hp[0] = a + fz_mul255(hp[0], t);
				}
			}
		}
		dp += 3 + da;
		if (hp)
			hp++;
		u += fa;
		v += fb;
	}
	while (--w);
}

/* Blend non-premultiplied color in source image mask over destination */

static inline void
template_affine_color_N_lerp(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int u, int v, int fa, int fb, int w, int n1, const byte * restrict color, byte * restrict hp)
{
	int sa = color[n1];
	int k;

	do
	{
		if (u + 32768 >= 0 && u < sw && v + 32768 >= 0 && v < sh)
		{
			int ui = u >> 16;
			int vi = v >> 16;
			int uf = u & 0xffff;
			int vf = v & 0xffff;
			const byte *a = sample_nearest(sp, sw, sh, ss, 1, ui, vi);
			const byte *b = sample_nearest(sp, sw, sh, ss, 1, ui+1, vi);
			const byte *c = sample_nearest(sp, sw, sh, ss, 1, ui, vi+1);
			const byte *d = sample_nearest(sp, sw, sh, ss, 1, ui+1, vi+1);
			int ma = bilerp(a[0], b[0], c[0], d[0], uf, vf);
			int masa = FZ_COMBINE(FZ_EXPAND(ma), sa);
			if (masa != 0)
			{
				for (k = 0; k < n1; k++)
					dp[k] = FZ_BLEND(color[k], dp[k], masa);
				if (da)
					dp[n1] = FZ_BLEND(255, dp[n1], masa);
				if (hp)
					hp[0] = FZ_BLEND(255, hp[0], masa);
			}
		}
		dp += n1 + da;
		if (hp)
			hp++;
		u += fa;
		v += fb;
	}
	while (--w);
}

static inline void
template_affine_color_N_near(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int u, int v, int fa, int fb, int w, int n1, const byte * restrict color, byte * restrict hp)
{
	int sa = color[n1];
	int k;

	do
	{
		int ui = u >> 16;
		int vi = v >> 16;
		if (ui >= 0 && ui < sw && vi >= 0 && vi < sh)
		{
			int ma = sp[vi * ss + ui];
			int masa = FZ_COMBINE(FZ_EXPAND(ma), sa);
			if (masa)
			{
				for (k = 0; k < n1; k++)
					dp[k] = FZ_BLEND(color[k], dp[k], masa);
				if (da)
					dp[n1] = FZ_BLEND(255, dp[n1], masa);
				if (hp)
					hp[0] = FZ_BLEND(255, hp[0], masa);
			}
		}
		dp += n1+da;
		if (hp)
			hp++;
		u += fa;
		v += fb;
	}
	while (--w);
}

static void
paint_affine_lerp_da_sa_0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 0, hp);
}

static void
paint_affine_lerp_da_sa_alpha_0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 0, alpha, hp);
}

static void
paint_affine_lerp_da_0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 0, hp);
}

static void
paint_affine_lerp_da_alpha_0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 0, alpha, hp);
}

static void
paint_affine_lerp_da_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_lerp_da_alpha_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_lerp_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_lerp_alpha_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, alpha, hp);
}

#if FZ_PLOTTERS_G
static void
paint_affine_lerp_da_sa_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_lerp_da_sa_alpha_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_lerp_sa_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_lerp_sa_alpha_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, alpha, hp);
}
#endif /* FZ_PLOTTERS_G */

#if FZ_PLOTTERS_RGB
static void
paint_affine_lerp_da_sa_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_lerp_da_sa_alpha_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_lerp_da_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_lerp_da_alpha_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_lerp_sa_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_lerp_sa_alpha_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_lerp_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_lerp_alpha_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, alpha, hp);
}
#endif /* FZ_PLOTTERS_RGB */

#if FZ_PLOTTERS_CMYK
static void
paint_affine_lerp_da_sa_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_lerp_da_sa_alpha_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_lerp_da_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_lerp_da_alpha_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_lerp_sa_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_lerp_sa_alpha_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_lerp_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_lerp_alpha_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, alpha, hp);
}
#endif /* FZ_PLOTTERS_CMYK */

#if FZ_PLOTTERS_N
static void
paint_affine_lerp_da_sa_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_lerp_da_sa_alpha_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_lerp_da_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_lerp_da_alpha_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_lerp_sa_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_lerp_sa_alpha_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_lerp_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_lerp(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_lerp_alpha_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_lerp(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, alpha, hp);
}
#endif /* FZ_PLOTTERS_N */

static paintfn_t *
fz_paint_affine_lerp(int da, int sa, int fa, int fb, int n, int alpha)
{
	switch(n)
	{
	case 0:
		if (da)
		{
			if (sa)
			{
				if (alpha == 255)
					return paint_affine_lerp_da_sa_0;
				else if (alpha > 0)
					return paint_affine_lerp_da_sa_alpha_0;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_lerp_da_0;
				else if (alpha > 0)
					return paint_affine_lerp_da_alpha_0;
			}
		}
		break;

	case 1:
		if (sa)
		{
#if FZ_PLOTTERS_G
			if (da)
			{
				if (alpha == 255)
					return paint_affine_lerp_da_sa_1;
				else if (alpha > 0)
					return paint_affine_lerp_da_sa_alpha_1;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_lerp_sa_1;
				else if (alpha > 0)
					return paint_affine_lerp_sa_alpha_1;
			}
#else
			goto fallback;
#endif /* FZ_PLOTTERS_H */
		}
		else
		{
			if (da)
			{
				if (alpha == 255)
					return paint_affine_lerp_da_1;
				else if (alpha > 0)
					return paint_affine_lerp_da_alpha_1;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_lerp_1;
				else if (alpha > 0)
					return paint_affine_lerp_alpha_1;
			}
		}
		break;

#if FZ_PLOTTERS_RGB
	case 3:
		if (da)
		{
			if (sa)
			{
				if (alpha == 255)
					return paint_affine_lerp_da_sa_3;
				else if (alpha > 0)
					return paint_affine_lerp_da_sa_alpha_3;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_lerp_da_3;
				else if (alpha > 0)
					return paint_affine_lerp_da_alpha_3;
			}
		}
		else
		{
			if (sa)
			{
				if (alpha == 255)
					return paint_affine_lerp_sa_3;
				else if (alpha > 0)
					return paint_affine_lerp_sa_alpha_3;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_lerp_3;
				else if (alpha > 0)
					return paint_affine_lerp_alpha_3;
			}
		}
		break;
#endif /* FZ_PLOTTERS_RGB */

#if FZ_PLOTTERS_CMYK
	case 4:
		if (da)
		{
			if (sa)
			{
				if (alpha == 255)
					return paint_affine_lerp_da_sa_4;
				else if (alpha > 0)
					return paint_affine_lerp_da_sa_alpha_4;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_lerp_da_4;
				else if (alpha > 0)
					return paint_affine_lerp_da_alpha_4;
			}
		}
		else
		{
			if (sa)
			{
				if (alpha == 255)
					return paint_affine_lerp_sa_4;
				else if (alpha > 0)
					return paint_affine_lerp_sa_alpha_4;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_lerp_4;
				else if (alpha > 0)
					return paint_affine_lerp_alpha_4;
			}
		}
		break;
#endif /* FZ_PLOTTERS_CMYK */

#if !FZ_PLOTTERS_G
fallback:
#endif /* FZ_PLOTTERS_G */
	default:
#if FZ_PLOTTERS_N
		if (da)
		{
			if (sa)
			{
				if (alpha == 255)
					return paint_affine_lerp_da_sa_N;
				else if (alpha > 0)
					return paint_affine_lerp_da_sa_alpha_N;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_lerp_da_N;
				else if (alpha > 0)
					return paint_affine_lerp_da_alpha_N;
			}
		}
		else
		{
			if (sa)
			{
				if (alpha == 255)
					return paint_affine_lerp_sa_N;
				else if (alpha > 0)
					return paint_affine_lerp_sa_alpha_N;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_lerp_N;
				else if (alpha > 0)
					return paint_affine_lerp_alpha_N;
			}
		}
#endif /* FZ_PLOTTERS_N */
		break;
	}
	return NULL;
}

#if FZ_PLOTTERS_RGB
static void
paint_affine_lerp_da_sa_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, hp);
}

static void
paint_affine_lerp_da_sa_g2rgb_alpha(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_lerp(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_lerp_da_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, hp);
}

static void
paint_affine_lerp_da_g2rgb_alpha(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_lerp(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_lerp_sa_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_lerp(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, hp);
}

static void
paint_affine_lerp_sa_g2rgb_alpha(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_lerp(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_lerp_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_lerp(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, hp);
}

static void
paint_affine_lerp_g2rgb_alpha(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_lerp(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, alpha, hp);
}

static paintfn_t *
fz_paint_affine_g2rgb_lerp(int da, int sa, int fa, int fb, int n, int alpha)
{
	if (da)
	{
		if (sa)
		{
			if (alpha == 255)
				return paint_affine_lerp_da_sa_g2rgb;
			else if (alpha > 0)
				return paint_affine_lerp_da_sa_g2rgb_alpha;
		}
		else
		{
			if (alpha == 255)
				return paint_affine_lerp_da_g2rgb;
			else if (alpha > 0)
				return paint_affine_lerp_da_g2rgb_alpha;
		}
	}
	else
	{
		if (sa)
		{
			if (alpha == 255)
				return paint_affine_lerp_sa_g2rgb;
			else if (alpha > 0)
				return paint_affine_lerp_sa_g2rgb_alpha;
		}
		else
		{
			if (alpha == 255)
				return paint_affine_lerp_g2rgb;
			else if (alpha > 0)
				return paint_affine_lerp_g2rgb_alpha;
		}
	}
	return NULL;
}
#endif /* FZ_PLOTTERS_RGB */

static void
paint_affine_near_da_sa_0_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 0, hp);
}

static void
paint_affine_near_da_sa_alpha_0_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 0, alpha, hp);
}

static void
paint_affine_near_da_0_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 0, hp);
}

static void
paint_affine_near_da_alpha_0_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 0, alpha, hp);
}

static void
paint_affine_near_da_sa_0_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 0, hp);
}

static void
paint_affine_near_da_sa_alpha_0_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 0, alpha, hp);
}

static void
paint_affine_near_da_0_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 0, hp);
}

static void
paint_affine_near_da_alpha_0_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 0, alpha, hp);
}

static void
paint_affine_near_da_sa_0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 0, hp);
}

static void
paint_affine_near_da_sa_alpha_0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 0, alpha, hp);
}

static void
paint_affine_near_da_0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 0, hp);
}

static void
paint_affine_near_da_alpha_0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 0, alpha, hp);
}

static void
paint_affine_near_1_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_1_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_alpha_1_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_near_alpha_1_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_near_alpha_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_near_da_1_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_da_alpha_1_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_near_da_1_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_da_alpha_1_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_near_da_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_da_alpha_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 1, alpha, hp);
}

#if FZ_PLOTTERS_G
static void
paint_affine_near_da_sa_1_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_da_sa_alpha_1_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_near_sa_1_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_sa_alpha_1_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_near_da_sa_1_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_da_sa_alpha_1_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_near_sa_alpha_1_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_near_da_sa_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_sa_1_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_da_sa_alpha_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, alpha, hp);
}

static void
paint_affine_near_sa_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, hp);
}

static void
paint_affine_near_sa_alpha_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 1, alpha, hp);
}
#endif /* FZ_PLOTTERS_G */

#if FZ_PLOTTERS_RGB
static void
paint_affine_near_da_sa_3_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_da_sa_alpha_3_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_da_3_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_da_alpha_3_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_sa_3_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_sa_alpha_3_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_3_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_alpha_3_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_da_sa_3_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_da_sa_alpha_3_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_da_3_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_da_alpha_3_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_sa_alpha_3_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_da_sa_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_alpha_3_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_3_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_sa_3_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_da_sa_alpha_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_da_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_sa_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_da_alpha_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_sa_alpha_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 3, alpha, hp);
}

static void
paint_affine_near_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, hp);
}

static void
paint_affine_near_alpha_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 3, alpha, hp);
}
#endif /* FZ_PLOTTERS_RGB */

#if FZ_PLOTTERS_CMYK
static void
paint_affine_near_da_sa_4_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_da_sa_alpha_4_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_da_4_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_da_alpha_4_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_sa_4_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_sa_alpha_4_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_4_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_alpha_4_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_da_sa_4_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_da_sa_alpha_4_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_da_4_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_da_alpha_4_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_sa_4_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_sa_alpha_4_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_4_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_alpha_4_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_da_sa_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_da_sa_alpha_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_da_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_da_alpha_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_sa_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_sa_alpha_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, 4, alpha, hp);
}

static void
paint_affine_near_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, hp);
}

static void
paint_affine_near_alpha_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, 4, alpha, hp);
}
#endif /* FZ_PLOTTERS_CMYK */

#if FZ_PLOTTERS_N
static void
paint_affine_near_da_sa_N_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_da_sa_alpha_N_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_da_N_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_da_alpha_N_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_sa_N_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_sa_alpha_N_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_N_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fa0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_alpha_N_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fa0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_da_sa_N_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_da_sa_alpha_N_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_da_N_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_da_alpha_N_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_sa_N_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_sa_alpha_N_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_N_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near_fb0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_alpha_N_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near_fb0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_da_sa_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_da_sa_alpha_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_da_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_da_alpha_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_sa_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_sa_alpha_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, n, alpha, hp);
}

static void
paint_affine_near_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_N_near(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, hp);
}

static void
paint_affine_near_alpha_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_N_near(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, n, alpha, hp);
}
#endif

static paintfn_t *
fz_paint_affine_near(int da, int sa, int fa, int fb, int n, int alpha)
{
	switch(n)
	{
	case 0:
		if (da)
		{
			if (sa)
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_da_sa_0_fa0;
					else if (fb == 0)
						return paint_affine_near_da_sa_0_fb0;
					else
						return paint_affine_near_da_sa_0;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_da_sa_alpha_0_fa0;
					else if (fb == 0)
						return paint_affine_near_da_sa_alpha_0_fb0;
					else
						return paint_affine_near_da_sa_alpha_0;
				}
			}
			else
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_da_0_fa0;
					else if (fb == 0)
						return paint_affine_near_da_0_fb0;
					else
						return paint_affine_near_da_0;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_da_alpha_0_fa0;
					else if (fb == 0)
						return paint_affine_near_da_alpha_0_fb0;
					else
						return paint_affine_near_da_alpha_0;
				}
			}
		}
		break;

	case 1:
		if (sa)
		{
#if FZ_PLOTTERS_G
			if (da)
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_da_sa_1_fa0;
					else if (fb == 0)
						return paint_affine_near_da_sa_1_fb0;
					else
						return paint_affine_near_da_sa_1;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_da_sa_alpha_1_fa0;
					else if (fb == 0)
						return paint_affine_near_da_sa_alpha_1_fb0;
					else
						return paint_affine_near_da_sa_alpha_1;
				}
			}
			else
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_sa_1_fa0;
					else if (fb == 0)
						return paint_affine_near_sa_1_fb0;
					else
						return paint_affine_near_sa_1;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_sa_alpha_1_fa0;
					else if (fb == 0)
						return paint_affine_near_sa_alpha_1_fb0;
					else
						return paint_affine_near_sa_alpha_1;
				}
			}
#else
			goto fallback;
#endif /* FZ_PLOTTERS_G */
		}
		else
		{
			if (da)
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_da_1_fa0;
					else if (fb == 0)
						return paint_affine_near_da_1_fb0;
					else
						return paint_affine_near_da_1;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_da_alpha_1_fa0;
					else if (fb == 0)
						return paint_affine_near_da_alpha_1_fb0;
					else
						return paint_affine_near_da_alpha_1;
				}
			}
			else
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_1_fa0;
					else if (fb == 0)
						return paint_affine_near_1_fb0;
					else
						return paint_affine_near_1;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_alpha_1_fa0;
					else if (fb == 0)
						return paint_affine_near_alpha_1_fb0;
					else
						return paint_affine_near_alpha_1;
				}
			}
		}
		break;

#if FZ_PLOTTERS_RGB
	case 3:
		if (da)
		{
			if (sa)
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_da_sa_3_fa0;
					else if (fb == 0)
						return paint_affine_near_da_sa_3_fb0;
					else
						return paint_affine_near_da_sa_3;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_da_sa_alpha_3_fa0;
					else if (fb == 0)
						return paint_affine_near_da_sa_alpha_3_fb0;
					else
						return paint_affine_near_da_sa_alpha_3;
				}
			}
			else
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_da_3_fa0;
					else if (fb == 0)
						return paint_affine_near_da_3_fb0;
					else
						return paint_affine_near_da_3;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_da_alpha_3_fa0;
					else if (fb == 0)
						return paint_affine_near_da_alpha_3_fb0;
					else
						return paint_affine_near_da_alpha_3;
				}
			}
		}
		else
		{
			if (sa)
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_sa_3_fa0;
					else if (fb == 0)
						return paint_affine_near_sa_3_fb0;
					else
						return paint_affine_near_sa_3;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_sa_alpha_3_fa0;
					else if (fb == 0)
						return paint_affine_near_sa_alpha_3_fb0;
					else
						return paint_affine_near_sa_alpha_3;
				}
			}
			else
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_3_fa0;
					else if (fb == 0)
						return paint_affine_near_3_fb0;
					else
						return paint_affine_near_3;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_alpha_3_fa0;
					else if (fb == 0)
						return paint_affine_near_alpha_3_fb0;
					else
						return paint_affine_near_alpha_3;
				}
			}
		}
		break;
#endif /* FZ_PLOTTERS_RGB */

#if FZ_PLOTTERS_CMYK
	case 4:
		if (da)
		{
			if (sa)
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_da_sa_4_fa0;
					else if (fb == 0)
						return paint_affine_near_da_sa_4_fb0;
					else
						return paint_affine_near_da_sa_4;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_da_sa_alpha_4_fa0;
					else if (fb == 0)
						return paint_affine_near_da_sa_alpha_4_fb0;
					else
						return paint_affine_near_da_sa_alpha_4;
				}
			}
			else
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_da_4_fa0;
					else if (fb == 0)
						return paint_affine_near_da_4_fb0;
					else
						return paint_affine_near_da_4;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_da_alpha_4_fa0;
					else if (fb == 0)
						return paint_affine_near_da_alpha_4_fb0;
					else
						return paint_affine_near_da_alpha_4;
				}
			}
		}
		else
		{
			if (sa)
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_sa_4_fa0;
					else if (fb == 0)
						return paint_affine_near_sa_4_fb0;
					else
						return paint_affine_near_sa_4;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_sa_alpha_4_fa0;
					else if (fb == 0)
						return paint_affine_near_sa_alpha_4_fb0;
					else
						return paint_affine_near_sa_alpha_4;
				}
			}
			else
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_4_fa0;
					else if (fb == 0)
						return paint_affine_near_4_fb0;
					else
						return paint_affine_near_4;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_alpha_4_fa0;
					else if (fb == 0)
						return paint_affine_near_alpha_4_fb0;
					else
						return paint_affine_near_alpha_4;
				}
			}
		}
		break;
#endif /* FZ_PLOTTERS_CMYK */

#if !FZ_PLOTTERS_G
fallback:
#endif /* FZ_PLOTTERS_G */
	default:
#if FZ_PLOTTERS_N
		if (da)
		{
			if (sa)
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_da_sa_N_fa0;
					else if (fb == 0)
						return paint_affine_near_da_sa_N_fb0;
					else
						return paint_affine_near_da_sa_N;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_da_sa_alpha_N_fa0;
					else if (fb == 0)
						return paint_affine_near_da_sa_alpha_N_fb0;
					else
						return paint_affine_near_da_sa_alpha_N;
				}
			}
			else
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_da_N_fa0;
					else if (fb == 0)
						return paint_affine_near_da_N_fb0;
					else
						return paint_affine_near_da_N;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_da_alpha_N_fa0;
					else if (fb == 0)
						return paint_affine_near_da_alpha_N_fb0;
					else
						return paint_affine_near_da_alpha_N;
				}
			}
		}
		else
		{
			if (sa)
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_sa_N_fa0;
					else if (fb == 0)
						return paint_affine_near_sa_N_fb0;
					else
						return paint_affine_near_sa_N;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_sa_alpha_N_fa0;
					else if (fb == 0)
						return paint_affine_near_sa_alpha_N_fb0;
					else
						return paint_affine_near_sa_alpha_N;
				}
			}
			else
			{
				if (alpha == 255)
				{
					if (fa == 0)
						return paint_affine_near_N_fa0;
					else if (fb == 0)
						return paint_affine_near_N_fb0;
					else
						return paint_affine_near_N;
				}
				else if (alpha > 0)
				{
					if (fa == 0)
						return paint_affine_near_alpha_N_fa0;
					else if (fb == 0)
						return paint_affine_near_alpha_N_fb0;
					else
						return paint_affine_near_alpha_N;
				}
			}
		}
#endif /* FZ_PLOTTERS_N */
		break;
	}
	return NULL;
}

#if FZ_PLOTTERS_RGB
static void
paint_affine_near_da_sa_g2rgb_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_da_sa_alpha_g2rgb_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near_fa0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_da_g2rgb_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_da_alpha_g2rgb_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near_fa0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_sa_g2rgb_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near_fa0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_sa_alpha_g2rgb_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near_fa0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_g2rgb_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near_fa0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_alpha_g2rgb_fa0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near_fa0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_da_sa_g2rgb_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_da_sa_alpha_g2rgb_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near_fb0(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_da_g2rgb_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_da_alpha_g2rgb_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near_fb0(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_sa_g2rgb_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near_fb0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_sa_alpha_g2rgb_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near_fb0(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_g2rgb_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near_fb0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_alpha_g2rgb_fb0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near_fb0(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_da_sa_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_da_sa_alpha_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near(dp, 1, sp, sw, sh, ss, 1, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_da_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_da_alpha_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near(dp, 1, sp, sw, sh, ss, 0, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_sa_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_sa_alpha_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near(dp, 0, sp, sw, sh, ss, 1, u, v, fa, fb, w, alpha, hp);
}

static void
paint_affine_near_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_solid_g2rgb_near(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, hp);
}

static void
paint_affine_near_alpha_g2rgb(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n1, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_alpha_g2rgb_near(dp, 0, sp, sw, sh, ss, 0, u, v, fa, fb, w, alpha, hp);
}

static paintfn_t *
fz_paint_affine_g2rgb_near(int da, int sa, int fa, int fb, int n, int alpha)
{
	if (da)
	{
		if (sa)
		{
			if (fa == 0)
			{
				if (alpha == 255)
					return paint_affine_near_da_sa_g2rgb_fa0;
				else if (alpha > 0)
					return paint_affine_near_da_sa_alpha_g2rgb_fa0;
			}
			else if (fb == 0)
			{
				if (alpha == 255)
					return paint_affine_near_da_sa_g2rgb_fb0;
				else if (alpha > 0)
					return paint_affine_near_da_sa_alpha_g2rgb_fb0;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_near_da_sa_g2rgb;
				else if (alpha > 0)
					return paint_affine_near_da_sa_alpha_g2rgb;
			}
		}
		else
		{
			if (fa == 0)
			{
				if (alpha == 255)
					return paint_affine_near_da_g2rgb_fa0;
				else if (alpha > 0)
					return paint_affine_near_da_alpha_g2rgb_fa0;
			}
			else if (fb == 0)
			{
				if (alpha == 255)
					return paint_affine_near_da_g2rgb_fb0;
				else if (alpha > 0)
					return paint_affine_near_da_alpha_g2rgb_fb0;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_near_da_g2rgb;
				else if (alpha > 0)
					return paint_affine_near_da_alpha_g2rgb;
			}
		}
	}
	else
	{
		if (sa)
		{
			if (fa == 0)
			{
				if (alpha == 255)
					return paint_affine_near_sa_g2rgb_fa0;
				else if (alpha > 0)
					return paint_affine_near_sa_alpha_g2rgb_fa0;
			}
			else if (fb == 0)
			{
				if (alpha == 255)
					return paint_affine_near_sa_g2rgb_fb0;
				else if (alpha > 0)
					return paint_affine_near_sa_alpha_g2rgb_fb0;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_near_sa_g2rgb;
				else if (alpha > 0)
					return paint_affine_near_sa_alpha_g2rgb;
			}
		}
		else
		{
			if (fa == 0)
			{
				if (alpha == 255)
					return paint_affine_near_g2rgb_fa0;
				else if (alpha > 0)
					return paint_affine_near_alpha_g2rgb_fa0;
			}
			else if (fb == 0)
			{
				if (alpha == 255)
					return paint_affine_near_g2rgb_fb0;
				else if (alpha > 0)
					return paint_affine_near_alpha_g2rgb_fb0;
			}
			else
			{
				if (alpha == 255)
					return paint_affine_near_g2rgb;
				else if (alpha > 0)
					return paint_affine_near_alpha_g2rgb;
			}
		}
	}
	return NULL;
}
#endif /* FZ_PLOTTERS_RGB */

static void
paint_affine_color_lerp_da_0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_lerp(dp, 1, sp, sw, sh, ss, u, v, fa, fb, w, 0, color, hp);
}

#if FZ_PLOTTERS_G
static void
paint_affine_color_lerp_da_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_lerp(dp, 1, sp, sw, sh, ss, u, v, fa, fb, w, 1, color, hp);
}

static void
paint_affine_color_lerp_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_lerp(dp, 0, sp, sw, sh, ss, u, v, fa, fb, w, 1, color, hp);
}
#endif /* FZ_PLOTTERS_G */

#if FZ_PLOTTERS_RGB
static void
paint_affine_color_lerp_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_lerp(dp, 0, sp, sw, sh, ss, u, v, fa, fb, w, 3, color, hp);
}

static void
paint_affine_color_lerp_da_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_lerp(dp, 1, sp, sw, sh, ss, u, v, fa, fb, w, 3, color, hp);
}
#endif /* FZ_PLOTTERS_RGB */

#if FZ_PLOTTERS_CMYK
static void
paint_affine_color_lerp_da_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_lerp(dp, 1, sp, sw, sh, ss, u, v, fa, fb, w, 4, color, hp);
}

static void
paint_affine_color_lerp_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_lerp(dp, 0, sp, sw, sh, ss, u, v, fa, fb, w, 4, color, hp);
}
#endif /* FZ_PLOTTERS_G */

#if FZ_PLOTTERS_N
static void
paint_affine_color_lerp_da_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_lerp(dp, 1, sp, sw, sh, ss, u, v, fa, fb, w, n, color, hp);
}

static void
paint_affine_color_lerp_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_lerp(dp, 0, sp, sw, sh, ss, u, v, fa, fb, w, n, color, hp);
}
#endif /* FZ_PLOTTERS_CMYK */

static paintfn_t *
fz_paint_affine_color_lerp(int da, int sa, int fa, int fb, int n, int alpha)
{
	switch (n)
	{
	case 0: return da ? paint_affine_color_lerp_da_0 : NULL;
#if FZ_PLOTTERS_G
	case 1: return da ? paint_affine_color_lerp_da_1 : paint_affine_color_lerp_1;
#endif /* FZ_PLOTTERS_G */
#if FZ_PLOTTERS_RGB
	case 3: return da ? paint_affine_color_lerp_da_3 : paint_affine_color_lerp_3;
#endif /* FZ_PLOTTERS_RGB */
#if FZ_PLOTTERS_CMYK
	case 4: return da ? paint_affine_color_lerp_da_4 : paint_affine_color_lerp_4;
#endif /* FZ_PLOTTERS_CMYK */
#if FZ_PLOTTERS_N
	default: return da ? paint_affine_color_lerp_da_N : paint_affine_color_lerp_N;
#endif /* FZ_PLOTTERS_N */
	}
	return NULL;
}

static void
paint_affine_color_near_da_0(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_near(dp, 1, sp, sw, sh, ss, u, v, fa, fb, w, 0, color, hp);
}

#if FZ_PLOTTERS_G
static void
paint_affine_color_near_da_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_near(dp, 1, sp, sw, sh, ss, u, v, fa, fb, w, 1, color, hp);
}

static void
paint_affine_color_near_1(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_near(dp, 0, sp, sw, sh, ss, u, v, fa, fb, w, 1, color, hp);
}
#endif /* FZ_PLOTTERS_G */

#if FZ_PLOTTERS_RGB
static void
paint_affine_color_near_da_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_near(dp, 1, sp, sw, sh, ss, u, v, fa, fb, w, 3, color, hp);
}

static void
paint_affine_color_near_3(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_near(dp, 0, sp, sw, sh, ss, u, v, fa, fb, w, 3, color, hp);
}
#endif /* FZ_PLOTTERS_RGB */

#if FZ_PLOTTERS_CMYK
static void
paint_affine_color_near_da_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_near(dp, 1, sp, sw, sh, ss, u, v, fa, fb, w, 4, color, hp);
}

static void
paint_affine_color_near_4(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_near(dp, 0, sp, sw, sh, ss, u, v, fa, fb, w, 4, color, hp);
}
#endif /* FZ_PLOTTERS_CMYK */

#if FZ_PLOTTERS_N
static void
paint_affine_color_near_da_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_near(dp, 1, sp, sw, sh, ss, u, v, fa, fb, w, n, color, hp);
}

static void
paint_affine_color_near_N(byte * restrict dp, int da, const byte * restrict sp, int sw, int sh, int ss, int sa, int u, int v, int fa, int fb, int w, int n, int alpha, const byte * restrict color, byte * restrict hp)
{
	TRACK_FN();
	template_affine_color_N_near(dp, 0, sp, sw, sh, ss, u, v, fa, fb, w, n, color, hp);
}
#endif /* FZ_PLOTTERS_N */

static paintfn_t *
fz_paint_affine_color_near(int da, int sa, int fa, int fb, int n, int alpha)
{
	switch (n)
	{
	case 0: return da ? paint_affine_color_near_da_0 : NULL;
#if FZ_PLOTTERS_G
	case 1: return da ? paint_affine_color_near_da_1 : paint_affine_color_near_1;
#endif /* FZ_PLOTTERS_G */
#if FZ_PLOTTERS_RGB
	case 3: return da ? paint_affine_color_near_da_3 : paint_affine_color_near_3;
#endif /* FZ_PLOTTERS_RGB */
#if FZ_PLOTTERS_CMYK
	case 4: return da ? paint_affine_color_near_da_4 : paint_affine_color_near_4;
#endif /* FZ_PLOTTERS_CMYK */
#if FZ_PLOTTERS_N
	default: return da ? paint_affine_color_near_da_N : paint_affine_color_near_N;
#else
	default: return NULL;
#endif /* FZ_PLOTTERS_N */
	}
}

/* RJW: The following code was originally written to be sensitive to
 * FLT_EPSILON. Given the way the 'minimum representable difference'
 * between 2 floats changes size as we scale, we now pick a larger
 * value to ensure idempotency even with rounding problems. The
 * value we pick is still far smaller than would ever show up with
 * antialiasing.
 */
#define MY_EPSILON 0.001

/* We have 2 possible ways of gridfitting images. The first way, considered
 * 'safe' in all cases, is to expand an image out to fill a box that entirely
 * covers all the pixels touched by the current image. This is our 'standard'
 * mechanism.
 * The alternative, used when we know images are tiled across a page, is to
 * round the edge of each image to the closest integer pixel boundary. This
 * would not be safe in the general case, but gives less distortion across
 * neighbouring images when tiling is used. We use this for .gproof files.
 */
void
fz_gridfit_matrix(int as_tiled, fz_matrix *m)
{
	if (fabsf(m->b) < FLT_EPSILON && fabsf(m->c) < FLT_EPSILON)
	{
		if (as_tiled)
		{
			float f;
			/* Nearest boundary for left */
			f = (float)(int)(m->e + 0.5);
			m->a += m->e - f; /* Adjust width for change */
			m->e = f;
			/* Nearest boundary for right (width really) */
			m->a = (float)(int)(m->a + 0.5);
		}
		else if (m->a > 0)
		{
			float f;
			/* Adjust left hand side onto pixel boundary */
			f = (float)(int)(m->e);
			if (f - m->e > MY_EPSILON)
				f -= 1.0; /* Ensure it moves left */
			m->a += m->e - f; /* width gets wider as f <= m.e */
			m->e = f;
			/* Adjust right hand side onto pixel boundary */
			f = (float)(int)(m->a);
			if (m->a - f > MY_EPSILON)
				f += 1.0; /* Ensure it moves right */
			m->a = f;
		}
		else if (m->a < 0)
		{
			float f;
			/* Adjust right hand side onto pixel boundary */
			f = (float)(int)(m->e);
			if (m->e - f > MY_EPSILON)
				f += 1.0; /* Ensure it moves right */
			m->a += m->e - f; /* width gets wider (more -ve) */
			m->e = f;
			/* Adjust left hand side onto pixel boundary */
			f = (float)(int)(m->a);
			if (f - m->a > MY_EPSILON)
				f -= 1.0; /* Ensure it moves left */
			m->a = f;
		}
		if (as_tiled)
		{
			float f;
			/* Nearest boundary for top */
			f = (float)(int)(m->f + 0.5);
			m->d += m->f - f; /* Adjust width for change */
			m->f = f;
			/* Nearest boundary for bottom (height really) */
			m->d = (float)(int)(m->d + 0.5);
		}
		else if (m->d > 0)
		{
			float f;
			/* Adjust top onto pixel boundary */
			f = (float)(int)(m->f);
			if (f - m->f > MY_EPSILON)
				f -= 1.0; /* Ensure it moves upwards */
			m->d += m->f - f; /* width gets wider as f <= m.f */
			m->f = f;
			/* Adjust bottom onto pixel boundary */
			f = (float)(int)(m->d);
			if (m->d - f > MY_EPSILON)
				f += 1.0; /* Ensure it moves down */
			m->d = f;
		}
		else if (m->d < 0)
		{
			float f;
			/* Adjust bottom onto pixel boundary */
			f = (float)(int)(m->f);
			if (m->f - f > MY_EPSILON)
				f += 1.0; /* Ensure it moves down */
			m->d += m->f - f; /* width gets wider (more -ve) */
			m->f = f;
			/* Adjust top onto pixel boundary */
			f = (float)(int)(m->d);
			if (f - m->d > MY_EPSILON)
				f -= 1.0; /* Ensure it moves up */
			m->d = f;
		}
	}
	else if (fabsf(m->a) < FLT_EPSILON && fabsf(m->d) < FLT_EPSILON)
	{
		if (as_tiled)
		{
			float f;
			/* Nearest boundary for left */
			f = (float)(int)(m->e + 0.5);
			m->b += m->e - f; /* Adjust width for change */
			m->e = f;
			/* Nearest boundary for right (width really) */
			m->b = (float)(int)(m->b + 0.5);
		}
		else if (m->b > 0)
		{
			float f;
			/* Adjust left hand side onto pixel boundary */
			f = (float)(int)(m->f);
			if (f - m->f > MY_EPSILON)
				f -= 1.0; /* Ensure it moves left */
			m->b += m->f - f; /* width gets wider as f <= m.f */
			m->f = f;
			/* Adjust right hand side onto pixel boundary */
			f = (float)(int)(m->b);
			if (m->b - f > MY_EPSILON)
				f += 1.0; /* Ensure it moves right */
			m->b = f;
		}
		else if (m->b < 0)
		{
			float f;
			/* Adjust right hand side onto pixel boundary */
			f = (float)(int)(m->f);
			if (m->f - f > MY_EPSILON)
				f += 1.0; /* Ensure it moves right */
			m->b += m->f - f; /* width gets wider (more -ve) */
			m->f = f;
			/* Adjust left hand side onto pixel boundary */
			f = (float)(int)(m->b);
			if (f - m->b > MY_EPSILON)
				f -= 1.0; /* Ensure it moves left */
			m->b = f;
		}
		if (as_tiled)
		{
			float f;
			/* Nearest boundary for left */
			f = (float)(int)(m->f + 0.5);
			m->c += m->f - f; /* Adjust width for change */
			m->f = f;
			/* Nearest boundary for right (width really) */
			m->c = (float)(int)(m->c + 0.5);
		}
		else if (m->c > 0)
		{
			float f;
			/* Adjust top onto pixel boundary */
			f = (float)(int)(m->e);
			if (f - m->e > MY_EPSILON)
				f -= 1.0; /* Ensure it moves upwards */
			m->c += m->e - f; /* width gets wider as f <= m.e */
			m->e = f;
			/* Adjust bottom onto pixel boundary */
			f = (float)(int)(m->c);
			if (m->c - f > MY_EPSILON)
				f += 1.0; /* Ensure it moves down */
			m->c = f;
		}
		else if (m->c < 0)
		{
			float f;
			/* Adjust bottom onto pixel boundary */
			f = (float)(int)(m->e);
			if (m->e - f > MY_EPSILON)
				f += 1.0; /* Ensure it moves down */
			m->c += m->e - f; /* width gets wider (more -ve) */
			m->e = f;
			/* Adjust top onto pixel boundary */
			f = (float)(int)(m->c);
			if (f - m->c > MY_EPSILON)
				f -= 1.0; /* Ensure it moves up */
			m->c = f;
		}
	}
}

/* Draw an image with an affine transform on destination */

static void
fz_paint_image_imp(fz_pixmap * restrict dst, const fz_irect *scissor, const fz_pixmap * restrict shape, const fz_pixmap * restrict img, const fz_matrix * restrict ctm, const byte * restrict color, int alpha, int lerp_allowed, int as_tiled)
{
	byte *dp, *sp, *hp;
	int u, v, fa, fb, fc, fd;
	int x, y, w, h;
	int sw, sh, ss, sa, n, hs, da;
	fz_irect bbox;
	int dolerp;
	paintfn_t *paintfn;
	fz_matrix local_ctm = *ctm;
	fz_rect rect;
	int is_rectilinear;

	/* grid fit the image */
	fz_gridfit_matrix(as_tiled, &local_ctm);

	/* turn on interpolation for upscaled and non-rectilinear transforms */
	dolerp = 0;
	is_rectilinear = fz_is_rectilinear(&local_ctm);
	if (!is_rectilinear)
		dolerp = lerp_allowed;
	if (sqrtf(local_ctm.a * local_ctm.a + local_ctm.b * local_ctm.b) > img->w)
		dolerp = lerp_allowed;
	if (sqrtf(local_ctm.c * local_ctm.c + local_ctm.d * local_ctm.d) > img->h)
		dolerp = lerp_allowed;

	/* except when we shouldn't, at large magnifications */
	if (!img->interpolate)
	{
		if (sqrtf(local_ctm.a * local_ctm.a + local_ctm.b * local_ctm.b) > img->w * 2)
			dolerp = 0;
		if (sqrtf(local_ctm.c * local_ctm.c + local_ctm.d * local_ctm.d) > img->h * 2)
			dolerp = 0;
	}

	rect = fz_unit_rect;
	fz_irect_from_rect(&bbox, fz_transform_rect(&rect, &local_ctm));
	fz_intersect_irect(&bbox, scissor);

	x = bbox.x0;
	if (shape && shape->x > x)
		x = shape->x;
	y = bbox.y0;
	if (shape && shape->y > y)
		y = shape->y;
	w = bbox.x1;
	if (shape && shape->x + shape->w < w)
		w = shape->x + shape->w;
	w -= x;
	h = bbox.y1;
	if (shape && shape->y + shape->h < h)
		h = shape->y + shape->h;
	h -= y;
	if (w <= 0 || h <= 0)
		return;

	/* map from screen space (x,y) to image space (u,v) */
	fz_pre_scale(&local_ctm, 1.0f / img->w, 1.0f / img->h);
	fz_invert_matrix(&local_ctm, &local_ctm);

	fa = (int)(local_ctm.a *= 65536.0f);
	fb = (int)(local_ctm.b *= 65536.0f);
	fc = (int)(local_ctm.c *= 65536.0f);
	fd = (int)(local_ctm.d *= 65536.0f);
	local_ctm.e *= 65536.0f;
	local_ctm.f *= 65536.0f;

	/* Calculate initial texture positions. Do a half step to start. */
	/* Bug 693021: Keep calculation in float for as long as possible to
	 * avoid overflow. */
	u = (int)((local_ctm.a * x) + (local_ctm.c * y) + local_ctm.e + ((local_ctm.a + local_ctm.c) * .5f));
	v = (int)((local_ctm.b * x) + (local_ctm.d * y) + local_ctm.f + ((local_ctm.b + local_ctm.d) * .5f));

	dp = dst->samples + (unsigned int)((y - dst->y) * dst->stride + (x - dst->x) * dst->n);
	da = dst->alpha;
	n = dst->n - da;
	sp = img->samples;
	sw = img->w;
	sh = img->h;
	ss = img->stride;
	sa = img->alpha;
	if (shape)
	{
		hs = shape->stride;
		hp = shape->samples + (unsigned int)((y - shape->y) * shape->stride + x - shape->x);
	}
	else
	{
		hs = 0;
		hp = NULL;
	}

	/* TODO: if (fb == 0 && fa == 1) call fz_paint_span */

	/* Sometimes we can get an alpha only input to be
	 * plotted. In this case treat it as a greyscale
	 * input. */
	if (img->n == sa && color)
		sa = 0;

#if FZ_PLOTTERS_RGB
	if (n == 3 && img->n == 1 + sa && !color)
	{
		if (dolerp)
			paintfn = fz_paint_affine_g2rgb_lerp(da, sa, fa, fb, n, alpha);
		else
			paintfn = fz_paint_affine_g2rgb_near(da, sa, fa, fb, n, alpha);
	}
	else
#endif /* FZ_PLOTTERS_RGB */
	{
		assert((!color && img->n - sa == n) || (color && img->n - sa == 1));
		if (dolerp)
		{
			if (color)
				paintfn = fz_paint_affine_color_lerp(da, sa, fa, fb, n, alpha);
			else
				paintfn = fz_paint_affine_lerp(da, sa, fa, fb, n, alpha);
		}
		else
		{
			if (color)
				paintfn = fz_paint_affine_color_near(da, sa, fa, fb, n, alpha);
			else
				paintfn = fz_paint_affine_near(da, sa, fa, fb, n, alpha);
		}
	}

	assert(paintfn);
	if (paintfn == NULL)
		return;

	if (dolerp)
	{
		u -= 32768;
		v -= 32768;
		sw = (sw<<16) + 32768;
		sh = (sh<<16) + 32768;
	}

	while (h--)
	{
		paintfn(dp, da, sp, sw, sh, ss, sa, u, v, fa, fb, w, n, alpha, color, hp);
		dp += dst->stride;
		hp += hs;
		u += fc;
		v += fd;
	}
}

void
fz_paint_image_with_color(fz_pixmap * restrict dst, const fz_irect * restrict scissor, fz_pixmap * restrict shape, const fz_pixmap * restrict img, const fz_matrix * restrict ctm, const byte * restrict color, int lerp_allowed, int as_tiled)
{
	assert(img->n == 1);
	fz_paint_image_imp(dst, scissor, shape, img, ctm, color, 255, lerp_allowed, as_tiled);
}

void
fz_paint_image(fz_pixmap * restrict dst, const fz_irect * restrict scissor, fz_pixmap * restrict shape, const fz_pixmap * restrict img, const fz_matrix * restrict ctm, int alpha, int lerp_allowed, int as_tiled)
{
	assert(dst->n - dst->alpha == img->n - img->alpha|| (dst->n == 3 + dst->alpha && img->n == 1 + img->alpha));
	fz_paint_image_imp(dst, scissor, shape, img, ctm, NULL, alpha, lerp_allowed, as_tiled);
}
