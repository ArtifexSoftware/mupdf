#include "mupdf/fitz.h"
#include "draw-imp.h"

/*

The functions in this file implement various flavours of Porter-Duff blending.

We take the following as definitions:

	Cx = Color (from plane x)
	ax = Alpha (from plane x)
	cx = Cx.ax = Premultiplied color (from plane x)

The general PorterDuff blending equation is:

	Blend Z = X op Y	cz = Fx.cx + Fy. cy	where Fx and Fy depend on op

The two operations we use in this file are: '(X in Y) over Z' and
'S over Z'. The definitions of the 'over' and 'in' operations are as
follows:

	For S over Z,	Fs = 1, Fz = 1-as
	For X in Y,	Fx = ay, Fy = 0

We have 2 choices; we can either work with premultiplied data, or non
premultiplied data. Our

First the premultiplied case:

	Let S = (X in Y)
	Let R = (X in Y) over Z = S over Z

	cs	= cx.Fx + cy.Fy	(where Fx = ay, Fy = 0)
		= cx.ay
	as	= ax.Fx + ay.Fy
		= ax.ay

	cr	= cs.Fs + cz.Fz	(where Fs = 1, Fz = 1-as)
		= cs + cz.(1-as)
		= cx.ay + cz.(1-ax.ay)
	ar	= as.Fs + az.Fz
		= as + az.(1-as)
		= ax.ay + az.(1-ax.ay)

This has various nice properties, like not needing any divisions, and
being symmetric in color and alpha, so this is what we use. Because we
went through the pain of deriving the non premultiplied forms, we list
them here too, though they are not used.

Non Pre-multiplied case:

	Cs.as	= Fx.Cx.ax + Fy.Cy.ay	(where Fx = ay, Fy = 0)
		= Cx.ay.ax
	Cs	= (Cx.ay.ax)/(ay.ax)
		= Cx
	Cr.ar	= Fs.Cs.as + Fz.Cz.az	(where Fs = 1, Fz = 1-as)
		= Cs.as	+ (1-as).Cz.az
		= Cx.ax.ay + Cz.az.(1-ax.ay)
	Cr	= (Cx.ax.ay + Cz.az.(1-ax.ay))/(ax.ay + az.(1-ax-ay))

Much more complex, it seems. However, if we could restrict ourselves to
the case where we were always plotting onto an opaque background (i.e.
az = 1), then:

	Cr	= Cx.(ax.ay) + Cz.(1-ax.ay)
		= (Cx-Cz)*(1-ax.ay) + Cz	(a single MLA operation)
	ar	= 1

Sadly, this is not true in the general case, so we abandon this effort
and stick to using the premultiplied form.

*/

typedef unsigned char byte;

/* These are used by the non-aa scan converter */

static inline void
fz_paint_solid_color_2_da(byte * restrict dp, int w, const byte * restrict color)
{
	int sa = FZ_EXPAND(color[1]);
	if (sa == 0)
		return;
	if (sa == 256)
	{
		while (w--)
		{
			dp[0] = color[0];
			dp[1] = 255;
			dp += 2;
		}
	}
	else
	{
		while (w--)
		{
			dp[0] = FZ_BLEND(color[0], dp[0], sa);
			dp[1] = FZ_BLEND(255, dp[1], sa);
			dp += 2;
		}
	}
}

static inline int isbigendian(void)
{
	union { int i; char c[sizeof(int)]; } u = {1};
	return u.c[0] != 1;
}

static inline void
fz_paint_solid_color_4_da(byte * restrict dp, int w, const byte * restrict color)
{
	unsigned int rgba = *(int *)color;
	int sa = FZ_EXPAND(color[3]);
	if (sa == 0)
		return;
	if (isbigendian())
		rgba |= 0x000000FF;
	else
		rgba |= 0xFF000000;
	if (sa == 256)
	{
		while (w--)
		{
			*(unsigned int *)dp = rgba;
			dp += 4;
		}
	}
	else
	{
		unsigned int mask = 0xFF00FF00;
		unsigned int rb = rgba & (mask>>8);
		unsigned int ga = (rgba & mask)>>8;
		while (w--)
		{
			unsigned int RGBA = *(unsigned int *)dp;
			unsigned int RB = (RGBA<<8) & mask;
			unsigned int GA = RGBA & mask;
			RB += (rb-(RB>>8))*sa;
			GA += (ga-(GA>>8))*sa;
			RB &= mask;
			GA &= mask;
			*(unsigned int *)dp = (RB>>8) | GA;
			dp += 4;
		}
	}
}

static inline void
fz_paint_solid_color_5_da(byte * restrict dp, int w, const byte * restrict color)
{
	int sa = FZ_EXPAND(color[4]);
	if (sa == 0)
		return;
	if (sa == 256)
	{
#ifdef ARCH_UNALIGNED_OK
		if (w > 4)
		{
			if (isbigendian())
			{
				const uint32_t a = *(uint32_t*)color;
				const uint32_t b = 0xFF000000|(a>>8);
				const uint32_t c = 0x00FF0000|(a>>16)|(a<<24);
				const uint32_t d = 0x0000FF00|(a>>24)|(a<<16);
				const uint32_t e = 0x000000FF|(a<<8);
				w -= 3;
				do
				{
					((uint32_t *)(void *)dp)[0] = a;
					((uint32_t *)(void *)dp)[1] = b;
					((uint32_t *)(void *)dp)[2] = c;
					((uint32_t *)(void *)dp)[3] = d;
					((uint32_t *)(void *)dp)[4] = e;
					dp += 20;
					w -= 4;
				}
				while (w > 0);
			}
			else
			{
				const uint32_t a = *(uint32_t*)color;
				const uint32_t b = 0x000000FF|(a<<8);
				const uint32_t c = 0x0000FF00|(a<<16)|(a>>24);
				const uint32_t d = 0x00FF0000|(a<<24)|(a>>16);
				const uint32_t e = 0xFF000000|(a>>8);
				w -= 3;
				do
				{
					((uint32_t *)(void *)dp)[0] = a;
					((uint32_t *)(void *)dp)[1] = b;
					((uint32_t *)(void *)dp)[2] = c;
					((uint32_t *)(void *)dp)[3] = d;
					((uint32_t *)(void *)dp)[4] = e;
					dp += 20;
					w -= 4;
				}
				while (w > 0);
			}
			w += 3;
		}
#endif
		while (w--)
		{
			dp[0] = color[0];
			dp[1] = color[1];
			dp[2] = color[2];
			dp[3] = color[3];
			dp[4] = 255;
			dp += 5;
		}
	}
	else
	{
		while (w--)
		{
			dp[0] = FZ_BLEND(color[0], dp[0], sa);
			dp[1] = FZ_BLEND(color[1], dp[1], sa);
			dp[2] = FZ_BLEND(color[2], dp[2], sa);
			dp[3] = FZ_BLEND(color[3], dp[3], sa);
			dp[4] = FZ_BLEND(255, dp[5], sa);
			dp += 5;
		}
	}
}

static inline void
fz_paint_solid_color_N(byte * restrict dp, int n, int w, const byte * restrict color, int da)
{
	int k;
	int n1 = n - da;
	int sa = FZ_EXPAND(color[n1]);
	if (sa == 0)
		return;
	if (sa == 256)
	{
		while (w--)
		{
			for (k = 0; k < n1; k++)
				dp[k] = color[k];
			if (da)
				dp[k] = 255;
			dp += n;
		}
	}
	else
	{
		while (w--)
		{
			for (k = 0; k < n1; k++)
				dp[k] = FZ_BLEND(color[k], dp[k], sa);
			if (da)
				dp[k] = FZ_BLEND(255, dp[k], sa);
			dp += n;
		}
	}
}

void
fz_paint_solid_color(byte * restrict dp, int n, int w, const byte * restrict color, int da)
{
	if (da)
	{
		switch (n)
		{
		case 2: fz_paint_solid_color_2_da(dp, w, color); break;
		case 4: fz_paint_solid_color_4_da(dp, w, color); break;
		case 5: fz_paint_solid_color_5_da(dp, w, color); break;
		default: fz_paint_solid_color_N(dp, n, w, color, 1); break;
		}
	}
	else
	{
		switch (n)
		{
		case 1: fz_paint_solid_color_N(dp, 1, w, color, 0); break;
		case 3: fz_paint_solid_color_N(dp, 3, w, color, 0); break;
		case 4: fz_paint_solid_color_N(dp, 4, w, color, 0); break;
		default: fz_paint_solid_color_N(dp, n, w, color, 0); break;
		}
	}
}

/* Blend a non-premultiplied color in mask over destination */

static inline void
fz_paint_span_with_color_2_da(byte * restrict dp, const byte * restrict mp, int w, const byte * restrict color)
{
	int sa = FZ_EXPAND(color[1]);
	int g = color[0];
	if (sa == 256)
	{
		while (w--)
		{
			int ma = *mp++;
			ma = FZ_EXPAND(ma);
			if (ma == 0)
			{
			}
			else if (ma == 256)
			{
				dp[0] = g;
				dp[1] = 255;
			}
			else
			{
				dp[0] = FZ_BLEND(g, dp[0], ma);
				dp[1] = FZ_BLEND(255, dp[1], ma);
			}
			dp += 2;
		}
	}
	else
	{
		while (w--)
		{
			int ma = *mp++;
			ma = FZ_EXPAND(ma);
			if (ma == 0)
			{
			}
			else
			{
				ma = FZ_COMBINE(ma, sa);
				dp[0] = FZ_BLEND(g, dp[0], ma);
				dp[1] = FZ_BLEND(255, dp[1], ma);
			}
			dp += 2;
		}
	}
}

static inline void
fz_paint_span_with_color_4_da(byte * restrict dp, const byte * restrict mp, int w, const byte * restrict color)
{
	unsigned int rgba = *((const unsigned int *)color);
	unsigned int mask, rb, ga;
	int sa = FZ_EXPAND(color[3]);
	if (sa == 0)
		return;
	if (isbigendian())
		rgba |= 0x000000FF;
	else
		rgba |= 0xFF000000;
	mask = 0xFF00FF00;
	rb = rgba & (mask>>8);
	ga = (rgba & mask)>>8;
	if (sa == 256)
	{
		while (w--)
		{
			unsigned int ma = *mp++;
			dp += 4;
			ma = FZ_EXPAND(ma);
			if (ma == 0)
			{
			}
			else if (ma == 256)
			{
				((unsigned int *)dp)[-1] = rgba;
			}
			else
			{
				unsigned int RGBA = ((unsigned int *)dp)[-1];
				unsigned int RB = (RGBA<<8) & mask;
				unsigned int GA = RGBA & mask;
				RB += (rb-(RB>>8))*ma;
				GA += (ga-(GA>>8))*ma;
				RB &= mask;
				GA &= mask;
				((unsigned int *)dp)[-1] = (RB>>8) | GA;
			}
		}
	}
	else
	{
		while (w--)
		{
			unsigned int ma = *mp++;
			ma = FZ_COMBINE(FZ_EXPAND(ma), sa);
			dp += 4;
			if (ma != 0)
 			{
				unsigned int RGBA = ((unsigned int*)dp)[-1];
				unsigned int RB = (RGBA<<8) & mask;
				unsigned int GA = RGBA & mask;
				RB += (rb-(RB>>8))*ma;
				GA += (ga-(GA>>8))*ma;
				RB &= mask;
				GA &= mask;
				((unsigned int *)dp)[-1] = (RB>>8) | GA;
			}
		}
	}
}

static inline void
fz_paint_span_with_color_5_da(byte * restrict dp, const byte * restrict mp, int w, const byte * restrict color)
{
	int sa = FZ_EXPAND(color[4]);
	int c = color[0];
	int m = color[1];
	int y = color[2];
	int k = color[3];
	if (sa == 256)
	{
		while (w--)
		{
			int ma = *mp++;
			ma = FZ_EXPAND(ma);
			if (ma == 0)
			{
			}
			else if (ma == 256)
			{
				dp[0] = c;
				dp[1] = m;
				dp[2] = y;
				dp[3] = k;
				dp[4] = 255;
			}
			else
			{
				dp[0] = FZ_BLEND(c, dp[0], ma);
				dp[1] = FZ_BLEND(m, dp[1], ma);
				dp[2] = FZ_BLEND(y, dp[2], ma);
				dp[3] = FZ_BLEND(k, dp[3], ma);
				dp[4] = FZ_BLEND(255, dp[4], ma);
			}
			dp += 5;
		}
	}
	else
	{
		while (w--)
		{
			int ma = *mp++;
			ma = FZ_EXPAND(ma);
			if (ma == 0)
			{
			}
			else
			{
				ma = FZ_COMBINE(ma, sa);
				dp[0] = FZ_BLEND(c, dp[0], ma);
				dp[1] = FZ_BLEND(m, dp[1], ma);
				dp[2] = FZ_BLEND(y, dp[2], ma);
				dp[3] = FZ_BLEND(k, dp[3], ma);
				dp[4] = FZ_BLEND(255, dp[4], ma);
			}
			dp += 5;
		}
	}
}

static inline void
fz_paint_span_with_color_N(byte * restrict dp, const byte * restrict mp, int n, int w, const byte * restrict color, int da)
{
	int k;
	int n1 = n - da;
	int sa = FZ_EXPAND(color[n1]);
	if (sa == 0)
		return;
	if (sa == 256)
	{
		while (w--)
		{
			int ma = *mp++;
			ma = FZ_EXPAND(ma);
			if (ma == 0)
			{
			}
			else if (ma == 256)
			{
				for (k = 0; k < n1; k++)
					dp[k] = color[k];
				if (da)
					dp[k] = 255;
			}
			else
			{
				for (k = 0; k < n1; k++)
					dp[k] = FZ_BLEND(color[k], dp[k], ma);
				if (da)
					dp[k] = FZ_BLEND(255, dp[k], ma);
			}
			dp += n;
		}
	}
	else
	{
		while (w--)
		{
			int ma = *mp++;
			ma = FZ_COMBINE(FZ_EXPAND(ma), sa);
			for (k = 0; k < n1; k++)
				dp[k] = FZ_BLEND(color[k], dp[k], ma);
			if (da)
				dp[k] = FZ_BLEND(255, dp[k], ma);
			dp += n;
		}
	}
}

void
fz_paint_span_with_color(byte * restrict dp, const byte * restrict mp, int n, int w, const byte * restrict color, int da)
{
	if (da)
	{
		switch (n)
		{
		case 2: fz_paint_span_with_color_2_da(dp, mp, w, color); break;
		case 4: fz_paint_span_with_color_4_da(dp, mp, w, color); break;
		case 5: fz_paint_span_with_color_5_da(dp, mp, w, color); break;
		default: fz_paint_span_with_color_N(dp, mp, n, w, color, 1); break;
		}
	}
	else
	{
		switch (n)
		{
		case 1: fz_paint_span_with_color_N(dp, mp, 1, w, color, 0); break;
		case 3: fz_paint_span_with_color_N(dp, mp, 3, w, color, 0); break;
		case 4: fz_paint_span_with_color_N(dp, mp, 4, w, color, 0); break;
		default: fz_paint_span_with_color_N(dp, mp, n, w, color, 0); break;
		}
	}
}

/* Blend source in mask over destination */

/* FIXME: There is potential for SWAR optimisation here */
static inline void
fz_paint_span_with_mask_1(byte * restrict dp, int da, const byte * restrict sp, int sa, const byte * restrict mp, int w)
{
	while (w--)
	{
		int masa;
		int ma = *mp++;
		ma = FZ_EXPAND(ma);
		if (ma == 0)
		{
			dp += 1 + da;
			sp += 1 + sa;
		}
		else if (ma == 256)
		{
			masa = (sa ? 255 - sp[1] : 0);
			if (masa == 0)
			{
				*dp++ = *sp++;
				if (da)
					*dp++ = (sa ? *sp++ : 255);
			}
			else
			{
				masa = FZ_EXPAND(masa);
				*dp = *sp + FZ_COMBINE(*dp, masa);
				sp++; dp++;
				if (da)
				{
					*dp = (sa ? *sp : 255) + FZ_COMBINE(*dp, masa);
					dp++;
				}
				if (sa)
					sp++;
			}
		}
		else
		{
			if (sa)
			{
				masa = FZ_COMBINE(sp[1], ma);
				masa = 255 - masa;
				masa = FZ_EXPAND(masa);
				*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
				sp++; dp++;
				if (da)
				{
					*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
					dp++;
				}
				sp++;
			}
			else
			{
				*dp = FZ_BLEND(*sp, *dp, ma);
				sp++; dp++;
				if (da)
				{
					*dp = FZ_BLEND(255, *dp, ma);
					dp++;
				}
			}
		}
	}
}

/* FIXME: There is potential for SWAR optimisation here */
static inline void
fz_paint_span_with_mask_3(byte * restrict dp, int da, const byte * restrict sp, int sa, const byte * restrict mp, int w)
{
	while (w--)
	{
		int masa;
		int ma = *mp++;
		ma = FZ_EXPAND(ma);
		if (ma == 0)
		{
			dp += 3 + da;
			sp += 3 + sa;
		}
		else if (ma == 256)
		{
			masa = (sa ? 255 - sp[3] : 0);
			if (masa == 0)
			{
				if (da && sa)
				{
					*(int*)dp = *(int *)sp;
					sp += 4; dp += 4;
				}
				else
				{
					*dp++ = *sp++;
					*dp++ = *sp++;
					*dp++ = *sp++;
					if (da)
						*dp++ = (sa ? *sp : 255);
					if (sa)
						sp++;
				}
			}
			else
			{
				masa = FZ_EXPAND(masa);
				*dp = *sp + FZ_COMBINE(*dp, masa);
				sp++; dp++;
				*dp = *sp + FZ_COMBINE(*dp, masa);
				sp++; dp++;
				*dp = *sp + FZ_COMBINE(*dp, masa);
				sp++; dp++;
				if (da)
				{
					*dp = (sa ? *sp : 255) + FZ_COMBINE(*dp, masa);
					dp++;
				}
				if (sa)
					sp++;
			}
		}
		else
		{
			/* FIXME: There is potential for SWAR optimisation here */
			if (sa)
			{
				masa = FZ_COMBINE(sp[3], ma);
				masa = 255 - masa;
				masa = FZ_EXPAND(masa);
				*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
				sp++; dp++;
				*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
				sp++; dp++;
				*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
				sp++; dp++;
				if (da)
				{
					*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
					dp++;
				}
				sp++;
			}
			else
			{
				*dp = FZ_BLEND(*sp, *dp, ma);
				sp++; dp++;
				*dp = FZ_BLEND(*sp, *dp, ma);
				sp++; dp++;
				*dp = FZ_BLEND(*sp, *dp, ma);
				sp++; dp++;
				if (da)
				{
					*dp = FZ_BLEND(255, *dp, ma);
					dp++;
				}
			}
		}
	}
}

/* FIXME: There is potential for SWAR optimisation here */
static inline void
fz_paint_span_with_mask_4(byte * restrict dp, int da, const byte * restrict sp, int sa, const byte * restrict mp, int w)
{
	while (w--)
	{
		int masa;
		int ma = *mp++;
		ma = FZ_EXPAND(ma);
		if (ma == 0)
		{
			dp += 4 + da;
			sp += 4 + sa;
		}
		else if (ma == 256)
		{
			masa = (sa ? 255 - sp[4] : 0);
			if (masa == 0)
			{
				*dp++ = *sp++;
				*dp++ = *sp++;
				*dp++ = *sp++;
				*dp++ = *sp++;
				if (da)
					*dp++ = (sa ? *sp : 255);
				if (sa)
					sp++;
			}
			else
			{
				masa = FZ_EXPAND(masa);
				*dp = *sp + FZ_COMBINE(*dp, masa);
				sp++; dp++;
				*dp = *sp + FZ_COMBINE(*dp, masa);
				sp++; dp++;
				*dp = *sp + FZ_COMBINE(*dp, masa);
				sp++; dp++;
				*dp = *sp + FZ_COMBINE(*dp, masa);
				sp++; dp++;
				if (da)
				{
					*dp = (sa ? *sp : 255) + FZ_COMBINE(*dp, masa);
					dp++;
				}
				if (sa)
					sp++;
			}
		}
		else
		{
			if (sa)
			{
				masa = FZ_COMBINE(sp[4], ma);
				masa = 255 - masa;
				masa = FZ_EXPAND(masa);
				*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
				sp++; dp++;
				*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
				sp++; dp++;
				*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
				sp++; dp++;
				*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
				sp++; dp++;
				if (da)
				{
					*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
					dp++;
				}
				sp++;
			}
			else
			{
				*dp = FZ_BLEND(*sp, *dp, ma);
				sp++; dp++;
				*dp = FZ_BLEND(*sp, *dp, ma);
				sp++; dp++;
				*dp = FZ_BLEND(*sp, *dp, ma);
				sp++; dp++;
				*dp = FZ_BLEND(*sp, *dp, ma);
				sp++; dp++;
				if (da)
				{
					*dp = FZ_BLEND(255, *dp, ma);
					dp++;
				}
			}
		}
	}
}

static inline void
fz_paint_span_with_mask_N(byte * restrict dp, int da, const byte * restrict sp, int sa, const byte * restrict mp, int n, int w)
{
	while (w--)
	{
		int ma = *mp++;
		ma = FZ_EXPAND(ma);
		if (ma == 0)
		{
			dp += n + da;
			sp += n + sa;
		}
		else if (ma == 256)
		{
			int k = n;
			int masa = (sa ? 255 - sp[n] : 0);
			if (masa == 0)
			{
				while (k--)
				{
					*dp++ = *sp++;
				}
				if (da)
					*dp++ = (sa ? *sp : 255);
				if (sa)
					sp++;
			}
			else
			{
				masa = FZ_EXPAND(masa);
				while (k--)
				{
					*dp = *sp + FZ_COMBINE(*dp, masa);
					sp++; dp++;
				}
				if (da)
				{
					*dp = (sa ? *sp : 255) + FZ_COMBINE(*dp, masa);
					dp++;
				}
				if (sa)
					sp++;
			}
		}
		else
		{
			int k = n;
			if (sa)
			{
				int masa;
				masa = FZ_COMBINE(sp[n], ma);
				masa = 255-masa;
				masa = FZ_EXPAND(masa);
				while (k--)
				{
					*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
					sp++; dp++;
				}
				if (da)
				{
					*dp = FZ_COMBINE2(*sp, ma, *dp, masa);
					dp++;
				}
				sp++;
			}
			else
			{
				while (k--)
				{
					*dp = FZ_BLEND(*sp, *dp, ma);
					sp++; dp++;
				}
				if (da)
				{
					*dp = FZ_BLEND(255, *dp, ma);
					dp++;
				}
			}
		}
	}
}

static void
fz_paint_span_with_mask(byte * restrict dp, int da, const byte * restrict sp, int sa, const byte * restrict mp, int n, int w)
{
	if (da)
	{
		if (sa)
		{
			switch (n)
			{
			case 1: fz_paint_span_with_mask_1(dp, 1, sp, 1, mp, w); break;
			case 3: fz_paint_span_with_mask_3(dp, 1, sp, 1, mp, w); break;
			case 4: fz_paint_span_with_mask_4(dp, 1, sp, 1, mp, w); break;
			default: fz_paint_span_with_mask_N(dp, 1, sp, 1, mp, n, w); break;
			}
		}
		else
		{
			switch (n)
			{
			case 1: fz_paint_span_with_mask_1(dp, 1, sp, 0, mp, w); break;
			case 3: fz_paint_span_with_mask_3(dp, 1, sp, 0, mp, w); break;
			case 4: fz_paint_span_with_mask_4(dp, 1, sp, 0, mp, w); break;
			default: fz_paint_span_with_mask_N(dp, 1, sp, 0, mp, n, w); break;
			}
		}
	}
	else
	{
		if (sa)
		{
			switch (n)
			{
			case 1: fz_paint_span_with_mask_1(dp, 0, sp, 1, mp, w); break;
			case 3: fz_paint_span_with_mask_3(dp, 0, sp, 1, mp, w); break;
			case 4: fz_paint_span_with_mask_4(dp, 0, sp, 1, mp, w); break;
			default: fz_paint_span_with_mask_N(dp, 0, sp, 1, mp, n, w); break;
			}
		}
		else
		{
			switch (n)
			{
			case 1: fz_paint_span_with_mask_1(dp, 0, sp, 0, mp, w); break;
			case 3: fz_paint_span_with_mask_3(dp, 0, sp, 0, mp, w); break;
			case 4: fz_paint_span_with_mask_4(dp, 0, sp, 0, mp, w); break;
			default: fz_paint_span_with_mask_N(dp, 0, sp, 0, mp, n, w); break;
			}
		}
	}
}

/* Blend source in constant alpha over destination */

static inline void
fz_paint_span_1_with_alpha(byte * restrict dp, int da, const byte * restrict sp, int sa, int w, int alpha)
{
	if (sa)
		alpha = FZ_EXPAND(alpha);
	while (w--)
	{
		int masa = (sa ? FZ_COMBINE(sp[1], alpha) : alpha);
		*dp = FZ_BLEND(*sp, *dp, masa);
		dp++; sp++;
		if (da)
		{
			*dp = FZ_BLEND((sa ? *sp : 255), *dp, masa);
			dp++;
		}
		if (sa)
			 sp++;
	}
}

static inline void
fz_paint_span_3_with_alpha(byte * restrict dp, int da, const byte * restrict sp, int sa, int w, int alpha)
{
	if (sa)
		alpha = FZ_EXPAND(alpha);
	while (w--)
	{
		int masa = (sa ? FZ_COMBINE(sp[3], alpha) : alpha);
		*dp = FZ_BLEND(*sp, *dp, masa);
		sp++; dp++;
		*dp = FZ_BLEND(*sp, *dp, masa);
		sp++; dp++;
		*dp = FZ_BLEND(*sp, *dp, masa);
		sp++; dp++;
		if (da)
		{
			*dp = FZ_BLEND((sa ? *sp : 255), *dp, masa);
			dp++;
		}
		if (sa)
			sp++;
	}
}

static inline void
fz_paint_span_4_with_alpha(byte * restrict dp, int da, const byte * restrict sp, int sa, int w, int alpha)
{
	if (sa)
		alpha = FZ_EXPAND(alpha);
	while (w--)
	{
		int masa = (sa ? FZ_COMBINE(sp[4], alpha) : alpha);
		*dp = FZ_BLEND(*sp, *dp, masa);
		sp++; dp++;
		*dp = FZ_BLEND(*sp, *dp, masa);
		sp++; dp++;
		*dp = FZ_BLEND(*sp, *dp, masa);
		sp++; dp++;
		*dp = FZ_BLEND(*sp, *dp, masa);
		sp++; dp++;
		if (da)
		{
			*dp = FZ_BLEND((sa ? *sp : 255), *dp, masa);
			dp++;
		}
		if (sa)
			sp++;
	}
}

static inline void
fz_paint_span_N_with_alpha(byte * restrict dp, int da, const byte * restrict sp, int sa, int n1, int w, int alpha)
{
	if (sa)
		alpha = FZ_EXPAND(alpha);
	while (w--)
	{
		int masa = (sa ? FZ_COMBINE(sp[n1], alpha) : alpha);
		int k = n1;
		while (k--)
		{
			*dp = FZ_BLEND(*sp++, *dp, masa);
			dp++;
		}
		if (da)
		{
			*dp = FZ_BLEND((sa ? *sp : 255), *dp, masa);
			dp++;
		}
		if (sa)
			sp++;
	}
}

/* Blend source over destination */

static inline void
fz_paint_span_1_dasa(byte * restrict dp, const byte * restrict sp, int w)
{
	while (w--)
	{
		int t = FZ_EXPAND(255 - sp[0]);
		*dp = *sp++ + FZ_COMBINE(*dp, t);
		dp ++;
	}
}

static inline void
fz_paint_span_1(byte * restrict dp, int da, const byte * restrict sp, int sa, int w)
{
	while (w--)
	{
		int t = (sa ? FZ_EXPAND(sp[1]): 256);
		if (t == 0)
		{
			dp += 1 + da; sp += 1 + sa;
		}
		else
		{
			t = 256 - t;
			if (t == 0)
			{
				*dp++ = *sp++;
				if (da)
					*dp++ = (sa ? *sp : 255);
				if (sa)
					sp++;
			}
			else
			{
				*dp = *sp++ + FZ_COMBINE(*dp, t);
				dp++;
				if (da)
				{
					*dp = (sa ? *sp + FZ_COMBINE(*dp, t) : 255);
					dp++;
				}
				if (sa)
					sp++;
			}
		}
	}
}

static inline void
fz_paint_span_3(byte * restrict dp, int da, const byte * restrict sp, int sa, int w)
{
	while (w--)
	{
		int t = (sa ? FZ_EXPAND(sp[3]) : 256);
		if (t == 0)
		{
			dp += 3 + da; sp += 3 + sa;
		}
		else
		{
			t = 256 - t;
			if (t == 0)
			{
				if (da && sa)
					*(int *)dp = *(const int *)sp;
				else
				{
					dp[0] = sp[0];
					dp[1] = sp[1];
					dp[2] = sp[2];
					if (da)
						dp[3] = (sa ? sp[3] : 255);
				}
				dp += 3+da; sp += 3+sa;
			}
			else
			{
				*dp = *sp++ + FZ_COMBINE(*dp, t);
				dp++;
				*dp = *sp++ + FZ_COMBINE(*dp, t);
				dp++;
				*dp = *sp++ + FZ_COMBINE(*dp, t);
				dp++;
				if (da)
				{
					*dp = (sa ? *sp + FZ_COMBINE(*dp, t) : 255);
					dp++;
				}
				if (sa)
					sp++;
			}
		}
	}
}

static inline void
fz_paint_span_4(byte * restrict dp, int da, const byte * restrict sp, int sa, int w)
{
	while (w--)
	{
		int t = (sa ? FZ_EXPAND(sp[4]) : 256);
		if (t == 0)
		{
			dp += 4+da; sp += 4+sa;
		}
		else
		{
			t = 256 - t;
			if (t == 0)
			{
				dp[0] = sp[0];
				dp[1] = sp[1];
				dp[2] = sp[2];
				dp[3] = sp[3];
				if (da)
					dp[4] = (sa ? sp[4] : 255);
				dp += 4+da; sp += 4 + sa;
			}
			else
			{
				*dp = *sp++ + FZ_COMBINE(*dp, t);
				dp++;
				*dp = *sp++ + FZ_COMBINE(*dp, t);
				dp++;
				*dp = *sp++ + FZ_COMBINE(*dp, t);
				dp++;
				*dp = *sp++ + FZ_COMBINE(*dp, t);
				dp++;
				if (da)
				{
					*dp = (sa ? *sp + FZ_COMBINE(*dp, t) : 255);
					dp++;
				}
				if (sa)
					sp++;
			}
		}
	}
}

static inline void
fz_paint_span_N(byte * restrict dp, int da, const byte * restrict sp, int sa, int n1, int w)
{
	while (w--)
	{
		int t = (sa ? FZ_EXPAND(sp[n1]) : 256);
		if (t == 0)
		{
			dp += n1 + da; sp += n1 + sa;
		}
		else
		{
			t = 256 - t;
			if (t == 0)
			{
				int k = n1;
				while (k--)
				{
					*dp++ = *sp++;
				}
				if (da)
					*dp++ = (sa ? *sp : 255);
				if (sa)
					sp++;
			}
			else
			{
				int k = n1;
				while (k--)
				{
					*dp = *sp++ + FZ_COMBINE(*dp, t);
					dp++;
				}
				if (da)
				{
					*dp = (sa ? *sp + FZ_COMBINE(*dp, t) : 255);
					dp++;
				}
				if (sa)
					sp++;
			}
		}
	}
}

void
fz_paint_span(byte * restrict dp, int da, const byte * restrict sp, int sa, int n, int w, int alpha)
{
	if (da)
	{
		if (sa)
		{
			if (alpha == 255)
			{
				switch (n)
				{
				case 0: fz_paint_span_1_dasa(dp, sp, w); break;
				case 1: fz_paint_span_1(dp, 1, sp, 1, w); break;
				case 3: fz_paint_span_3(dp, 1, sp, 1, w); break;
				case 4: fz_paint_span_4(dp, 1, sp, 1, w); break;
				default: fz_paint_span_N(dp, 1, sp, 1, n, w); break;
				}
			}
			else if (alpha > 0)
			{
				switch (n)
				{
				case 1: fz_paint_span_1_with_alpha(dp, 1, sp, 1, w, alpha); break;
				case 3: fz_paint_span_3_with_alpha(dp, 1, sp, 1, w, alpha); break;
				case 4: fz_paint_span_4_with_alpha(dp, 1, sp, 1, w, alpha); break;
				default: fz_paint_span_N_with_alpha(dp, 1, sp, 1, n, w, alpha); break;
				}
			}
		}
		else
		{
			if (alpha == 255)
			{
				switch (n)
				{
				case 1: fz_paint_span_1(dp, 1, sp, 0, w); break;
				case 3: fz_paint_span_3(dp, 1, sp, 0, w); break;
				case 4: fz_paint_span_4(dp, 1, sp, 0, w); break;
				default: fz_paint_span_N(dp, 1, sp, 0, n, w); break;
				}
			}
			else if (alpha > 0)
			{
				switch (n)
				{
				case 1: fz_paint_span_1_with_alpha(dp, 1, sp, 0, w, alpha); break;
				case 3: fz_paint_span_3_with_alpha(dp, 1, sp, 0, w, alpha); break;
				case 4: fz_paint_span_4_with_alpha(dp, 1, sp, 0, w, alpha); break;
				default: fz_paint_span_N_with_alpha(dp, 1, sp, 0, n, w, alpha); break;
				}
			}
		}
	}
	else
	{
		if (sa)
		{
			if (alpha == 255)
			{
				switch (n)
				{
				case 1: fz_paint_span_1(dp, 0, sp, 1, w); break;
				case 3: fz_paint_span_3(dp, 0, sp, 1, w); break;
				case 4: fz_paint_span_4(dp, 0, sp, 1, w); break;
				default: fz_paint_span_N(dp, 0, sp, 1, n, w); break;
				}
			}
			else if (alpha > 0)
			{
				switch (n)
				{
				case 1: fz_paint_span_1_with_alpha(dp, 0, sp, 1, w, alpha); break;
				case 3: fz_paint_span_3_with_alpha(dp, 0, sp, 1, w, alpha); break;
				case 4: fz_paint_span_4_with_alpha(dp, 0, sp, 1, w, alpha); break;
				default: fz_paint_span_N_with_alpha(dp, 0, sp, 1, n, w, alpha); break;
				}
			}
		}
		else
		{
			if (alpha == 255)
			{
				switch (n)
				{
				case 1: fz_paint_span_1(dp, 0, sp, 0, w); break;
				case 3: fz_paint_span_3(dp, 0, sp, 0, w); break;
				case 4: fz_paint_span_4(dp, 0, sp, 0, w); break;
				default: fz_paint_span_N(dp, 0, sp, 0, n, w); break;
				}
			}
			else if (alpha > 0)
			{
				switch (n)
				{
				case 1: fz_paint_span_1_with_alpha(dp, 0, sp, 0, w, alpha); break;
				case 3: fz_paint_span_3_with_alpha(dp, 0, sp, 0, w, alpha); break;
				case 4: fz_paint_span_4_with_alpha(dp, 0, sp, 0, w, alpha); break;
				default: fz_paint_span_N_with_alpha(dp, 0 ,sp, 0, n, w, alpha); break;
				}
			}
		}
	}
}

/*
 * Pixmap blending functions
 */

void
fz_paint_pixmap_with_bbox(fz_pixmap * restrict dst, const fz_pixmap * restrict src, int alpha, fz_irect bbox)
{
	const unsigned char *sp;
	unsigned char *dp;
	int x, y, w, h, n, da, sa;
	fz_irect bbox2;

	assert(dst->n - dst->alpha == src->n - src->alpha);

	fz_pixmap_bbox_no_ctx(dst, &bbox2);
	fz_intersect_irect(&bbox, &bbox2);
	fz_pixmap_bbox_no_ctx(src, &bbox2);
	fz_intersect_irect(&bbox, &bbox2);

	x = bbox.x0;
	y = bbox.y0;
	w = bbox.x1 - bbox.x0;
	h = bbox.y1 - bbox.y0;
	if ((w | h) == 0)
		return;

	n = src->n;
	sp = src->samples + (unsigned int)((y - src->y) * src->stride + (x - src->x) * src->n);
	sa = src->alpha;
	dp = dst->samples + (unsigned int)((y - dst->y) * dst->stride + (x - dst->x) * dst->n);
	da = dst->alpha;

	n -= sa;
	while (h--)
	{
		fz_paint_span(dp, da, sp, sa, n, w, alpha);
		sp += src->stride;
		dp += dst->stride;
	}
}

void
fz_paint_pixmap(fz_pixmap * restrict dst, const fz_pixmap * restrict src, int alpha)
{
	const unsigned char *sp;
	unsigned char *dp;
	fz_irect bbox;
	fz_irect bbox2;
	int x, y, w, h, n, da, sa;

	assert(dst->n - dst->alpha == src->n - src->alpha);

	fz_pixmap_bbox_no_ctx(dst, &bbox);
	fz_pixmap_bbox_no_ctx(src, &bbox2);
	fz_intersect_irect(&bbox, &bbox2);

	x = bbox.x0;
	y = bbox.y0;
	w = bbox.x1 - bbox.x0;
	h = bbox.y1 - bbox.y0;
	if ((w | h) == 0)
		return;

	n = src->n;
	sp = src->samples + (unsigned int)((y - src->y) * src->stride + (x - src->x) * src->n);
	sa = src->alpha;
	dp = dst->samples + (unsigned int)((y - dst->y) * dst->stride + (x - dst->x) * dst->n);
	da = dst->alpha;

	n -= sa;
	while (h--)
	{
		fz_paint_span(dp, da, sp, sa, n, w, alpha);
		sp += src->stride;
		dp += dst->stride;
	}
}

void
fz_paint_pixmap_with_mask(fz_pixmap * restrict dst, const fz_pixmap * restrict src, const fz_pixmap * restrict msk)
{
	const unsigned char *sp, *mp;
	unsigned char *dp;
	fz_irect bbox, bbox2;
	int x, y, w, h, n, sa, da;

	assert(dst->n == src->n);
	assert(msk->n == 1);

	fz_pixmap_bbox_no_ctx(dst, &bbox);
	fz_pixmap_bbox_no_ctx(src, &bbox2);
	fz_intersect_irect(&bbox, &bbox2);
	fz_pixmap_bbox_no_ctx(msk, &bbox2);
	fz_intersect_irect(&bbox, &bbox2);

	x = bbox.x0;
	y = bbox.y0;
	w = bbox.x1 - bbox.x0;
	h = bbox.y1 - bbox.y0;
	if ((w | h) == 0)
		return;

	n = src->n;
	sp = src->samples + (unsigned int)((y - src->y) * src->stride + (x - src->x) * src->n);
	sa = src->alpha;
	mp = msk->samples + (unsigned int)((y - msk->y) * msk->stride + (x - msk->x) * msk->n);
	dp = dst->samples + (unsigned int)((y - dst->y) * dst->stride + (x - dst->x) * dst->n);
	da = dst->alpha;

	n -= sa;
	while (h--)
	{
		fz_paint_span_with_mask(dp, da, sp, sa, mp, n, w);
		sp += src->stride;
		dp += dst->stride;
		mp += msk->stride;
	}
}

static inline void
fz_paint_glyph_mask(int span, unsigned char *dp, int da, const fz_glyph *glyph, int w, int h, int skip_x, int skip_y)
{
	while (h--)
	{
		int skip_xx, ww, len, extend;
		const unsigned char *runp;
		unsigned char *ddp = dp;
		int offset = ((const int *)(glyph->data))[skip_y++];
		if (offset >= 0)
		{
			int eol = 0;
			runp = &glyph->data[offset];
			extend = 0;
			ww = w;
			skip_xx = skip_x;
			while (skip_xx)
			{
				int v = *runp++;
				switch (v & 3)
				{
				case 0: /* Extend */
					extend = v>>2;
					len = 0;
					break;
				case 1: /* Transparent */
					len = (v>>2) + 1 + (extend<<6);
					extend = 0;
					if (len > skip_xx)
					{
						len -= skip_xx;
						goto transparent_run;
					}
					break;
				case 2: /* Solid */
					eol = v & 4;
					len = (v>>3) + 1 + (extend<<5);
					extend = 0;
					if (len > skip_xx)
					{
						len -= skip_xx;
						goto solid_run;
					}
					break;
				default: /* Intermediate */
					eol = v & 4;
					len = (v>>3) + 1 + (extend<<5);
					extend = 0;
					if (len > skip_xx)
					{
						runp += skip_xx;
						len -= skip_xx;
						goto intermediate_run;
					}
					runp += len;
					break;
				}
				if (eol)
				{
					ww = 0;
					break;
				}
				skip_xx -= len;
			}
			while (ww > 0)
			{
				int v = *runp++;
				switch(v & 3)
				{
				case 0: /* Extend */
					extend = v>>2;
					break;
				case 1: /* Transparent */
					len = (v>>2) + 1 + (extend<<6);
					extend = 0;
transparent_run:
					if (len > ww)
						len = ww;
					ww -= len;
					ddp += len;
					break;
				case 2: /* Solid */
					eol = v & 4;
					len = (v>>3) + 1 + (extend<<5);
					extend = 0;
solid_run:
					if (len > ww)
						len = ww;
					ww -= len;
					do
					{
						*ddp++ = 0xFF;
					}
					while (--len);
					break;
				default: /* Intermediate */
					eol = v & 4;
					len = (v>>3) + 1 + (extend<<5);
					extend = 0;
intermediate_run:
					if (len > ww)
						len = ww;
					ww -= len;
					do
					{
						int v = *ddp;
						int a = *runp++;
						if (v == 0)
						{
							*ddp++ = a;
						}
						else
						{
							a = FZ_EXPAND(a);
							*ddp = FZ_BLEND(0xFF, v, a);
							ddp++;
						}
					}
					while (--len);
					break;
				}
				if (eol)
					break;
			}
		}
		dp += span;
	}
}

#define DA
#define N 1
#include "paint-glyph.h"

#define DA
#define N 3
#include "paint-glyph.h"

#define DA
#define N 4
#include "paint-glyph.h"

#define DA
#include "paint-glyph.h"

#define DA
#define ALPHA
#define N 1
#include "paint-glyph.h"

#define DA
#define ALPHA
#define N 3
#include "paint-glyph.h"

#define DA
#define ALPHA
#define N 4
#include "paint-glyph.h"

#define DA
#define ALPHA
#include "paint-glyph.h"

#define N 1
#include "paint-glyph.h"

#define N 3
#include "paint-glyph.h"

#define N 4
#include "paint-glyph.h"

#include "paint-glyph.h"

#define ALPHA
#define N 1
#include "paint-glyph.h"

#define ALPHA
#define N 3
#include "paint-glyph.h"

#define ALPHA
#define N 4
#include "paint-glyph.h"

#define ALPHA
#include "paint-glyph.h"

static inline void
fz_paint_glyph_alpha(const unsigned char * restrict colorbv, int n, int span, unsigned char * restrict dp, int da, const fz_glyph *glyph, int w, int h, int skip_x, int skip_y)
{
	if (da)
	{
		switch (n)
		{
		case 1:
			fz_paint_glyph_alpha_1_da(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		case 3:
			fz_paint_glyph_alpha_3_da(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		case 4:
			fz_paint_glyph_alpha_4_da(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		default:
			fz_paint_glyph_alpha_N_da(colorbv, n, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		}
	}
	else
	{
		switch (n)
		{
		case 1:
			fz_paint_glyph_alpha_1(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		case 3:
			fz_paint_glyph_alpha_3(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		case 4:
			fz_paint_glyph_alpha_4(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		default:
			fz_paint_glyph_alpha_N(colorbv, n, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		}
	}
}

static inline void
fz_paint_glyph_solid(const unsigned char * restrict colorbv, int n, int span, unsigned char * restrict dp, int da, const fz_glyph * restrict glyph, int w, int h, int skip_x, int skip_y)
{
	if (da)
	{
		switch (n)
		{
		case 1:
			fz_paint_glyph_solid_1_da(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		case 3:
			fz_paint_glyph_solid_3_da(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		case 4:
			fz_paint_glyph_solid_4_da(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		default:
			fz_paint_glyph_solid_N_da(colorbv, n, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		}
	}
	else
	{
		switch (n)
		{
		case 1:
			fz_paint_glyph_solid_1(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		case 3:
			fz_paint_glyph_solid_3(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		case 4:
			fz_paint_glyph_solid_4(colorbv, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		default:
			fz_paint_glyph_solid_N(colorbv, n, span, dp, glyph, w, h, skip_x, skip_y);
			break;
		}
	}
}

void
fz_paint_glyph(const unsigned char * restrict colorbv, fz_pixmap * restrict dst, unsigned char * restrict dp, const fz_glyph * restrict glyph, int w, int h, int skip_x, int skip_y)
{
	int n = dst->n - dst->alpha;
	if (dst->colorspace)
	{
		assert(n > 0);
		if (colorbv[n] == 255)
			fz_paint_glyph_solid(colorbv, n, dst->stride, dp, dst->alpha, glyph, w, h, skip_x, skip_y);
		else if (colorbv[n] != 0)
			fz_paint_glyph_alpha(colorbv, n, dst->stride, dp, dst->alpha, glyph, w, h, skip_x, skip_y);
	}
	else
	{
		assert(dst->alpha && dst->n == 1 && dst->colorspace == NULL);
		fz_paint_glyph_mask(dst->stride, dp, dst->alpha, glyph, w, h, skip_x, skip_y);
	}
}
