/*
	This file is #included by draw-paint.c multiple times to
	produce optimised plotters.
*/

#ifdef ALPHA
#define NAME alpha
#else
#define NAME solid
#endif

#define FUNCTION_NAMER(NAME,N) fz_paint_glyph_##NAME##_##N
#define FUNCTION_NAME(NAME,N) FUNCTION_NAMER(NAME,N)

static inline void
FUNCTION_NAME(NAME,N)(const unsigned char * restrict colorbv,
#ifndef N
				int n,
#endif
				int span, unsigned char * restrict dp, const fz_glyph * restrict glyph, int w, int h, int skip_x, int skip_y)
{
#ifdef N
	const int n = N;
#endif
#ifdef ALPHA
	int sa = FZ_EXPAND(colorbv[n-1]);
#else
#if defined(N) && N == 2
	const uint16_t color = *(const uint16_t *)colorbv;
#elif defined(N) && N == 4
	const uint32_t color = *(const uint32_t *)colorbv;
#endif
#endif
	while (h--)
	{
		int skip_xx, ww, len, extend;
		const unsigned char *runp;
		unsigned char *ddp = dp;
		int offset = ((int *)(glyph->data))[skip_y++];
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
					ddp += len * n;
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
#ifdef ALPHA
#if defined(N) && N == 2
						ddp[0] = FZ_BLEND(colorbv[0], ddp[0], sa);
						ddp[1] = FZ_BLEND(0xFF, ddp[1], sa);
						ddp += 2;
#elif defined(N) && N == 4
						ddp[0] = FZ_BLEND(colorbv[0], ddp[0], sa);
						ddp[1] = FZ_BLEND(colorbv[1], ddp[1], sa);
						ddp[2] = FZ_BLEND(colorbv[2], ddp[2], sa);
						ddp[3] = FZ_BLEND(0xFF, ddp[3], sa);
						ddp += 4;
#elif defined(N) && N == 5
						ddp[0] = FZ_BLEND(colorbv[0], ddp[0], sa);
						ddp[1] = FZ_BLEND(colorbv[1], ddp[1], sa);
						ddp[2] = FZ_BLEND(colorbv[2], ddp[2], sa);
						ddp[3] = FZ_BLEND(colorbv[3], ddp[3], sa);
						ddp[4] = FZ_BLEND(0xFF, ddp[4], sa);
						ddp += 5;
#else
						int k = 0;
						do
						{
							*ddp = FZ_BLEND(colorbv[k++], *ddp, sa);
							ddp++;
						}
						while (k != n-1);
						*ddp = FZ_BLEND(0xFF, *ddp, sa);
						ddp++;
#endif
#else
#if defined(N) && N == 2
						*(uint16_t *)ddp = color;
						ddp += 2;
#elif defined(N) && N == 4
						*(uint32_t *)ddp = color;
						ddp += 4;
#elif defined(N) && N == 5
						ddp[0] = colorbv[0];
						ddp[1] = colorbv[1];
						ddp[2] = colorbv[2];
						ddp[3] = colorbv[3];
						ddp[4] = colorbv[4];
						ddp += 5;
#else
						int k = 0;
						do
						{
							*ddp++ = colorbv[k++];
						}
						while (k != n);
#endif
#endif
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
						int k = 0;
						int a = *runp++;
#ifdef ALPHA
						a = FZ_COMBINE(sa, FZ_EXPAND(a));
#else
						a = FZ_EXPAND(a);
#endif
						(void)k;
#if defined(N) && N == 2
						ddp[0] = FZ_BLEND(colorbv[0], ddp[0], a);
						ddp[1] = FZ_BLEND(0xFF, ddp[1], a);
						ddp += 2;
#elif defined(N) && N == 4
						ddp[0] = FZ_BLEND(colorbv[0], ddp[0], a);
						ddp[1] = FZ_BLEND(colorbv[1], ddp[1], a);
						ddp[2] = FZ_BLEND(colorbv[2], ddp[2], a);
						ddp[3] = FZ_BLEND(0xFF, ddp[3], a);
						ddp += 4;
#elif defined(N) && N == 5
						ddp[0] = FZ_BLEND(colorbv[0], ddp[0], a);
						ddp[1] = FZ_BLEND(colorbv[1], ddp[1], a);
						ddp[2] = FZ_BLEND(colorbv[2], ddp[2], a);
						ddp[3] = FZ_BLEND(colorbv[3], ddp[3], a);
						ddp[4] = FZ_BLEND(0xFF, ddp[4], a);
						ddp += 5;
#else
						do
						{
							*ddp = FZ_BLEND(colorbv[k++], *ddp, a);
							ddp++;
						}
						while (k != n-1);
						*ddp = FZ_BLEND(0xFF, *ddp, a);
						ddp++;
#endif
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

#undef NAME
#undef ALPHA
#undef N
#undef FUNCTION_NAMER
#undef FUNCTION_NAME
