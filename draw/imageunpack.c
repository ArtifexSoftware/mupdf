#include "fitz.h"

/*
 * Unpack image samples and optionally pad pixels with opaque alpha
 */

#define get1(buf,x) ((buf[x >> 3] >> ( 7 - (x & 7) ) ) & 1 )
#define get2(buf,x) ((buf[x >> 2] >> ( ( 3 - (x & 3) ) << 1 ) ) & 3 )
#define get4(buf,x) ((buf[x >> 1] >> ( ( 1 - (x & 1) ) << 2 ) ) & 15 )
#define get8(buf,x) (buf[x])
#define get16(buf,x) (buf[x << 1])

void
fz_unpacktile(fz_pixmap *dst, unsigned char * restrict src, int n, int depth, int stride)
{
	int pad, x, y, k;

	pad = 0;
	if (dst->n > n)
		pad = (1 << depth) - 1;

	/* TODO: reinsert Robin Watts' specialized loops here */

	for (y = 0; y < dst->h; y++)
	{
		unsigned char *sp = src + y * stride;
		unsigned char *dp = dst->samples + y * (dst->w * dst->n);
		int b = 0;
		for (x = 0; x < dst->w; x++)
		{
			for (k = 0; k < n; k++)
			{
				switch (depth)
				{
				case 1: *dp++ = get1(sp, b); break;
				case 2: *dp++ = get2(sp, b); break;
				case 4: *dp++ = get4(sp, b); break;
				case 8: *dp++ = get8(sp, b); break;
				case 16: *dp++ = get16(sp, b); break;
				}
				b++;
			}
			if (pad)
				*dp++ = pad;
		}
	}
}

/*
 * Apply decode parameters and scale integers
 */

void
fz_decodetile(fz_pixmap *pix, float *decode, int scale)
{
	int min[FZ_MAXCOLORS + 2];
	int max[FZ_MAXCOLORS + 2];
	int sub[FZ_MAXCOLORS + 2];
	unsigned char *p = pix->samples;
	int len = pix->w * pix->h;
	int n = pix->n;
	int needed;
	int k;

	needed = scale != 1;
	for (k = 0; k < n; k++)
	{
		min[k] = decode[k * 2] * 255;
		max[k] = decode[k * 2 + 1] * 255;
		sub[k] = max[k] - min[k];
		needed |= min[k] != 0 || max[k] != 255;
	}

	if (!needed)
		return;

	while (len--)
	{
		for (k = 0; k < n; k++)
			p[k] = min[k] + fz_mul255(sub[k], p[k] * scale);
		p += n;
	}
}
