#include "mupdf/fitz.h"
#include "draw-imp.h"

#include <string.h>

/* Unpack image samples and optionally pad pixels with opaque alpha */

#define get1(buf,x) ((buf[x >> 3] >> ( 7 - (x & 7) ) ) & 1 )
#define get2(buf,x) ((buf[x >> 2] >> ( ( 3 - (x & 3) ) << 1 ) ) & 3 )
#define get4(buf,x) ((buf[x >> 1] >> ( ( 1 - (x & 1) ) << 2 ) ) & 15 )
#define get8(buf,x) (buf[x])
#define get16(buf,x) (buf[x << 1])

static unsigned char get1_tab_1[256][8];
static unsigned char get1_tab_1p[256][16];
static unsigned char get1_tab_255[256][8];
static unsigned char get1_tab_255p[256][16];

/*
	Bug 697012 shows that the unpacking code can confuse valgrind due
	to the use of undefined bits in the padding at the end of lines.
	We unpack from bits to bytes by copying from a lookup table.
	Valgrind is not capable of understanding that it doesn't matter
	what the undefined bits are, as the bytes we copy that correspond
	to the defined bits will always agree regardless of these
	undefined bits by construction of the table.

	We therefore have a VGMASK macro that explicitly masks off these
	bits in PACIFY_VALGRIND builds.
*/
#ifdef PACIFY_VALGRIND
static const unsigned char mask[9] = { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
#define VGMASK(v,m) (v & mask[(m)])
#else
#define VGMASK(v,m) (v)
#endif

static void
init_get1_tables(void)
{
	static int once = 0;
	unsigned char bits[1];
	int i, k, x;

	/* TODO: mutex lock here */

	if (once)
		return;

	for (i = 0; i < 256; i++)
	{
		bits[0] = i;
		for (k = 0; k < 8; k++)
		{
			x = get1(bits, k);

			get1_tab_1[i][k] = x;
			get1_tab_1p[i][k * 2] = x;
			get1_tab_1p[i][k * 2 + 1] = 255;

			get1_tab_255[i][k] = x * 255;
			get1_tab_255p[i][k * 2] = x * 255;
			get1_tab_255p[i][k * 2 + 1] = 255;
		}
	}

	once = 1;
}

void
fz_unpack_tile(fz_context *ctx, fz_pixmap *dst, unsigned char * restrict src, int n, int depth, size_t stride, int scale)
{
	int pad, x, y, k, skip;
	int w = dst->w;

	pad = 0;
	skip = 0;
	if (dst->n > n)
		pad = 255;
	if (dst->n < n)
	{
		skip = n - dst->n;
		n = dst->n;
	}

	if (depth == 1)
		init_get1_tables();

	if (scale == 0)
	{
		switch (depth)
		{
		case 1: scale = 255; break;
		case 2: scale = 85; break;
		case 4: scale = 17; break;
		}
	}

	for (y = 0; y < dst->h; y++)
	{
		unsigned char *sp = src + (y * stride);
		unsigned char *dp = dst->samples + (y * dst->stride);

		/* Specialized loops */

		if (n == 1 && depth == 1 && scale == 1 && !pad && !skip)
		{
			int w3 = w >> 3;
			for (x = 0; x < w3; x++)
			{
				memcpy(dp, get1_tab_1[*sp++], 8);
				dp += 8;
			}
			x = x << 3;
			if (x < w)
				memcpy(dp, get1_tab_1[VGMASK(*sp, w - x)], w - x);
		}

		else if (n == 1 && depth == 1 && scale == 255 && !pad && !skip)
		{
			int w3 = w >> 3;
			for (x = 0; x < w3; x++)
			{
				memcpy(dp, get1_tab_255[*sp++], 8);
				dp += 8;
			}
			x = x << 3;
			if (x < w)
				memcpy(dp, get1_tab_255[VGMASK(*sp, w - x)], w - x);
		}

		else if (n == 1 && depth == 1 && scale == 1 && pad && !skip)
		{
			int w3 = w >> 3;
			for (x = 0; x < w3; x++)
			{
				memcpy(dp, get1_tab_1p[*sp++], 16);
				dp += 16;
			}
			x = x << 3;
			if (x < w)
				memcpy(dp, get1_tab_1p[VGMASK(*sp, w - x)], (w - x) << 1);
		}

		else if (n == 1 && depth == 1 && scale == 255 && pad && !skip)
		{
			int w3 = w >> 3;
			for (x = 0; x < w3; x++)
			{
				memcpy(dp, get1_tab_255p[*sp++], 16);
				dp += 16;
			}
			x = x << 3;
			if (x < w)
				memcpy(dp, get1_tab_255p[VGMASK(*sp, w - x)], (w - x) << 1);
		}

		else if (depth == 8 && !pad && !skip)
		{
			int len = w * n;
			while (len--)
				*dp++ = *sp++;
		}

		else if (depth == 8 && pad && !skip)
		{
			for (x = 0; x < w; x++)
			{
				for (k = 0; k < n; k++)
					*dp++ = *sp++;
				*dp++ = 255;
			}
		}

		else
		{
			int b = 0;
			for (x = 0; x < w; x++)
			{
				for (k = 0; k < n; k++)
				{
					switch (depth)
					{
					case 1: *dp++ = get1(sp, b) * scale; break;
					case 2: *dp++ = get2(sp, b) * scale; break;
					case 4: *dp++ = get4(sp, b) * scale; break;
					case 8: *dp++ = get8(sp, b); break;
					case 16: *dp++ = get16(sp, b); break;
					}
					b++;
				}
				b += skip;
				if (pad)
					*dp++ = 255;
			}
		}
	}
}

/* Apply decode array */

void
fz_decode_indexed_tile(fz_context *ctx, fz_pixmap *pix, const float *decode, int maxval)
{
	int add[FZ_MAX_COLORS];
	int mul[FZ_MAX_COLORS];
	unsigned char *p = pix->samples;
	int stride = pix->stride - pix->w * pix->n;
	int len;
	int pn = pix->n;
	int n = pn - pix->alpha;
	int needed;
	int k;
	int h;

	needed = 0;
	for (k = 0; k < n; k++)
	{
		int min = decode[k * 2] * 256;
		int max = decode[k * 2 + 1] * 256;
		add[k] = min;
		mul[k] = (max - min) / maxval;
		needed |= min != 0 || max != maxval * 256;
	}

	if (!needed)
		return;

	h = pix->h;
	while (h--)
	{
		len = pix->w;
		while (len--)
		{
			for (k = 0; k < n; k++)
			{
				int value = (add[k] + (((p[k] << 8) * mul[k]) >> 8)) >> 8;
				p[k] = fz_clampi(value, 0, 255);
			}
			p += pn;
		}
		p += stride;
	}
}

void
fz_decode_tile(fz_context *ctx, fz_pixmap *pix, const float *decode)
{
	int add[FZ_MAX_COLORS];
	int mul[FZ_MAX_COLORS];
	unsigned char *p = pix->samples;
	int stride = pix->stride - pix->w * pix->n;
	int len;
	int n = fz_maxi(1, pix->n - pix->alpha);
	int k;
	int h;

	for (k = 0; k < n; k++)
	{
		int min = decode[k * 2] * 255;
		int max = decode[k * 2 + 1] * 255;
		add[k] = min;
		mul[k] = max - min;
	}

	h = pix->h;
	while (h--)
	{
		len = pix->w;
		while (len--)
		{
			for (k = 0; k < n; k++)
			{
				int value = add[k] + fz_mul255(p[k], mul[k]);
				p[k] = fz_clampi(value, 0, 255);
			}
			p += pix->n;
		}
		p += stride;
	}
}
