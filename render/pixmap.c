#include <fitz.h>

fz_error *
fz_newpixmap(fz_pixmap **pixp, fz_colorspace *cs, int x, int y, int w, int h, int n, int a)
{
	fz_pixmap *pix;

	pix = *pixp = fz_malloc(sizeof (fz_pixmap));
	if (!pix)
		return fz_outofmem;

	pix->cs = cs;
	pix->x = x;
	pix->y = y;
	pix->w = w;
	pix->h = h;
	pix->n = n;
	pix->a = a;
	pix->stride = (pix->n + pix->a) * pix->w;

	pix->samples = fz_malloc(sizeof(short) * pix->stride * pix->h);
	if (!pix->samples) {
		fz_free(pix);
		return fz_outofmem;
	}

	memset(pix->samples, 0, sizeof(short) * pix->stride * pix->h);

	return nil;
}

void
fz_freepixmap(fz_pixmap *pix)
{
	fz_free(pix->samples);
	fz_free(pix);
}

void
fz_clearpixmap(fz_pixmap *pix)
{
	memset(pix->samples, 0, sizeof(short) * pix->stride * pix->h);
}

void
fz_debugpixmap(fz_pixmap *pix)
{
	int x, y;

	FILE *f = fopen("out.ppm", "w");

	if (pix->n == 3 && pix->a == 1)
	{
		fprintf(f, "P6\n%d %d\n255\n", pix->w, pix->h);
		for (y = 0; y < pix->h; y++)
			for (x = 0; x < pix->w; x++)
			{
				int r = (pix->samples[x * 4 + y * pix->stride + 0] * 255) >> 14;
				int g = (pix->samples[x * 4 + y * pix->stride + 1] * 255) >> 14;
				int b = (pix->samples[x * 4 + y * pix->stride + 2] * 255) >> 14;
				int a = (pix->samples[x * 4 + y * pix->stride + 3] * 255) >> 14;
				putc(((r * a) / 255) + (255 - a), f);
				putc(((g * a) / 255) + (255 - a), f);
				putc(((b * a) / 255) + (255 - a), f);
				// putc(a, f);
				// putc(a, f);
				// putc(a, f);
			}
	}
	else if (pix->n == 0 && pix->a == 1)
	{
		fprintf(f, "P5\n%d %d\n255\n", pix->w, pix->h);
		for (y = 0; y < pix->h; y++)
			for (x = 0; x < pix->w; x++)
			{
				int a = (pix->samples[x + y * pix->stride] * 255) >> 14;
				putc(a, f);
			}
	}
	fclose(f);
}

void
fz_blendover(fz_pixmap *src, fz_pixmap *dst)
{
	int x, y;

	assert(dst->n == src->n);
	assert(dst->a == 1);
	assert(src->n == 3);
	assert(src->a == 1);

	for (y = 0; y < dst->h; y++)
	{
		short *s = &src->samples[y * src->stride];
		short *d = &dst->samples[y * dst->stride];

		for (x = 0; x < dst->w; x++)
		{
			int sa = s[3];
			int ssa = (1 << 14) - sa;

			d[0] = ((s[0] * sa) >> 14) + ((d[0] * ssa) >> 14);
			d[1] = ((s[1] * sa) >> 14) + ((d[1] * ssa) >> 14);
			d[2] = ((s[2] * sa) >> 14) + ((d[2] * ssa) >> 14);
			d[3] = sa + ((ssa * d[3]) >> 14);

			s += 4;
			d += 4;
		}
	}
}

void
fz_blendmask(fz_pixmap *dst, fz_pixmap *src, fz_pixmap *msk)
{
	int x, y, k;

	assert(src->n == dst->n);
	assert(src->a == 1);
	assert(msk->n == 0);
	assert(msk->a == 1);
	assert(dst->a == 1);

	for (y = 0; y < dst->h; y++)
	{
		short *d = &dst->samples[y * dst->stride];
		short *s = &src->samples[y * src->stride];
		short *m = &msk->samples[y * msk->stride];

		for (x = 0; x < dst->w; x++)
		{
			for (k = 0; k < dst->n; k++)
				*d++ = *s++;
			*d++ = (*m++ * *s++) >> 14;
		}
	}
}

