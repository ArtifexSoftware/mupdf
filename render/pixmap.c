#include <fitz.h>

fz_error *
fz_newpixmap(fz_pixmap **pixp, int x, int y, int w, int h, int n)
{
	fz_pixmap *pix;

	pix = *pixp = fz_malloc(sizeof(fz_pixmap));
	if (!pix)
		return fz_outofmem;

	pix->x = x;
	pix->y = y;
	pix->w = w;
	pix->h = h;
	pix->n = n;

	pix->samples = fz_malloc(pix->w * pix->h * pix->n * sizeof(fz_sample));
	if (!pix->samples) {
		fz_free(pix);
		return fz_outofmem;
	}

	memset(pix->samples, 0, pix->w * pix->h * pix->n * sizeof(fz_sample));

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
	memset(pix->samples, 0, pix->w * pix->h * pix->n * sizeof(fz_sample));
}

fz_error *
fz_convertpixmap(fz_pixmap **dstp, fz_pixmap *src, fz_colorspace *srcs, fz_colorspace *dsts)
{
	fz_error *error;
	fz_pixmap *dst;
	float srcv[32];
	float dstv[32];
	int y, x, k;

	error = fz_newpixmap(&dst, src->x, src->y, src->w, src->h, dsts->n + 1);
	if (error)
		return error;

	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;

	printf("convert pixmap from %s to %s\n", srcs->name, dsts->name);

	for (y = 0; y < src->h; y++)
	{
		for (x = 0; x < src->w; x++)
		{
			*s++ = *d++;

			for (k = 0; k < src->n - 1; k++)
				srcv[k] = *s++ / 255.0;

			fz_convertcolor(srcs, srcv, dsts, dstv);

			for (k = 0; k < dst->n - 1; k++)
				*d++ = dstv[k] * 255 + 0.5;
		}
	}

	*dstp = dst;
	return nil;
}

void
fz_blendover(fz_pixmap *src, fz_pixmap *dst)
{
	int x, y, k;

	assert(dst->n == src->n);
	assert(dst->w == src->w);
	assert(dst->h == src->h);

	unsigned char *s = src->samples;
	unsigned char *d = dst->samples;

	for (y = 0; y < dst->h; y++)
	{
		for (x = 0; x < dst->w; x++)
		{
			int sa = s[0];
			int ssa = 255 - sa;

			for (k = 0; k < dst->n; k++)
				d[k] = s[k] + fz_mul255(d[k], ssa);

			s += src->n;
			d += dst->n;
		}
	}
}

void
fz_blendmask(fz_pixmap *dst, fz_pixmap *src, fz_pixmap *msk)
{
	int x, y, k;

	assert(src->n == dst->n);
	assert(msk->n == 1);

	unsigned char *d = dst->samples;
	unsigned char *s = src->samples;
	unsigned char *m = msk->samples;

	for (y = 0; y < dst->h; y++)
	{
		for (x = 0; x < dst->w; x++)
		{
			for (k = 0; k < dst->n; k++)
			{
				*d++ = fz_mul255(*s++, *m);
			}
			m++;
		}
	}
}

void
fz_debugpixmap(fz_pixmap *pix)
{
	if (pix->n == 4)
	{
		int x, y;
		FILE *ppm = fopen("out.ppm", "w");
		FILE *pgm = fopen("out.pgm", "w");
		fprintf(ppm, "P6\n%d %d\n255\n", pix->w, pix->h);
		fprintf(pgm, "P5\n%d %d\n255\n", pix->w, pix->h);

		for (y = 0; y < pix->h; y++)
			for (x = 0; x < pix->w; x++)
			{
				int a = pix->samples[x * pix->n + y * pix->w * pix->n + 0];
				int r = pix->samples[x * pix->n + y * pix->w * pix->n + 1];
				int g = pix->samples[x * pix->n + y * pix->w * pix->n + 2];
				int b = pix->samples[x * pix->n + y * pix->w * pix->n + 3];
				putc(a, pgm);
				putc(r, ppm);
				putc(g, ppm);
				putc(b, ppm);
				// putc(((r * a) / 255) + (255 - a), ppm);
				// putc(((g * a) / 255) + (255 - a), ppm);
				// putc(((b * a) / 255) + (255 - a), ppm);
			}
		fclose(ppm);
		fclose(pgm);
	}

	else if (pix->n == 1)
	{
		FILE *pgm = fopen("out.pgm", "w");
		fprintf(pgm, "P5\n%d %d\n255\n", pix->w, pix->h);
		fwrite(pix->samples, 1, pix->w * pix->h, pgm);
		fclose(pgm);
	}
}

