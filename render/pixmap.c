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

	return nil;
}

fz_error *
fz_newpixmapwithrect(fz_pixmap **pixp, fz_irect r, int n)
{
	return fz_newpixmap(pixp,
				r.min.x, r.min.y,
				r.max.x - r.min.x,
				r.max.y - r.min.y, n);
}

void
fz_droppixmap(fz_pixmap *pix)
{
	fz_free(pix->samples);
	fz_free(pix);
}

void
fz_clearpixmap(fz_pixmap *pix)
{
	memset(pix->samples, 0, pix->w * pix->h * pix->n * sizeof(fz_sample));
}

void
fz_blendover(fz_pixmap *src, fz_pixmap *dst)
{
	int x, y, k;
	fz_irect sr, dr, rect;
	unsigned char *s;
	unsigned char *d;

	assert(dst->n == src->n || src->n == 1);

	sr.min.x = src->x;
	sr.min.y = src->y;
	sr.max.x = src->x + src->w;
	sr.max.y = src->y + src->h;

	dr.min.x = dst->x;
	dr.min.y = dst->y;
	dr.max.x = dst->x + dst->w;
	dr.max.y = dst->y + dst->h;

	rect = fz_intersectirects(sr, dr);

	if (dst->n == src->n)
	{
		for (y = rect.min.y; y < rect.max.y; y++)
		{
			s = src->samples + ((rect.min.x - src->x) + (y - src->y) * src->w) * src->n;
			d = dst->samples + ((rect.min.x - dst->x) + (y - dst->y) * dst->w) * dst->n;
			for (x = rect.min.x; x < rect.max.x; x++)
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
	else if (src->n == 1)
	{
		for (y = rect.min.y; y < rect.max.y; y++)
		{
			s = src->samples + ((rect.min.x - src->x) + (y - src->y) * src->w) * src->n;
			d = dst->samples + ((rect.min.x - dst->x) + (y - dst->y) * dst->w) * dst->n;
			for (x = rect.min.x; x < rect.max.x; x++)
			{
				int sa = s[0];
				int ssa = 255 - sa;

				d[0] = s[0] + fz_mul255(d[0], ssa);
				for (k = 1; k < dst->n; k++)
					d[k] = 0 + fz_mul255(d[k], ssa);

				s += src->n;
				d += dst->n;
			}
		}
	}
}

void
fz_blendmask(fz_pixmap *dst, fz_pixmap *src, fz_pixmap *msk)
{
	unsigned char *d;
	unsigned char *s;
	unsigned char *m;
	fz_irect sr, dr, mr, rect;
	int x, y, k;

	assert(src->n == dst->n);

	sr.min.x = src->x;
	sr.min.y = src->y;
	sr.max.x = src->x + src->w;
	sr.max.y = src->y + src->h;

	dr.min.x = dst->x;
	dr.min.y = dst->y;
	dr.max.x = dst->x + dst->w;
	dr.max.y = dst->y + dst->h;

	mr.min.x = msk->x;
	mr.min.y = msk->y;
	mr.max.x = msk->x + msk->w;
	mr.max.y = msk->y + msk->h;

	rect = fz_intersectirects(sr, dr);
	rect = fz_intersectirects(rect, mr);

	for (y = rect.min.y; y < rect.max.y; y++)
	{
		s = src->samples + ((rect.min.x - src->x) + (y - src->y) * src->w) * src->n;
		d = dst->samples + ((rect.min.x - dst->x) + (y - dst->y) * dst->w) * dst->n;
		m = msk->samples + ((rect.min.x - msk->x) + (y - msk->y) * msk->w) * msk->n;
		for (x = rect.min.x; x < rect.max.x; x++)
		{
			for (k = 0; k < dst->n; k++)
				*d++ = fz_mul255(*s++, *m);
			m += msk->n;
		}
	}
}

void
fz_gammapixmap(fz_pixmap *pix, float gamma)
{
	unsigned char table[255];
	int n = pix->w * pix->h * pix->n;
	unsigned char *p = pix->samples;
	int i;
	for (i = 0; i < 256; i++)
		table[i] = CLAMP(pow(i / 255.0, gamma) * 255.0, 0, 255);
	while (n--)
		*p = table[*p]; p++;
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
			}
		fclose(ppm);
		fclose(pgm);
	}

	else if (pix->n == 2)
	{
		int x, y;
		FILE *pgm = fopen("out.pgm", "w");
		fprintf(pgm, "P5\n%d %d\n255\n", pix->w, pix->h);

		for (y = 0; y < pix->h; y++)
			for (x = 0; x < pix->w; x++)
			{
				putc(pix->samples[y * pix->w * 2 + x * 2 + 1], pgm);
			}
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

