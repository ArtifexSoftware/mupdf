#include <fitz.h>

fz_error *
fz_newpixmap(fz_pixmap **pixp, int x, int y, int w, int h, int n, int a)
{
	fz_pixmap *pix;

	pix = *pixp = fz_malloc(sizeof (fz_pixmap));
	if (!pix)
		return fz_outofmem;

	pix->x = x;
	pix->y = y;
	pix->w = w;
	pix->h = h;
	pix->n = n;
	pix->a = a;
	pix->cs = nil;
	pix->stride = (pix->n + pix->a) * pix->w;

	pix->samples = fz_malloc(sizeof(short) * pix->stride * pix->h);
	if (!pix->samples) {
		fz_free(pix);
		return fz_outofmem;
	}

	memset(pix->samples, 0, sizeof(short) * pix->stride * pix->h);

	return nil;
}

fz_pixmap *
fz_keeppixmap(fz_pixmap *pix)
{
	pix->refcount ++;
	return pix;
}

void
fz_droppixmap(fz_pixmap *pix)
{
	pix->refcount --;
	if (pix->refcount == 0)
	{
		fz_free(pix->samples);
		fz_free(pix);
	}
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
	assert(pix->n == 3 && pix->a == 1);
	FILE *f = fopen("out.ppm", "w");
	fprintf(f, "P6\n%d %d\n255\n", pix->w, pix->h);
	for (y = 0; y < pix->h; y++)
		for (x = 0; x < pix->w; x++)
		{
			int r = (pix->samples[x * 4 + y * pix->stride + 0] * 255) >> 14;
			int g = (pix->samples[x * 4 + y * pix->stride + 1] * 255) >> 14;
			int b = (pix->samples[x * 4 + y * pix->stride + 2] * 255) >> 14;
			putc(r, f);
			putc(g, f);
			putc(b, f);
		}
	fclose(f);
}

void
fz_blendover(fz_pixmap *dst, fz_pixmap *fg, fz_pixmap *bg)
{
	int x, y;

printf("dst=%d,%d fg=%d,%d bg=%d,%d\n",
dst->n, dst->a,
fg->n, fg->a,
bg->n, bg->a);

	assert(fg->n == bg->n);
	assert(fg->n == 3);
	assert(fg->a == 1);
	assert(bg->a == 1);

	for (y = 0; y < dst->h; y++)
	{
		short *bgp = &fg->samples[y * fg->stride];
		short *fgp = &bg->samples[y * bg->stride];
		short *dstp = &dst->samples[y * dst->stride];
		for (x = 0; x < dst->w; x++)
		{
			dstp[0] = ((fgp[3] * (fgp[0] - bgp[0])) >> 14) + bgp[0];
			dstp[1] = ((fgp[3] * (fgp[1] - bgp[1])) >> 14) + bgp[1];
			dstp[2] = ((fgp[3] * (fgp[2] - bgp[2])) >> 14) + bgp[2];
			dstp[3] = ((fgp[3] * (fgp[3] - bgp[3])) >> 14) + bgp[3];
			dstp += 4;
			fgp += 4;
			bgp += 4;
		}
	}
}

void
fz_blendmask(fz_pixmap *dst, fz_pixmap *src, fz_pixmap *mask)
{
	int x, y, k;

	assert(src->n == dst->n);
	assert(src->a == 0);
	assert(mask->n == 0);
	assert(mask->a == 1);
	assert(dst->a == 1);

	for (y = 0; y < dst->h; y++)
	{
		short *dstp = &dst->samples[y * dst->stride];
		short *srcp = &src->samples[y * src->stride];
		short *mskp = &mask->samples[y * mask->stride];
		for (x = 0; x < dst->w; x++)
		{
			for (k = 0; k < dst->n; k++)
				*dstp++ = *srcp++;
			*dstp++ = *mskp++;
		}
	}
}

