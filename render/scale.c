#include <fitz.h>

static void
scalerow(unsigned char *src, int w, int denom, unsigned char *dst, int ncomp)
{
	int x, left, n;
	int sum[32];

	left = 0;
	for (n = 0; n < ncomp; n++)
		sum[n] = 0;

	for (x = 0; x < w; x++)
	{
		for (n = 0; n < ncomp; n++)
            sum[n] += src[x * ncomp + n];
		if (++left == denom)
		{
			left = 0;
			for (n = 0; n < ncomp; n++)
			{
				dst[n] = sum[n] / denom;
				sum[n] = 0;
			}
			dst += ncomp;
		}
	}

	/* left overs */
	if (left)
		for (n = 0; n < ncomp; n++)
			dst[n] = sum[n] / left;
}

static void
scalecols(unsigned char *src, int stride, int w, int denom, unsigned char *dst, int ncomp)
{
	int x, y, n;
	unsigned char *s;
	int sum[32];

	for (x = 0; x < w; x++)
	{
		s = src + (x * ncomp);
		for (n = 0; n < ncomp; n++)
			sum[n] = 0;
		for (y = 0; y < denom; y++)
			for (n = 0; n < ncomp; n++)
				sum[n] += s[y * stride + n];
		for (n = 0; n < ncomp; n++)
			dst[n] = sum[n] / denom;
		dst += ncomp;
	}
}

fz_error *
fz_scalepixmap(fz_pixmap *src, fz_pixmap *dst, int xdenom, int ydenom)
{
	assert(src->n == dst->n);
	assert(src->a == dst->a);
	assert((src->w + xdenom - 1) / xdenom == dst->w);
	assert((src->h + ydenom - 1) / ydenom == dst->h);

	int ncomp = src->n + src->a;
	unsigned char scratch[dst->stride * ydenom];

	int y, iy, oy;

	for (y = 0, oy = 0; y < (dst->h - 1) * ydenom; y += ydenom, oy++)
	{
		for (iy = 0; iy < ydenom; iy++)
			scalerow(src->samples + (y + iy) * src->stride, src->w, xdenom,
				scratch + iy * dst->stride, ncomp);
		scalecols(scratch, ncomp * dst->w, dst->w, ydenom,
			dst->samples + (oy * dst->stride), ncomp);
	}

	ydenom = src->h - y;
	if (ydenom)
	{
		for (iy = 0; iy < ydenom; iy++)
			scalerow(src->samples + (y + iy) * src->stride, src->w, xdenom,
				scratch + iy * (ncomp * dst->w), ncomp);
		scalecols(scratch, ncomp * dst->w, dst->w, ydenom,
			dst->samples + (oy * dst->stride), ncomp);
	}

//printf("unscaled image ");fz_debugpixmap(src);getchar();
//printf("scaled image ");fz_debugpixmap(dst);getchar();

	return nil;
}

