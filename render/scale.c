#include <fitz.h>

static void
scalerow(unsigned char *src, unsigned char *dst, int w, int ncomp, int denom)
{
	int x, left, k;
	int sum[32];

	left = 0;
	for (k = 0; k < ncomp; k++)
		sum[k] = 0;

	for (x = 0; x < w; x++)
	{
		for (k = 0; k < ncomp; k++)
            sum[k] += src[x * ncomp + k];
		if (++left == denom)
		{
			left = 0;
			for (k = 0; k < ncomp; k++)
			{
				dst[k] = sum[k] / denom;
				sum[k] = 0;
			}
			dst += ncomp;
		}
	}

	/* left overs */
	if (left)
		for (k = 0; k < ncomp; k++)
			dst[k] = sum[k] / left;
}

static void
scalecols(unsigned char *src, unsigned char *dst, int w, int ncomp, int denom)
{
	int x, y, k;
	unsigned char *s;
	int sum[32];

	for (x = 0; x < w; x++)
	{
		s = src + (x * ncomp);
		for (k = 0; k < ncomp; k++)
			sum[k] = 0;
		for (y = 0; y < denom; y++)
			for (k = 0; k < ncomp; k++)
				sum[k] += s[y * w * ncomp + k];
		for (k = 0; k < ncomp; k++)
			dst[k] = sum[k] / denom;
		dst += ncomp;
	}
}

fz_error *
fz_scalepixmap(fz_pixmap **dstp, fz_pixmap *src, int xdenom, int ydenom)
{
	fz_error *error;
	fz_pixmap *dst;
	unsigned char *buf;
	int y, iy, oy;
	int ow, oh, n;

	ow = (src->w + xdenom - 1) / xdenom;
	oh = (src->h + ydenom - 1) / ydenom;
	n = src->n;

	buf = fz_malloc(ow * n * ydenom);
	if (!buf)
		return fz_outofmem;

	error = fz_newpixmap(&dst, 0, 0, ow, oh, src->n);
	if (error)
	{
		fz_free(buf);
		return error;
	}

	for (y = 0, oy = 0; y < (src->h / ydenom) * ydenom; y += ydenom, oy++)
	{
		for (iy = 0; iy < ydenom; iy++)
			scalerow(src->samples + (y + iy) * src->w * n,
					 buf + iy * ow * n,
					 src->w, n, xdenom);
		scalecols(buf, dst->samples + oy * dst->w * n, dst->w, n, ydenom);
	}

	ydenom = src->h - y;
	if (ydenom)
	{
		for (iy = 0; iy < ydenom; iy++)
			scalerow(src->samples + (y + iy) * src->w * n,
					 buf + iy * ow * n,
					 src->w, n, xdenom);
		scalecols(buf, dst->samples + oy * dst->w * n, dst->w, n, ydenom);
	}

//printf("unscaled image ");fz_debugpixmap(src);getchar();
//printf("scaled image ");fz_debugpixmap(dst);getchar();

	fz_free(buf);
	*dstp = dst;
	return nil;
}

