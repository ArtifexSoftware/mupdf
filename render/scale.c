#include <fitz.h>

typedef void (*rowfunc)(unsigned char *src, unsigned char *dst, int w, int ncomp, int denom);
typedef void (*colfunc)(unsigned char *src, unsigned char *dst, int w, int ncomp, int denom);

static void
scalerow(unsigned char *src, unsigned char *dst, int w, int ncomp, int denom)
{
	int x, left, k;
	int sum[FZ_MAXCOLORS];

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
scalerow1(unsigned char *src, unsigned char *dst, int w, int ncomp, int denom)
{
	int x, left;
	int sum;

	left = 0;
	sum = 0;

	for (x = 0; x < w; x++)
	{
		sum += *src++;
		if (++left == denom)
		{
			left = 0;
			*dst++ = sum / denom;
			sum = 0;
		}
	}

	/* left overs */
	if (left)
	{
		*dst++ = sum / left;
	}
}

static void
scalerow2(unsigned char *src, unsigned char *dst, int w, int ncomp, int denom)
{
	int x, left;
	int sum0, sum1;

	left = 0;
	sum0 = 0;
	sum1 = 0;

	for (x = 0; x < w; x++)
	{
		sum0 += *src++;
		sum1 += *src++;
		if (++left == denom)
		{
			left = 0;
			*dst++ = sum0 / denom;
			*dst++ = sum1 / denom;
			sum0 = 0;
			sum1 = 0;
		}
	}

	/* left overs */
	if (left)
	{
		*dst++ = sum0 / left;
		*dst++ = sum1 / left;
	}
}


static void
scalecols(unsigned char *src, unsigned char *dst, int w, int ncomp, int denom)
{
	int x, y, k;
	unsigned char *s;
	int sum[FZ_MAXCOLORS];

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

static void
scalecols1(unsigned char *src, unsigned char *dst, int w, int ncomp, int denom)
{
	int x, y, k;
	unsigned char *s;
	int sum;

	for (x = 0; x < w; x++)
	{
		s = src + x;
		sum = 0;
		for (y = 0; y < denom; y++)
			sum += s[y * w];
		*dst++ = sum / denom;
	}
}

static void
scalecols2(unsigned char *src, unsigned char *dst, int w, int ncomp, int denom)
{
	int x, y, k;
	unsigned char *s;
	int sum0, sum1;

	for (x = 0; x < w; x++)
	{
		s = src + (x * 2);
		sum0 = 0;
		sum1 = 0;
		for (y = 0; y < denom; y++)
		{
			sum0 += s[y * w * 2 + 0];
			sum1 += s[y * w * 2 + 1];
		}
		*dst++ = sum0 / denom;
		*dst++ = sum1 / denom;
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
	rowfunc rowfunc;
	colfunc colfunc;

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

	switch (n)
	{
	case 1:
		rowfunc = scalerow1;
		colfunc = scalecols1;
		break;
	case 2:
		rowfunc = scalerow2;
		colfunc = scalecols2;
		break;
	default:
		rowfunc = scalerow;
		colfunc = scalecols;
		break;
	}

	for (y = 0, oy = 0; y < (src->h / ydenom) * ydenom; y += ydenom, oy++)
	{
		for (iy = 0; iy < ydenom; iy++)
			rowfunc(src->samples + (y + iy) * src->w * n,
					 buf + iy * ow * n,
					 src->w, n, xdenom);
		colfunc(buf, dst->samples + oy * dst->w * n, dst->w, n, ydenom);
	}

	ydenom = src->h - y;
	if (ydenom)
	{
		for (iy = 0; iy < ydenom; iy++)
			rowfunc(src->samples + (y + iy) * src->w * n,
					 buf + iy * ow * n,
					 src->w, n, xdenom);
		colfunc(buf, dst->samples + oy * dst->w * n, dst->w, n, ydenom);
	}

	fz_free(buf);
	*dstp = dst;
	return nil;
}

