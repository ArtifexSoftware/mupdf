#include <fitz.h>
#include <mupdf.h>

static inline int getbit(const unsigned char *buf, int x)
{
	return ( buf[x >> 3] >> ( 7 - (x & 7) ) ) & 1;
}

static void loadtile1(pdf_image *src, fz_pixmap *dst, int n)
{
	int x, y, k;
	for (y = dst->y; y < dst->y + dst->h; y++)
	{
		unsigned char *s = src->samples->bp + y * src->stride;
		unsigned char *d = dst->samples + y * dst->w * dst->n;
		for (x = dst->x; x < dst->x + dst->w; x++)
		{
			for (k = 0; k < n; k++)
				d[x * n + k] = getbit(s, x * n + k);
		}
	}
}

static void loadtile1a(pdf_image *src, fz_pixmap *dst, int n)
{
	int x, y, k;
	for (y = dst->y; y < dst->y + dst->h; y++)
	{
		unsigned char *s = src->samples->bp + y * src->stride;
		unsigned char *d = dst->samples + y * dst->w * dst->n;
		for (x = dst->x; x < dst->x + dst->w; x++)
		{
			d[x * (n+1) + 0] = 1;
			for (k = 0; k < n; k++)
				d[x * (n+1) + k + 1] = getbit(s, x * n + k);
		}
	}
}

static void loadtile8(pdf_image *src, fz_pixmap *dst, int n)
{
	int x, y, k;
	for (y = dst->y; y < dst->y + dst->h; y++)
	{
		unsigned char *s = src->samples->bp + y * src->stride;
		unsigned char *d = dst->samples + y * dst->w * dst->n;
		for (x = dst->x; x < dst->x + dst->w; x++)
			for (k = 0; k < n; k++)
				*d++ = *s++;
	}
}

static void loadtile8a(pdf_image *src, fz_pixmap *dst, int n)
{
	int x, y, k;
	for (y = dst->y; y < dst->y + dst->h; y++)
	{
		unsigned char *s = src->samples->bp + y * src->stride;
		unsigned char *d = dst->samples + y * dst->w * dst->n;
		for (x = dst->x; x < dst->x + dst->w; x++)
		{
			*d++ = 255;
			for (k = 0; k < n; k++)
				*d++ = *s++;
		}
	}
}

static void
decodetile(fz_pixmap *pix, int bpc, int skip, float *decode)
{
	unsigned char table[32][256];
	float invtwon = 1.0 / ((1 << bpc) - 1);
	int x, y, k, i;

	for (i = 0; i < (1 << bpc); i++)
	{
		if (skip)
			table[0][i] = (i * 255) * invtwon;
		for (k = skip; k < pix->n; k++)
		{
			float min = decode[(k - skip) * 2 + 0];
			float max = decode[(k - skip) * 2 + 1];
			float f = min + i * (max - min) * invtwon;
			table[k][i] = f * 255;
		}
	}

	for (y = 0; y < pix->h; y++)
	{
		for (x = 0; x < pix->w; x++)
		{
			for (k = 0; k < pix->n; k++)
			{
				i = pix->samples[ (y * pix->w + x) * pix->n + k];
				pix->samples[ (y * pix->w + x) * pix->n + k] = table[k][i];
			}
		}
	}
}

fz_error *
pdf_loadtile(fz_image *img, fz_pixmap *tile)
{
	pdf_image *src = (pdf_image*)img;
	fz_error *error;

	assert(tile->n == img->n + 1);
	assert(tile->x >= 0);
	assert(tile->y >= 0);
	assert(tile->x + tile->w <= img->w);
	assert(tile->y + tile->h <= img->h);

	if (src->indexed)
	{
		fz_pixmap *tmp;
		int x, y, k, i;

		error = fz_newpixmap(&tmp, tile->x, tile->y, tile->w, tile->h, 1);
		if (error)
			return error;

		switch (src->bpc)
		{
		case 1: loadtile1(src, tmp, 1); break;
	/*	case 2: loadtile2(src, tmp, 1); break; */
	/*	case 4: loadtile4(src, tmp, 1); break; */
		case 8: loadtile8(src, tmp, 1); break;
		default:
			return fz_throw("rangecheck: unsupported bit depth: %d", src->bpc);
		}

printf("  unpack n=%d\n", tile->n);
		for (y = 0; y < tile->h; y++)
		{
			for (x = 0; x < tile->w; x++)
			{
				tile->samples[(y * tile->w + x) * tile->n] = 255;
				i = tmp->samples[y * tile->w + x];
				i = CLAMP(i, 0, src->indexed->high);
				for (k = 0; k < src->indexed->base->n; k++)
				{
					tile->samples[(y * tile->w + x) * tile->n + k + 1] =
						src->indexed->lookup[i * src->indexed->base->n + k];
				}
			}
		}

		fz_droppixmap(tmp);
	}

	else
	{
		if (img->a)
		{
			switch (src->bpc)
			{
			case 1: loadtile1(src, tile, img->n + img->a); break;
		/*	case 2: loadtile2(src, tile, img->n + img->a); break; */
		/*	case 4: loadtile4(src, tile, img->n + img->a); break; */
			case 8: loadtile8(src, tile, img->n + img->a); break;
			default:
				return fz_throw("rangecheck: unsupported bit depth: %d", src->bpc);
			}
		}
		else
		{
			switch (src->bpc)
			{
			case 1: loadtile1a(src, tile, img->n); break;
		/*	case 2: loadtile2a(src, tile, img->n); break; */
		/*	case 4: loadtile4a(src, tile, img->n); break; */
			case 8: loadtile8a(src, tile, img->n); break;
			default:
				return fz_throw("rangecheck: unsupported bit depth: %d", src->bpc);
			}
		}

		decodetile(tile, src->bpc, !img->a, src->decode);
	}

	return nil;
}

