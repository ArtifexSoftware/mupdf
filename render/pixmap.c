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
	fprintf(f, "P6\n%d %d\n255\n", pix->w, pix->h);
	for (y = 0; y < pix->h; y++)
		for (x = 0; x < pix->w; x++)
		{
			putc(255 - pix->samples[x + y * pix->stride], f);
			putc(255 - pix->samples[x + y * pix->stride], f);
			putc(255 - pix->samples[x + y * pix->stride], f);
		}
	fclose(f);
}

