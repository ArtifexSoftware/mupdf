#include <fitz.h>

/*
 * polygon clipping
 */

enum { IN, OUT, ENTER, LEAVE };
enum { MAXV = 3 + 4 };
enum { MAXN = 2 + FZ_MAXCOLORS };

typedef struct { float v[MAXV][MAXN]; } polygon;

static inline float winding(float *a, float *b, float *c)
{
	return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0]);
}

static inline float sideline(float *v, float *a, float *b)
{
	return (a[1] - v[1]) * (b[0] - a[0]) - (a[0] - v[0]) * (b[1] - a[1]);
}

static int clipline(float *c1, float *c2, float *v1, float *v2, int n)
{
	float a, b, c, d1, d2, t;
	int v1o, v2o;
	int i;

	/* cross */
	v1o = sideline(v1, c1, c2) > 1.0;
	v2o = sideline(v2, c1, c2) > 1.0;

	if (v1o + v2o == 0)
		return IN;

	if (v1o + v2o == 2)
		return OUT;

	/* ax + by + c = 0 */
	a = (c2[1] - c1[1]);
	b = (c1[0] - c2[0]);
	c = (c2[0] * c1[1]) - (c1[0] * c2[1]);

	/* distance */
	d1 = fabs(a * v1[0] + b * v1[1] + c);
	d2 = fabs(a * v2[0] + b * v2[1] + c);

	if (v2o)
	{
		t = d1 / (d1 + d2);
		for (i = 0; i < n; i++)
			v2[i] = v1[i] + t * (v2[i] - v1[i]);
		return LEAVE;
	}

	else
	{
		t = d2 / (d1 + d2);
		for (i = 0; i < n; i++)
			v1[i] = v2[i] + t * (v1[i] - v2[i]);
		return ENTER;
	}
}

static inline void copyvert(float *dst, float *src, int n)
{
	while (n--)
		*dst++ = *src++;
}

static int clippoly(float *c1, float *c2, polygon *src, polygon *dst, int len, int n)
{
	float cv1[MAXN];
	float cv2[MAXN];
	int v1, v2, cp;

	v1 = len - 1;
	cp = 0;

	for (v2 = 0; v2 < len; v2++)
	{
		copyvert(cv1, src->v[v1], n);
		copyvert(cv2, src->v[v2], n);
		switch (clipline(c1, c2, cv1, cv2, n))
		{
			case IN:
				copyvert(dst->v[cp++], cv2, n);
				break;
			case OUT:
				break;
			case LEAVE:
				copyvert(dst->v[cp++], cv2, n);
				break;
			case ENTER:
				copyvert(dst->v[cp++], cv1, n);
				copyvert(dst->v[cp++], cv2, n);
				break;
		}
		v1 = v2;
	}

	return cp;
}

/*
 * gouraud shaded polygon scan conversion
 */

static inline void
drawscan(fz_pixmap *pix, int y, int x1, int x2, int *v1, int *v2, int n)
{
	unsigned char *p = pix->samples + ((y - pix->y) * pix->w + (x1 - pix->x)) * pix->n;
	int v[FZ_MAXCOLORS];
	int dv[FZ_MAXCOLORS];
	int w = x2 - x1;
	int k;

	for (k = 0; k < n; k++)
	{
		v[k] = v1[k];
		dv[k] = (v2[k] - v1[k]) / w;
	}

	while (w--)
	{
		*p++ = 255;
		for (k = 0; k < n; k++)
		{
			*p++ = v[k] >> 16;
			v[k] += dv[k];
		}
	}
}

void
fz_drawtriangle(fz_pixmap *pix, float *av, float *bv, float *cv, int n)
{
	int i, k;
	polygon poly;
	polygon temp;
	float clip[4][2];
	int vert[MAXV][MAXN];
	int len;

	int top, bot;
	int sv1, sv2;
	int ev1, ev2;

	int y, diffy1, diffy2;
	int x1, x2, dx1, dx2;
	int v1[MAXN], d1[MAXN];
	int v2[MAXN], d2[MAXN];

	/*
	 * Round coords and correct winding order
	 */

	av[0] = fz_floor(av[0]);
	av[1] = fz_floor(av[1]);
	bv[0] = fz_floor(bv[0]);
	bv[1] = fz_floor(bv[1]);
	cv[0] = fz_floor(cv[0]);
	cv[1] = fz_floor(cv[1]);

	if (winding(av, bv, cv) > 0)
		for (i = 0; i < n; i++)
		{
			poly.v[0][i] = av[i];
			poly.v[1][i] = bv[i];
			poly.v[2][i] = cv[i];
		}
	else
		for (i = 0; i < n; i++)
		{
			poly.v[0][i] = av[i];
			poly.v[1][i] = cv[i];
			poly.v[2][i] = bv[i];
		}

	/*
	 * Clip triangle
	 */

	clip[0][0] = pix->x;
	clip[0][1] = pix->y;

	clip[1][0] = pix->x + pix->w;
	clip[1][1] = pix->y;

	clip[2][0] = pix->x + pix->w;
	clip[2][1] = pix->y + pix->h;

	clip[3][0] = pix->x;
	clip[3][1] = pix->y + pix->h;

	len = clippoly(clip[0], clip[1], &poly, &temp, 3, n);
	len = clippoly(clip[1], clip[2], &temp, &poly, len, n);
	len = clippoly(clip[2], clip[3], &poly, &temp, len, n);
	len = clippoly(clip[3], clip[0], &temp, &poly, len, n);

	if (len < 3)
		return;

	/*
	 * Init scan conversion
	 */

	for (i = 0; i < len; i++)
	{
		vert[i][0] = poly.v[i][0];
		vert[i][1] = poly.v[i][1];
		for (k = 2; k < n; k++)
			vert[i][k] = poly.v[i][k] * 65536;
	}

	top = bot = 0;
	for (i = 0; i < len; i++)
	{
		if (vert[i][1] < vert[top][1])
			 top = i;
		if (vert[i][1] > vert[bot][1])
			 bot = i;
	}

	y = vert[top][1];
	sv1 = ev1 = top;
	sv2 = ev2 = top;

	x1 = x2 = dx1 = dx2 = 0;	/* silence compiler */

	goto start;

	/*
	 * Loopetyloop
	 */

	while (sv1 != bot && sv2 != bot)
	{
		drawscan(pix, y, x1 >> 16, x2 >> 16, v1+2, v2+2, n-2);

		y += 1;
		x1 += dx1;
		x2 += dx2;
		for (k = 2; k < n; k++)
		{
			v1[k] += d1[k];
			v2[k] += d2[k];
		}

start:

		while (y >= vert[ev1][1] && sv1 != bot)
		{
			sv1 = ev1;
			ev1 = sv1 == 0 ? len - 1 : sv1 - 1;

			diffy1 = vert[ev1][1] - vert[sv1][1];
			if (diffy1 == 0)
				continue;

			x1 = vert[sv1][0] << 16;
			dx1 = ((vert[ev1][0] - vert[sv1][0]) << 16) / diffy1;

			for (k = 2; k < n; k++)
			{
				v1[k] = vert[sv1][k];
				d1[k] = (vert[ev1][k] - vert[sv1][k]) / diffy1;
			}
		}

		while (y >= vert[ev2][1] && sv2 != bot)
		{
			sv2 = ev2;
			ev2 = sv2 == len - 1 ? 0 : sv2 + 1;

			diffy2 = vert[ev2][1] - vert[sv2][1];
			if (diffy2 == 0)
				continue;

			x2 = vert[sv2][0] << 16;
			dx2 = ((vert[ev2][0] - vert[sv2][0]) << 16) / diffy2;

			for (k = 2; k < n; k++)
			{
				v2[k] = vert[sv2][k];
				d2[k] = (vert[ev2][k] - vert[sv2][k]) / diffy2;
			}
		}
	}
}

/*
 * mesh drawing
 */

fz_error *
fz_rendershade(fz_shade *shade, fz_matrix ctm, fz_colorspace *destcs, fz_pixmap *dest)
{
	unsigned char clut[256][3];
	unsigned char *s, *d;
	fz_error *error;
	fz_pixmap *temp;
	float rgb[3];
	float tri[3][MAXN];
	fz_point p;
	int i, j, k, n;

	assert(dest->n == 4);

	ctm = fz_concat(shade->matrix, ctm);

	if (shade->usefunction)
	{
printf("draw function mesh\n");
		n = 3;
		error = fz_newpixmap(&temp, dest->x, dest->y, dest->w, dest->h, 2);
		if (error)
			return error;
	}
	else if (shade->colorspace != destcs)
	{
printf("draw colorspace mesh\n");
		n = 2 + shade->colorspace->n;
		error = fz_newpixmap(&temp, dest->x, dest->y, dest->w, dest->h,
					shade->colorspace->n + 1);
		if (error)
			return error;
	}
	else
	{
printf("draw direct mesh\n");
		n = 2 + shade->colorspace->n;
		temp = dest;
	}

	fz_clearpixmap(temp);

	for (i = 0; i < shade->meshlen; i++)
	{
		for (k = 0; k < 3; k++)
		{
			p.x = shade->mesh[(i * 3 + k) * n + 0];
			p.y = shade->mesh[(i * 3 + k) * n + 1];
			p = fz_transformpoint(ctm, p);
			tri[k][0] = p.x;
			tri[k][1] = p.y;
			for (j = 2; j < n; j++)
				tri[k][j] = shade->mesh[( i * 3 + k) * n + j] * 255;
		}
		fz_drawtriangle(temp, tri[0], tri[1], tri[2], n);
	}

	if (shade->usefunction)
	{
		for (int i = 0; i < 256; i++)
		{
			fz_convertcolor(shade->colorspace, shade->function[i], destcs, rgb);
			clut[i][0] = rgb[0] * 255;
			clut[i][1] = rgb[1] * 255;
			clut[i][2] = rgb[2] * 255;
		}

		n = temp->w * temp->h;
		s = temp->samples;
		d = dest->samples;

		while (n--)
		{
			d[0] = s[0];
			d[1] = fz_mul255(s[0], clut[s[1]][0]);
			d[2] = fz_mul255(s[0], clut[s[1]][1]);
			d[3] = fz_mul255(s[0], clut[s[1]][2]);
			s += 2;
			d += 4;
		}

		fz_droppixmap(temp);
	}

	else if (shade->colorspace != destcs)
	{
		fz_convertpixmap(shade->colorspace, temp, destcs, dest);
		fz_droppixmap(temp);
	}

	return nil;
}

