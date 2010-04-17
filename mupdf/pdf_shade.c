#include "fitz.h"
#include "mupdf.h"

/* most of this mess is jeong's */

#define HUGENUM 32000
#define BIGNUM 1024

#define NSEGS 32
#define MAX_RAD_SEGS 36

#define SEGMENTATION_DEPTH 2

typedef struct pdf_tensorpatch_s pdf_tensorpatch;

struct pdf_tensorpatch_s
{
	fz_point pole[4][4];
	float color[4][FZ_MAXCOLORS];
};

static void
pdf_setmeshvalue(float *mesh, int i, float x, float y, float t)
{
	mesh[i*3+0] = x;
	mesh[i*3+1] = y;
	mesh[i*3+2] = t;
}

static void
growshademesh(fz_shade *shade, int amount)
{
	if (shade->meshlen + amount < shade->meshcap)
		return;

	if (shade->meshcap == 0)
		shade->meshcap = 1024;

	while (shade->meshlen + amount > shade->meshcap)
		shade->meshcap = (shade->meshcap * 3) / 2;

	shade->mesh = fz_realloc(shade->mesh, sizeof(float) * shade->meshcap);
}

static fz_error
pdf_samplecompositeshadefunction(fz_shade *shade,
	pdf_function *func, float t0, float t1)
{
	fz_error error;
	int i;

	for (i = 0; i < 256; i++)
	{
		float t = t0 + (i / 256.0) * (t1 - t0);

		error = pdf_evalfunction(func, &t, 1, shade->function[i], shade->cs->n);
		if (error)
			return fz_rethrow(error, "unable to evaluate shading function at %g", t);
	}

	return fz_okay;
}

static fz_error
pdf_samplecomponentshadefunction(fz_shade *shade,
	int funcs, pdf_function **func, float t0, float t1)
{
	fz_error error;
	int i, k;

	for (i = 0; i < 256; i++)
	{
		float t = t0 + (i / 256.0) * (t1 - t0);

		for (k = 0; k < funcs; k++)
		{
			error = pdf_evalfunction(func[k], &t, 1, &shade->function[i][k], 1);
			if (error)
				return fz_rethrow(error, "unable to evaluate shading function at %g", t);
		}
	}

	return fz_okay;
}

static fz_error
pdf_sampleshadefunction(fz_shade *shade, int funcs, pdf_function **func, float t0, float t1)
{
	fz_error error;

	shade->usefunction = 1;

	if (funcs == 1)
		error = pdf_samplecompositeshadefunction(shade, func[0], t0, t1);
	else
		error = pdf_samplecomponentshadefunction(shade, funcs, func, t0, t1);

	if (error)
		return fz_rethrow(error, "cannot sample shading function");

	return fz_okay;
}

static fz_error
pdf_loadtype1shade(fz_shade *shade, pdf_xref *xref,
	float *domain, fz_matrix matrix, pdf_function *func)
{
	fz_error error;
	int xx, yy;
	float x, y;
	float xn, yn;
	float x0, y0, x1, y1;
	int n;
	int ncomp;

	pdf_logshade("load type1 shade {\n");

	ncomp = shade->cs->n;

	x0 = domain[0];
	x1 = domain[1];
	y0 = domain[2];
	y1 = domain[3];

	pdf_logshade("domain %g %g %g %g\n", x0, x1, y0, y1);
	pdf_logshade("matrix [%g %g %g %g %g %g]\n",
			matrix.a, matrix.b, matrix.c,
			matrix.d, matrix.e, matrix.f);

	shade->meshlen = NSEGS * NSEGS * 2;
	shade->mesh = fz_malloc(sizeof(float) * (2 + ncomp) * 3 * shade->meshlen);

#define ADD_VERTEX(xx, yy) \
			{\
				fz_point p;\
				float cp[2], cv[FZ_MAXCOLORS];\
				int c;\
				p.x = xx;\
				p.y = yy;\
				p = fz_transformpoint(matrix, p);\
				shade->mesh[n++] = p.x;\
				shade->mesh[n++] = p.y;\
				\
				cp[0] = xx;\
				cp[1] = yy;\
				error = pdf_evalfunction(func, cp, 2, cv, ncomp);\
				if (error) \
					return fz_rethrow(error, "unable to evaluate shading function"); \
				\
				for (c = 0; c < ncomp; c++)\
				{\
					shade->mesh[n++] = cv[c];\
				}\
			}

	n = 0;
	for (yy = 0; yy < NSEGS; yy++)
	{
		y = y0 + (y1 - y0) * yy / (float)NSEGS;
		yn = y0 + (y1 - y0) * (yy + 1) / (float)NSEGS;
		for (xx = 0; xx < NSEGS; xx++)
		{
			x = x0 + (x1 - x0) * (xx / (float)NSEGS);
			xn = x0 + (x1 - x0) * (xx + 1) / (float)NSEGS;

			ADD_VERTEX(x, y);
			ADD_VERTEX(xn, y);
			ADD_VERTEX(xn, yn);

			ADD_VERTEX(x, y);
			ADD_VERTEX(xn, yn);
			ADD_VERTEX(x, yn);
		}
	}

#undef ADD_VERTEX

	pdf_logshade("}\n");

	return fz_okay;
}

static fz_error
pdf_loadtype2shade(fz_shade *shade, pdf_xref *xref,
	float *coords, float *domain, int funcs, pdf_function **func, int *extend)
{
	fz_point p1, p2, p3, p4;
	fz_point ep1, ep2, ep3, ep4;
	float x0, y0, x1, y1;
	float t0, t1;
	int e0, e1;
	float theta;
	float dist;
	int n;
	fz_error error;

	pdf_logshade("load type2 shade {\n");

	x0 = coords[0];
	y0 = coords[1];
	x1 = coords[2];
	y1 = coords[3];

	t0 = domain[0];
	t1 = domain[1];

	e0 = extend[0];
	e1 = extend[1];

	pdf_logshade("coords %g %g %g %g\n", x0, y0, x1, y1);
	pdf_logshade("domain %g %g\n", t0, t1);
	pdf_logshade("extend %d %d\n", e0, e1);

	error = pdf_sampleshadefunction(shade, funcs, func, t0, t1);
	if (error)
		return fz_rethrow(error, "unable to sample shading function");

	theta = atan2(y1 - y0, x1 - x0);
	theta += M_PI / 2.0;

	pdf_logshade("theta=%g\n", theta);

	dist = hypot(x1 - x0, y1 - y0);

	/* if the axis has virtually length 0 (a point),
	do not extend as there is nothing to extend beyond */
	if (dist < FLT_EPSILON)
	{
		e0 = 0;
		e1 = 0;
	}

	shade->meshlen = 2 + e0 * 2 + e1 * 2;
	shade->mesh = fz_malloc(sizeof(float) * 3*3 * shade->meshlen);

	p1.x = x0 + HUGENUM * cos(theta);
	p1.y = y0 + HUGENUM * sin(theta);
	p2.x = x1 + HUGENUM * cos(theta);
	p2.y = y1 + HUGENUM * sin(theta);
	p3.x = x0 - HUGENUM * cos(theta);
	p3.y = y0 - HUGENUM * sin(theta);
	p4.x = x1 - HUGENUM * cos(theta);
	p4.y = y1 - HUGENUM * sin(theta);

	pdf_logshade("p1 %g %g\n", p1.x, p1.y);
	pdf_logshade("p2 %g %g\n", p2.x, p2.y);
	pdf_logshade("p3 %g %g\n", p3.x, p3.y);
	pdf_logshade("p4 %g %g\n", p4.x, p4.y);

	n = 0;

	/* if the axis has virtually length 0 (a point), use the same axis
	position t = 0 for all triangle vertices */
	if (dist < FLT_EPSILON)
	{
		pdf_setmeshvalue(shade->mesh, n++, p1.x, p1.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p2.x, p2.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p4.x, p4.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p1.x, p1.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p4.x, p4.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p3.x, p3.y, 0);
	}
	else
	{
		pdf_setmeshvalue(shade->mesh, n++, p1.x, p1.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p2.x, p2.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, p4.x, p4.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, p1.x, p1.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p4.x, p4.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, p3.x, p3.y, 0);
	}

	if (e0)
	{
		ep1.x = p1.x - (x1 - x0) / dist * HUGENUM;
		ep1.y = p1.y - (y1 - y0) / dist * HUGENUM;
		ep3.x = p3.x - (x1 - x0) / dist * HUGENUM;
		ep3.y = p3.y - (y1 - y0) / dist * HUGENUM;

		pdf_setmeshvalue(shade->mesh, n++, ep1.x, ep1.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p1.x, p1.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p3.x, p3.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, ep1.x, ep1.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, p3.x, p3.y, 0);
		pdf_setmeshvalue(shade->mesh, n++, ep3.x, ep3.y, 0);
	}

	if (e1)
	{
		ep2.x = p2.x + (x1 - x0) / dist * HUGENUM;
		ep2.y = p2.y + (y1 - y0) / dist * HUGENUM;
		ep4.x = p4.x + (x1 - x0) / dist * HUGENUM;
		ep4.y = p4.y + (y1 - y0) / dist * HUGENUM;

		pdf_setmeshvalue(shade->mesh, n++, p2.x, p2.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, ep2.x, ep2.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, ep4.x, ep4.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, p2.x, p2.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, ep4.x, ep4.y, 1);
		pdf_setmeshvalue(shade->mesh, n++, p4.x, p4.y, 1);
	}

	pdf_logshade("}\n");

	return fz_okay;
}

static int
buildannulusmesh(float* mesh, int pos,
	float x0, float y0, float r0, float x1, float y1, float r1,
	float c0, float c1, int nomesh)
{
	int n = pos * 3;
	float dist = hypot(x1 - x0, y1 - y0);
	float step;
	float theta;
	int i;

	if (dist != 0)
		theta = asin((r1 - r0) / dist) + M_PI/2.0 + atan2(y1 - y0, x1 - x0);
	else
		theta = 0;

	if (!(theta >= 0 && theta <= M_PI))
		theta = 0;

	step = M_PI * 2. / (float)MAX_RAD_SEGS;

	for (i = 0; i < MAX_RAD_SEGS; theta -= step, i++)
	{
		fz_point pt1, pt2, pt3, pt4;

		pt1.x = cos (theta) * r1 + x1;
		pt1.y = sin (theta) * r1 + y1;
		pt2.x = cos (theta) * r0 + x0;
		pt2.y = sin (theta) * r0 + y0;
		pt3.x = cos (theta+step) * r1 + x1;
		pt3.y = sin (theta+step) * r1 + y1;
		pt4.x = cos (theta+step) * r0 + x0;
		pt4.y = sin (theta+step) * r0 + y0;

		if (r0 > 0)
		{
			if (!nomesh)
			{
				pdf_setmeshvalue(mesh, n++, pt1.x, pt1.y, c1);
				pdf_setmeshvalue(mesh, n++, pt2.x, pt2.y, c0);
				pdf_setmeshvalue(mesh, n++, pt4.x, pt4.y, c0);
			}
			pos++;
		}

		if (r1 > 0)
		{
			if (!nomesh)
			{
				pdf_setmeshvalue(mesh, n++, pt1.x, pt1.y, c1);
				pdf_setmeshvalue(mesh, n++, pt3.x, pt3.y, c1);
				pdf_setmeshvalue(mesh, n++, pt4.x, pt4.y, c0);
			}
			pos++;
		}
	}

	return pos;
}

static fz_error
pdf_loadtype3shade(fz_shade *shade, pdf_xref *xref,
	float *coords, float *domain, int funcs, pdf_function **func, int *extend)
{
	float x0, y0, r0, x1, y1, r1;
	float t0, t1;
	int e0, e1;
	float ex0, ey0, er0;
	float ex1, ey1, er1;
	float rs;
	int i;
	fz_error error;

	pdf_logshade("load type3 shade {\n");

	x0 = coords[0];
	y0 = coords[1];
	r0 = coords[2];
	x1 = coords[3];
	y1 = coords[4];
	r1 = coords[5];

	pdf_logshade("coords %g %g %g  %g %g %g\n", x0, y0, r0, x1, y1, r1);

	t0 = domain[0];
	t1 = domain[1];

	e0 = extend[0];
	e1 = extend[1];

	pdf_logshade("domain %g %g\n", t0, t1);
	pdf_logshade("extend %d %d\n", e0, e1);

	error = pdf_sampleshadefunction(shade, funcs, func, t0, t1);
	if (error)
		return fz_rethrow(error, "unable to sample shading function");

	if (r0 < r1)
		rs = r0 / (r0 - r1);
	else
		rs = -HUGENUM;

	ex0 = x0 + (x1 - x0) * rs;
	ey0 = y0 + (y1 - y0) * rs;
	er0 = r0 + (r1 - r0) * rs;

	if (r0 > r1)
		rs = r1 / (r1 - r0);
	else
		rs = -HUGENUM;

	ex1 = x1 + (x0 - x1) * rs;
	ey1 = y1 + (y0 - y1) * rs;
	er1 = r1 + (r0 - r1) * rs;

	for (i=0; i<2; i++)
	{
		int pos = 0;
		if (e0)
			pos = buildannulusmesh(shade->mesh, pos, ex0, ey0, er0, x0, y0, r0, 0, 0, 1-i);
		pos = buildannulusmesh(shade->mesh, pos, x0, y0, r0, x1, y1, r1, 0, 1., 1-i);
		if (e1)
			pos = buildannulusmesh(shade->mesh, pos, x1, y1, r1, ex1, ey1, er1, 1., 1., 1-i);

		if (i == 0)
		{
			shade->meshlen = pos;
			shade->mesh = fz_malloc(sizeof(float) * 9 * shade->meshlen);
		}
	}

	pdf_logshade("}\n");

	return fz_okay;
}

static int
getdata(fz_stream *stream, int bps)
{
	unsigned int bitmask = (1 << bps) - 1;
	unsigned int buf = 0;
	int bits = 0;
	int s;

	while (bits < bps)
	{
		buf = (buf << 8) | (fz_readbyte(stream) & 0xff); // TODO: EOF? No? Oh, ok...
		bits += 8;
	}
	s = buf >> (bits - bps);
	if (bps < 32)
		s = s & bitmask;
	bits -= bps;

	return s;
}

static fz_error
pdf_loadtype4shade(fz_shade *shade, pdf_xref *xref,
	int bpcoord, int bpcomp, int bpflag, float *decode,
	int funcs, pdf_function **func, fz_stream *stream)
{
	fz_error error;
	int ncomp;
	float x0, x1, y0, y1;
	float c0[FZ_MAXCOLORS];
	float c1[FZ_MAXCOLORS];
	int i;
	int bitspervertex;
	int bytepervertex;
	int n, j;
	float cval[FZ_MAXCOLORS];

	int flag;
	unsigned int t;
	float x, y;

	pdf_logshade("load type4 shade {\n");

	ncomp = shade->cs->n;

	x0 = decode[0];
	x1 = decode[1];
	y0 = decode[2];
	y1 = decode[3];
	for (i = 0; i < ncomp; i++)
	{
		c0[i] = decode[4 + i * 2 + 0];
		c1[i] = decode[4 + i * 2 + 1];
	}

	pdf_logshade("decode [%g %g %g %g", x0, x1, y0, y1);
	for (i = 0; i < ncomp; i++)
		pdf_logshade(" %g %g", c0[i], c1[i]);
	pdf_logshade("]\n");

	if (funcs > 0)
	{
		ncomp = 1;
		error = pdf_sampleshadefunction(shade, funcs, func, c0[0], c1[0]);
		if (error)
			return fz_rethrow(error, "cannot load shading function");
	}

	bitspervertex = bpflag + bpcoord * 2 + bpcomp * ncomp;
	bytepervertex = (bitspervertex+7) / 8;

	shade->meshlen = 0;
	shade->meshcap = 0;
	shade->mesh = nil;

	n = 2 + ncomp;
	j = 0;

	while (fz_peekbyte(stream) != EOF)
	{
		flag = getdata(stream, bpflag);

		t = getdata(stream, bpcoord);
		x = x0 + (t * (x1 - x0) / (pow(2, 24) - 1));

		t = getdata(stream, bpcoord);
		y = y0 + (t * (y1 - y0) / (pow(2, 24) - 1));

		for (i = 0; i < ncomp; i++)
		{
			t = getdata(stream, bpcomp);
			cval[i] = t / (double)(pow(2, 16) - 1);
		}

		if (flag == 0)
		{
			growshademesh(shade, 2 + ncomp);
			shade->mesh[j++] = x;
			shade->mesh[j++] = y;
			for (i=0; i < ncomp; i++)
			{
				shade->mesh[j++] = cval[i];
			}
		}
		if (flag == 1)
		{
			growshademesh(shade, 3 * (2 + ncomp));
			memcpy(&(shade->mesh[j]), &(shade->mesh[j - 2 * n]), n * sizeof(float));
			memcpy(&(shade->mesh[j + 1 * n]), &(shade->mesh[j - 1 * n]), n * sizeof(float));
			j+= 2 * n;
			shade->mesh[j++] = x;
			shade->mesh[j++] = y;
			for (i=0; i < ncomp; i++)
			{
				shade->mesh[j++] = cval[i];
			}
		}
		if (flag == 2)
		{
			growshademesh(shade, 3 * (2 + ncomp));
			memcpy(&(shade->mesh[j]), &(shade->mesh[j - 3 * n]), n * sizeof(float));
			memcpy(&(shade->mesh[j + 1 * n]), &(shade->mesh[j - 1 * n]), n * sizeof(float));
			j+= 2 * n;
			shade->mesh[j++] = x;
			shade->mesh[j++] = y;
			for (i=0; i < ncomp; i++)
			{
				shade->mesh[j++] = cval[i];
			}
		}
	}

	shade->meshlen = j / n / 3;

	pdf_logshade("}\n");

	return fz_okay;
}

static fz_error
pdf_loadtype5shade(fz_shade *shade, pdf_xref *xref,
	int bpcoord, int bpcomp, int vprow, float *decode,
	int funcs, pdf_function **func, fz_stream *stream)
{
	fz_error error;
	int vpc;
	int ncomp;
	float x0, x1, y0, y1;
	float c0[FZ_MAXCOLORS];
	float c1[FZ_MAXCOLORS];
	int i, n, j;
	int p, q;
	unsigned int t;
	float *x, *y, *c[FZ_MAXCOLORS];

	pdf_logshade("load type5 shade {\n");

	ncomp = shade->cs->n;

	x0 = decode[0];
	x1 = decode[1];
	y0 = decode[2];
	y1 = decode[3];
	for (i = 0; i < ncomp; i++)
	{
		c0[i] = decode[4 + i * 2 + 0];
		c1[i] = decode[4 + i * 2 + 1];
	}

	pdf_logshade("decode [%g %g %g %g", x0, x1, y0, y1);
	for (i = 0; i < ncomp; i++)
		pdf_logshade(" %g %g", c0[i], c1[i]);
	pdf_logshade("]\n");

	if (funcs > 0)
	{
		ncomp = 1;
		error = pdf_sampleshadefunction(shade, funcs, func, c0[0], c1[0]);
		if (error)
			return fz_rethrow(error, "cannot sample shading function");
	}

	n = 2 + ncomp;
	j = 0;

	x = fz_malloc(sizeof(float) * vprow * BIGNUM);
	y = fz_malloc(sizeof(float) * vprow * BIGNUM);
	for (i = 0; i < ncomp; i++)
	{
		c[i] = fz_malloc(sizeof(float) * vprow * BIGNUM);
	}
	q = 0;

	while (fz_peekbyte(stream) != EOF)
	{
		for (p = 0; p < vprow; p++)
		{
			int idx;
			idx = q * vprow + p;

			t = getdata(stream, bpcoord);
			x[idx] = x0 + (t * (x1 - x0) / ((float)pow(2, bpcoord) - 1));
			t = getdata(stream, bpcoord);
			y[idx] = y0 + (t * (y1 - y0) / ((float)pow(2, bpcoord) - 1));

			for (i=0; i < ncomp; i++)
			{
				t = getdata(stream, bpcomp);
				c[i][idx] = c0[i] + (t * (c1[i] - c0[i]) / (float)(pow(2, bpcomp) - 1));
			}
		}
		q++;
	}

	vpc = q;

	shade->meshlen = 0;
	shade->meshcap = 0;
	shade->mesh = nil;

#define ADD_VERTEX(idx) \
			{\
				int z;\
				growshademesh(shade, 2 + ncomp); \
				shade->mesh[j++] = x[idx];\
				shade->mesh[j++] = y[idx];\
				for (z = 0; z < ncomp; z++) \
					shade->mesh[j++] = c[z][idx];\
				shade->meshlen += 2 + ncomp; \
			}

	j = 0;
	for (p = 0; p < vprow-1; p++)
	{
		for (q = 0; q < vpc-1; q++)
		{
			ADD_VERTEX(q * vprow + p);
			ADD_VERTEX(q * vprow + p + 1);
			ADD_VERTEX((q + 1) * vprow + p + 1);

			ADD_VERTEX(q * vprow + p);
			ADD_VERTEX((q + 1) * vprow + p + 1);
			ADD_VERTEX((q + 1) * vprow + p);
		}
	}

#undef ADD_VERTEX

	shade->meshlen /= n;
	shade->meshlen /= 3;

	for (i = 0; i < ncomp; i++)
		free(c[i]);

	fz_free(x);
	fz_free(y);

	pdf_logshade("}\n");

	return fz_okay;
}

static inline void copyvert(float *dst, float *src, int n)
{
	while (n--)
		*dst++ = *src++;
}

static inline void copycolor(float *c, const float *s)
{
	int i;
	for (i = 0; i<FZ_MAXCOLORS; i++)
		c[i] = s[i];
}

static inline void midcolor(float *c, const float *c1, const float *c2)
{
	int i;
	for (i = 0; i<FZ_MAXCOLORS; i++)
		c[i] = (float)((c1[i] + c2[i]) / 2.0);
}

static void
filltensorinterior(pdf_tensorpatch *p)
{
#define lcp1(p0, p3)\
	((p0 + p0 + p3) / 3.0f)

#define lcp2(p0, p3)\
	((p0 + p3 + p3) / 3.0f)

	p->pole[1][1].x = lcp1(p->pole[0][1].x, p->pole[3][1].x) +
	lcp1(p->pole[1][0].x, p->pole[1][3].x) -
	lcp1(lcp1(p->pole[0][0].x, p->pole[0][3].x),
		lcp1(p->pole[3][0].x, p->pole[3][3].x));
	p->pole[1][2].x = lcp1(p->pole[0][2].x, p->pole[3][2].x) +
	lcp2(p->pole[1][0].x, p->pole[1][3].x) -
	lcp1(lcp2(p->pole[0][0].x, p->pole[0][3].x),
		lcp2(p->pole[3][0].x, p->pole[3][3].x));
	p->pole[2][1].x = lcp2(p->pole[0][1].x, p->pole[3][1].x) +
	lcp1(p->pole[2][0].x, p->pole[2][3].x) -
	lcp2(lcp1(p->pole[0][0].x, p->pole[0][3].x),
		lcp1(p->pole[3][0].x, p->pole[3][3].x));
	p->pole[2][2].x = lcp2(p->pole[0][2].x, p->pole[3][2].x) +
	lcp2(p->pole[2][0].x, p->pole[2][3].x) -
	lcp2(lcp2(p->pole[0][0].x, p->pole[0][3].x),
		lcp2(p->pole[3][0].x, p->pole[3][3].x));

	p->pole[1][1].y = lcp1(p->pole[0][1].y, p->pole[3][1].y) +
	lcp1(p->pole[1][0].y, p->pole[1][3].y) -
	lcp1(lcp1(p->pole[0][0].y, p->pole[0][3].y),
		lcp1(p->pole[3][0].y, p->pole[3][3].y));
	p->pole[1][2].y = lcp1(p->pole[0][2].y, p->pole[3][2].y) +
	lcp2(p->pole[1][0].y, p->pole[1][3].y) -
	lcp1(lcp2(p->pole[0][0].y, p->pole[0][3].y),
		lcp2(p->pole[3][0].y, p->pole[3][3].y));
	p->pole[2][1].y = lcp2(p->pole[0][1].y, p->pole[3][1].y) +
	lcp1(p->pole[2][0].y, p->pole[2][3].y) -
	lcp2(lcp1(p->pole[0][0].y, p->pole[0][3].y),
		lcp1(p->pole[3][0].y, p->pole[3][3].y));
	p->pole[2][2].y = lcp2(p->pole[0][2].y, p->pole[3][2].y) +
	lcp2(p->pole[2][0].y, p->pole[2][3].y) -
	lcp2(lcp2(p->pole[0][0].y, p->pole[0][3].y),
		lcp2(p->pole[3][0].y, p->pole[3][3].y));

#undef lcp1
#undef lcp2
}

static void
split_curve_s(const fz_point *pole, fz_point *q0, fz_point *q1, int pole_step)
{
#define midpoint(a,b)\
	((a)/2.0f + (b)/2.0f) /* to avoid overflow */
	float x12 = midpoint(pole[1 * pole_step].x, pole[2 * pole_step].x);
	float y12 = midpoint(pole[1 * pole_step].y, pole[2 * pole_step].y);

	q0[1 * pole_step].x = midpoint(pole[0 * pole_step].x, pole[1 * pole_step].x);
	q0[1 * pole_step].y = midpoint(pole[0 * pole_step].y, pole[1 * pole_step].y);
	q1[2 * pole_step].x = midpoint(pole[2 * pole_step].x, pole[3 * pole_step].x);
	q1[2 * pole_step].y = midpoint(pole[2 * pole_step].y, pole[3 * pole_step].y);
	q0[2 * pole_step].x = midpoint(q0[1 * pole_step].x, x12);
	q0[2 * pole_step].y = midpoint(q0[1 * pole_step].y, y12);
	q1[1 * pole_step].x = midpoint(x12, q1[2 * pole_step].x);
	q1[1 * pole_step].y = midpoint(y12, q1[2 * pole_step].y);
	q0[0 * pole_step].x = pole[0 * pole_step].x;
	q0[0 * pole_step].y = pole[0 * pole_step].y;
	q0[3 * pole_step].x = q1[0 * pole_step].x = midpoint(q0[2 * pole_step].x, q1[1 * pole_step].x);
	q0[3 * pole_step].y = q1[0 * pole_step].y = midpoint(q0[2 * pole_step].y, q1[1 * pole_step].y);
	q1[3 * pole_step].x = pole[3 * pole_step].x;
	q1[3 * pole_step].y = pole[3 * pole_step].y;
#undef midpoint
}

static inline void
split_patch(pdf_tensorpatch *s0, pdf_tensorpatch *s1, const pdf_tensorpatch *p)
{
	split_curve_s(&p->pole[0][0], &s0->pole[0][0], &s1->pole[0][0], 4);
	split_curve_s(&p->pole[0][1], &s0->pole[0][1], &s1->pole[0][1], 4);
	split_curve_s(&p->pole[0][2], &s0->pole[0][2], &s1->pole[0][2], 4);
	split_curve_s(&p->pole[0][3], &s0->pole[0][3], &s1->pole[0][3], 4);

	copycolor(s0->color[0], p->color[0]);
	midcolor(s0->color[1], p->color[0], p->color[1]);
	midcolor(s0->color[2], p->color[2], p->color[3]);
	copycolor(s0->color[3], p->color[3]);

	copycolor(s1->color[0], s0->color[1]);
	copycolor(s1->color[1], p->color[1]);
	copycolor(s1->color[2], p->color[2]);
	copycolor(s1->color[3], s0->color[2]);
}

static inline void
split_stripe(pdf_tensorpatch *s0, pdf_tensorpatch *s1, const pdf_tensorpatch *p)
{
	split_curve_s(p->pole[0], s0->pole[0], s1->pole[0], 1);
	split_curve_s(p->pole[1], s0->pole[1], s1->pole[1], 1);
	split_curve_s(p->pole[2], s0->pole[2], s1->pole[2], 1);
	split_curve_s(p->pole[3], s0->pole[3], s1->pole[3], 1);

	copycolor(s0->color[0], p->color[0]);
	copycolor(s0->color[1], p->color[1]);
	midcolor(s0->color[2], p->color[1], p->color[2]);
	midcolor(s0->color[3], p->color[0], p->color[3]);

	copycolor(s1->color[0], s0->color[3]);
	copycolor(s1->color[1], s0->color[2]);
	copycolor(s1->color[2], p->color[2]);
	copycolor(s1->color[3], p->color[3]);
}

static inline void
setvertex(float *mesh, fz_point pt, float *color, int ncomp)
{
	int i;

	mesh[0] = pt.x;
	mesh[1] = pt.y;
	for (i=0; i < ncomp; i++)
	{
		mesh[2 + i] = color[i];
	}
}

static void
triangulatepatch(pdf_tensorpatch p, fz_shade *shade, int ncomp)
{
	growshademesh(shade, 6 * (2 + ncomp));

	setvertex(&shade->mesh[shade->meshlen], p.pole[0][0], p.color[0], ncomp);
	shade->meshlen += 2 + ncomp;
	setvertex(&shade->mesh[shade->meshlen], p.pole[3][0], p.color[1], ncomp);
	shade->meshlen += 2 + ncomp;
	setvertex(&shade->mesh[shade->meshlen], p.pole[3][3], p.color[2], ncomp);
	shade->meshlen += 2 + ncomp;

	setvertex(&shade->mesh[shade->meshlen], p.pole[0][0], p.color[0], ncomp);
	shade->meshlen += 2 + ncomp;
	setvertex(&shade->mesh[shade->meshlen], p.pole[3][3], p.color[2], ncomp);
	shade->meshlen += 2 + ncomp;
	setvertex(&shade->mesh[shade->meshlen], p.pole[0][3], p.color[3], ncomp);
	shade->meshlen += 2 + ncomp;
}

static void
drawstripe(pdf_tensorpatch patch, fz_shade *shade, int ncomp, int depth)
{
	pdf_tensorpatch s0, s1;

	split_stripe(&s0, &s1, &patch);

	depth++;

	if (depth >= SEGMENTATION_DEPTH)
	{
		triangulatepatch(s0, shade, ncomp);
		triangulatepatch(s1, shade, ncomp);
	}
	else
	{
		drawstripe(s0, shade, ncomp, depth);
		drawstripe(s1, shade, ncomp, depth);
	}
}

static void
drawpatch(pdf_tensorpatch patch, fz_shade *shade, int ncomp, int depth)
{
	pdf_tensorpatch s0, s1;

	split_patch(&s0, &s1, &patch);
	depth++;

	if (depth > SEGMENTATION_DEPTH)
	{
		drawstripe(s0, shade, ncomp, 0);
		drawstripe(s1, shade, ncomp, 0);
	}
	else
	{
		drawpatch(s0, shade, ncomp, depth);
		drawpatch(s1, shade, ncomp, depth);
	}
}

static fz_error
pdf_loadtype6shade(fz_shade *shade, pdf_xref *xref,
	int bpcoord, int bpcomp, int bpflag, float *decode,
	int funcs, pdf_function **func, fz_stream *stream)
{
	fz_error error;
	int ncomp;
	fz_point p0, p1;
	float c0[FZ_MAXCOLORS];
	float c1[FZ_MAXCOLORS];
	int i, n;
	unsigned int t;
	int flag;
	fz_point p[12];
	pdf_tensorpatch patch;

	pdf_logshade("load type6 shade {\n");

	ncomp = shade->cs->n;

	p0.x = decode[0];
	p1.x = decode[1];
	p0.y = decode[2];
	p1.y = decode[3];
	for (i = 0; i < ncomp; i++)
	{
		c0[i] = decode[4 + i * 2 + 0];
		c1[i] = decode[4 + i * 2 + 1];
	}

	pdf_logshade("decode [%g %g %g %g", p0.x, p1.x, p0.y, p1.y);
	for (i = 0; i < ncomp; i++)
		pdf_logshade(" %g %g", c0[i], c1[i]);
	pdf_logshade("]\n");

	if (funcs > 0)
	{
		ncomp = 1;
		error = pdf_sampleshadefunction(shade, funcs, func, c0[0], c1[0]);
		if (error)
			return fz_rethrow(error, "cannot load shading function");
	}

	shade->meshcap = 0;
	shade->mesh = nil;

	n = 2 + ncomp;

	while (fz_peekbyte(stream) != EOF)
	{
		flag = getdata(stream, bpflag);

		for (i = 0; i < 12; i++)
		{
			t = getdata(stream, bpcoord);
			p[i].x = (float)(p0.x + (t * (p1.x - p0.x) / (pow(2, bpcoord) - 1.)));
			t = getdata(stream, bpcoord);
			p[i].y = (float)(p0.y + (t * (p1.y - p0.y) / (pow(2, bpcoord) - 1.)));
		}

		for (i = 0; i < 4; i++)
		{
			int k;
			for (k=0; k < ncomp; k++)
			{
				t = getdata(stream, bpcomp);
				patch.color[i][k] =
				c0[k] + (t * (c1[k] - c0[k]) / (pow(2, bpcomp) - 1.0f));
			}
		}

		patch.pole[0][0] = p[0];
		patch.pole[1][0] = p[1];
		patch.pole[2][0] = p[2];
		patch.pole[3][0] = p[3];
		patch.pole[3][1] = p[4];
		patch.pole[3][2] = p[5];
		patch.pole[3][3] = p[6];
		patch.pole[2][3] = p[7];
		patch.pole[1][3] = p[8];
		patch.pole[0][3] = p[9];
		patch.pole[0][2] = p[10];
		patch.pole[0][1] = p[11];
		filltensorinterior(&patch);

		drawpatch(patch, shade, ncomp, 0);
	}

	shade->meshlen = shade->meshlen / n / 3;

	pdf_logshade("}\n");

	return fz_okay;
}

static fz_error
pdf_loadtype7shade(fz_shade *shade, pdf_xref *xref,
	int bpcoord, int bpcomp, int bpflag, float *decode,
	int funcs, pdf_function **func, fz_stream *stream)
{
	fz_error error;
	int ncomp;
	float x0, x1, y0, y1;
	float c0[FZ_MAXCOLORS];
	float c1[FZ_MAXCOLORS];
	int i, n;
	unsigned int t;
	int flag;
	fz_point p[16];
	pdf_tensorpatch patch;

	pdf_logshade("load type7 shade {\n");

	ncomp = shade->cs->n;

	x0 = decode[0];
	x1 = decode[1];
	y0 = decode[2];
	y1 = decode[3];
	for (i = 0; i < ncomp; i++)
	{
		c0[i] = decode[4 + i * 2 + 0];
		c1[i] = decode[4 + i * 2 + 1];
	}

	pdf_logshade("decode [%g %g %g %g", x0, x1, y0, y1);
	for (i = 0; i < ncomp; i++)
		pdf_logshade(" %g %g", c0[i], c1[i]);
	pdf_logshade("]\n");

	if (funcs > 0)
	{
		ncomp = 1;
		error = pdf_sampleshadefunction(shade, funcs, func, c0[0], c1[0]);
		if (error)
			return fz_rethrow(error, "cannot load shading function");
	}

	shade->meshcap = 0;
	shade->mesh = nil;

	n = 2 + ncomp;

	while (fz_peekbyte(stream) != EOF)
	{
		flag = getdata(stream, bpflag);

		for (i = 0; i < 16; i++)
		{
			t = getdata(stream, bpcoord);
			p[i].x = x0 + (t * (x1 - x0) / (pow(2, bpcoord) - 1.));
			t = getdata(stream, bpcoord);
			p[i].y = y0 + (t * (y1 - y0) / (pow(2, bpcoord) - 1.));
		}

		for (i = 0; i < 4; i++)
		{
			int k;
			for (k=0; k < ncomp; k++)
			{
				t = getdata(stream, bpcomp);
				patch.color[i][k] =
				c0[k] + (t * (c1[k] - c0[k]) / (pow(2, bpcomp) - 1.0f));
			}
		}

		patch.pole[0][0] = p[0];
		patch.pole[0][1] = p[1];
		patch.pole[0][2] = p[2];
		patch.pole[0][3] = p[3];
		patch.pole[1][3] = p[4];
		patch.pole[2][3] = p[5];
		patch.pole[3][3] = p[6];
		patch.pole[3][2] = p[7];
		patch.pole[3][1] = p[8];
		patch.pole[3][0] = p[9];
		patch.pole[2][0] = p[10];
		patch.pole[1][0] = p[11];
		patch.pole[1][1] = p[12];
		patch.pole[1][2] = p[13];
		patch.pole[2][2] = p[14];
		patch.pole[2][1] = p[15];

		drawpatch(patch, shade, ncomp, 0);
	}

	shade->meshlen = shade->meshlen / n / 3;

	pdf_logshade("}\n");

	return fz_okay;
}

static fz_error
parsedecode(fz_obj *obj, int ncomp, float *decode)
{
	int i;

	decode[0] = fz_toreal(fz_arrayget(obj, 0));
	decode[1] = fz_toreal(fz_arrayget(obj, 1));
	decode[2] = fz_toreal(fz_arrayget(obj, 2));
	decode[3] = fz_toreal(fz_arrayget(obj, 3));

	for (i = 0; i < MIN(fz_arraylen(obj) / 2, ncomp); i++)
	{
		decode[4 + i * 2 + 0] = fz_toreal(fz_arrayget(obj, i * 2 + 4));
		decode[4 + i * 2 + 1] = fz_toreal(fz_arrayget(obj, i * 2 + 5));
	}

	return fz_okay;
}


static fz_error
pdf_loadshadedict(fz_shade **shadep, pdf_xref *xref, fz_obj *dict, fz_matrix transform)
{
	fz_error error;
	fz_shade *shade;
	float decode[4 + 2 * FZ_MAXCOLORS] = {0}; // [x0 x1 y0 y1 c1[0] c1[1] ... cn[0] cn[1]]
	float coords[6] = {0}; // [x0 y0 x1 y1] or [x0 y0 r0 x1 y1 r1]
	float domain[6] = {0}; // [x0 x1 y0 y1] or [t0 t1]
	int extend[2] = {0}; // [e0 e1]
	pdf_function *func[FZ_MAXCOLORS] = { nil };
	fz_stream *stream = nil;
	fz_matrix matrix;
	int bpcoord = 0;
	int bpcomp = 0;
	int bpflag = 0;
	int vprow = 0;
	fz_obj *obj;
	int funcs;
	int type;
	int i;

	pdf_logshade("load shade dict (%d %d R) {\n", fz_tonum(dict), fz_togen(dict));

	shade = fz_malloc(sizeof(fz_shade));
	shade->refs = 1;
	shade->usebackground = 0;
	shade->usefunction = 0;
	shade->matrix = transform;
	shade->bbox = fz_infiniterect;

	shade->meshlen = 0;
	shade->meshcap = 0;
	shade->mesh = nil;

	shade->cs = nil;

	obj = fz_dictgets(dict, "ShadingType");
	type = fz_toint(obj);
	pdf_logshade("type %d\n", type);

	obj = fz_dictgets(dict, "ColorSpace");
	error = pdf_loadcolorspace(&shade->cs, xref, obj);
	if (error)
	{
		fz_dropshade(shade);
		return fz_rethrow(error, "cannot load colorspace");
	}
	pdf_logshade("colorspace %s\n", shade->cs->name);

	obj = fz_dictgets(dict, "Background");
	if (obj)
	{
		pdf_logshade("background\n");
		shade->usebackground = 1;
		for (i = 0; i < shade->cs->n; i++)
			shade->background[i] = fz_toreal(fz_arrayget(obj, i));
	}

	obj = fz_dictgets(dict, "BBox");
	if (fz_isarray(obj))
	{
		shade->bbox = pdf_torect(obj);
		pdf_logshade("bbox [%g %g %g %g]\n",
			shade->bbox.x0, shade->bbox.y0,
			shade->bbox.x1, shade->bbox.y1);
	}

	domain[0] = 0.0;
	domain[1] = 1.0;
	domain[2] = 0.0;
	domain[3] = 1.0;

	obj = fz_dictgets(dict, "Domain");
	if (fz_isarray(obj))
	{
		for (i = 0; i < MIN(nelem(domain), fz_arraylen(obj)); i++)
			domain[i] = fz_toreal(fz_arrayget(obj, i));
	}

	matrix = fz_identity();

	obj = fz_dictgets(dict, "Matrix");
	if (fz_isarray(obj))
		matrix = pdf_tomatrix(obj);

	obj = fz_dictgets(dict, "Coords");
	if (fz_isarray(obj))
	{
		for (i = 0; i < MIN(nelem(domain), fz_arraylen(obj)); i++)
			coords[i] = fz_toreal(fz_arrayget(obj, i));
	}

	obj = fz_dictgets(dict, "Extend");
	if (fz_isarray(obj))
	{
		extend[0] = fz_tobool(fz_arrayget(obj, 0));
		extend[1] = fz_tobool(fz_arrayget(obj, 1));
	}

	bpcoord = fz_toint(fz_dictgets(dict, "BitsPerCoordinate"));
	bpcomp = fz_toint(fz_dictgets(dict, "BitsPerComponent"));
	bpflag = fz_toint(fz_dictgets(dict, "BitsPerFlag"));
	vprow = fz_toint(fz_dictgets(dict, "VerticesPerRow"));
	if (type == 5 && vprow < 2)
	{
		error = fz_throw("VerticesPerRow must be greater than or equal to 2");
		goto cleanup;
	}

	obj = fz_dictgets(dict, "Decode");
	if (fz_isarray(obj))
	{
		error = parsedecode(obj, shade->cs->n, decode);
		if (error)
		{
			error = fz_rethrow(error, "cannot parse shading decode");
			goto cleanup;
		}
	}
	else if (type >=4 && type <=7 )
		fz_warn("shading vertex color decoding invalid, continuing...");

	funcs = 0;

	obj = fz_dictgets(dict, "Function");
	if (fz_isdict(obj))
	{
		funcs = 1;

		error = pdf_loadfunction(&func[0], xref, obj);
		if (error)
		{
			error = fz_rethrow(error, "cannot load shading function");
			goto cleanup;
		}
	}
	else if (fz_isarray(obj))
	{
		funcs = fz_arraylen(obj);
		if (funcs != 1 && funcs != shade->cs->n)
		{
			error = fz_throw("incorrect number of shading functions");
			goto cleanup;
		}

		for (i = 0; i < funcs; i++)
		{
			error = pdf_loadfunction(&func[i], xref, fz_arrayget(obj, i));
			if (error)
			{
				error = fz_rethrow(error, "cannot load shading function");
				goto cleanup;
			}
		}
	}

	if (type >= 4 && type <= 7)
	{
		error = pdf_openstream(&stream, xref, fz_tonum(dict), fz_togen(dict));
		if (error)
			return fz_rethrow(error, "cannot open shading stream");
	}

	switch (type)
	{
	case 1:
		error = pdf_loadtype1shade(shade, xref, domain, matrix, func[0]);
		if (error) goto cleanup;
		break;
	case 2:
		error = pdf_loadtype2shade(shade, xref, coords, domain, funcs, func, extend);
		if (error) goto cleanup;
		break;
	case 3:
		error = pdf_loadtype3shade(shade, xref, coords, domain, funcs, func, extend);
		if (error) goto cleanup;
		break;
	case 4:
		error = pdf_loadtype4shade(shade, xref, bpcoord, bpcomp, bpflag, decode, funcs, func, stream);
		if (error) goto cleanup;
		break;
	case 5:
		error = pdf_loadtype5shade(shade, xref, bpcoord, bpcomp, vprow, decode, funcs, func, stream);
		if (error) goto cleanup;
		break;
	case 6:
		error = pdf_loadtype6shade(shade, xref, bpcoord, bpcomp, bpflag, decode, funcs, func, stream);
		if (error) goto cleanup;
		break;
	case 7:
		error = pdf_loadtype7shade(shade, xref, bpcoord, bpcomp, bpflag, decode, funcs, func, stream);
		if (error) goto cleanup;
		break;
	default:
		fz_warn("syntaxerror: unknown shading type: %d", type);
		break;
	}

	if (stream)
		fz_dropstream(stream);
	for (i = 0; i < funcs; i++)
		if (func[i])
			pdf_dropfunction(func[i]);

	pdf_logshade("}\n");

	*shadep = shade;
	return fz_okay;

cleanup:
	if (stream)
		fz_dropstream(stream);
	for (i = 0; i < funcs; i++)
		if (func[i])
			pdf_dropfunction(func[i]);
	fz_dropshade(shade);

	return fz_rethrow(error, "cannot load shading");
}

fz_error
pdf_loadshade(fz_shade **shadep, pdf_xref *xref, fz_obj *dict)
{
	fz_error error;
	fz_matrix mat;
	fz_obj *obj;

	if ((*shadep = pdf_finditem(xref->store, PDF_KSHADE, dict)))
	{
		fz_keepshade(*shadep);
		return fz_okay;
	}

	/*
	 * Type 2 pattern dictionary
	 */
	if (fz_dictgets(dict, "PatternType"))
	{
		pdf_logshade("load shade pattern (%d %d R) {\n", fz_tonum(dict), fz_togen(dict));

		obj = fz_dictgets(dict, "Matrix");
		if (obj)
		{
			mat = pdf_tomatrix(obj);
			pdf_logshade("matrix [%g %g %g %g %g %g]\n",
				mat.a, mat.b, mat.c, mat.d, mat.e, mat.f);
		}
		else
		{
			mat = fz_identity();
		}

		obj = fz_dictgets(dict, "ExtGState");
		if (obj)
		{
			pdf_logshade("extgstate ...\n");
		}

		obj = fz_dictgets(dict, "Shading");
		if (!obj)
			return fz_throw("syntaxerror: missing shading dictionary");

		error = pdf_loadshadedict(shadep, xref, obj, mat);
		if (error)
			return fz_rethrow(error, "cannot load shading dictionary");

		pdf_logshade("}\n");
	}

	/*
	 * Naked shading dictionary
	 */
	else
	{
		error = pdf_loadshadedict(shadep, xref, dict, fz_identity());
		if (error)
			return fz_rethrow(error, "cannot load shading dictionary");
	}

	pdf_storeitem(xref->store, PDF_KSHADE, dict, *shadep);

	return fz_okay;
}

