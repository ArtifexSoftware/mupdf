#include <fitz.h>
#include <mupdf.h>

int
getdata(fz_file *stream, int bps)
{
	unsigned int bitmask = (1 << bps) - 1;
	unsigned int buf = 0;
	int bits = 0;
	int s;

	while (bits < bps)
	{
		buf = (buf << 8) | (fz_readbyte(stream) & 0xff);
		bits += 8;
	}
	s = buf >> (bits - bps);
	if (bps < 32)
		s = s & bitmask;
	bits -= bps;

	return s;
}

fz_error *
pdf_loadtype5shade(fz_shade *shade, pdf_xref *xref, fz_obj *shading, fz_obj *ref)
{
	fz_error *error;
	fz_obj *obj;

	int bpcoord;
	int bpcomp;
	int vpr, vpc;
	int ncomp;

	float x0, x1, y0, y1;

	float c0[FZ_MAXCOLORS];
	float c1[FZ_MAXCOLORS];

	int i, n, j;
	int p, q;
	unsigned int t;

	float *x, *y, *c[FZ_MAXCOLORS];

	error = nil;

	ncomp = shade->cs->n;
	bpcoord = fz_toint(fz_dictgets(shading, "BitsPerCoordinate"));
	bpcomp = fz_toint(fz_dictgets(shading, "BitsPerComponent"));
	vpr = fz_toint(fz_dictgets(shading, "VerticesPerRow"));
	if (vpr < 2) {
		error = fz_throw("VerticesPerRow must be greater than or equal to 2");
		goto cleanup;
	}

	obj = fz_dictgets(shading, "Decode");
	if (fz_isarray(obj))
	{
		pdf_logshade("decode array\n");
		x0 = fz_toreal(fz_arrayget(obj, 0));
		x1 = fz_toreal(fz_arrayget(obj, 1));
		y0 = fz_toreal(fz_arrayget(obj, 2));
		y1 = fz_toreal(fz_arrayget(obj, 3));
		for (i=0; i < fz_arraylen(obj) / 2; ++i) {
			c0[i] = fz_toreal(fz_arrayget(obj, i*2+4));
			c1[i] = fz_toreal(fz_arrayget(obj, i*2+5));
		}
	}
	else {
		error = fz_throw("syntaxerror: No Decode key in Type 4 Shade");
		goto cleanup;
	}

	obj = fz_dictgets(shading, "Function");
	if (obj) {
		ncomp = 1;
		pdf_loadshadefunction(shade, xref, shading, c0[0], c1[0]);
		shade->usefunction;
	} 
	else
		shade->usefunction = 0;

	n = 2 + shade->cs->n;
	j = 0;

#define BIGNUM 1024

	x = fz_malloc(sizeof(float) * vpr * BIGNUM);
	y = fz_malloc(sizeof(float) * vpr * BIGNUM);
	for (i = 0; i < ncomp; ++i) {
		c[i] = fz_malloc(sizeof(float) * vpr * BIGNUM);
	}
	q = 0;

	error = pdf_openstream(xref, fz_tonum(ref), fz_togen(ref));
	if (error) goto cleanup;

	while (fz_peekbyte(xref->stream) != EOF)
	{
		for (p = 0; p < vpr; ++p) {
			int idx;
			idx = q * vpr + p;

			t = getdata(xref->stream, bpcoord);
			x[idx] = x0 + (t * (x1 - x0) / ((float)pow(2, bpcoord) - 1));
			t = getdata(xref->stream, bpcoord);
			y[idx] = y0 + (t * (y1 - y0) / ((float)pow(2, bpcoord) - 1));

			for (i=0; i < ncomp; ++i) {
				t = getdata(xref->stream, bpcomp);
				c[i][idx] = c0[i] + (t * (c1[i] - c0[i]) / (float)(pow(2, bpcomp) - 1));
			}
		}
		q++;
	}
	if (error = fz_ferror(xref->stream)) 
		goto cleanup;

	pdf_closestream(xref);

#define ADD_VERTEX(idx) \
			{\
				int z;\
				shade->mesh[j++] = x[idx];\
				shade->mesh[j++] = y[idx];\
				for (z = 0; z < shade->cs->n; ++z) {\
					shade->mesh[j++] = c[z][idx];\
				}\
			}\

	vpc = q;

	shade->meshcap = 0;
	shade->mesh = fz_malloc(sizeof(float) * 1024);
	if (!shade) {
		error = fz_outofmem;
		goto cleanup;
	}

	j = 0;
	for (p = 0; p < vpr-1; ++p) {
		for (q = 0; q < vpc-1; ++q) {
			ADD_VERTEX(q * vpr + p);
			ADD_VERTEX(q * vpr + p + 1);
			ADD_VERTEX((q + 1) * vpr + p + 1);
			
			ADD_VERTEX(q * vpr + p);
			ADD_VERTEX((q + 1) * vpr + p + 1);
			ADD_VERTEX((q + 1) * vpr + p);
		}
	}

	shade->meshlen = j / n / 3;

	fz_free(x);
	fz_free(y);
	for (i = 0; i < ncomp; ++i) {
		fz_free(c[i]);
	}


cleanup:

	return nil;
}

