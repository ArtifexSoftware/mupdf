#include <fitz.h>
#include <mupdf.h>

fz_error *
pdf_loadtype4shade(fz_shade *shade, pdf_xref *xref, fz_obj *shading, fz_obj *ref)
{
	fz_error *error;
	fz_obj *obj;
	int bpcoord;
	int bpcomp;
	int bpflag;
	int ncomp;
	float x0, x1, y0, y1;
	float c0[FZ_MAXCOLORS];
	float c1[FZ_MAXCOLORS];
	int i, z;
	int bitspervertex;
	int bytepervertex;
	fz_buffer *buf;
	int n;
	int j;
	float cval[16];

	int flag;
	unsigned int t;
	float x, y;

	error = nil;

	ncomp = shade->cs->n;
	bpcoord = fz_toint(fz_dictgets(shading, "BitsPerCoordinate"));
	bpcomp = fz_toint(fz_dictgets(shading, "BitsPerComponent"));
	bpflag = fz_toint(fz_dictgets(shading, "BitsPerFlag"));

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
	}

	bitspervertex = bpflag + bpcoord * 2 + bpcomp * ncomp;	
	bytepervertex = (bitspervertex+7) / 8;

	error = pdf_loadstream(&buf, xref, fz_tonum(ref), fz_togen(ref));
	if (error) goto cleanup;

	shade->usefunction = 0;


	n = 2 + shade->cs->n;
	j = 0;
	for (z = 0; z < (buf->ep - buf->bp) / bytepervertex; ++z)
	{
		flag = *buf->rp++;

		t = *buf->rp++;
		t = (t << 8) + *buf->rp++;
		t = (t << 8) + *buf->rp++;
		x = x0 + (t * (x1 - x0) / (pow(2, 24) - 1));

		t = *buf->rp++;
		t = (t << 8) + *buf->rp++;
		t = (t << 8) + *buf->rp++;
		y = y0 + (t * (y1 - y0) / (pow(2, 24) - 1));

		for (i=0; i < ncomp; ++i) {
			t = *buf->rp++;
			t = (t << 8) + *buf->rp++;
		}

		if (flag == 0) {
			j += n;
		}
		if (flag == 1 || flag == 2) {
			j += 3 * n;
		}
	}
	buf->rp = buf->bp;

	shade->mesh = (float*) malloc(sizeof(float) * j);
	/* 8, 24, 16 only */
	j = 0;
	for (z = 0; z < (buf->ep - buf->bp) / bytepervertex; ++z)
	{
		flag = *buf->rp++;

		t = *buf->rp++;
		t = (t << 8) + *buf->rp++;
		t = (t << 8) + *buf->rp++;
		x = x0 + (t * (x1 - x0) / (pow(2, 24) - 1));

		t = *buf->rp++;
		t = (t << 8) + *buf->rp++;
		t = (t << 8) + *buf->rp++;
		y = y0 + (t * (y1 - y0) / (pow(2, 24) - 1));

		for (i=0; i < ncomp; ++i) {
			t = *buf->rp++;
			t = (t << 8) + *buf->rp++;
			cval[i] = t / (double)(pow(2, 16) - 1);
		}

		if (flag == 0) {
			shade->mesh[j++] = x;
			shade->mesh[j++] = y;
			for (i=0; i < ncomp; ++i) {
				shade->mesh[j++] = cval[i];
			}
		}
		if (flag == 1) {
			memcpy(&(shade->mesh[j]), &(shade->mesh[j - 2 * n]), n * sizeof(float));
			memcpy(&(shade->mesh[j + 1 * n]), &(shade->mesh[j - 1 * n]), n * sizeof(float));
			j+= 2 * n;
			shade->mesh[j++] = x;
			shade->mesh[j++] = y;
			for (i=0; i < ncomp; ++i) {
				shade->mesh[j++] = cval[i];
			}
		}
		if (flag == 2) {
			memcpy(&(shade->mesh[j]), &(shade->mesh[j - 3 * n]), n * sizeof(float));
			memcpy(&(shade->mesh[j + 1 * n]), &(shade->mesh[j - 1 * n]), n * sizeof(float));
			j+= 2 * n;
			shade->mesh[j++] = x;
			shade->mesh[j++] = y;
			for (i=0; i < ncomp; ++i) {
				shade->mesh[j++] = cval[i];
			}
		}
	}
	shade->meshlen = j / n / 3;

	fz_dropbuffer(buf);

cleanup:

	return nil;
}

