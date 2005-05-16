#include <fitz.h>
#include <mupdf.h>

int
getdata(fz_file *stream, int bps);

int
drawpatch(pdf_tensorpatch patch, fz_shade *shade, int ptr, int ncomp, int depth);

static fz_error *
growshademesh(fz_shade *shade, int amount)
{
	float *newmesh;
	int newcap;

	newcap = shade->meshcap + amount;
	newmesh = fz_realloc(shade->mesh, sizeof(float) * newcap);
	if (!newmesh)
		return fz_outofmem;

	shade->mesh = newmesh;
	shade->meshcap = newcap;

	return nil;
}

static inline void copyvert(float *dst, float *src, int n)
{
	while (n--)
		*dst++ = *src++;
}

fz_error *
pdf_loadtype7shade(fz_shade *shade, pdf_xref *xref, fz_obj *shading, fz_obj *ref)
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

	int i, n, j;
	unsigned int t;

	int flag;
	fz_point p[16];
	pdf_tensorpatch patch;

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
		error = fz_throw("syntaxerror: No Decode key in Type 6 Shade");
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

	shade->meshcap = 0;
	shade->mesh = nil;
	error = growshademesh(shade, 1024);
	if (error) goto cleanup;

	n = 2 + shade->cs->n;
	j = 0;

	error = pdf_openstream(xref, fz_tonum(ref), fz_togen(ref));
	if (error) goto cleanup;

	while (fz_peekbyte(xref->stream) != EOF)
	{
		flag = getdata(xref->stream, bpflag);

		for (i = 0; i < 16; ++i) {
			t = getdata(xref->stream, bpcoord);
			p[i].x = x0 + (t * (x1 - x0) / (pow(2, bpcoord) - 1.));
			t = getdata(xref->stream, bpcoord);
			p[i].y = y0 + (t * (y1 - y0) / (pow(2, bpcoord) - 1.));
		}

		for (i = 0; i < 4; ++i) {
			int k;
			for (k=0; k < ncomp; ++k) {
				t = getdata(xref->stream, bpcomp);
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

		j = drawpatch(patch, shade, j, ncomp, 0);
	}
	if (error = fz_ferror(xref->stream)) 
		goto cleanup;

	pdf_closestream(xref);

	shade->meshlen = j / n / 3;

cleanup:

	return nil;
}

