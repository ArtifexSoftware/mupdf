#include <fitz.h>
#include <mupdf.h>

static void initcs(fz_colorspace *cs, char *name, int n,
	void(*to)(fz_colorspace*,float*,float*),
	void(*from)(fz_colorspace*,float*,float*),
	void(*free)(fz_colorspace*))
{
	strlcpy(cs->name, name, sizeof cs->name);
	cs->frozen = 0;
	cs->n = n;
	cs->toxyz = to;
	cs->fromxyz = from;
	cs->free = free;
}

static void mat3x3inv(float *dst, float *m)
{
	float det;
	int i;

#define M3(m,i,j) (m)[3*i+j]
#define D2(a,b,c,d) (a * d - b * c)
#define D3(a1,a2,a3,b1,b2,b3,c1,c2,c3) \
	(a1 * D2(b2,b3,c2,c3)) - \
	(b1 * D2(a2,a3,c2,c3)) + \
	(c1 * D2(a2,a3,b2,b3))

	det = D3(M3(m,0,0), M3(m,1,0), M3(m,2,0),
			 M3(m,0,1), M3(m,1,1), M3(m,2,1),
			 M3(m,0,2), M3(m,1,2), M3(m,2,2));
	if (det == 0)
		det = 1.0;
	det = 1.0 / det;

	M3(dst,0,0) =  M3(m,1,1) * M3(m,2,2) - M3(m,1,2) * M3(m,2,1);
	M3(dst,0,1) = -M3(m,0,1) * M3(m,2,2) + M3(m,0,2) * M3(m,2,1);
	M3(dst,0,2) =  M3(m,0,1) * M3(m,1,2) - M3(m,0,2) * M3(m,1,1);

	M3(dst,1,0) = -M3(m,1,0) * M3(m,2,2) + M3(m,1,2) * M3(m,2,0);
	M3(dst,1,1) =  M3(m,0,0) * M3(m,2,2) - M3(m,0,2) * M3(m,2,0);
	M3(dst,1,2) = -M3(m,0,0) * M3(m,1,2) + M3(m,0,2) * M3(m,1,0);

	M3(dst,2,0) =  M3(m,1,0) * M3(m,2,1) - M3(m,1,1) * M3(m,2,0);
	M3(dst,2,1) = -M3(m,0,0) * M3(m,2,1) + M3(m,0,1) * M3(m,2,0);
	M3(dst,2,2) =  M3(m,0,0) * M3(m,1,1) - M3(m,0,1) * M3(m,1,0);

	for (i = 0; i < 9; i++)
		dst[i] *= det;
}

/*
 * DeviceGray
 */

struct calgray
{
	fz_colorspace super;
	float white[3];
	float black[3];
	float gamma;
};

static void graytoxyz(fz_colorspace *fzcs, float *gray, float *xyz)
{
	struct calgray *cs = (struct calgray *) fzcs;
	xyz[0] = cs->white[0] * pow(gray[0], cs->gamma);
	xyz[1] = cs->white[1] * pow(gray[0], cs->gamma);
	xyz[2] = cs->white[2] * pow(gray[0], cs->gamma);
}

static void xyztogray(fz_colorspace *fzcs, float *xyz, float *gray)
{
	struct calgray *cs = (struct calgray *) fzcs;
	float r = pow(xyz[0], 1.0 / cs->gamma);
	float g = pow(xyz[1], 1.0 / cs->gamma);
	float b = pow(xyz[2], 1.0 / cs->gamma);
	gray[0] = r * 0.3 + g * 0.59 + b * 0.11;
}

static struct calgray kdevicegray =
{
	{ "DeviceGray", 1, 1, graytoxyz, xyztogray, nil },
	{ 1.0000, 1.0000, 1.0000 },
	{ 0.0000, 0.0000, 0.0000 },
	2.2000
};

fz_colorspace *pdf_devicegray = &kdevicegray.super;

static fz_error *
newcalgray(fz_colorspace **csp, float *white, float *black, float gamma)
{
	struct calgray *cs;
	int i;

	cs = fz_malloc(sizeof(struct calgray));
	if (!cs)
		return fz_outofmem;

	initcs((fz_colorspace*)cs, "CalGray", 1, graytoxyz, xyztogray, nil);

	for (i = 0; i < 3; i++)
	{
		cs->white[i] = white[i];
		cs->black[i] = black[i];
	}

	cs->gamma = gamma;

	*csp = (fz_colorspace*) cs;
	return nil;
}

static fz_error *
loadcalgray(fz_colorspace **csp, pdf_xref *xref, fz_obj *dict)
{
	fz_obj *tmp;

	float white[3];
	float black[3];
	float gamma;

	tmp = fz_dictgets(dict, "WhitePoint");
	if (!fz_isarray(tmp))
		return fz_throw("syntaxerror: CalGray missing WhitePoint");
	white[0] = fz_toreal(fz_arrayget(tmp, 0));
	white[1] = fz_toreal(fz_arrayget(tmp, 1));
	white[2] = fz_toreal(fz_arrayget(tmp, 2));

	tmp = fz_dictgets(dict, "BlackPoint");
	if (fz_isarray(tmp))
	{
		black[0] = fz_toreal(fz_arrayget(tmp, 0));
		black[1] = fz_toreal(fz_arrayget(tmp, 1));
		black[2] = fz_toreal(fz_arrayget(tmp, 2));
	}
	else
	{
		black[0] = 0.0;
		black[1] = 0.0;
		black[2] = 0.0;
	}

	tmp = fz_dictgets(dict, "Gamma");
	if (fz_isreal(tmp))
		gamma = fz_toreal(tmp);
	else
		gamma = 1.0;

	return newcalgray(csp, white, black, gamma);
}

/*
 * DeviceRGB
 */

struct calrgb
{
	fz_colorspace super;
	float white[3];
	float black[3];
	float gamma[3];
	float matrix[9];
	float invmat[9];
};

static void rgbtoxyz(fz_colorspace *fzcs, float *rgb, float *xyz)
{
	struct calrgb *cs = (struct calrgb *) fzcs;
	float a = pow(rgb[0], cs->gamma[0]);
	float b = pow(rgb[1], cs->gamma[1]);
	float c = pow(rgb[2], cs->gamma[2]);
	xyz[0] = a * cs->matrix[0] + b * cs->matrix[1] + c * cs->matrix[2];
	xyz[1] = a * cs->matrix[3] + b * cs->matrix[4] + c * cs->matrix[5];
	xyz[2] = a * cs->matrix[6] + b * cs->matrix[7] + c * cs->matrix[8];
}

static void xyztorgb(fz_colorspace *fzcs, float *xyz, float *rgb)
{
	struct calrgb *cs = (struct calrgb *) fzcs;
	float a = xyz[0] * cs->invmat[0] + xyz[1] * cs->invmat[1] + xyz[2] * cs->invmat[2];
	float b = xyz[0] * cs->invmat[3] + xyz[1] * cs->invmat[4] + xyz[2] * cs->invmat[5];
	float c = xyz[0] * cs->invmat[6] + xyz[1] * cs->invmat[7] + xyz[2] * cs->invmat[8];
	rgb[0] = pow(a, 1.0 / cs->gamma[0]);
	rgb[1] = pow(b, 1.0 / cs->gamma[1]);
	rgb[2] = pow(c, 1.0 / cs->gamma[2]);
}

static struct calrgb kdevicergb =
{
	{ "DeviceRGB", 1, 3, rgbtoxyz, xyztorgb, nil },
	{ 1.0000, 1.0000, 1.0000 },
	{ 0.0000, 0.0000, 0.0000 },
	{ 2.2000, 2.2000, 2.2000 },
	{ 1.0000, 0.0000, 0.0000,
	  0.0000, 1.0000, 0.0000,
	  0.0000, 0.0000, 1.0000 },
	{ 1.0000, 0.0000, 0.0000,
	  0.0000, 1.0000, 0.0000,
	  0.0000, 0.0000, 1.0000 }
};

fz_colorspace *pdf_devicergb = &kdevicergb.super;

static fz_error *
newcalrgb(fz_colorspace **csp, float *white, float *black, float *gamma, float *matrix)
{
	struct calrgb *cs;
	int i;

	cs = fz_malloc(sizeof(struct calrgb));
	if (!cs)
		return fz_outofmem;

	initcs((fz_colorspace*)cs, "CalRGB", 3, rgbtoxyz, xyztorgb, nil);

	for (i = 0; i < 3; i++)
	{
		cs->white[i] = white[i];
		cs->black[i] = black[i];
		cs->gamma[i] = gamma[i];
	}

	for (i = 0; i < 9; i++)
		cs->matrix[i] = matrix[i];

	mat3x3inv(cs->invmat, cs->matrix);

	*csp = (fz_colorspace*) cs;
	return nil;
}

static fz_error *
loadcalrgb(fz_colorspace **csp, pdf_xref *xref, fz_obj *dict)
{
	fz_obj *tmp;

	float white[3];
	float black[3];
	float gamma[3];
	float matrix[9];

	tmp = fz_dictgets(dict, "WhitePoint");
	if (!fz_isarray(tmp))
		return fz_throw("syntaxerror: CalRGB missing White");
	white[0] = fz_toreal(fz_arrayget(tmp, 0));
	white[1] = fz_toreal(fz_arrayget(tmp, 1));
	white[2] = fz_toreal(fz_arrayget(tmp, 2));

	tmp = fz_dictgets(dict, "BlackPoint");
	if (fz_isarray(tmp))
	{
		black[0] = fz_toreal(fz_arrayget(tmp, 0));
		black[1] = fz_toreal(fz_arrayget(tmp, 1));
		black[2] = fz_toreal(fz_arrayget(tmp, 2));
	}
	else
	{
		black[0] = 0.0;
		black[1] = 0.0;
		black[2] = 0.0;
	}

	tmp = fz_dictgets(dict, "Gamma");
	if (fz_isarray(tmp))
	{
		gamma[0] = fz_toreal(fz_arrayget(tmp, 0));
		gamma[1] = fz_toreal(fz_arrayget(tmp, 1));
		gamma[2] = fz_toreal(fz_arrayget(tmp, 2));
	}
	else
	{
		gamma[0] = 1.0;
		gamma[1] = 1.0;
		gamma[2] = 1.0;
	}

	tmp = fz_dictgets(dict, "Matrix");
	if (fz_isarray(tmp))
	{
		int i;
		for (i = 0; i < 9; i++)
			matrix[i] = fz_toreal(fz_arrayget(tmp, i));
	}
	else
	{
		matrix[0] = 1.0; matrix[1] = 0.0; matrix[2] = 0.0;
		matrix[3] = 0.0; matrix[4] = 1.0; matrix[5] = 0.0;
		matrix[6] = 0.0; matrix[7] = 0.0; matrix[8] = 1.0;
	}

	return newcalrgb(csp, white, black, gamma, matrix);
}

/*
 * DeviceCMYK
 */

static void devicecmyktoxyz(fz_colorspace *cs, float *cmyk, float *xyz)
{
	float rgb[3];
	rgb[0] = 1.0 - MIN(1.0, cmyk[0] + cmyk[3]);
	rgb[1] = 1.0 - MIN(1.0, cmyk[1] + cmyk[3]);
	rgb[2] = 1.0 - MIN(1.0, cmyk[2] + cmyk[3]);
	rgbtoxyz(pdf_devicergb, rgb, xyz);
}

static void xyztodevicecmyk(fz_colorspace *cs, float *xyz, float *cmyk)
{
	float rgb[3];
	xyztorgb(pdf_devicergb, xyz, rgb);
	float c = 1.0 - rgb[0];
	float m = 1.0 - rgb[0];
	float y = 1.0 - rgb[0];
	float k = MIN(c, MIN(y, k));
	cmyk[0] = c - k;
	cmyk[1] = m - k;
	cmyk[2] = y - k;
	cmyk[3] = k;
}

static fz_colorspace kdevicecmyk =
{
	"DeviceCMYK", 1, 4, devicecmyktoxyz, xyztodevicecmyk, nil
};

fz_colorspace *pdf_devicecmyk = &kdevicecmyk;

/*
 * CIE Lab
 */

struct cielab
{
	fz_colorspace super;
	float white[3];
	float black[3];
	float range[4];
};

static inline float cielabg(float x)
{
	if (x >= 6.0 / 29.0)
		return x * x * x;
	return (108.0 / 841.0) * (x - (4.0 / 29.0));
}

static inline float cielabinvg(float x)
{
	if (x > 0.008856)
		return pow(x, 1.0 / 3.0);
	return (7.787 * x) + (16.0 / 116.0);
}

static void labtoxyz(fz_colorspace *fzcs, float *lab, float *xyz)
{
	struct cielab *cs = (struct cielab *) fzcs;
	float lstar = lab[0];
	float astar = MAX(MIN(lab[1], cs->range[1]), cs->range[0]);
	float bstar = MAX(MIN(lab[2], cs->range[3]), cs->range[2]);
	float l = ((lstar * 16.0) / 116.0) + (astar / 500.0);
	float m = (lstar * 16.0) / 116.0;
	float n = ((lstar * 16.0) / 116.0) - (bstar / 200.0);
	xyz[0] = cs->white[0] * cielabg(l);
	xyz[1] = cs->white[1] * cielabg(m);
	xyz[2] = cs->white[2] * cielabg(n);
}

static void xyztolab(fz_colorspace *fzcs, float *xyz, float *lab)
{
	struct cielab *cs = (struct cielab *) fzcs;
	float yyn = xyz[1] / cs->white[1];
	if (yyn < 0.008856)
		lab[0] = 116.0 * yyn * (1.0 / 3.0) - 16.0;
	else
		lab[0] = 903.3 * yyn;
	lab[1] = 500 * (cielabinvg(xyz[0]/cs->white[0]) - cielabinvg(xyz[1]/cs->white[1]));
	lab[2] = 200 * (cielabinvg(xyz[1]/cs->white[1]) - cielabinvg(xyz[2]/cs->white[2]));
}

static fz_error *
newlab(fz_colorspace **csp, float *white, float *black, float *range)
{
	struct cielab *cs;
	int i;

	cs = fz_malloc(sizeof(struct cielab));
	if (!cs)
		return fz_outofmem;

	initcs((fz_colorspace*)cs, "Lab", 3, labtoxyz, xyztolab, nil);

	for (i = 0; i < 3; i++)
	{
		cs->white[i] = white[i];
		cs->black[i] = black[i];
	}

	for (i = 0; i < 4; i++)
		cs->range[i] = range[i];

	*csp = (fz_colorspace*) cs;
	return nil;
}

static fz_error *
loadlab(fz_colorspace **csp, pdf_xref *xref, fz_obj *dict)
{
	fz_obj *tmp;

	float white[3];
	float black[3];
	float range[4];

	tmp = fz_dictgets(dict, "WhitePoint");
	if (!fz_isarray(tmp))
		return fz_throw("syntaxerror: Lab missing WhitePoint");
	white[0] = fz_toreal(fz_arrayget(tmp, 0));
	white[1] = fz_toreal(fz_arrayget(tmp, 1));
	white[2] = fz_toreal(fz_arrayget(tmp, 2));

	tmp = fz_dictgets(dict, "BlackPoint");
	if (fz_isarray(tmp))
	{
		black[0] = fz_toreal(fz_arrayget(tmp, 0));
		black[1] = fz_toreal(fz_arrayget(tmp, 1));
		black[2] = fz_toreal(fz_arrayget(tmp, 2));
	}
	else
	{
		black[0] = 0.0;
		black[1] = 0.0;
		black[2] = 0.0;
	}

	tmp = fz_dictgets(dict, "Range");
	if (fz_isarray(tmp))
	{
		range[0] = fz_toreal(fz_arrayget(tmp, 0));
		range[1] = fz_toreal(fz_arrayget(tmp, 1));
		range[2] = fz_toreal(fz_arrayget(tmp, 2));
		range[3] = fz_toreal(fz_arrayget(tmp, 3));
	}
	else
	{
		range[0] = -100;
		range[1] = 100;
		range[2] = -100;
		range[3] = 100;
	}

	return newlab(csp, white, black, range);
}

/*
 * ICCBased
 */

static fz_error *
loadiccbased(fz_colorspace **csp, pdf_xref *xref, fz_obj *ref)
{
	fz_error *error;
	fz_obj *dict;
	int n;

	error = pdf_loadindirect(&dict, xref, ref);
	if (error)
		return error;

	n = fz_toint(fz_dictgets(dict, "N"));

	fz_dropobj(dict);

	switch (n)
	{
	case 1: *csp = pdf_devicegray; return nil;
	case 3: *csp = pdf_devicergb; return nil;
	case 4: *csp = pdf_devicecmyk; return nil;
	}

	return fz_throw("syntaxerror: ICCBased must have 1, 3 or 4 components");
}

/*
 * Separation
 */

struct separation
{
	fz_colorspace super;
	fz_colorspace *base;
	pdf_function *tint;
};

static void separationtoxyz(fz_colorspace *fzcs, float *sep, float *xyz)
{
	struct separation *cs = (struct separation *)fzcs;
	fz_error *error;
	float alt[32];

	error = pdf_evalfunction(cs->tint, sep, 1, alt, cs->base->n);
	if (error)
	{
		fz_warn("separation: %s", error->msg);
		fz_freeerror(error);
		xyz[0] = 0;
		xyz[1] = 0;
		xyz[2] = 0;
		return;
	}

	cs->base->toxyz(cs->base, alt, xyz);
}

static void
freeseparation(fz_colorspace *fzcs)
{
	struct separation *cs = (struct separation *)fzcs;
	fz_freecolorspace(cs->base);
	pdf_freefunction(cs->tint);
}

static fz_error *
loadseparation(fz_colorspace **csp, pdf_xref *xref, fz_obj *array)
{
	fz_error *error;
	struct separation *sep;
	fz_obj *baseobj = fz_arrayget(array, 2);
	fz_obj *tintobj = fz_arrayget(array, 3);
	fz_colorspace *base;
	pdf_function *tint;

	error = pdf_resolve(&baseobj, xref);
	if (error)
		return error;
	error = pdf_loadcolorspace(&base, xref, baseobj);
	fz_dropobj(baseobj);
	if (error)
		return error;

	error = pdf_loadfunction(&tint, xref, tintobj);
	if (error)
	{
		fz_freecolorspace(base);
		return error;
	}

	sep = fz_malloc(sizeof(struct separation));
	if (!sep)
	{
		pdf_freefunction(tint);
		fz_freecolorspace(base);
		return fz_outofmem;
	}

	initcs((fz_colorspace*)sep, "Separation", 1, separationtoxyz, nil, freeseparation);

	sep->base = base;
	sep->tint = tint;

	*csp = (fz_colorspace*)sep;
	return nil;
}

/*
 * Indexed
 */

struct indexed
{
	fz_colorspace super;
	fz_colorspace *base;
	int high;
	float *lookup;
};

static void
indexedtoxyz(fz_colorspace *fzcs, float *ind, float *xyz)
{
	struct indexed *cs = (struct indexed *)fzcs;
	int i = ind[0] * 255; // FIXME
	i = CLAMP(i, 0, cs->high);
	cs->base->toxyz(cs->base, cs->lookup + i * cs->base->n, xyz);
}

static void
freeindexed(fz_colorspace *fzcs)
{
	struct indexed *cs = (struct indexed *)fzcs;
	fz_freecolorspace(cs->base);
	fz_free(cs->lookup);
}

static fz_error *
loadindexed(fz_colorspace **csp, pdf_xref *xref, fz_obj *array)
{
	fz_error *error;
	struct indexed *cs;
	fz_obj *baseobj = fz_arrayget(array, 1);
	fz_obj *highobj = fz_arrayget(array, 2);
	fz_obj *lookup = fz_arrayget(array, 3);
	fz_colorspace *base;
	int n;

	error = pdf_resolve(&baseobj, xref);
	if (error)
		return error;
	error = pdf_loadcolorspace(&base, xref, baseobj);
	fz_dropobj(baseobj);
	if (error)
		return error;

	cs = fz_malloc(sizeof(struct indexed));
	if (!cs)
	{
		fz_freecolorspace(base);
		return fz_outofmem;
	}

	initcs((fz_colorspace*)cs, "Indexed", 1, indexedtoxyz, nil, freeindexed);

	cs->base = base;
	cs->high = fz_toint(highobj);

	n = base->n * (cs->high + 1);

	cs->lookup = fz_malloc(n * sizeof(float));
	if (!cs->lookup)
	{
		freeindexed((fz_colorspace*)cs);
		return fz_outofmem;
	}

	if (fz_isstring(lookup) && fz_tostringlen(lookup) == n)
	{
		unsigned char *buf = fz_tostringbuf(lookup);
		int i;
		for (i = 0; i < n; i++)
			cs->lookup[i] = buf[i] / 255.0;	// FIXME base range
	}

	if (fz_isindirect(lookup))
	{
		fz_buffer *buf;
		int i;

		error = pdf_loadstream(&buf, xref, fz_tonum(lookup), fz_togen(lookup));
		if (error)
		{
			freeindexed((fz_colorspace*)cs);
			return error;
		}

		for (i = 0; i < n && i < (buf->wp - buf->rp); i++)
			cs->lookup[i] = buf->rp[i] / 255.0;	// FIXME base range

		fz_freebuffer(buf);
	}

	*csp = (fz_colorspace*)cs;
	return nil;
}

/*
 * Parse and create colorspace from PDF object.
 */

fz_error *
pdf_loadcolorspace(fz_colorspace **csp, pdf_xref *xref, fz_obj *obj)
{
printf("loading colorspace: ");
fz_debugobj(obj);
printf("\n");

	if (fz_isname(obj))
	{
		if (!strcmp(fz_toname(obj), "DeviceGray"))
		{
			*csp = pdf_devicegray;
			return nil;
		}

		if (!strcmp(fz_toname(obj), "DeviceRGB"))
		{
			*csp = pdf_devicergb;
			return nil;
		}

		if (!strcmp(fz_toname(obj), "DeviceCMYK"))
		{
			*csp = pdf_devicecmyk;
			return nil;
		}
	}

	else if (fz_isarray(obj))
	{
		fz_obj *name = fz_arrayget(obj, 0);

		if (fz_isname(name))
		{
			if (!strcmp(fz_toname(name), "CalGray"))
				return loadcalgray(csp, xref, fz_arrayget(obj, 1));

			if (!strcmp(fz_toname(name), "CalRGB"))
				return loadcalrgb(csp, xref, fz_arrayget(obj, 1));

			if (!strcmp(fz_toname(name), "CalCMYK"))
			{
				*csp = pdf_devicecmyk;
				return nil;
			}

			if (!strcmp(fz_toname(name), "Lab"))
				return loadlab(csp, xref, fz_arrayget(obj, 1));

			if (!strcmp(fz_toname(name), "ICCBased"))
				return loadiccbased(csp, xref, fz_arrayget(obj, 1));

			if (!strcmp(fz_toname(name), "Indexed"))
				return loadindexed(csp, xref, obj);

			if (!strcmp(fz_toname(name), "Separation"))
				return loadseparation(csp, xref, obj);
		}
	}

	return fz_throw("syntaxerror: could not parse color space");
}

