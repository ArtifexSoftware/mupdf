typedef struct fz_colorspace_s fz_colorspace;

struct fz_colorspace_s
{
	char name[16];
	int frozen;
	int n;
	void (*toxyz)(fz_colorspace *, float *src, float *xyz);
	void (*fromxyz)(fz_colorspace *, float *xyz, float *dst);
	void (*free)(fz_colorspace *);
};

void fz_freecolorspace(fz_colorspace *cs);
void fz_convertcolor(fz_colorspace *srcs, float *srcv, fz_colorspace *dsts, float *dstv);

