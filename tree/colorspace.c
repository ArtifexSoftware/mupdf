#include <fitz.h>

void
fz_freecolorspace(fz_colorspace *cs)
{
	if (cs->frozen)
		return;
	if (cs->free)
		cs->free(cs);
	fz_free(cs);
}

void
fz_convertcolor(fz_colorspace *srcs, float *srcv, fz_colorspace *dsts, float *dstv)
{
	float xyz[3];
	int i;
	if (srcs != dsts)
	{	
//printf("convert color from %s to %s\n  ", srcs->name, dsts->name);
//for(i=0;i<srcs->n;i++)printf("%g ", srcv[i]);printf("\n");
		srcs->toxyz(srcs, srcv, xyz);
//printf("  %g %g %g\n  ", xyz[0], xyz[1], xyz[2]);
		dsts->fromxyz(dsts, xyz, dstv);
		for (i = 0; i < dsts->n; i++)
			dstv[i] = CLAMP(dstv[i], 0.0, 1.0);
//for(i=0;i<dsts->n;i++)printf("%g ", dstv[i]);printf("\n");
	}
	else
	{
		for (i = 0; i < srcs->n; i++)
			dstv[i] = srcv[i];
	}
}

