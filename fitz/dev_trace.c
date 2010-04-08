#include "fitz.h"

static void
fz_tracematrix(fz_matrix ctm)
{
	printf("%g %g %g %g %g %g setmatrix\n",
		ctm.a, ctm.b, ctm.c, ctm.d, ctm.e, ctm.f);
}

static void
fz_tracecolor(fz_colorspace *colorspace, float *color, float alpha)
{
	int i;
	printf("/%s setcolorspace\n", colorspace->name);
	for (i = 0; i < colorspace->n; i++)
		printf("%g ", color[i]);
	printf("setcolor\n");
	printf("%g setalpha\n", alpha);
}

static void
fz_tracefillpath(void *user, fz_path *path, fz_matrix ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_printpath(path, 0);
	if (path->evenodd)
		printf("eofill\n");
	else
		printf("fill\n");
}

static void
fz_tracestrokepath(void *user, fz_path *path, fz_matrix ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	int i;

	fz_tracecolor(colorspace, color, alpha);

	printf("%g setlinewidth\n", path->linewidth);
	printf("%g setmiterlimit\n", path->miterlimit);
	printf("%d setlinecap\n", path->linecap);
	printf("%d setlinejoin\n", path->linejoin);

	if (path->dashlen)
	{
		printf("%g [ ", path->dashphase);
		for (i = 0; i < path->dashlen; i++)
			printf("%g ", path->dashlist[i]);
		printf("] setdash\n");
	}

	fz_printpath(path, 0);

	printf("stroke\n");
}

static void
fz_traceclippath(void *user, fz_path *path, fz_matrix ctm)
{
	printf("gsave\n");
	fz_printpath(path, 0);
	if (path->evenodd)
		printf("eoclip\n");
	else
		printf("clip\n");
}

static void
fz_tracefilltext(void *user, fz_text *text, fz_matrix ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	printf("/%s setfont\n", text->font->name);
	fz_tracematrix(text->trm);
	fz_debugtext(text, 0);
	printf("show\n");
}

static void
fz_tracestroketext(void *user, fz_text *text, fz_matrix ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	printf("/%s setfont\n", text->font->name);
	fz_tracematrix(text->trm);
	fz_debugtext(text, 0);
	printf("charpath stroke\n");
}

static void
fz_tracecliptext(void *user, fz_text *text, fz_matrix ctm)
{
	printf("gsave\n");
	printf("/%s setfont\n", text->font->name);
	fz_tracematrix(text->trm);
	fz_debugtext(text, 0);
	printf("charpath clip\n");
}

static void
fz_traceignoretext(void *user, fz_text *text, fz_matrix ctm)
{
	printf("/%s setfont\n", text->font->name);
	fz_tracematrix(text->trm);
	fz_debugtext(text, 0);
	printf("invisibletext\n");
}

static void
fz_tracefillimage(void *user, fz_pixmap *image, fz_matrix ctm)
{
	fz_tracematrix(ctm);
	printf("fillimage\n");
}

static void
fz_tracefillshade(void *user, fz_shade *shade, fz_matrix ctm)
{
	fz_tracematrix(ctm);
	printf("fillshade\n");
}

static void
fz_tracepopclip(void *user)
{
	printf("grestore\n");
}

fz_device *fz_newtracedevice(void)
{
	fz_device *dev = fz_newdevice(nil);

	dev->fillpath = fz_tracefillpath;
	dev->strokepath = fz_tracestrokepath;
	dev->clippath = fz_traceclippath;

	dev->filltext = fz_tracefilltext;
	dev->stroketext = fz_tracestroketext;
	dev->cliptext = fz_tracecliptext;
	dev->ignoretext = fz_traceignoretext;

	dev->fillshade = fz_tracefillshade;
	dev->fillimage = fz_tracefillimage;

	dev->popclip = fz_tracepopclip;

	return dev;
}

