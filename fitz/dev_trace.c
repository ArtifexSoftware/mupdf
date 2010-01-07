#include "fitz.h"

static void fz_tracematrix(fz_matrix ctm)
{
	printf("%g %g %g %g %g %g setmatrix\n",
		ctm.a, ctm.b, ctm.c, ctm.d, ctm.e, ctm.f);
}

static void fz_tracecolor(fz_colorspace *colorspace, float *color, float alpha)
{
	printf("... setcolor\n");
	printf("%g setalpha\n", alpha);
}

void fz_tracefillpath(void *user, fz_path *path, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_tracematrix(path->ctm);
	fz_printpath(path, 0);
	if (path->winding == FZ_EVENODD)
		printf("eofill\n");
	else
		printf("fill\n");
}

void fz_tracestrokepath(void *user, fz_path *path, fz_colorspace *colorspace, float *color, float alpha)
{
	int i;

	fz_tracecolor(colorspace, color, alpha);
	fz_tracematrix(path->ctm);

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

void fz_traceclippath(void *user, fz_path *path)
{
	printf("gsave\n");
	fz_tracematrix(path->ctm);
	fz_printpath(path, 0);
	if (path->winding == FZ_EVENODD)
		printf("eoclip\n");
	else
		printf("clip\n");
}

void fz_tracefilltext(void *user, fz_text *text, fz_colorspace *colorspace, float *color, float alpha)
{
	printf("/%s setfont\n", text->font->name);
	fz_tracematrix(text->trm);
	fz_debugtext(text, 0);
	printf("show\n");
}

void fz_tracestroketext(void *user, fz_text *text, fz_colorspace *colorspace, float *color, float alpha)
{
	printf("/%s setfont\n", text->font->name);
	fz_tracematrix(text->trm);
	fz_debugtext(text, 0);
	printf("charpath stroke\n");
}

void fz_tracecliptext(void *user, fz_text *text)
{
	printf("gsave\n");
	printf("/%s setfont\n", text->font->name);
	fz_tracematrix(text->trm);
	fz_debugtext(text, 0);
	printf("charpath clip\n");
}

void fz_traceignoretext(void *user, fz_text *text)
{
	printf("/%s setfont\n", text->font->name);
	fz_tracematrix(text->trm);
	fz_debugtext(text, 0);
	printf("invisibletext\n");
}

void fz_tracedrawimage(void *user, fz_image *image, fz_matrix ctm)
{
	fz_tracematrix(ctm);
	printf("drawimage\n");
}

void fz_tracedrawshade(void *user, fz_shade *shade, fz_matrix ctm)
{
	fz_tracematrix(ctm);
	printf("drawshade\n");
}

void fz_tracepopclip(void *user)
{
	printf("grestore\n");
}

fz_device *fz_newtracedevice(void)
{
	fz_device *dev = fz_malloc(sizeof(fz_device));
	dev->user = nil;

	dev->fillpath = fz_tracefillpath;
	dev->strokepath = fz_tracestrokepath;
	dev->clippath = fz_traceclippath;

	dev->filltext = fz_tracefilltext;
	dev->stroketext = fz_tracestroketext;
	dev->cliptext = fz_tracecliptext;
	dev->ignoretext = fz_traceignoretext;

	dev->drawimage = fz_tracedrawimage;
	dev->drawshade = fz_tracedrawshade;

	dev->popclip = fz_tracepopclip;

	return dev;
}

