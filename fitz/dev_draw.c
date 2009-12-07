#include "fitz.h"

typedef struct fz_drawdevice_s fz_drawdevice;

struct fz_drawdevice_s
{
	int maskonly;
	fz_colorspace *model;
	fz_glyphcache *cache;
	fz_gel *gel;
	fz_ael *ael;
	fz_pixmap *dest;
};

void fz_drawfillpath(void *user, fz_path *path, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_drawdevice *dev = user;
	float expansion = fz_matrixexpansion(path->ctm);
	float flatness = 0.3 / expansion;
	fz_irect bbox;
	fz_irect clip;
	unsigned char argb[4];

	if (flatness < 0.1)
		flatness = 0.1;
	argb[0] = 0xFF;
	argb[1] = 0xFF;
	argb[2] = 0x00;
	argb[3] = 0x00;

	clip.x0 = dev->dest->x;
	clip.y0 = dev->dest->y;
	clip.x1 = dev->dest->x + dev->dest->w;
	clip.y1 = dev->dest->y + dev->dest->h;

	fz_resetgel(dev->gel, clip);
	fz_fillpath(dev->gel, path, path->ctm, flatness);
	fz_sortgel(dev->gel);

	bbox = fz_boundgel(dev->gel);
	bbox = fz_intersectirects(bbox, clip);
	if (fz_isemptyrect(bbox))
		return;

	fz_scanconvert(dev->gel, dev->ael, path->winding == FZ_EVENODD, bbox, dev->dest, argb, 1);
}

void fz_drawstrokepath(void *user, fz_path *path, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_drawdevice *dev = user;
	float expansion = fz_matrixexpansion(path->ctm);
	float flatness = 0.3 / expansion;
	float linewidth = path->linewidth;
	fz_irect bbox;
	fz_irect clip;
	unsigned char argb[4];

	if (flatness < 0.1)
		flatness = 0.1;
	if (linewidth < 0.1)
		linewidth = 1.0 / expansion;
	argb[0] = 0xFF;
	argb[1] = 0x00;
	argb[2] = 0xFF;
	argb[3] = 0x00;

	clip.x0 = dev->dest->x;
	clip.y0 = dev->dest->y;
	clip.x1 = dev->dest->x + dev->dest->w;
	clip.y1 = dev->dest->y + dev->dest->h;

	fz_resetgel(dev->gel, clip);
	if (path->dashlen > 0)
		fz_dashpath(dev->gel, path, path->ctm, flatness, linewidth);
	else
		fz_strokepath(dev->gel, path, path->ctm, flatness, linewidth);
	fz_sortgel(dev->gel);

	bbox = fz_boundgel(dev->gel);
	bbox = fz_intersectirects(bbox, clip);
	if (fz_isemptyrect(bbox))
		return;

	fz_scanconvert(dev->gel, dev->ael, FZ_NONZERO, bbox, dev->dest, argb, 1);
}

void fz_drawclippath(void *user, fz_path *path)
{
	fz_drawdevice *dev = user;
}

void fz_drawfilltext(void *user, fz_text *text, fz_colorspace *colorspace, float *color, float alpha)
{
	printf("/%s setfont\n", text->font->name);
	fz_debugtext(text, 0);
	printf("show\n");
}

void fz_drawstroketext(void *user, fz_text *text, fz_colorspace *colorspace, float *color, float alpha)
{
	printf("/%s setfont\n", text->font->name);
	fz_debugtext(text, 0);
	printf("charpath stroke\n");
}

void fz_drawcliptext(void *user, fz_text *text)
{
	printf("gsave\n");
	printf("/%s setfont\n", text->font->name);
	fz_debugtext(text, 0);
	printf("charpath clip\n");
}

void fz_drawignoretext(void *user, fz_text *text)
{
	printf("/%s setfont\n", text->font->name);
	fz_debugtext(text, 0);
	printf("invisibletext\n");
}

void fz_drawdrawimage(void *user, fz_image *image, fz_matrix *ctm)
{
	printf("drawimage\n");
}

void fz_drawdrawshade(void *user, fz_shade *shade, fz_matrix *ctm)
{
	printf("drawshade\n");
}

void fz_drawpopclip(void *user)
{
	printf("grestore\n");
}

fz_device *fz_newdrawdevice(fz_colorspace *colorspace, fz_pixmap *dest)
{
	fz_drawdevice *ddev = fz_malloc(sizeof(fz_drawdevice));
	ddev->model = fz_keepcolorspace(colorspace);
	ddev->cache = fz_newglyphcache(512, 512 * 512);
	ddev->gel = fz_newgel();
	ddev->ael = fz_newael();
	ddev->dest = dest;

	fz_device *dev = fz_malloc(sizeof(fz_device));
	dev->user = ddev;

	dev->fillpath = fz_drawfillpath;
	dev->strokepath = fz_drawstrokepath;
	dev->clippath = fz_drawclippath;

	dev->filltext = fz_drawfilltext;
	dev->stroketext = fz_drawstroketext;
	dev->cliptext = fz_drawcliptext;
	dev->ignoretext = fz_drawignoretext;

	dev->drawimage = fz_drawdrawimage;
	dev->drawshade = fz_drawdrawshade;

	dev->popclip = fz_drawpopclip;

	return dev;
}

void
fz_freedrawdevice(void *user)
{
	fz_drawdevice *dev = user;
	fz_dropcolorspace(dev->model);
	fz_freeglyphcache(dev->cache);
	fz_freegel(dev->gel);
	fz_freeael(dev->ael);
	fz_free(dev);
}
