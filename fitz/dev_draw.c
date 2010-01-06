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
	unsigned char argb[7];
	float rgb[3];

	if (flatness < 0.1)
		flatness = 0.1;

	fz_convertcolor(colorspace, color, dev->model, rgb);
	argb[0] = alpha * 255;
	argb[1] = rgb[0] * alpha * 255;
	argb[2] = rgb[1] * alpha * 255;
	argb[3] = rgb[2] * alpha * 255;
	argb[4] = rgb[0] * 255;
	argb[5] = rgb[1] * 255;
	argb[6] = rgb[2] * 255;

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
	unsigned char argb[7];
	float rgb[3];

	if (flatness < 0.1)
		flatness = 0.1;
	if (linewidth < 0.1)
		linewidth = 1.0 / expansion;

	fz_convertcolor(colorspace, color, dev->model, rgb);
	argb[0] = alpha * 255;
	argb[1] = rgb[0] * alpha * 255;
	argb[2] = rgb[1] * alpha * 255;
	argb[3] = rgb[2] * alpha * 255;
	argb[4] = rgb[0] * 255;
	argb[5] = rgb[1] * 255;
	argb[6] = rgb[2] * 255;

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

	fz_scanconvert(dev->gel, dev->ael, 0, bbox, dev->dest, argb, 1);
}

void fz_drawclippath(void *user, fz_path *path)
{
	fz_drawdevice *dev = user;
	fz_printpath(path, 0);
	printf("clippath\n");
}

void fz_drawfilltext(void *user, fz_text *text, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_drawdevice *dev = user;
	unsigned char argb[7];
	float rgb[3];

	fz_convertcolor(colorspace, color, dev->model, rgb);
	argb[0] = alpha * 255;
	argb[1] = rgb[0] * alpha * 255;
	argb[2] = rgb[1] * alpha * 255;
	argb[3] = rgb[2] * alpha * 255;
	argb[4] = rgb[0] * 255;
	argb[5] = rgb[1] * 255;
	argb[6] = rgb[2] * 255;

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
