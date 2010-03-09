#include "fitz.h"

void fz_nullfillpath(void *user, fz_path *path, fz_colorspace *colorspace, float *color, float alpha) {}
void fz_nullstrokepath(void *user, fz_path *path, fz_colorspace *colorspace, float *color, float alpha) {}
void fz_nullclippath(void *user, fz_path *path) {}
void fz_nullfilltext(void *user, fz_text *text, fz_colorspace *colorspace, float *color, float alpha) {}
void fz_nullstroketext(void *user, fz_text *text, fz_colorspace *colorspace, float *color, float alpha) {}
void fz_nullcliptext(void *user, fz_text *text) {}
void fz_nullignoretext(void *user, fz_text *text) {}
void fz_nullpopclip(void *user) {}
void fz_nulldrawshade(void *user, fz_shade *shade, fz_matrix ctm) {}
void fz_nulldrawimage(void *user, fz_pixmap *image, fz_matrix ctm) {}
void fz_nullfillimagemask(void *user, fz_pixmap *image, fz_matrix ctm, fz_colorspace *colorspace, float *color, float alpha) {}
void fz_nullclipimagemask(void *user, fz_pixmap *image, fz_matrix ctm) {}

fz_device *fz_newdevice(void *user)
{
	fz_device *dev = fz_malloc(sizeof(fz_device));
	memset(dev, 0, sizeof(fz_device));

	dev->user = user;

	dev->fillpath = fz_nullfillpath;
	dev->strokepath = fz_nullstrokepath;
	dev->clippath = fz_nullclippath;

	dev->filltext = fz_nullfilltext;
	dev->stroketext = fz_nullstroketext;
	dev->cliptext = fz_nullcliptext;
	dev->ignoretext = fz_nullignoretext;

	dev->fillimagemask = fz_nullfillimagemask;
	dev->clipimagemask = fz_nullclipimagemask;
	dev->drawimage = fz_nulldrawimage;
	dev->drawshade = fz_nulldrawshade;

	dev->popclip = fz_nullpopclip;

	return dev;
}
