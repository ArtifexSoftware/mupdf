#include "fitz.h"

static void fz_null_free_user(void *user) {}
static void fz_null_fill_path(void *user, fz_path *path, int even_odd, fz_matrix ctm, fz_colorspace *colorspace, float *color, float alpha) {}
static void fz_null_stroke_path(void *user, fz_path *path, fz_stroke_state *stroke, fz_matrix ctm, fz_colorspace *colorspace, float *color, float alpha) {}
static void fz_null_clip_path(void *user, fz_path *path, int even_odd, fz_matrix ctm) {}
static void fz_null_clip_stroke_path(void *user, fz_path *path, fz_stroke_state *stroke, fz_matrix ctm) {}
static void fz_null_fill_text(void *user, fz_text *text, fz_matrix ctm, fz_colorspace *colorspace, float *color, float alpha) {}
static void fz_null_stroke_text(void *user, fz_text *text, fz_stroke_state *stroke, fz_matrix ctm, fz_colorspace *colorspace, float *color, float alpha) {}
static void fz_null_clip_text(void *user, fz_text *text, fz_matrix ctm, int accumulate) {}
static void fz_null_clip_stroke_text(void *user, fz_text *text, fz_stroke_state *stroke, fz_matrix ctm) {}
static void fz_null_ignore_text(void *user, fz_text *text, fz_matrix ctm) {}
static void fz_null_pop_clip(void *user) {}
static void fz_null_fill_shade(void *user, fz_shade *shade, fz_matrix ctm, float alpha) {}
static void fz_null_fill_image(void *user, fz_pixmap *image, fz_matrix ctm, float alpha) {}
static void fz_null_fill_image_mask(void *user, fz_pixmap *image, fz_matrix ctm, fz_colorspace *colorspace, float *color, float alpha) {}
static void fz_null_clip_image_mask(void *user, fz_pixmap *image, fz_matrix ctm) {}
static void fz_null_begin_mask(void *user, fz_rect r, int luminosity, fz_colorspace *colorspace, float *bc) {}
static void fz_null_end_mask(void *user) {}
static void fz_null_begin_group(void *user, fz_rect r, int isolated, int knockout, fz_blendmode blendmode, float alpha) {}
static void fz_null_end_group(void *user) {}
static void fz_null_begin_tile(void *user, fz_rect area, fz_rect view, float xstep, float ystep, fz_matrix ctm) {}
static void fz_null_end_tile(void *user) {}

fz_device *
fz_new_device(void *user)
{
	fz_device *dev = fz_malloc(sizeof(fz_device));
	memset(dev, 0, sizeof(fz_device));

	dev->hints = 0;

	dev->user = user;
	dev->free_user = fz_null_free_user;

	dev->fill_path = fz_null_fill_path;
	dev->stroke_path = fz_null_stroke_path;
	dev->clip_path = fz_null_clip_path;
	dev->clip_stroke_path = fz_null_clip_stroke_path;

	dev->fill_text = fz_null_fill_text;
	dev->stroke_text = fz_null_stroke_text;
	dev->clip_text = fz_null_clip_text;
	dev->clip_stroke_text = fz_null_clip_stroke_text;
	dev->ignore_text = fz_null_ignore_text;

	dev->fill_shade = fz_null_fill_shade;
	dev->fill_image = fz_null_fill_image;
	dev->fill_image_mask = fz_null_fill_image_mask;
	dev->clip_image_mask = fz_null_clip_image_mask;

	dev->pop_clip = fz_null_pop_clip;

	dev->begin_mask = fz_null_begin_mask;
	dev->end_mask = fz_null_end_mask;
	dev->begin_group = fz_null_begin_group;
	dev->end_group = fz_null_end_group;

	dev->begin_tile = fz_null_begin_tile;
	dev->end_tile = fz_null_end_tile;

	return dev;
}

void
fz_free_device(fz_device *dev)
{
	if (dev->free_user)
		dev->free_user(dev->user);
	fz_free(dev);
}
