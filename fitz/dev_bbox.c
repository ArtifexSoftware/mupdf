#include "fitz-internal.h"

/* TODO: add clip stack and use to intersect bboxes */

static void
fz_bbox_fill_path(fz_device *dev, fz_path *path, int even_odd, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_rect *result = dev->user;
	fz_rect r;
	fz_union_rect(result, fz_bound_path(dev->ctx, path, NULL, ctm, &r));
}

static void
fz_bbox_stroke_path(fz_device *dev, fz_path *path, fz_stroke_state *stroke,
	const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_rect *result = dev->user;
	fz_rect r;
	fz_union_rect(result, fz_bound_path(dev->ctx, path, stroke, ctm, &r));
}

static void
fz_bbox_fill_text(fz_device *dev, fz_text *text, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_rect *result = dev->user;
	fz_rect r;
	fz_union_rect(result, fz_bound_text(dev->ctx, text, ctm, &r));
}

static void
fz_bbox_stroke_text(fz_device *dev, fz_text *text, fz_stroke_state *stroke,
	const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_rect *result = dev->user;
	fz_rect r;
	fz_union_rect(result, fz_bound_text(dev->ctx, text, ctm, &r));
}

static void
fz_bbox_fill_shade(fz_device *dev, fz_shade *shade, const fz_matrix *ctm, float alpha)
{
	fz_rect *result = dev->user;
	fz_rect r;
	fz_union_rect(result, fz_bound_shade(dev->ctx, shade, ctm, &r));
}

static void
fz_bbox_fill_image(fz_device *dev, fz_image *image, const fz_matrix *ctm, float alpha)
{
	fz_rect *result = dev->user;
	fz_rect r = fz_unit_rect;
	fz_union_rect(result, fz_transform_rect(&r, ctm));
}

static void
fz_bbox_fill_image_mask(fz_device *dev, fz_image *image, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_rect *result = dev->user;
	fz_rect r = fz_unit_rect;
	fz_union_rect(result, fz_transform_rect(&r, ctm));
}

fz_device *
fz_new_bbox_device(fz_context *ctx, fz_rect *result)
{
	fz_device *dev;

	dev = fz_new_device(ctx, result);

	dev->fill_path = fz_bbox_fill_path;
	dev->stroke_path = fz_bbox_stroke_path;
	dev->fill_text = fz_bbox_fill_text;
	dev->stroke_text = fz_bbox_stroke_text;
	dev->fill_shade = fz_bbox_fill_shade;
	dev->fill_image = fz_bbox_fill_image;
	dev->fill_image_mask = fz_bbox_fill_image_mask;

	*result = fz_empty_rect;

	return dev;
}
