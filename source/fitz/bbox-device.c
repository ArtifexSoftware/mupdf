#include "mupdf/fitz.h"

#define STACK_SIZE 96

typedef struct fz_bbox_device_s
{
	fz_device super;

	fz_rect *result;
	int top;
	fz_rect stack[STACK_SIZE];
	/* mask content and tiles are ignored */
	int ignore;
} fz_bbox_device;

static void
fz_bbox_add_rect(fz_context *ctx, fz_device *dev, const fz_rect *rect, int clip)
{
	fz_bbox_device *bdev = (fz_bbox_device*)dev;
	fz_rect r = *rect;

	if (0 < bdev->top && bdev->top <= STACK_SIZE)
	{
		fz_intersect_rect(&r, &bdev->stack[bdev->top-1]);
	}
	if (!clip && bdev->top <= STACK_SIZE && !bdev->ignore)
	{
		fz_union_rect(bdev->result, &r);
	}
	if (clip && ++bdev->top <= STACK_SIZE)
	{
		bdev->stack[bdev->top-1] = r;
	}
}

static void
fz_bbox_fill_path(fz_context *ctx, fz_device *dev, fz_path *path, int even_odd, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_rect r;
	fz_bbox_add_rect(ctx, dev, fz_bound_path(ctx, path, NULL, ctm, &r), 0);
}

static void
fz_bbox_stroke_path(fz_context *ctx, fz_device *dev, fz_path *path, fz_stroke_state *stroke,
	const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_rect r;
	fz_bbox_add_rect(ctx, dev, fz_bound_path(ctx, path, stroke, ctm, &r), 0);
}

static void
fz_bbox_fill_text(fz_context *ctx, fz_device *dev, fz_text *text, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_rect r;
	fz_bbox_add_rect(ctx, dev, fz_bound_text(ctx, text, NULL, ctm, &r), 0);
}

static void
fz_bbox_stroke_text(fz_context *ctx, fz_device *dev, fz_text *text, fz_stroke_state *stroke,
	const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_rect r;
	fz_bbox_add_rect(ctx, dev, fz_bound_text(ctx, text, stroke, ctm, &r), 0);
}

static void
fz_bbox_fill_shade(fz_context *ctx, fz_device *dev, fz_shade *shade, const fz_matrix *ctm, float alpha)
{
	fz_rect r;
	fz_bbox_add_rect(ctx, dev, fz_bound_shade(ctx, shade, ctm, &r), 0);
}

static void
fz_bbox_fill_image(fz_context *ctx, fz_device *dev, fz_image *image, const fz_matrix *ctm, float alpha)
{
	fz_rect r = fz_unit_rect;
	fz_bbox_add_rect(ctx, dev, fz_transform_rect(&r, ctm), 0);
}

static void
fz_bbox_fill_image_mask(fz_context *ctx, fz_device *dev, fz_image *image, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_rect r = fz_unit_rect;
	fz_bbox_add_rect(ctx, dev, fz_transform_rect(&r, ctm), 0);
}

static void
fz_bbox_clip_path(fz_context *ctx, fz_device *dev, fz_path *path, const fz_rect *rect, int even_odd, const fz_matrix *ctm)
{
	fz_rect r;
	fz_bbox_add_rect(ctx, dev, fz_bound_path(ctx, path, NULL, ctm, &r), 1);
}

static void
fz_bbox_clip_stroke_path(fz_context *ctx, fz_device *dev, fz_path *path, const fz_rect *rect, fz_stroke_state *stroke, const fz_matrix *ctm)
{
	fz_rect r;
	fz_bbox_add_rect(ctx, dev, fz_bound_path(ctx, path, stroke, ctm, &r), 1);
}

static void
fz_bbox_clip_text(fz_context *ctx, fz_device *dev, fz_text *text, const fz_matrix *ctm, int accumulate)
{
	fz_rect r = fz_infinite_rect;
	if (accumulate)
		fz_bbox_add_rect(ctx, dev, &r, accumulate != 2);
	else
		fz_bbox_add_rect(ctx, dev, fz_bound_text(ctx, text, NULL, ctm, &r), 1);
}

static void
fz_bbox_clip_stroke_text(fz_context *ctx, fz_device *dev, fz_text *text, fz_stroke_state *stroke, const fz_matrix *ctm)
{
	fz_rect r;
	fz_bbox_add_rect(ctx, dev, fz_bound_text(ctx, text, stroke, ctm, &r), 1);
}

static void
fz_bbox_clip_image_mask(fz_context *ctx, fz_device *dev, fz_image *image, const fz_rect *rect, const fz_matrix *ctm)
{
	fz_rect r = fz_unit_rect;
	fz_bbox_add_rect(ctx, dev, fz_transform_rect(&r, ctm), 1);
}

static void
fz_bbox_pop_clip(fz_context *ctx, fz_device *dev)
{
	fz_bbox_device *bdev = (fz_bbox_device*)dev;
	if (bdev->top > 0)
		bdev->top--;
	else
		fz_warn(ctx, "unexpected pop clip");
}

static void
fz_bbox_begin_mask(fz_context *ctx, fz_device *dev, const fz_rect *rect, int luminosity, fz_colorspace *colorspace, float *color)
{
	fz_bbox_device *bdev = (fz_bbox_device*)dev;
	fz_bbox_add_rect(ctx, dev, rect, 1);
	bdev->ignore++;
}

static void
fz_bbox_end_mask(fz_context *ctx, fz_device *dev)
{
	fz_bbox_device *bdev = (fz_bbox_device*)dev;
	assert(bdev->ignore > 0);
	bdev->ignore--;
}

static void
fz_bbox_begin_group(fz_context *ctx, fz_device *dev, const fz_rect *rect, int isolated, int knockout, int blendmode, float alpha)
{
	fz_bbox_add_rect(ctx, dev, rect, 1);
}

static void
fz_bbox_end_group(fz_context *ctx, fz_device *dev)
{
	fz_bbox_pop_clip(ctx, dev);
}

static int
fz_bbox_begin_tile(fz_context *ctx, fz_device *dev, const fz_rect *area, const fz_rect *view, float xstep, float ystep, const fz_matrix *ctm, int id)
{
	fz_bbox_device *bdev = (fz_bbox_device*)dev;
	fz_rect r = *area;
	fz_bbox_add_rect(ctx, dev, fz_transform_rect(&r, ctm), 0);
	bdev->ignore++;
	return 0;
}

static void
fz_bbox_end_tile(fz_context *ctx, fz_device *dev)
{
	fz_bbox_device *bdev = (fz_bbox_device*)dev;
	assert(bdev->ignore > 0);
	bdev->ignore--;
}

static void
fz_bbox_drop_imp(fz_context *ctx, fz_device *dev)
{
	fz_bbox_device *bdev = (fz_bbox_device*)dev;
	if (bdev->top > 0)
		fz_warn(ctx, "items left on stack in bbox device: %d", bdev->top);
}

fz_device *
fz_new_bbox_device(fz_context *ctx, fz_rect *result)
{
	fz_bbox_device *dev = fz_new_device(ctx, sizeof *dev);

	dev->super.drop_imp = fz_bbox_drop_imp;

	dev->super.fill_path = fz_bbox_fill_path;
	dev->super.stroke_path = fz_bbox_stroke_path;
	dev->super.clip_path = fz_bbox_clip_path;
	dev->super.clip_stroke_path = fz_bbox_clip_stroke_path;

	dev->super.fill_text = fz_bbox_fill_text;
	dev->super.stroke_text = fz_bbox_stroke_text;
	dev->super.clip_text = fz_bbox_clip_text;
	dev->super.clip_stroke_text = fz_bbox_clip_stroke_text;

	dev->super.fill_shade = fz_bbox_fill_shade;
	dev->super.fill_image = fz_bbox_fill_image;
	dev->super.fill_image_mask = fz_bbox_fill_image_mask;
	dev->super.clip_image_mask = fz_bbox_clip_image_mask;

	dev->super.pop_clip = fz_bbox_pop_clip;

	dev->super.begin_mask = fz_bbox_begin_mask;
	dev->super.end_mask = fz_bbox_end_mask;
	dev->super.begin_group = fz_bbox_begin_group;
	dev->super.end_group = fz_bbox_end_group;

	dev->super.begin_tile = fz_bbox_begin_tile;
	dev->super.end_tile = fz_bbox_end_tile;

	dev->result = result;
	dev->top = 0;
	dev->ignore = 0;

	*result = fz_empty_rect;

	return (fz_device*)dev;
}
