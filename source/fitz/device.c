#include "mupdf/fitz.h"
#include "fitz-imp.h"

#include <string.h>

fz_device *
fz_new_device_of_size(fz_context *ctx, int size)
{
	fz_device *dev = Memento_label(fz_calloc(ctx, 1, size), "fz_device");
	dev->refs = 1;
	return dev;
}

void
fz_close_device(fz_context *ctx, fz_device *dev)
{
	if (dev == NULL)
		return;
	if (dev->close_device)
		dev->close_device(ctx, dev);

	/* Don't call more than once! */
	dev->close_device = NULL;

	/* And disable all further device calls. */
	dev->fill_path = NULL;
	dev->stroke_path = NULL;
	dev->clip_path = NULL;
	dev->clip_stroke_path = NULL;
	dev->fill_text = NULL;
	dev->stroke_text = NULL;
	dev->clip_text = NULL;
	dev->clip_stroke_text = NULL;
	dev->ignore_text = NULL;
	dev->fill_shade = NULL;
	dev->fill_image = NULL;
	dev->fill_image_mask = NULL;
	dev->clip_image_mask = NULL;
	dev->pop_clip = NULL;
	dev->begin_mask = NULL;
	dev->end_mask = NULL;
	dev->begin_group = NULL;
	dev->end_group = NULL;
	dev->begin_tile = NULL;
	dev->end_tile = NULL;
}

fz_device *
fz_keep_device(fz_context *ctx, fz_device *dev)
{
	return fz_keep_imp(ctx, dev, &dev->refs);
}

void
fz_drop_device(fz_context *ctx, fz_device *dev)
{
	if (fz_drop_imp(ctx, dev, &dev->refs))
	{
		if (dev->close_device)
			fz_warn(ctx, "dropping unclosed device");
		if (dev->drop_device)
			dev->drop_device(ctx, dev);
		fz_free(ctx, dev->container);
		fz_free(ctx, dev);
	}
}

void
fz_enable_device_hints(fz_context *ctx, fz_device *dev, int hints)
{
	dev->hints |= hints;
}

void
fz_disable_device_hints(fz_context *ctx, fz_device *dev, int hints)
{
	dev->hints &= ~hints;
}

static void
push_clip_stack(fz_context *ctx, fz_device *dev, const fz_rect *rect, int flags)
{
	if (dev->container_len == dev->container_cap)
	{
		int newmax = dev->container_cap * 2;
		if (newmax == 0)
			newmax = 4;
		dev->container = fz_resize_array(ctx, dev->container, newmax, sizeof(*dev->container));
		dev->container_cap = newmax;
	}
	if (dev->container_len == 0)
		dev->container[0].scissor = *rect;
	else
	{
		dev->container[dev->container_len].scissor = dev->container[dev->container_len-1].scissor;
		fz_intersect_rect(&dev->container[dev->container_len].scissor, rect);
	}
	dev->container[dev->container_len].flags = flags;
	dev->container[dev->container_len].user = 0;
	dev->container_len++;
}

static void
pop_clip_stack(fz_context *ctx, fz_device *dev)
{
	if (dev->container_len > 0)
		dev->container_len--;
}

void
fz_fill_path(fz_context *ctx, fz_device *dev, const fz_path *path, int even_odd, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	if (dev->error_depth)
		return;
	if (dev->fill_path)
		dev->fill_path(ctx, dev, path, even_odd, ctm, colorspace, color, alpha);
}

void
fz_stroke_path(fz_context *ctx, fz_device *dev, const fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	if (dev->error_depth)
		return;
	if (dev->stroke_path)
		dev->stroke_path(ctx, dev, path, stroke, ctm, colorspace, color, alpha);
}

void
fz_clip_path(fz_context *ctx, fz_device *dev, const fz_path *path, int even_odd, const fz_matrix *ctm, const fz_rect *scissor)
{
	if (dev->error_depth)
	{
		dev->error_depth++;
		return;
	}

	fz_try(ctx)
	{
		if (dev->hints & FZ_MAINTAIN_CONTAINER_STACK)
		{
			if (scissor == NULL)
			{
				fz_rect bbox;
				fz_bound_path(ctx, path, NULL, ctm, &bbox);
				push_clip_stack(ctx, dev, &bbox, fz_device_container_stack_is_clip_path);
			}
			else
				push_clip_stack(ctx, dev, scissor, fz_device_container_stack_is_clip_path);
		}
		if (dev->clip_path)
			dev->clip_path(ctx, dev, path, even_odd, ctm, scissor);
	}
	fz_catch(ctx)
	{
		dev->error_depth = 1;
		strcpy(dev->errmess, fz_caught_message(ctx));
		/* Error swallowed */
	}
}

void
fz_clip_stroke_path(fz_context *ctx, fz_device *dev, const fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, const fz_rect *scissor)
{
	if (dev->error_depth)
	{
		dev->error_depth++;
		return;
	}

	fz_try(ctx)
	{
		if (dev->hints & FZ_MAINTAIN_CONTAINER_STACK)
		{
			if (scissor == NULL)
			{
				fz_rect bbox;
				fz_bound_path(ctx, path, stroke, ctm, &bbox);
				push_clip_stack(ctx, dev, &bbox, fz_device_container_stack_is_clip_stroke_path);
			}
			else
				push_clip_stack(ctx, dev, scissor, fz_device_container_stack_is_clip_stroke_path);
		}
		if (dev->clip_stroke_path)
			dev->clip_stroke_path(ctx, dev, path, stroke, ctm, scissor);
	}
	fz_catch(ctx)
	{
		dev->error_depth = 1;
		strcpy(dev->errmess, fz_caught_message(ctx));
		/* Error swallowed */
	}
}

void
fz_fill_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	if (dev->error_depth)
		return;
	if (dev->fill_text)
		dev->fill_text(ctx, dev, text, ctm, colorspace, color, alpha);
}

void
fz_stroke_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_stroke_state *stroke, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	if (dev->error_depth)
		return;
	if (dev->stroke_text)
		dev->stroke_text(ctx, dev, text, stroke, ctm, colorspace, color, alpha);
}

void
fz_clip_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm, const fz_rect *scissor)
{
	if (dev->error_depth)
	{
		dev->error_depth++;
		return;
	}

	fz_try(ctx)
	{
		if (dev->hints & FZ_MAINTAIN_CONTAINER_STACK)
		{
			if (scissor == NULL)
			{
				fz_rect bbox;
				fz_bound_text(ctx, text, NULL, ctm, &bbox);
				push_clip_stack(ctx, dev, &bbox, fz_device_container_stack_is_clip_text);
			}
			else
				push_clip_stack(ctx, dev, scissor, fz_device_container_stack_is_clip_text);
		}
		if (dev->clip_text)
			dev->clip_text(ctx, dev, text, ctm, scissor);
	}
	fz_catch(ctx)
	{
		dev->error_depth = 1;
		strcpy(dev->errmess, fz_caught_message(ctx));
		/* Error swallowed */
	}
}

void
fz_clip_stroke_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_stroke_state *stroke, const fz_matrix *ctm, const fz_rect *scissor)
{
	if (dev->error_depth)
	{
		dev->error_depth++;
		return;
	}

	fz_try(ctx)
	{
		if (dev->hints & FZ_MAINTAIN_CONTAINER_STACK)
		{
			if (scissor == NULL)
			{
				fz_rect bbox;
				fz_bound_text(ctx, text, stroke, ctm, &bbox);
				push_clip_stack(ctx, dev, &bbox, fz_device_container_stack_is_clip_stroke_text);
			}
			else
				push_clip_stack(ctx, dev, scissor, fz_device_container_stack_is_clip_stroke_text);
		}
		if (dev->clip_stroke_text)
			dev->clip_stroke_text(ctx, dev, text, stroke, ctm, scissor);
	}
	fz_catch(ctx)
	{
		dev->error_depth = 1;
		strcpy(dev->errmess, fz_caught_message(ctx));
		/* Error swallowed */
	}
}

void
fz_ignore_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm)
{
	if (dev->error_depth)
		return;
	if (dev->ignore_text)
		dev->ignore_text(ctx, dev, text, ctm);
}

void
fz_pop_clip(fz_context *ctx, fz_device *dev)
{
	if (dev->error_depth)
	{
		dev->error_depth--;
		if (dev->error_depth == 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "%s", dev->errmess);
		return;
	}
	if (dev->hints & FZ_MAINTAIN_CONTAINER_STACK)
		pop_clip_stack(ctx, dev);
	if (dev->pop_clip)
		dev->pop_clip(ctx, dev);
}

void
fz_fill_shade(fz_context *ctx, fz_device *dev, fz_shade *shade, const fz_matrix *ctm, float alpha)
{
	if (dev->error_depth)
		return;
	if (dev->fill_shade)
		dev->fill_shade(ctx, dev, shade, ctm, alpha);
}

void
fz_fill_image(fz_context *ctx, fz_device *dev, fz_image *image, const fz_matrix *ctm, float alpha)
{
	if (dev->error_depth)
		return;
	if (dev->fill_image)
		dev->fill_image(ctx, dev, image, ctm, alpha);
}

void
fz_fill_image_mask(fz_context *ctx, fz_device *dev, fz_image *image, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha)
{
	if (dev->error_depth)
		return;
	if (dev->fill_image_mask)
		dev->fill_image_mask(ctx, dev, image, ctm, colorspace, color, alpha);
}

void
fz_clip_image_mask(fz_context *ctx, fz_device *dev, fz_image *image, const fz_matrix *ctm, const fz_rect *scissor)
{
	if (dev->error_depth)
	{
		dev->error_depth++;
		return;
	}

	fz_try(ctx)
	{
		if (dev->hints & FZ_MAINTAIN_CONTAINER_STACK)
		{
			if (scissor == NULL)
			{
				fz_rect bbox = fz_unit_rect;
				fz_transform_rect(&bbox, ctm);
				push_clip_stack(ctx, dev, &bbox, fz_device_container_stack_is_clip_image_mask);
			}
			else
				push_clip_stack(ctx, dev, scissor, fz_device_container_stack_is_clip_image_mask);
		}
		if (dev->clip_image_mask)
			dev->clip_image_mask(ctx, dev, image, ctm, scissor);
	}
	fz_catch(ctx)
	{
		dev->error_depth = 1;
		strcpy(dev->errmess, fz_caught_message(ctx));
		/* Error swallowed */
	}
}

void
fz_begin_mask(fz_context *ctx, fz_device *dev, const fz_rect *area, int luminosity, fz_colorspace *colorspace, const float *bc)
{
	if (dev->error_depth)
	{
		dev->error_depth++;
		return;
	}

	fz_try(ctx)
	{
		if (dev->hints & FZ_MAINTAIN_CONTAINER_STACK)
			push_clip_stack(ctx, dev, area, fz_device_container_stack_in_mask);
		if (dev->begin_mask)
			dev->begin_mask(ctx, dev, area, luminosity, colorspace, bc);
	}
	fz_catch(ctx)
	{
		dev->error_depth = 1;
		strcpy(dev->errmess, fz_caught_message(ctx));
		/* Error swallowed */
	}
}

void
fz_end_mask(fz_context *ctx, fz_device *dev)
{
	if (dev->error_depth)
	{
		/* Converts from mask to clip, so no change in stack depth */
		return;
	}
	if (dev->hints & FZ_MAINTAIN_CONTAINER_STACK)
	{
		dev->container[dev->container_len-1].flags &= ~fz_device_container_stack_in_mask;
		dev->container[dev->container_len-1].flags |= fz_device_container_stack_is_mask;
	}
	fz_try(ctx)
	{
		if (dev->end_mask)
			dev->end_mask(ctx, dev);
	}
	fz_catch(ctx)
	{
		dev->error_depth = 1;
		strcpy(dev->errmess, fz_caught_message(ctx));
		/* Error swallowed */
	}
}

void
fz_begin_group(fz_context *ctx, fz_device *dev, const fz_rect *area, int isolated, int knockout, int blendmode, float alpha)
{
	if (dev->error_depth)
	{
		dev->error_depth++;
		return;
	}

	fz_try(ctx)
	{
		if (dev->hints & FZ_MAINTAIN_CONTAINER_STACK)
			push_clip_stack(ctx, dev, area, fz_device_container_stack_is_group);
		if (dev->begin_group)
			dev->begin_group(ctx, dev, area, isolated, knockout, blendmode, alpha);
	}
	fz_catch(ctx)
	{
		dev->error_depth = 1;
		strcpy(dev->errmess, fz_caught_message(ctx));
		/* Error swallowed */
	}
}

void
fz_end_group(fz_context *ctx, fz_device *dev)
{
	if (dev->error_depth)
	{
		dev->error_depth--;
		if (dev->error_depth == 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "%s", dev->errmess);
		return;
	}
	if (dev->end_group)
		dev->end_group(ctx, dev);
	if (dev->hints & FZ_MAINTAIN_CONTAINER_STACK)
		pop_clip_stack(ctx, dev);
}

void
fz_begin_tile(fz_context *ctx, fz_device *dev, const fz_rect *area, const fz_rect *view, float xstep, float ystep, const fz_matrix *ctm)
{
	(void)fz_begin_tile_id(ctx, dev, area, view, xstep, ystep, ctm, 0);
}

int
fz_begin_tile_id(fz_context *ctx, fz_device *dev, const fz_rect *area, const fz_rect *view, float xstep, float ystep, const fz_matrix *ctm, int id)
{
	int ret = 0;

	if (dev->error_depth)
	{
		dev->error_depth++;
		return 0;
	}

	if (xstep < 0)
		xstep = -xstep;
	if (ystep < 0)
		ystep = -ystep;

	fz_var(ret);

	fz_try(ctx)
	{
		if (dev->begin_tile)
			ret = dev->begin_tile(ctx, dev, area, view, xstep, ystep, ctm, id);
	}
	fz_catch(ctx)
	{
		dev->error_depth = 1;
		strcpy(dev->errmess, fz_caught_message(ctx));
		/* Error swallowed */
	}
	return ret;
}

void
fz_end_tile(fz_context *ctx, fz_device *dev)
{
	if (dev->error_depth)
	{
		dev->error_depth--;
		if (dev->error_depth == 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "%s", dev->errmess);
		return;
	}
	if (dev->end_tile)
		dev->end_tile(ctx, dev);
}

void
fz_render_flags(fz_context *ctx, fz_device *dev, int set, int clear)
{
	if (dev->render_flags)
		dev->render_flags(ctx, dev, set, clear);
}
