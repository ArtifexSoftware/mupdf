#include "mupdf/fitz.h"
#include "mupdf/ucdn.h"

#include <math.h>
#include <float.h>
#include <string.h>

/* Extract text into blocks and lines. */

#define LINE_DIST 0.9f
#define SPACE_DIST 0.15f
#define SPACE_MAX_DIST 0.8f
#define PARAGRAPH_DIST 0.5f

typedef struct fz_stext_device_s fz_stext_device;

struct fz_stext_device_s
{
	fz_device super;
	fz_stext_page *page;
	fz_point pen, start;
	fz_matrix trm;
	int new_obj;
	int curdir;
	int lastchar;
	int flags;
};

const char *fz_stext_options_usage =
	"Text output options:\n"
	"\tpreserve-ligatures: do not expand ligatures into constituent characters\n"
	"\tpreserve-whitespace: do not convert all whitespace into space characters\n"
	"\tpreserve-images: keep images in output\n"
	"\n";

fz_stext_page *
fz_new_stext_page(fz_context *ctx, const fz_rect *mediabox)
{
	fz_pool *pool = fz_new_pool(ctx);
	fz_stext_page *page = NULL;
	fz_try(ctx)
	{
		page = fz_pool_alloc(ctx, pool, sizeof(*page));
		page->pool = pool;
		page->mediabox = *mediabox;
		page->first_block = NULL;
		page->last_block = NULL;
	}
	fz_catch(ctx)
	{
		fz_drop_pool(ctx, pool);
		fz_rethrow(ctx);
	}
	return page;
}

void
fz_drop_stext_page(fz_context *ctx, fz_stext_page *page)
{
	if (page)
	{
		fz_stext_block *block;
		for (block = page->first_block; block; block = block->next)
			if (block->type == FZ_STEXT_BLOCK_IMAGE)
				fz_drop_image(ctx, block->u.i.image);
		fz_drop_pool(ctx, page->pool);
	}
}

static fz_stext_block *
add_block_to_page(fz_context *ctx, fz_stext_page *page)
{
	fz_stext_block *block = fz_pool_alloc(ctx, page->pool, sizeof *page->first_block);
	block->prev = page->last_block;
	if (!page->first_block)
		page->first_block = page->last_block = block;
	else
	{
		page->last_block->next = block;
		page->last_block = block;
	}
	return block;
}

static fz_stext_block *
add_text_block_to_page(fz_context *ctx, fz_stext_page *page)
{
	fz_stext_block *block = add_block_to_page(ctx, page);
	block->type = FZ_STEXT_BLOCK_TEXT;
	return block;
}

static fz_stext_block *
add_image_block_to_page(fz_context *ctx, fz_stext_page *page, const fz_matrix *ctm, fz_image *image)
{
	fz_stext_block *block = add_block_to_page(ctx, page);
	block->type = FZ_STEXT_BLOCK_IMAGE;
	block->u.i.transform = *ctm;
	block->u.i.image = fz_keep_image(ctx, image);
	block->bbox.x0 = 0;
	block->bbox.y0 = 0;
	block->bbox.x1 = 1;
	block->bbox.y1 = 1;
	fz_transform_rect(&block->bbox, ctm);
	return block;
}

static fz_stext_line *
add_line_to_block(fz_context *ctx, fz_stext_page *page, fz_stext_block *block, const fz_point *dir, int wmode)
{
	fz_stext_line *line = fz_pool_alloc(ctx, page->pool, sizeof *block->u.t.first_line);
	line->prev = block->u.t.last_line;
	if (!block->u.t.first_line)
		block->u.t.first_line = block->u.t.last_line = line;
	else
	{
		block->u.t.last_line->next = line;
		block->u.t.last_line = line;
	}

	line->dir = *dir;
	line->wmode = wmode;

	return line;
}

static float min4(float a, float b, float c, float d)
{
	return fz_min(fz_min(a, b), fz_min(c, d));
}

static float max4(float a, float b, float c, float d)
{
	return fz_max(fz_max(a, b), fz_max(c, d));
}

static fz_stext_char *
add_char_to_line(fz_context *ctx, fz_stext_page *page, fz_stext_line *line, const fz_matrix *trm, fz_font *font, float size, int c, fz_point *p, fz_point *q)
{
	fz_stext_char *ch = fz_pool_alloc(ctx, page->pool, sizeof *line->first_char);
	fz_point a, d;

	if (!line->first_char)
		line->first_char = line->last_char = ch;
	else
	{
		line->last_char->next = ch;
		line->last_char = ch;
	}

	ch->c = c;
	ch->origin = *p;
	ch->size = size;
	ch->font = font; /* TODO: keep and drop */

	if (line->wmode == 0)
	{
		a.x = 0;
		d.x = 0;
		a.y = fz_font_ascender(ctx, font);
		d.y = fz_font_descender(ctx, font);
	}
	else
	{
		fz_rect *bbox = fz_font_bbox(ctx, font);
		a.x = bbox->x1;
		d.x = bbox->x0;
		a.y = 0;
		d.y = 0;
	}
	fz_transform_vector(&a, trm);
	fz_transform_vector(&d, trm);

	ch->bbox.x0 = min4(p->x + a.x, q->x + a.x, p->x + d.x, q->x + d.x);
	ch->bbox.x1 = max4(p->x + a.x, q->x + a.x, p->x + d.x, q->x + d.x);
	ch->bbox.y0 = min4(p->y + a.y, q->y + a.y, p->y + d.y, q->y + d.y);
	ch->bbox.y1 = max4(p->y + a.y, q->y + a.y, p->y + d.y, q->y + d.y);

	return ch;
}

static int
direction_from_bidi_class(int bidiclass, int curdir)
{
	switch (bidiclass)
	{
	/* strong */
	case UCDN_BIDI_CLASS_L: return 1;
	case UCDN_BIDI_CLASS_R: return -1;
	case UCDN_BIDI_CLASS_AL: return -1;

	/* weak */
	case UCDN_BIDI_CLASS_EN:
	case UCDN_BIDI_CLASS_ES:
	case UCDN_BIDI_CLASS_ET:
	case UCDN_BIDI_CLASS_AN:
	case UCDN_BIDI_CLASS_CS:
	case UCDN_BIDI_CLASS_NSM:
	case UCDN_BIDI_CLASS_BN:
		return curdir;

	/* neutral */
	case UCDN_BIDI_CLASS_B:
	case UCDN_BIDI_CLASS_S:
	case UCDN_BIDI_CLASS_WS:
	case UCDN_BIDI_CLASS_ON:
		return curdir;

	/* embedding, override, pop ... we don't support them */
	default:
		return 0;
	}
}

static float
vec_dot(const fz_point *a, const fz_point *b)
{
	return a->x * b->x + a->y * b->y;
}

static void
fz_add_stext_char_imp(fz_context *ctx, fz_stext_device *dev, fz_font *font, int c, int glyph, fz_matrix *trm, float adv, int wmode)
{
	fz_stext_page *page = dev->page;
	fz_stext_block *cur_block;
	fz_stext_line *cur_line;

	int new_para = 0;
	int new_line = 1;
	int add_space = 0;
	fz_point dir, ndir, p, q;
	float size;
	fz_point delta;
	float spacing = 0;
	float base_offset = 0;
	int rtl = 0;

	dev->curdir = direction_from_bidi_class(ucdn_get_bidi_class(c), dev->curdir);

	/* dir = direction vector for motion. ndir = normalised(dir) */
	if (wmode == 0)
	{
		dir.x = 1;
		dir.y = 0;
	}
	else
	{
		dir.x = 0;
		dir.y = -1;
	}
	fz_transform_vector(&dir, trm);
	ndir = dir;
	fz_normalize_vector(&ndir);

	size = fz_matrix_expansion(trm);

	/* We need to identify where glyphs 'start' (p) and 'stop' (q).
	 * Each glyph holds its 'start' position, and the next glyph in the
	 * span (or span->max if there is no next glyph) holds its 'end'
	 * position.
	 *
	 * For both horizontal and vertical motion, trm->{e,f} gives the
	 * origin (usually the bottom left) of the glyph.
	 *
	 * In horizontal mode:
	 *   + p is bottom left.
	 *   + q is the bottom right
	 * In vertical mode:
	 *   + p is top left (where it advanced from)
	 *   + q is bottom left
	 */
	if (wmode == 0)
	{
		p.x = trm->e;
		p.y = trm->f;
		q.x = trm->e + adv * dir.x;
		q.y = trm->f + adv * dir.y;
	}
	else
	{
		p.x = trm->e - adv * dir.x;
		p.y = trm->f - adv * dir.y;
		q.x = trm->e;
		q.y = trm->f;
	}

	/* Find current position to enter new text. */
	cur_block = page->last_block;
	if (cur_block && cur_block->type != FZ_STEXT_BLOCK_TEXT)
		cur_block = NULL;
	cur_line = cur_block ? cur_block->u.t.last_line : NULL;

	if (cur_line && glyph < 0)
	{
		/* Don't advance pen or break lines for no-glyph characters in a cluster */
		add_char_to_line(ctx, page, cur_line, trm, font, size, c, &dev->pen, &dev->pen);
		dev->lastchar = c;
		return;
	}

	if (cur_line == NULL || cur_line->wmode != wmode || vec_dot(&ndir, &cur_line->dir) < 0.999f)
	{
		/* If the matrix has changed rotation, or the wmode is different (or if we don't have a line at all),
		 * then we can't append to the current block/line. */
		new_para = 1;
		new_line = 1;
	}
	else
	{
		/* Detect fake bold where text is printed twice in the same place. */
		delta.x = fabsf(q.x - dev->pen.x);
		delta.y = fabsf(q.y - dev->pen.y);
		if (delta.x < FLT_EPSILON && delta.y < FLT_EPSILON && c == dev->lastchar)
			return;

		/* Calculate how far we've moved since the last character. */
		delta.x = p.x - dev->pen.x;
		delta.y = p.y - dev->pen.y;

		/* The transform has not changed, so we know we're in the same
		 * direction. Calculate 2 distances; how far off the previous
		 * baseline we are, together with how far along the baseline
		 * we are from the expected position. */
		spacing = ndir.x * delta.x + ndir.y * delta.y;
		base_offset = -ndir.y * delta.x + ndir.x * delta.y;

		/* Only a small amount off the baseline - we'll take this */
		if (fabsf(base_offset) < size * 0.8f)
		{
			/* LTR or neutral character */
			if (dev->curdir >= 0)
			{
				if (fabsf(spacing) < size * SPACE_DIST)
				{
					/* Motion is in line, and small. */
					new_line = 0;
				}
				else if (spacing >= size * SPACE_DIST && spacing < size * SPACE_MAX_DIST)
				{
					/* Motion is in line, but large enough to warrant us adding a space. */
					if (dev->lastchar != ' ' && wmode == 0)
						add_space = 1;
					new_line = 0;
				}
				else
				{
					/* Motion is in line, but large enough to warrant splitting to a new line */
					new_line = 1;
				}
			}

			/* RTL character -- disable space character and column detection heuristics */
			else
			{
				new_line = 0;
				if (spacing > size * SPACE_DIST || spacing < 0)
					rtl = 0; /* backward (or big jump to 'right' side) means logical order */
				else
					rtl = 1; /* visual order, we need to reverse in a post process pass */
			}
		}

		/* Enough for a new line, but not enough for a new paragraph */
		else if (fabsf(base_offset) < size * 1.3f)
		{
			/* Check indent to spot text-indent style paragraphs */
			if (wmode == 0 && cur_line && dev->new_obj)
				if (fabsf(p.x - dev->start.x) > size * 0.5f)
					new_para = 1;
			new_line = 1;
		}

		/* Way off the baseline - open a new paragraph */
		else
		{
			new_para = 1;
			new_line = 1;
		}
	}

	/* Start a new block (but only at the beginning of a text object) */
	if (new_para || !cur_block)
	{
		cur_block = add_text_block_to_page(ctx, page);
		cur_line = cur_block->u.t.last_line;
	}

	/* Start a new line */
	if (new_line || !cur_line)
	{
		cur_line = add_line_to_block(ctx, page, cur_block, &ndir, wmode);
		dev->start = p;
	}

	/* Add synthetic space */
	if (add_space)
		add_char_to_line(ctx, page, cur_line, trm, font, size, ' ', &dev->pen, &p);

	add_char_to_line(ctx, page, cur_line, trm, font, size, c, &p, &q);
	dev->lastchar = c;
	dev->pen = q;

	dev->new_obj = 0;
	dev->trm = *trm;
}

static void
fz_add_stext_char(fz_context *ctx, fz_stext_device *dev, fz_font *font, int c, int glyph, fz_matrix *trm, float adv, int wmode)
{
	/* ignore when one unicode character maps to multiple glyphs */
	if (c == -1)
		return;

	if (!(dev->flags & FZ_STEXT_PRESERVE_LIGATURES))
	{
		switch (c)
		{
		case 0xFB00: /* ff */
			fz_add_stext_char_imp(ctx, dev, font, 'f', glyph, trm, adv, wmode);
			fz_add_stext_char_imp(ctx, dev, font, 'f', -1, trm, 0, wmode);
			return;
		case 0xFB01: /* fi */
			fz_add_stext_char_imp(ctx, dev, font, 'f', glyph, trm, adv, wmode);
			fz_add_stext_char_imp(ctx, dev, font, 'i', -1, trm, 0, wmode);
			return;
		case 0xFB02: /* fl */
			fz_add_stext_char_imp(ctx, dev, font, 'f', glyph, trm, adv, wmode);
			fz_add_stext_char_imp(ctx, dev, font, 'l', -1, trm, 0, wmode);
			return;
		case 0xFB03: /* ffi */
			fz_add_stext_char_imp(ctx, dev, font, 'f', glyph, trm, adv, wmode);
			fz_add_stext_char_imp(ctx, dev, font, 'f', -1, trm, 0, wmode);
			fz_add_stext_char_imp(ctx, dev, font, 'i', -1, trm, 0, wmode);
			return;
		case 0xFB04: /* ffl */
			fz_add_stext_char_imp(ctx, dev, font, 'f', glyph, trm, adv, wmode);
			fz_add_stext_char_imp(ctx, dev, font, 'f', -1, trm, 0, wmode);
			fz_add_stext_char_imp(ctx, dev, font, 'l', -1, trm, 0, wmode);
			return;
		case 0xFB05: /* long st */
		case 0xFB06: /* st */
			fz_add_stext_char_imp(ctx, dev, font, 's', glyph, trm, adv, wmode);
			fz_add_stext_char_imp(ctx, dev, font, 't', -1, trm, 0, wmode);
			return;
		}
	}

	if (!(dev->flags & FZ_STEXT_PRESERVE_WHITESPACE))
	{
		switch (c)
		{
		case 0x0009: /* tab */
		case 0x0020: /* space */
		case 0x00A0: /* no-break space */
		case 0x1680: /* ogham space mark */
		case 0x180E: /* mongolian vowel separator */
		case 0x2000: /* en quad */
		case 0x2001: /* em quad */
		case 0x2002: /* en space */
		case 0x2003: /* em space */
		case 0x2004: /* three-per-em space */
		case 0x2005: /* four-per-em space */
		case 0x2006: /* six-per-em space */
		case 0x2007: /* figure space */
		case 0x2008: /* punctuation space */
		case 0x2009: /* thin space */
		case 0x200A: /* hair space */
		case 0x202F: /* narrow no-break space */
		case 0x205F: /* medium mathematical space */
		case 0x3000: /* ideographic space */
			c = ' ';
		}
	}

	fz_add_stext_char_imp(ctx, dev, font, c, glyph, trm, adv, wmode);
}

static void
fz_stext_extract(fz_context *ctx, fz_stext_device *dev, fz_text_span *span, const fz_matrix *ctm)
{
	fz_font *font = span->font;
	fz_matrix tm = span->trm;
	fz_matrix trm;
	float adv;
	int i;

	if (span->len == 0)
		return;

	tm.e = 0;
	tm.f = 0;
	fz_concat(&trm, &tm, ctm);

	for (i = 0; i < span->len; i++)
	{
		/* Calculate new pen location and delta */
		tm.e = span->items[i].x;
		tm.f = span->items[i].y;
		fz_concat(&trm, &tm, ctm);

		/* Calculate bounding box and new pen position based on font metrics */
		if (span->items[i].gid >= 0)
			adv = fz_advance_glyph(ctx, font, span->items[i].gid, span->wmode);
		else
			adv = 0;

		fz_add_stext_char(ctx, dev, font, span->items[i].ucs, span->items[i].gid, &trm, adv, span->wmode);
	}
}

static void
fz_stext_fill_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha, const fz_color_params *color_params)
{
	fz_stext_device *tdev = (fz_stext_device*)dev;
	fz_text_span *span;
	tdev->new_obj = 1;
	for (span = text->head; span; span = span->next)
		fz_stext_extract(ctx, tdev, span, ctm);
}

static void
fz_stext_stroke_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_stroke_state *stroke, const fz_matrix *ctm,
	fz_colorspace *colorspace, const float *color, float alpha, const fz_color_params *color_params)
{
	fz_stext_device *tdev = (fz_stext_device*)dev;
	fz_text_span *span;
	tdev->new_obj = 1;
	for (span = text->head; span; span = span->next)
		fz_stext_extract(ctx, tdev, span, ctm);
}

static void
fz_stext_clip_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_stext_device *tdev = (fz_stext_device*)dev;
	fz_text_span *span;
	tdev->new_obj = 1;
	for (span = text->head; span; span = span->next)
		fz_stext_extract(ctx, tdev, span, ctm);
}

static void
fz_stext_clip_stroke_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_stroke_state *stroke, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_stext_device *tdev = (fz_stext_device*)dev;
	fz_text_span *span;
	tdev->new_obj = 1;
	for (span = text->head; span; span = span->next)
		fz_stext_extract(ctx, tdev, span, ctm);
}

static void
fz_stext_ignore_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm)
{
	fz_stext_device *tdev = (fz_stext_device*)dev;
	fz_text_span *span;
	tdev->new_obj = 1;
	for (span = text->head; span; span = span->next)
		fz_stext_extract(ctx, tdev, span, ctm);
}

/* Images and shadings */

static void
fz_stext_fill_image(fz_context *ctx, fz_device *dev, fz_image *img, const fz_matrix *ctm, float alpha, const fz_color_params *color_params)
{
	fz_stext_device *tdev = (fz_stext_device*)dev;

	/* If the alpha is less than 50% then it's probably a watermark or effect or something. Skip it. */
	if (alpha < 0.5f)
		return;

	add_image_block_to_page(ctx, tdev->page, ctm, img);
}

static void
fz_stext_fill_image_mask(fz_context *ctx, fz_device *dev, fz_image *img, const fz_matrix *ctm,
		fz_colorspace *cspace, const float *color, float alpha, const fz_color_params *color_params)
{
	fz_stext_fill_image(ctx, dev, img, ctm, alpha, color_params);
}

static fz_image *
fz_new_image_from_shade(fz_context *ctx, fz_shade *shade, fz_matrix *in_out_ctm, const fz_color_params *color_params, const fz_rect *scissor)
{
	fz_matrix ctm = *in_out_ctm;
	fz_pixmap *pix;
	fz_image *img = NULL;
	fz_rect bounds;
	fz_irect bbox;

	fz_bound_shade(ctx, shade, &ctm, &bounds);
	fz_intersect_rect(&bounds, scissor);
	fz_irect_from_rect(&bbox, &bounds);

	pix = fz_new_pixmap_with_bbox(ctx, fz_device_rgb(ctx), &bbox, NULL, !shade->use_background);
	fz_try(ctx)
	{
		if (shade->use_background)
			fz_fill_pixmap_with_color(ctx, pix, shade->colorspace, shade->background, color_params);
		else
			fz_clear_pixmap(ctx, pix);
		fz_paint_shade(ctx, shade, NULL, &ctm, pix, color_params, &bbox, NULL);
		img = fz_new_image_from_pixmap(ctx, pix, NULL);
	}
	fz_always(ctx)
		fz_drop_pixmap(ctx, pix);
	fz_catch(ctx)
		fz_rethrow(ctx);

	in_out_ctm->a = pix->w;
	in_out_ctm->b = 0;
	in_out_ctm->c = 0;
	in_out_ctm->d = pix->h;
	in_out_ctm->e = pix->x;
	in_out_ctm->f = pix->y;
	return img;
}

static void
fz_stext_fill_shade(fz_context *ctx, fz_device *dev, fz_shade *shade, const fz_matrix *ctm, float alpha, const fz_color_params *color_params)
{
	fz_matrix local_ctm = *ctm;
	const fz_rect *scissor = fz_device_current_scissor(ctx, dev);
	fz_image *image = fz_new_image_from_shade(ctx, shade, &local_ctm, color_params, scissor);
	fz_try(ctx)
		fz_stext_fill_image(ctx, dev, image, &local_ctm, alpha, color_params);
	fz_always(ctx)
		fz_drop_image(ctx, image);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void
fz_stext_close_device(fz_context *ctx, fz_device *dev)
{
	fz_stext_device *tdev = (fz_stext_device*)dev;
	fz_stext_page *page = tdev->page;
	fz_stext_block *block;
	fz_stext_line *line;
	fz_stext_char *ch;

	for (block = page->first_block; block; block = block->next)
	{
		if (block->type != FZ_STEXT_BLOCK_TEXT)
			continue;
		for (line = block->u.t.first_line; line; line = line->next)
		{
			for (ch = line->first_char; ch; ch = ch->next)
				fz_union_rect(&line->bbox, &ch->bbox);
			fz_union_rect(&block->bbox, &line->bbox);
		}
	}

	/* TODO: smart sorting of blocks and lines in reading order */
	/* TODO: unicode NFC normalization */
}

static void
fz_stext_drop_device(fz_context *ctx, fz_device *dev)
{
}

fz_stext_options *
fz_parse_stext_options(fz_context *ctx, fz_stext_options *opts, const char *string)
{
	const char *val;

	memset(opts, 0, sizeof *opts);

	if (fz_has_option(ctx, string, "preserve-ligatures", &val) && fz_option_eq(val, "yes"))
		opts->flags |= FZ_STEXT_PRESERVE_LIGATURES;
	if (fz_has_option(ctx, string, "preserve-whitespace", &val) && fz_option_eq(val, "yes"))
		opts->flags |= FZ_STEXT_PRESERVE_WHITESPACE;
	if (fz_has_option(ctx, string, "preserve-images", &val) && fz_option_eq(val, "yes"))
		opts->flags |= FZ_STEXT_PRESERVE_IMAGES;

	return opts;
}

fz_device *
fz_new_stext_device(fz_context *ctx, fz_stext_page *page, const fz_stext_options *opts)
{
	fz_stext_device *dev = fz_new_derived_device(ctx, fz_stext_device);

	dev->super.close_device = fz_stext_close_device;
	dev->super.drop_device = fz_stext_drop_device;

	dev->super.fill_text = fz_stext_fill_text;
	dev->super.stroke_text = fz_stext_stroke_text;
	dev->super.clip_text = fz_stext_clip_text;
	dev->super.clip_stroke_text = fz_stext_clip_stroke_text;
	dev->super.ignore_text = fz_stext_ignore_text;

	if (opts && (opts->flags & FZ_STEXT_PRESERVE_IMAGES))
	{
		dev->super.hints |= FZ_MAINTAIN_CONTAINER_STACK;
		dev->super.fill_shade = fz_stext_fill_shade;
		dev->super.fill_image = fz_stext_fill_image;
		dev->super.fill_image_mask = fz_stext_fill_image_mask;
	}

	dev->page = page;
	dev->pen.x = 0;
	dev->pen.y = 0;
	dev->trm = fz_identity;
	dev->lastchar = ' ';
	dev->curdir = 1;

	return (fz_device*)dev;
}
