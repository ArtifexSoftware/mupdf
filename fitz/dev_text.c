#include "fitz-internal.h"

#define LINE_DIST 0.9f
#define SPACE_DIST 0.2f
#define SPACE_MAX_DIST 0.8f
#define PARAGRAPH_DIST 0.5f

#undef DEBUG_SPANS
#undef DEBUG_INTERNALS
#undef DEBUG_LINE_HEIGHTS

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_ADVANCES_H

typedef struct fz_text_device_s fz_text_device;

typedef struct span_soup_s span_soup;

struct fz_text_device_s
{
	fz_text_sheet *sheet;
	fz_text_page *page;
	span_soup *spans;
	fz_text_span *cur_span;
	int lastchar;
};

static fz_rect *
add_point_to_rect(fz_rect *a, const fz_point *p)
{
	if (p->x < a->x0)
		a->x0 = p->x;
	if (p->x > a->x1)
		a->x1 = p->x;
	if (p->y < a->y0)
		a->y0 = p->y;
	if (p->y > a->y1)
		a->y1 = p->y;
	return a;
}

fz_rect *
fz_text_char_bbox(fz_rect *bbox, fz_text_span *span, int i)
{
	fz_point a, d;
	const fz_point *max;
	fz_text_char *ch;

	if (!span || i >= span->len)
	{
		*bbox = fz_empty_rect;
	}
	ch = &span->text[i];
	if (i == span->len-1)
		max = &span->max;
	else
		max = &span->text[i+1].p;
	a.x = 0;
	a.y = span->ascender_max;
	fz_transform_vector(&a, &span->transform);
	d.x = 0;
	d.y = span->descender_min;
	fz_transform_vector(&d, &span->transform);
	bbox->x0 = bbox->x1 = ch->p.x + a.x;
	bbox->y0 = bbox->y1 = ch->p.y + a.y;
	a.x += max->x;
	a.y += max->y;
	add_point_to_rect(bbox, &a);
	a.x = ch->p.x + d.x;
	a.y = ch->p.y + d.y;
	add_point_to_rect(bbox, &a);
	a.x = max->x + d.x;
	a.y = max->y + d.y;
	add_point_to_rect(bbox, &a);
	return bbox;
}

static void
add_bbox_to_span(fz_text_span *span)
{
	fz_point a, d;
	fz_rect *bbox = &span->bbox;

	if (!span)
		return;
	a.x = 0;
	a.y = span->ascender_max;
	fz_transform_vector(&a, &span->transform);
	d.x = 0;
	d.y = span->descender_min;
	fz_transform_vector(&d, &span->transform);
	bbox->x0 = bbox->x1 = span->min.x + a.x;
	bbox->y0 = bbox->y1 = span->min.y + a.y;
	a.x += span->max.x;
	a.y += span->max.y;
	add_point_to_rect(bbox, &a);
	a.x = span->min.x + d.x;
	a.y = span->min.y + d.y;
	add_point_to_rect(bbox, &a);
	a.x = span->max.x + d.x;
	a.y = span->max.y + d.y;
	add_point_to_rect(bbox, &a);
}

struct span_soup_s
{
	fz_context *ctx;
	int len, cap;
	fz_text_span **spans;
};

static span_soup *
new_span_soup(fz_context *ctx)
{
	span_soup *soup = fz_malloc_struct(ctx, span_soup);
	soup->ctx = ctx;
	soup->len = 0;
	soup->cap = 0;
	soup->spans = NULL;
	return soup;
}

static void
free_span_soup(span_soup *soup)
{
	int i;

	if (soup == NULL)
		return;
	for (i = 0; i < soup->len; i++)
	{
		fz_free(soup->ctx, soup->spans[i]);
	}
	fz_free(soup->ctx, soup->spans);
	fz_free(soup->ctx, soup);
}

static void
add_span_to_soup(span_soup *soup, fz_text_span *span)
{
	if (span == NULL)
		return;
	if (soup->len == soup->cap)
	{
		int newcap = (soup->cap ? soup->cap * 2 : 16);
		soup->spans = fz_resize_array(soup->ctx, soup->spans, newcap, sizeof(*soup->spans));
		soup->cap = newcap;
	}
	add_bbox_to_span(span);
	soup->spans[soup->len++] = span;
}

static fz_text_line *
push_span(fz_context *ctx, fz_text_device *tdev, fz_text_span *span, int new_line, float distance)
{
	fz_text_line *line;
	fz_text_block *block;
	fz_text_page *page = tdev->page;

	if (new_line)
	{
		/* So, a new line. Part of the same block or not? */
		float size = fz_matrix_expansion(&span->transform);
		if (distance == 0 || distance > size * 1.5 || distance < -size * PARAGRAPH_DIST || page->len == 0)
		{
			/* New block */
			if (page->len == page->cap)
			{
				int newcap = (page->cap ? page->cap*2 : 4);
				page->blocks = fz_resize_array(ctx, page->blocks, newcap, sizeof(*page->blocks));
				page->cap = newcap;
			}
			page->blocks[page->len].cap = 0;
			page->blocks[page->len].len = 0;
			page->blocks[page->len].lines = 0;
			page->blocks[page->len].bbox = fz_empty_rect;
			page->len++;
			distance = 0;
		}

		/* New line */
		block = &page->blocks[page->len-1];
		if (block->len == block->cap)
		{
			int newcap = (block->cap ? block->cap*2 : 4);
			block->lines = fz_resize_array(ctx, block->lines, newcap, sizeof(*block->lines));
			block->cap = newcap;
		}
		block->lines[block->len].cap = 0;
		block->lines[block->len].len = 0;
		block->lines[block->len].spans = NULL;
		block->lines[block->len].distance = distance;
		block->lines[block->len].bbox = fz_empty_rect;
		block->len++;
	}

	/* Find last line and append to it */
	block = &page->blocks[page->len-1];
	line = &block->lines[block->len-1];

	if (line->len == line->cap)
	{
		int newcap = (line->cap ? line->cap*2 : 4);
		line->spans = fz_resize_array(ctx, line->spans, newcap, sizeof(*line->spans));
		line->cap = newcap;
	}
	fz_union_rect(&block->lines[block->len-1].bbox, &span->bbox);
	fz_union_rect(&block->bbox, &span->bbox);
	span->base_offset = distance;
	line->spans[line->len++] = span;
	return line;
}

#ifdef DEBUG_SPANS
static void
dump_span(fz_text_span *s)
{
	int i;
	for (i=0; i < s->len; i++)
	{
		printf("%c", s->text[i].c);
	}
}
#endif

static inline void
normalise(fz_point *p)
{
	float len = p->x * p->x + p->y * p->y;
	if (len != 0)
	{
		len = sqrtf(len);
		p->x /= len;
		p->y /= len;
	}
}

static void
strain_soup(fz_context *ctx, fz_text_device *tdev)
{
	span_soup *soup = tdev->spans;
	fz_text_line *last_line = NULL;
	fz_text_span *last_span = NULL;
	int span_num;

	/* Really dumb implementation to match what we had before */
	for (span_num=0; span_num < soup->len; span_num++)
	{
		fz_text_span *span = soup->spans[span_num];
		int new_line = 1;
		float distance = 0;
		float spacing = 0;
		soup->spans[span_num] = NULL;
		if (last_span)
		{
			/* If we have a last_span, we must have a last_line */
			/* Do span and last_line share the same baseline? */
			fz_point p, q, perp_r;
			float dot;
			float size = fz_matrix_expansion(&span->transform);

#ifdef DEBUG_SPANS
			{
				printf("Comparing: \"");
				dump_span(last_span);
				printf("\" and \"");
				dump_span(span);
				printf("\"\n");
			}
#endif

			p.x = last_line->spans[0]->max.x - last_line->spans[0]->min.x;
			p.y = last_line->spans[0]->max.y - last_line->spans[0]->min.y;
			normalise(&p);
			q.x = span->max.x - span->min.x;
			q.y = span->max.y - span->min.y;
			normalise(&q);
#ifdef DEBUG_SPANS
			printf("last_span=%g %g -> %g %g = %g %g\n", last_span->min.x, last_span->min.y, last_span->max.x, last_span->max.y, p.x, p.y);
			printf("span     =%g %g -> %g %g = %g %g\n", span->min.x, span->min.y, span->max.x, span->max.y, q.x, q.y);
#endif
			perp_r.y = last_line->spans[0]->min.x - span->min.x;
			perp_r.x = -(last_line->spans[0]->min.y - span->min.y);
			/* Check if p and q are parallel. If so, then this
			 * line is parallel with the last one. */
			dot = p.x * q.x + p.y * q.y;
			if (fabsf(dot) > 0.9995)
			{
				/* If we take the dot product of normalised(p) and
				 * perp(r), we get the perpendicular distance from
				 * one line to the next (assuming they are parallel). */
				distance = p.x * perp_r.x + p.y * perp_r.y;
				/* We allow 'small' distances of baseline changes
				 * to cope with super/subscript. FIXME: We should
				 * gather subscript/superscript information here. */
				new_line = (fabsf(distance) > size * LINE_DIST);
			}
			else
			{
				new_line = 1;
				distance = 0;
			}
			if (!new_line)
			{
				fz_point delta;

				delta.x = span->min.x - last_span->max.x;
				delta.y = span->min.y - last_span->max.y;

				spacing = (p.x * delta.x + p.y * delta.y);
				spacing = fabsf(spacing);
				/* Only allow changes in baseline (subscript/superscript etc)
				 * when the spacing is small. */
				if (spacing * fabsf(distance) > size * LINE_DIST && fabsf(distance) > size * 0.1f)
				{
					new_line = 1;
					distance = 0;
					spacing = 0;
				}
				else
				{
					spacing /= size * SPACE_DIST;
					/* Apply the same logic here as when we're adding chars to build spans. */
					if (spacing >= 1 && spacing < (SPACE_MAX_DIST/SPACE_DIST))
						spacing = 1;
				}
			}
#ifdef DEBUG_SPANS
			printf("dot=%g new_line=%d distance=%g size=%g spacing=%g\n", dot, new_line, distance, size, spacing);
#endif
		}
		span->spacing = spacing;
		last_line = push_span(ctx, tdev, span, new_line, distance);
		last_span = span;
	}
}

fz_text_sheet *
fz_new_text_sheet(fz_context *ctx)
{
	fz_text_sheet *sheet = fz_malloc(ctx, sizeof *sheet);
	sheet->maxid = 0;
	sheet->style = NULL;
	return sheet;
}

void
fz_free_text_sheet(fz_context *ctx, fz_text_sheet *sheet)
{
	fz_text_style *style = sheet->style;
	while (style)
	{
		fz_text_style *next = style->next;
		fz_drop_font(ctx, style->font);
		fz_free(ctx, style);
		style = next;
	}
	fz_free(ctx, sheet);
}

static fz_text_style *
fz_lookup_text_style_imp(fz_context *ctx, fz_text_sheet *sheet,
	float size, fz_font *font, int wmode, int script)
{
	fz_text_style *style;

	for (style = sheet->style; style; style = style->next)
	{
		if (style->font == font &&
			style->size == size &&
			style->wmode == wmode &&
			style->script == script) /* FIXME: others */
		{
			return style;
		}
	}

	/* Better make a new one and add it to our list */
	style = fz_malloc(ctx, sizeof *style);
	style->id = sheet->maxid++;
	style->font = fz_keep_font(ctx, font);
	style->size = size;
	style->wmode = wmode;
	style->script = script;
	style->next = sheet->style;
	sheet->style = style;
	return style;
}

static fz_text_style *
fz_lookup_text_style(fz_context *ctx, fz_text_sheet *sheet, fz_text *text, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha, fz_stroke_state *stroke)
{
	float size = 1.0f;
	fz_font *font = text ? text->font : NULL;
	int wmode = text ? text->wmode : 0;
	if (ctm && text)
	{
		fz_matrix tm = text->trm;
		fz_matrix trm;
		tm.e = 0;
		tm.f = 0;
		fz_concat(&trm, &tm, ctm);
		size = fz_matrix_expansion(&trm);
	}
	return fz_lookup_text_style_imp(ctx, sheet, size, font, wmode, 0);
}

fz_text_page *
fz_new_text_page(fz_context *ctx, const fz_rect *mediabox)
{
	fz_text_page *page = fz_malloc(ctx, sizeof(*page));
	page->mediabox = *mediabox;
	page->len = 0;
	page->cap = 0;
	page->blocks = NULL;
	return page;
}

static void
fz_free_text_line_contents(fz_context *ctx, fz_text_line *line)
{
	int span_num;
	for (span_num = 0; span_num < line->len; span_num++)
	{
		fz_text_span *span = line->spans[span_num];
		fz_free(ctx, span->text);
		fz_free(ctx, span);
	}
	fz_free(ctx, line->spans);
}

void
fz_free_text_page(fz_context *ctx, fz_text_page *page)
{
	fz_text_block *block;
	fz_text_line *line;
	for (block = page->blocks; block < page->blocks + page->len; block++)
	{
		for (line = block->lines; line < block->lines + block->len; line++)
			fz_free_text_line_contents(ctx, line);
		fz_free(ctx, block->lines);
	}
	fz_free(ctx, page->blocks);
	fz_free(ctx, page);
}

static fz_text_span *
fz_new_text_span(fz_context *ctx, const fz_point *p, int wmode, const fz_matrix *trm)
{
	fz_text_span *span = fz_malloc_struct(ctx, fz_text_span);
	span->ascender_max = 0;
	span->descender_min = 0;
	span->cap = 0;
	span->len = 0;
	span->min = *p;
	span->max = *p;
	span->wmode = wmode;
	span->transform.a = trm->a;
	span->transform.b = trm->b;
	span->transform.c = trm->c;
	span->transform.d = trm->d;
	span->transform.e = 0;
	span->transform.f = 0;
	span->text = NULL;
	return span;
}

static void
add_char_to_span(fz_context *ctx, fz_text_span *span, int c, fz_point *p, fz_point *max, fz_text_style *style)
{
	if (span->len == span->cap)
	{
		int newcap = (span->cap ? span->cap * 2 : 16);
		span->text = fz_resize_array(ctx, span->text, newcap, sizeof(fz_text_char));
		span->cap = newcap;
		span->bbox = fz_empty_rect;
	}
	span->max = *max;
	if (style->ascender > span->ascender_max)
		span->ascender_max = style->ascender;
	if (style->descender < span->descender_min)
		span->descender_min = style->descender;
	span->text[span->len].c = c;
	span->text[span->len].p = *p;
	span->text[span->len].style = style;
	span->len++;
}

static void
fz_add_text_char_imp(fz_context *ctx, fz_text_device *dev, fz_text_style *style, int c, fz_matrix *trm, float adv, int wmode)
{
	int can_append = 1;
	int add_space = 0;
	fz_point dir, ndir, p, q;
	float size;
	fz_point delta;
	float spacing = 0;
	float base_offset = 0;

	if (wmode == 0)
	{
		dir.x = 1;
		dir.y = 0;
	}
	else
	{
		dir.x = 0;
		dir.y = 1;
	}
	fz_transform_vector(&dir, trm);
	ndir = dir;
	normalise(&ndir);
	/* dir = direction vector for motion. ndir = normalised(dir) */

	size = fz_matrix_expansion(trm);

	if (dev->cur_span == NULL ||
		trm->a != dev->cur_span->transform.a || trm->b != dev->cur_span->transform.b ||
		trm->c != dev->cur_span->transform.c || trm->d != dev->cur_span->transform.d)
	{
		/* If the matrix has changed (or if we don't have a span at
		 * all), then we can't append. */
#ifdef DEBUG_SPANS
		printf("Transform changed\n");
#endif
		can_append = 0;
	}
	else
	{
		/* Calculate how far we've moved since the end of the current
		 * span. */
		delta.x = trm->e - dev->cur_span->max.x;
		delta.y = trm->f - dev->cur_span->max.y;

		/* The transform has not changed, so we know we're in the same
		 * direction. Calculate 2 distances; how far off the previous
		 * baseline we are, together with how far along the baseline
		 * we are from the expected position. */
		spacing = ndir.x * delta.x + ndir.y * delta.y;
		base_offset = -ndir.y * delta.x + ndir.x * delta.y;

		spacing /= size * SPACE_DIST;
		spacing = fabsf(spacing);
		if (fabsf(base_offset) < size * 0.1)
		{
			/* Only a small amount off the baseline - we'll take this */
			if (spacing < 1.0)
			{
				/* Motion is in line, and small. */
			}
			else if (spacing >= 1 && spacing < (SPACE_MAX_DIST/SPACE_DIST))
			{
				/* Motion is in line, but large enough
				 * to warrant us adding a space */
				if (dev->lastchar != ' ' && wmode == 0)
					add_space = 1;
			}
			else
			{
				/* Motion is in line, but too large - split to a new span */
				can_append = 0;
			}
		}
		else
		{
			can_append = 0;
			spacing = 0;
		}
	}

#ifdef DEBUG_SPANS
	printf("%c%c append=%d space=%d size=%g spacing=%g base_offset=%g\n", dev->lastchar, c, can_append, add_space, size, spacing, base_offset);
#endif

	p.x = trm->e;
	p.y = trm->f;
	if (can_append == 0)
	{
		/* Start a new span */
		add_span_to_soup(dev->spans, dev->cur_span);
		dev->cur_span = NULL;
		dev->cur_span = fz_new_text_span(ctx, &p, wmode, trm);
		dev->cur_span->spacing = 0;
	}
	if (add_space)
	{
		q.x = - 0.2f;
		q.y = 0;
		fz_transform_point(&q, trm);
		add_char_to_span(ctx, dev->cur_span, ' ', &p, &q, style);
	}
	/* Advance the matrix */
	q.x = trm->e += adv * dir.x;
	q.y = trm->f += adv * dir.y;
	add_char_to_span(ctx, dev->cur_span, c, &p, &q, style);
}

static void
fz_add_text_char(fz_context *ctx, fz_text_device *dev, fz_text_style *style, int c, fz_matrix *trm, float adv, int wmode)
{
	switch (c)
	{
	case -1: /* ignore when one unicode character maps to multiple glyphs */
		break;
	case 0xFB00: /* ff */
		fz_add_text_char_imp(ctx, dev, style, 'f', trm, adv/2, wmode);
		fz_add_text_char_imp(ctx, dev, style, 'f', trm, adv/2, wmode);
		break;
	case 0xFB01: /* fi */
		fz_add_text_char_imp(ctx, dev, style, 'f', trm, adv/2, wmode);
		fz_add_text_char_imp(ctx, dev, style, 'i', trm, adv/2, wmode);
		break;
	case 0xFB02: /* fl */
		fz_add_text_char_imp(ctx, dev, style, 'f', trm, adv/2, wmode);
		fz_add_text_char_imp(ctx, dev, style, 'l', trm, adv/2, wmode);
		break;
	case 0xFB03: /* ffi */
		fz_add_text_char_imp(ctx, dev, style, 'f', trm, adv/3, wmode);
		fz_add_text_char_imp(ctx, dev, style, 'f', trm, adv/3, wmode);
		fz_add_text_char_imp(ctx, dev, style, 'i', trm, adv/3, wmode);
		break;
	case 0xFB04: /* ffl */
		fz_add_text_char_imp(ctx, dev, style, 'f', trm, adv/3, wmode);
		fz_add_text_char_imp(ctx, dev, style, 'f', trm, adv/3, wmode);
		fz_add_text_char_imp(ctx, dev, style, 'l', trm, adv/3, wmode);
		break;
	case 0xFB05: /* long st */
	case 0xFB06: /* st */
		fz_add_text_char_imp(ctx, dev, style, 's', trm, adv/2, wmode);
		fz_add_text_char_imp(ctx, dev, style, 't', trm, adv/2, wmode);
		break;
	default:
		fz_add_text_char_imp(ctx, dev, style, c, trm, adv, wmode);
		break;
	}
}

static void
fz_text_extract(fz_context *ctx, fz_text_device *dev, fz_text *text, const fz_matrix *ctm, fz_text_style *style)
{
	fz_font *font = text->font;
	FT_Face face = font->ft_face;
	fz_matrix tm = text->trm;
	fz_matrix trm;
	float adv;
	float ascender = 1;
	float descender = 0;
	int multi;
	int i, j, err;

	if (text->len == 0)
		return;

	if (font->ft_face)
	{
		fz_lock(ctx, FZ_LOCK_FREETYPE);
		err = FT_Set_Char_Size(font->ft_face, 64, 64, 72, 72);
		if (err)
			fz_warn(ctx, "freetype set character size: %s", ft_error_string(err));
		ascender = (float)face->ascender / face->units_per_EM;
		descender = (float)face->descender / face->units_per_EM;
		fz_unlock(ctx, FZ_LOCK_FREETYPE);
	}
	else if (font->t3procs && !fz_is_empty_rect(&font->bbox))
	{
		ascender = font->bbox.y1;
		descender = font->bbox.y0;
	}
	style->ascender = ascender;
	style->descender = descender;

	tm.e = 0;
	tm.f = 0;
	fz_concat(&trm, &tm, ctm);

	for (i = 0; i < text->len; i++)
	{
		/* Calculate new pen location and delta */
		tm.e = text->items[i].x;
		tm.f = text->items[i].y;
		fz_concat(&trm, &tm, ctm);

		/* Calculate bounding box and new pen position based on font metrics */
		if (font->ft_face)
		{
			FT_Fixed ftadv = 0;
			int mask = FT_LOAD_NO_BITMAP | FT_LOAD_NO_HINTING | FT_LOAD_IGNORE_TRANSFORM;

			/* TODO: freetype returns broken vertical metrics */
			/* if (text->wmode) mask |= FT_LOAD_VERTICAL_LAYOUT; */

			fz_lock(ctx, FZ_LOCK_FREETYPE);
			err = FT_Set_Char_Size(font->ft_face, 64, 64, 72, 72);
			if (err)
				fz_warn(ctx, "freetype set character size: %s", ft_error_string(err));
			FT_Get_Advance(font->ft_face, text->items[i].gid, mask, &ftadv);
			adv = ftadv / 65536.0f;
			fz_unlock(ctx, FZ_LOCK_FREETYPE);
		}
		else
		{
			adv = font->t3widths[text->items[i].gid];
		}

		/* Check for one glyph to many char mapping */
		for (j = i + 1; j < text->len; j++)
			if (text->items[j].gid >= 0)
				break;
		multi = j - i;

		if (multi == 1)
		{
			fz_add_text_char(ctx, dev, style, text->items[i].ucs, &trm, adv, text->wmode);
		}
		else
		{
			for (j = 0; j < multi; j++)
			{
				fz_add_text_char(ctx, dev, style, text->items[i + j].ucs, &trm, adv/multi, text->wmode);
			}
			i += j - 1;
		}

		dev->lastchar = text->items[i].ucs;
	}
}

static void
fz_text_fill_text(fz_device *dev, fz_text *text, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_text_device *tdev = dev->user;
	fz_text_style *style;
	style = fz_lookup_text_style(dev->ctx, tdev->sheet, text, ctm, colorspace, color, alpha, NULL);
	fz_text_extract(dev->ctx, tdev, text, ctm, style);
}

static void
fz_text_stroke_text(fz_device *dev, fz_text *text, fz_stroke_state *stroke, const fz_matrix *ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_text_device *tdev = dev->user;
	fz_text_style *style;
	style = fz_lookup_text_style(dev->ctx, tdev->sheet, text, ctm, colorspace, color, alpha, stroke);
	fz_text_extract(dev->ctx, tdev, text, ctm, style);
}

static void
fz_text_clip_text(fz_device *dev, fz_text *text, const fz_matrix *ctm, int accumulate)
{
	fz_text_device *tdev = dev->user;
	fz_text_style *style;
	style = fz_lookup_text_style(dev->ctx, tdev->sheet, text, ctm, NULL, NULL, 0, NULL);
	fz_text_extract(dev->ctx, tdev, text, ctm, style);
}

static void
fz_text_clip_stroke_text(fz_device *dev, fz_text *text, fz_stroke_state *stroke, const fz_matrix *ctm)
{
	fz_text_device *tdev = dev->user;
	fz_text_style *style;
	style = fz_lookup_text_style(dev->ctx, tdev->sheet, text, ctm, NULL, NULL, 0, stroke);
	fz_text_extract(dev->ctx, tdev, text, ctm, style);
}

static void
fz_text_ignore_text(fz_device *dev, fz_text *text, const fz_matrix *ctm)
{
	fz_text_device *tdev = dev->user;
	fz_text_style *style;
	style = fz_lookup_text_style(dev->ctx, tdev->sheet, text, ctm, NULL, NULL, 0, NULL);
	fz_text_extract(dev->ctx, tdev, text, ctm, style);
}

static void
fz_text_free_user(fz_device *dev)
{
	fz_context *ctx = dev->ctx;
	fz_text_device *tdev = dev->user;

	add_span_to_soup(tdev->spans, tdev->cur_span);
	tdev->cur_span = NULL;

	strain_soup(ctx, tdev);
	free_span_soup(tdev->spans);

	/* TODO: smart sorting of blocks in reading order */
	/* TODO: unicode NFC normalization */
	/* TODO: bidi logical reordering */

	fz_free(dev->ctx, tdev);
}

fz_device *
fz_new_text_device(fz_context *ctx, fz_text_sheet *sheet, fz_text_page *page)
{
	fz_device *dev;

	fz_text_device *tdev = fz_malloc_struct(ctx, fz_text_device);
	tdev->sheet = sheet;
	tdev->page = page;
	tdev->spans = new_span_soup(ctx);
	tdev->cur_span = NULL;
	tdev->lastchar = ' ';

	dev = fz_new_device(ctx, tdev);
	dev->hints = FZ_IGNORE_IMAGE | FZ_IGNORE_SHADE;
	dev->free_user = fz_text_free_user;
	dev->fill_text = fz_text_fill_text;
	dev->stroke_text = fz_text_stroke_text;
	dev->clip_text = fz_text_clip_text;
	dev->clip_stroke_text = fz_text_clip_stroke_text;
	dev->ignore_text = fz_text_ignore_text;
	return dev;
}

/* XML, HTML and plain-text output */

static int font_is_bold(fz_font *font)
{
	FT_Face face = font->ft_face;
	if (face && (face->style_flags & FT_STYLE_FLAG_BOLD))
		return 1;
	if (strstr(font->name, "Bold"))
		return 1;
	return 0;
}

static int font_is_italic(fz_font *font)
{
	FT_Face face = font->ft_face;
	if (face && (face->style_flags & FT_STYLE_FLAG_ITALIC))
		return 1;
	if (strstr(font->name, "Italic") || strstr(font->name, "Oblique"))
		return 1;
	return 0;
}

static void
fz_print_style_begin(fz_output *out, fz_text_style *style)
{
	int script = style->script;
	fz_printf(out, "<span class=\"s%d\">", style->id);
	while (script-- > 0)
		fz_printf(out, "<sup>");
	while (++script < 0)
		fz_printf(out, "<sub>");
}

static void
fz_print_style_end(fz_output *out, fz_text_style *style)
{
	int script = style->script;
	while (script-- > 0)
		fz_printf(out, "</sup>");
	while (++script < 0)
		fz_printf(out, "</sub>");
	fz_printf(out, "</span>");
}

static void
fz_print_style(fz_output *out, fz_text_style *style)
{
	char *s = strchr(style->font->name, '+');
	s = s ? s + 1 : style->font->name;
	fz_printf(out, "span.s%d{font-family:\"%s\";font-size:%gpt;",
		style->id, s, style->size);
	if (font_is_italic(style->font))
		fz_printf(out, "font-style:italic;");
	if (font_is_bold(style->font))
		fz_printf(out, "font-weight:bold;");
	fz_printf(out, "}\n");
}

void
fz_print_text_sheet(fz_context *ctx, fz_output *out, fz_text_sheet *sheet)
{
	fz_text_style *style;
	for (style = sheet->style; style; style = style->next)
		fz_print_style(out, style);
}

void
fz_print_text_page_html(fz_context *ctx, fz_output *out, fz_text_page *page)
{
	int block_n, line_n, span_n, ch_n;
	fz_text_style *style = NULL;
	fz_text_block *block;
	fz_text_line *line;

	fz_printf(out, "<div class=\"page\">\n");

	for (block_n = 0; block_n < page->len; block_n++)
	{
		block = &page->blocks[block_n];
		fz_printf(out, "<div class=\"block\"><p>\n");
		for (line_n = 0; line_n < block->len; line_n++)
		{
			line = &block->lines[line_n];
			style = NULL;

#ifdef DEBUG_INTERNALS
			fz_printf(out, "<span class=\"line\">");
#endif
			for (span_n = 0; span_n < line->len; span_n++)
			{
				fz_text_span *span = line->spans[span_n];
#ifdef DEBUG_INTERNALS
				fz_printf(out, "<span class=\"internal_span\">");
#endif
				if (span->spacing >= 1)
					fz_printf(out, " ");
				for (ch_n = 0; ch_n < span->len; ch_n++)
				{
					fz_text_char *ch = &span->text[ch_n];
					if (style != ch->style)
					{
						if (style)
							fz_print_style_end(out, style);
						fz_print_style_begin(out, ch->style);
						style = ch->style;
					}

					if (ch->c == '<')
						fz_printf(out, "&lt;");
					else if (ch->c == '>')
						fz_printf(out, "&gt;");
					else if (ch->c == '&')
						fz_printf(out, "&amp;");
					else if (ch->c >= 32 && ch->c <= 127)
						fz_printf(out, "%c", ch->c);
					else
						fz_printf(out, "&#x%x;", ch->c);
				}
				if (style)
				{
					fz_print_style_end(out, style);
					style = NULL;
				}
#ifdef DEBUG_INTERNALS
				fz_printf(out, "</span>");
#endif
			}
#ifdef DEBUG_INTERNALS
			fz_printf(out, "</span>");
#endif
			fz_printf(out, "\n");
		}
		fz_printf(out, "</p></div>\n");
	}

	fz_printf(out, "</div>\n");
}

void
fz_print_text_page_xml(fz_context *ctx, fz_output *out, fz_text_page *page)
{
	fz_text_block *block;
	fz_text_line *line;
	char *s;

	fz_printf(out, "<page>\n");
	for (block = page->blocks; block < page->blocks + page->len; block++)
	{
		fz_printf(out, "<block bbox=\"%g %g %g %g\">\n",
			block->bbox.x0, block->bbox.y0, block->bbox.x1, block->bbox.y1);
		for (line = block->lines; line < block->lines + block->len; line++)
		{
			int span_num;
			fz_printf(out, "<line bbox=\"%g %g %g %g\">\n",
				line->bbox.x0, line->bbox.y0, line->bbox.x1, line->bbox.y1);
			for (span_num = 0; span_num < line->len; span_num++)
			{
				fz_text_span *span = line->spans[span_num];
				fz_text_style *style = NULL;
				int char_num;
				for (char_num = 0; char_num < span->len; char_num++)
				{
					fz_text_char *ch = &span->text[char_num];
					if (ch->style != style)
					{
						if (style)
						{
							fz_printf(out, "</span>\n");
						}
						style = ch->style;
						s = strchr(style->font->name, '+');
						s = s ? s + 1 : style->font->name;
						fz_printf(out, "<span bbox=\"%g %g %g %g\" font=\"%s\" size=\"%g\">\n",
							span->bbox.x0, span->bbox.y0, span->bbox.x1, span->bbox.y1,
							s, style->size);
					}
					{
						fz_rect rect;
						fz_text_char_bbox(&rect, span, char_num);
						fz_printf(out, "<char bbox=\"%g %g %g %g\" x=\"%g\" y=\"%g\" c=\"",
							rect.x0, rect.y0, rect.x1, rect.y1, ch->p.x, ch->p.y);
					}
					switch (ch->c)
					{
					case '<': fz_printf(out, "&lt;"); break;
					case '>': fz_printf(out, "&gt;"); break;
					case '&': fz_printf(out, "&amp;"); break;
					case '"': fz_printf(out, "&quot;"); break;
					case '\'': fz_printf(out, "&apos;"); break;
					default:
						if (ch->c >= 32 && ch->c <= 127)
							fz_printf(out, "%c", ch->c);
						else
							fz_printf(out, "&#x%x;", ch->c);
						break;
					}
					fz_printf(out, "\"/>\n");
				}
				if (style)
					fz_printf(out, "</span>\n");
			}
			fz_printf(out, "</line>\n");
		}
		fz_printf(out, "</block>\n");
	}
	fz_printf(out, "</page>\n");
}

void
fz_print_text_page(fz_context *ctx, fz_output *out, fz_text_page *page)
{
	fz_text_block *block;
	fz_text_line *line;
	fz_text_char *ch;
	char utf[10];
	int i, n;

	for (block = page->blocks; block < page->blocks + page->len; block++)
	{
		for (line = block->lines; line < block->lines + block->len; line++)
		{
			int span_num;
			for (span_num = 0; span_num < line->len; span_num++)
			{
				fz_text_span *span = line->spans[span_num];
				for (ch = span->text; ch < span->text + span->len; ch++)
				{
					n = fz_runetochar(utf, ch->c);
					for (i = 0; i < n; i++)
						fz_printf(out, "%c", utf[i]);
				}
			}
			fz_printf(out, "\n");
		}
		fz_printf(out, "\n");
	}
}

typedef struct line_height_s
{
	float height;
	int count;
	fz_text_style *style;
} line_height;

typedef struct line_heights_s
{
	fz_context *ctx;
	int cap;
	int len;
	line_height *lh;
} line_heights;

static line_heights *
new_line_heights(fz_context *ctx)
{
	line_heights *lh = fz_malloc_struct(ctx, line_heights);
	lh->ctx = ctx;
	return lh;
}

static void
free_line_heights(line_heights *lh)
{
	if (!lh)
		return;
	fz_free(lh->ctx, lh->lh);
	fz_free(lh->ctx, lh);
}

static void
insert_line_height(line_heights *lh, fz_text_style *style, float height)
{
	int i;

#ifdef DEBUG_LINE_HEIGHTS
	printf("style=%x height=%g\n", style, height);
#endif

	/* If we have one already, add it in */
	for (i=0; i < lh->cap; i++)
	{
		/* Match if we are within 5% */
		if (lh->lh[i].style == style && lh->lh[i].height * 0.95 <= height && lh->lh[i].height * 1.05 >= height)
		{
			/* Ensure that the average height is correct */
			lh->lh[i].height = (lh->lh[i].height * lh->lh[i].count + height) / (lh->lh[i].count+1);
			lh->lh[i].count++;
			return;
		}
	}

	/* Otherwise extend (if required) and add it */
	if (lh->cap == lh->len)
	{
		int newcap = (lh->cap ? lh->cap * 2 : 4);
		lh->lh = fz_resize_array(lh->ctx, lh->lh, newcap, sizeof(line_height));
		lh->cap = newcap;
	}

	lh->lh[lh->len].count = 1;
	lh->lh[lh->len].height = height;
	lh->lh[lh->len].style = style;
	lh->len++;
}

static void
cull_line_heights(line_heights *lh)
{
	int i, j, k;

#ifdef DEBUG_LINE_HEIGHTS
	printf("Before culling:\n");
	for (i = 0; i < lh->len; i++)
	{
		fz_text_style *style = lh->lh[i].style;
		printf("style=%x height=%g count=%d\n", style, lh->lh[i].height, lh->lh[i].count);
	}
#endif
	for (i = 0; i < lh->len; i++)
	{
		fz_text_style *style = lh->lh[i].style;
		int count = lh->lh[i].count;
		int max = i;

		/* Find the max for this style */
		for (j = i+1; j < lh->len; j++)
		{
			if (lh->lh[j].style == style && lh->lh[j].count > count)
			{
				max = j;
				count = lh->lh[j].count;
			}
		}

		/* Destroy all the ones other than the max */
		if (max != i)
		{
			lh->lh[i].count = count;
			lh->lh[i].height = lh->lh[max].height;
			lh->lh[max].count = 0;
		}
		j = i+1;
		for (k = j; k < lh->len; k++)
		{
			if (lh->lh[k].style == style)
			{
				k++;
			}
			else
			{
				lh->lh[j++] = lh->lh[k];
			}
		}
		lh->len = j;
	}
#ifdef DEBUG_LINE_HEIGHTS
	printf("After culling:\n");
	for (i = 0; i < lh->len; i++)
	{
		fz_text_style *style = lh->lh[i].style;
		printf("style=%x height=%g count=%d\n", style, lh->lh[i].height, lh->lh[i].count);
	}
#endif
}

static float
line_height_for_style(line_heights *lh, fz_text_style *style)
{
	int i;

	for (i=0; i < lh->len; i++)
	{
		if (lh->lh[i].style == style)
			return lh->lh[i].height;
	}
	return 0.0; /* Never reached */
}

static void
split_block(fz_context *ctx, fz_text_page *page, int block_num, int linenum)
{
	int split_len;

	if (page->len == page->cap)
	{
		int new_cap = fz_maxi(16, page->cap * 2);
		page->blocks = fz_resize_array(ctx, page->blocks, new_cap, sizeof(*page->blocks));
		page->cap = new_cap;
	}

	memmove(page->blocks+block_num+1, page->blocks+block_num, (page->len - block_num)*sizeof(*page->blocks));
	page->len++;

	split_len = page->blocks[block_num].len - linenum;
	page->blocks[block_num+1].bbox = page->blocks[block_num].bbox; /* FIXME! */
	page->blocks[block_num+1].cap = 0;
	page->blocks[block_num+1].len = 0;
	page->blocks[block_num+1].lines = NULL;
	page->blocks[block_num+1].lines = fz_malloc_array(ctx, split_len, sizeof(fz_text_line));
	page->blocks[block_num+1].cap = page->blocks[block_num+1].len;
	page->blocks[block_num+1].len = split_len;
	page->blocks[block_num].len = linenum;
	memcpy(page->blocks[block_num+1].lines, page->blocks[block_num].lines + linenum, split_len * sizeof(fz_text_line));
	page->blocks[block_num+1].lines[0].distance = 0;
}

void
fz_text_analysis(fz_context *ctx, fz_text_sheet *sheet, fz_text_page *page)
{
	fz_text_block *block;
	fz_text_line *line;
	line_heights *lh;
	int block_num;

	/* Simple paragraph analysis; look for the most common 'inter line'
	 * spacing. This will be assumed to be our line spacing. Anything
	 * more than 25% wider than this will be assumed to be a paragraph
	 * space. */

	/* Step 1: Gather the line height information */
	lh = new_line_heights(ctx);
	for (block = page->blocks; block < page->blocks + page->len; block++)
	{
		for (line = block->lines; line < block->lines + block->len; line++)
		{
			/* For every style in the line, add lineheight to the
			 * record for that style. FIXME: This is a nasty n^2
			 * algorithm at the moment. */
			int span_num;
			fz_text_style *style = NULL;

			if (line->distance == 0)
				continue;

			for (span_num = 0; span_num < line->len; span_num++)
			{
				fz_text_span *span = line->spans[span_num];
				int char_num;
				for (char_num = 0; char_num < span->len; char_num++)
				{
					fz_text_char *chr = &span->text[char_num];
					if (chr->style != style)
					{
						/* Have we had this style before? */
						int match = 0;
						int span_num2;
						for (span_num2 = 0; span_num2 < span_num; span_num2++)
						{
							fz_text_span *span2 = line->spans[span_num2];
							int char_num2;
							for (char_num2 = 0; char_num2 < span2->len; char_num2++)
							{
								fz_text_char *chr2 = &span2->text[char_num2];
								if (chr2->style == chr->style)
								{
									match = 1;
									break;
								}
							}
						}
						if (char_num > 0 && match == 0)
						{
							fz_text_span *span2 = line->spans[span_num];
							int char_num2;
							for (char_num2 = 0; char_num2 < char_num; char_num2++)
							{
								fz_text_char *chr2 = &span2->text[char_num2];
								if (chr2->style == chr->style)
								{
									match = 1;
									break;
								}
							}
						}
						if (match == 0)
							insert_line_height(lh, chr->style, line->distance);
						style = chr->style;
					}
				}
			}
		}
	}

	/* Step 2: Find the most popular line height for each style */
	cull_line_heights(lh);

	/* Step 3: Run through the blocks, breaking each block into two if
	 * the line height isn't right. */
	for (block_num = 0; block_num < page->len; block_num++)
	{
		int line_num;
		block = &page->blocks[block_num];
		for (line_num = 0; line_num < block->len; line_num++)
		{
			/* For every style in the line, check to see if lineheight
			 * is correct for that style. FIXME: We check each style
			 * more than once, currently. */
			int span_num;
			int ok = 0;
			fz_text_style *style = NULL;
			line = &block->lines[line_num];

			if (line->distance == 0)
				continue;

#ifdef DEBUG_LINE_HEIGHTS
			printf("line height=%g nspans=%d\n", line->distance, line->len);
#endif
			for (span_num = 0; span_num < line->len; span_num++)
			{
				fz_text_span *span = line->spans[span_num];
				int char_num;
				for (char_num = 0; char_num < span->len; char_num++)
				{
					fz_text_char *chr = &span->text[char_num];
					if (chr->style != style)
					{
						float proper_step = line_height_for_style(lh, chr->style);
						if (proper_step * 0.95 <= line->distance && line->distance <= proper_step * 1.05)
						{
							ok = 1;
							break;
						}
						style = chr->style;
					}
				}
				if (ok)
					break;
			}
			if (!ok)
			{
				split_block(ctx, page, block_num, line_num);
				break;
			}
		}
	}
	free_line_heights(lh);
}
