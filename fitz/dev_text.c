#include "fitz.h"

#define LINE_DIST 0.9f
#define SPACE_DIST 0.2f

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_ADVANCES_H

typedef struct fz_text_device_s fz_text_device;

struct fz_text_device_s
{
	fz_point point;
	fz_text_span *head;
	fz_text_span *span;
};

fz_text_span *
fz_new_text_span(void)
{
	fz_text_span *span;
	span = fz_malloc(sizeof(fz_text_span));
	span->font = NULL;
	span->wmode = 0;
	span->size = 0;
	span->len = 0;
	span->cap = 0;
	span->text = NULL;
	span->next = NULL;
	span->eol = 0;
	return span;
}

void
fz_free_text_span(fz_text_span *span)
{
	if (span->font)
		fz_drop_font(span->font);
	if (span->next)
		fz_free_text_span(span->next);
	fz_free(span->text);
	fz_free(span);
}

static void
fz_add_text_char_imp(fz_text_span *span, int c, fz_bbox bbox)
{
	if (span->len + 1 >= span->cap)
	{
		span->cap = span->cap > 1 ? (span->cap * 3) / 2 : 80;
		span->text = fz_realloc(span->text, span->cap, sizeof(fz_text_char));
	}
	span->text[span->len].c = c;
	span->text[span->len].bbox = bbox;
	span->len ++;
}

static fz_bbox
fz_split_bbox(fz_bbox bbox, int i, int n)
{
	float w = (float)(bbox.x1 - bbox.x0) / n;
	float x0 = bbox.x0;
	bbox.x0 = x0 + i * w;
	bbox.x1 = x0 + (i + 1) * w;
	return bbox;
}

static void
fz_add_text_char(fz_text_span **last, fz_font *font, float size, int wmode, int c, fz_bbox bbox)
{
	fz_text_span *span = *last;

	if (!span->font)
	{
		span->font = fz_keep_font(font);
		span->size = size;
	}

	if ((span->font != font || span->size != size || span->wmode != wmode) && c != 32)
	{
		span = fz_new_text_span();
		span->font = fz_keep_font(font);
		span->size = size;
		span->wmode = wmode;
		(*last)->next = span;
		*last = span;
	}

	switch (c)
	{
	case -1: /* ignore when one unicode character maps to multiple glyphs */
		break;
	case 0xFB00: /* ff */
		fz_add_text_char_imp(span, 'f', fz_split_bbox(bbox, 0, 2));
		fz_add_text_char_imp(span, 'f', fz_split_bbox(bbox, 1, 2));
		break;
	case 0xFB01: /* fi */
		fz_add_text_char_imp(span, 'f', fz_split_bbox(bbox, 0, 2));
		fz_add_text_char_imp(span, 'i', fz_split_bbox(bbox, 1, 2));
		break;
	case 0xFB02: /* fl */
		fz_add_text_char_imp(span, 'f', fz_split_bbox(bbox, 0, 2));
		fz_add_text_char_imp(span, 'l', fz_split_bbox(bbox, 1, 2));
		break;
	case 0xFB03: /* ffi */
		fz_add_text_char_imp(span, 'f', fz_split_bbox(bbox, 0, 3));
		fz_add_text_char_imp(span, 'f', fz_split_bbox(bbox, 1, 3));
		fz_add_text_char_imp(span, 'i', fz_split_bbox(bbox, 2, 3));
		break;
	case 0xFB04: /* ffl */
		fz_add_text_char_imp(span, 'f', fz_split_bbox(bbox, 0, 3));
		fz_add_text_char_imp(span, 'f', fz_split_bbox(bbox, 1, 3));
		fz_add_text_char_imp(span, 'l', fz_split_bbox(bbox, 2, 3));
		break;
	case 0xFB05: /* long st */
	case 0xFB06: /* st */
		fz_add_text_char_imp(span, 's', fz_split_bbox(bbox, 0, 2));
		fz_add_text_char_imp(span, 't', fz_split_bbox(bbox, 1, 2));
		break;
	default:
		fz_add_text_char_imp(span, c, bbox);
		break;
	}
}

static void
fz_divide_text_chars(fz_text_span **last, int n, fz_bbox bbox)
{
	fz_text_span *span = *last;
	int i, x;
	x = span->len - n;
	if (x >= 0)
		for (i = 0; i < n; i++)
			span->text[x + i].bbox = fz_split_bbox(bbox, i, n);
}

static void
fz_add_text_newline(fz_text_span **last, fz_font *font, float size, int wmode)
{
	fz_text_span *span;
	span = fz_new_text_span();
	span->font = fz_keep_font(font);
	span->size = size;
	span->wmode = wmode;
	(*last)->eol = 1;
	(*last)->next = span;
	*last = span;
}

void
fz_debug_text_span_xml(fz_text_span *span)
{
	char buf[10];
	int c, n, k, i;

	printf("<span font=\"%s\" size=\"%g\" wmode=\"%d\" eol=\"%d\">\n",
		span->font ? span->font->name : "NULL", span->size, span->wmode, span->eol);

	for (i = 0; i < span->len; i++)
	{
		printf("\t<char ucs=\"");
		c = span->text[i].c;
		if (c < 128)
			putchar(c);
		else
		{
			n = runetochar(buf, &c);
			for (k = 0; k < n; k++)
				putchar(buf[k]);
		}
		printf("\" bbox=\"%d %d %d %d\" />\n",
			span->text[i].bbox.x0,
			span->text[i].bbox.y0,
			span->text[i].bbox.x1,
			span->text[i].bbox.y1);
	}

	printf("</span>\n");

	if (span->next)
		fz_debug_text_span_xml(span->next);
}

void
fz_debug_text_span(fz_text_span *span)
{
	char buf[10];
	int c, n, k, i;

	for (i = 0; i < span->len; i++)
	{
		c = span->text[i].c;
		if (c < 128)
			putchar(c);
		else
		{
			n = runetochar(buf, &c);
			for (k = 0; k < n; k++)
				putchar(buf[k]);
		}
	}

	if (span->eol)
		putchar('\n');

	if (span->next)
		fz_debug_text_span(span->next);
}

static void
fz_text_extract_span(fz_text_span **last, fz_text *text, fz_matrix ctm, fz_point *pen)
{
	fz_font *font = text->font;
	FT_Face face = font->ft_face;
	fz_matrix tm = text->trm;
	fz_matrix trm;
	float size;
	float adv;
	fz_rect rect;
	fz_point dir, ndir;
	fz_point delta, ndelta;
	float dist, dot;
	float ascender = 1;
	float descender = 0;
	int multi;
	int i, err;

	if (text->len == 0)
		return;

	if (font->ft_face)
	{
		err = FT_Set_Char_Size(font->ft_face, 64, 64, 72, 72);
		if (err)
			fz_warn("freetype set character size: %s", ft_error_string(err));
		ascender = (float)face->ascender / face->units_per_EM;
		descender = (float)face->descender / face->units_per_EM;
	}

	rect = fz_empty_rect;

	if (text->wmode == 0)
	{
		dir.x = 1;
		dir.y = 0;
	}
	else
	{
		dir.x = 0;
		dir.y = 1;
	}

	tm.e = 0;
	tm.f = 0;
	trm = fz_concat(tm, ctm);
	dir = fz_transform_vector(trm, dir);
	dist = sqrtf(dir.x * dir.x + dir.y * dir.y);
	ndir.x = dir.x / dist;
	ndir.y = dir.y / dist;

	size = fz_matrix_expansion(trm);

	multi = 1;

	for (i = 0; i < text->len; i++)
	{
		if (text->items[i].gid < 0)
		{
			fz_add_text_char(last, font, size, text->wmode, text->items[i].ucs, fz_round_rect(rect));
			multi ++;
			fz_divide_text_chars(last, multi, fz_round_rect(rect));
			continue;
		}
		multi = 1;

		/* Calculate new pen location and delta */
		tm.e = text->items[i].x;
		tm.f = text->items[i].y;
		trm = fz_concat(tm, ctm);

		delta.x = pen->x - trm.e;
		delta.y = pen->y - trm.f;
		if (pen->x == -1 && pen->y == -1)
			delta.x = delta.y = 0;

		dist = sqrtf(delta.x * delta.x + delta.y * delta.y);

		/* Add space and newlines based on pen movement */
		if (dist > 0)
		{
			ndelta.x = delta.x / dist;
			ndelta.y = delta.y / dist;
			dot = ndelta.x * ndir.x + ndelta.y * ndir.y;

			if (dist > size * LINE_DIST)
			{
				fz_add_text_newline(last, font, size, text->wmode);
			}
			else if (fabsf(dot) > 0.95f && dist > size * SPACE_DIST)
			{
				if ((*last)->len > 0 && (*last)->text[(*last)->len - 1].c != ' ')
				{
					fz_rect spacerect;
					spacerect.x0 = -0.2f;
					spacerect.y0 = 0;
					spacerect.x1 = 0;
					spacerect.y1 = 1;
					spacerect = fz_transform_rect(trm, spacerect);
					fz_add_text_char(last, font, size, text->wmode, ' ', fz_round_rect(spacerect));
				}
			}
		}

		/* Calculate bounding box and new pen position based on font metrics */
		if (font->ft_face)
		{
			FT_Fixed ftadv = 0;
			int mask = FT_LOAD_NO_BITMAP | FT_LOAD_NO_HINTING | FT_LOAD_IGNORE_TRANSFORM;

			/* TODO: freetype returns broken vertical metrics */
			/* if (text->wmode) mask |= FT_LOAD_VERTICAL_LAYOUT; */

			FT_Get_Advance(font->ft_face, text->items[i].gid, mask, &ftadv);
			adv = ftadv / 65536.0f;

			rect.x0 = 0;
			rect.y0 = descender;
			rect.x1 = adv;
			rect.y1 = ascender;
		}
		else
		{
			adv = font->t3widths[text->items[i].gid];
			rect.x0 = 0;
			rect.y0 = descender;
			rect.x1 = adv;
			rect.y1 = ascender;
		}

		rect = fz_transform_rect(trm, rect);
		pen->x = trm.e + dir.x * adv;
		pen->y = trm.f + dir.y * adv;

		fz_add_text_char(last, font, size, text->wmode, text->items[i].ucs, fz_round_rect(rect));
	}
}

static void
fz_text_fill_text(void *user, fz_text *text, fz_matrix ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_text_device *tdev = user;
	fz_text_extract_span(&tdev->span, text, ctm, &tdev->point);
}

static void
fz_text_stroke_text(void *user, fz_text *text, fz_stroke_state *stroke, fz_matrix ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_text_device *tdev = user;
	fz_text_extract_span(&tdev->span, text, ctm, &tdev->point);
}

static void
fz_text_clip_text(void *user, fz_text *text, fz_matrix ctm, int accumulate)
{
	fz_text_device *tdev = user;
	fz_text_extract_span(&tdev->span, text, ctm, &tdev->point);
}

static void
fz_text_clip_stroke_text(void *user, fz_text *text, fz_stroke_state *stroke, fz_matrix ctm)
{
	fz_text_device *tdev = user;
	fz_text_extract_span(&tdev->span, text, ctm, &tdev->point);
}

static void
fz_text_ignore_text(void *user, fz_text *text, fz_matrix ctm)
{
	fz_text_device *tdev = user;
	fz_text_extract_span(&tdev->span, text, ctm, &tdev->point);
}

static void
fz_text_free_user(void *user)
{
	fz_text_device *tdev = user;

	tdev->span->eol = 1;

	/* TODO: unicode NFC normalization */
	/* TODO: bidi logical reordering */

	fz_free(tdev);
}

fz_device *
fz_new_text_device(fz_text_span *root)
{
	fz_device *dev;
	fz_text_device *tdev = fz_malloc(sizeof(fz_text_device));
	tdev->head = root;
	tdev->span = root;
	tdev->point.x = -1;
	tdev->point.y = -1;

	dev = fz_new_device(tdev);
	dev->hints = FZ_IGNORE_IMAGE | FZ_IGNORE_SHADE;
	dev->free_user = fz_text_free_user;
	dev->fill_text = fz_text_fill_text;
	dev->stroke_text = fz_text_stroke_text;
	dev->clip_text = fz_text_clip_text;
	dev->clip_stroke_text = fz_text_clip_stroke_text;
	dev->ignore_text = fz_text_ignore_text;
	return dev;
}
