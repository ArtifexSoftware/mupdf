#include "mupdf/fitz.h"

fz_text *
fz_new_text(fz_context *ctx)
{
	fz_text *text = fz_malloc_struct(ctx, fz_text);
	text->refs = 1;
	return text;
}

fz_text *
fz_keep_text(fz_context *ctx, const fz_text *textc)
{
	fz_text *text = (fz_text *)textc; /* Explicit cast away of const */

	return fz_keep_imp(ctx, text, &text->refs);
}

void
fz_drop_text(fz_context *ctx, const fz_text *textc)
{
	fz_text *text = (fz_text *)textc; /* Explicit cast away of const */

	if (fz_drop_imp(ctx, text, &text->refs))
	{
		fz_text_span *span = text->head;
		while (span)
		{
			fz_text_span *next = span->next;
			fz_drop_font(ctx, span->font);
			fz_free(ctx, span->items);
			fz_free(ctx, span);
			span = next;
		}
		fz_free(ctx, text);
	}
}

static fz_text_span *
fz_new_text_span(fz_context *ctx, fz_font *font, int wmode, const fz_matrix *trm)
{
	fz_text_span *span = fz_malloc_struct(ctx, fz_text_span);
	span->font = fz_keep_font(ctx, font);
	span->wmode = wmode;
	span->trm = *trm;
	span->trm.e = 0;
	span->trm.f = 0;
	return span;
}

static fz_text_span *
fz_add_text_span(fz_context *ctx, fz_text *text, fz_font *font, int wmode, const fz_matrix *trm)
{
	if (!text->tail)
	{
		text->head = text->tail = fz_new_text_span(ctx, font, wmode, trm);
	}
	else if (text->tail->font != font ||
		text->tail->wmode != wmode ||
		text->tail->trm.a != trm->a ||
		text->tail->trm.b != trm->b ||
		text->tail->trm.c != trm->c ||
		text->tail->trm.d != trm->d)
	{
		text->tail = text->tail->next = fz_new_text_span(ctx, font, wmode, trm);
	}
	return text->tail;
}

static void
fz_grow_text_span(fz_context *ctx, fz_text_span *span, int n)
{
	int new_cap = span->cap;
	if (span->len + n < new_cap)
		return;
	while (span->len + n > new_cap)
		new_cap = new_cap + 36;
	span->items = fz_resize_array(ctx, span->items, new_cap, sizeof(fz_text_item));
	span->cap = new_cap;
}

void
fz_show_glyph(fz_context *ctx, fz_text *text, fz_font *font, const fz_matrix *trm, int gid, int ucs, int wmode)
{
	fz_text_span *span;

	if (text->refs != 1)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot modify shared text objects");

	span = fz_add_text_span(ctx, text, font, wmode, trm);

	fz_grow_text_span(ctx, span, 1);

	span->items[span->len].ucs = ucs;
	span->items[span->len].gid = gid;
	span->items[span->len].x = trm->e;
	span->items[span->len].y = trm->f;
	span->len++;
}

void
fz_show_string(fz_context *ctx, fz_text *text, fz_font *user_font, fz_matrix *trm, const char *s, int wmode)
{
	fz_font *font;
	int gid, ucs;
	float adv;

	while (*s)
	{
		s += fz_chartorune(&ucs, s);
		gid = fz_encode_character_with_fallback(ctx, user_font, ucs, 0, &font);
		fz_show_glyph(ctx, text, font, trm, gid, ucs, wmode);
		adv = fz_advance_glyph(ctx, font, gid, wmode);
		if (wmode == 0)
			fz_pre_translate(trm, adv, 0);
		else
			fz_pre_translate(trm, 0, -adv);
	}
}

fz_rect *
fz_bound_text(fz_context *ctx, const fz_text *text, const fz_stroke_state *stroke, const fz_matrix *ctm, fz_rect *bbox)
{
	fz_text_span *span;
	fz_matrix tm, trm;
	fz_rect gbox;
	int i;

	*bbox = fz_empty_rect;

	for (span = text->head; span; span = span->next)
	{
		if (span->len > 0)
		{
			tm = span->trm;
			for (i = 0; i < span->len; i++)
			{
				if (span->items[i].gid >= 0)
				{
					tm.e = span->items[i].x;
					tm.f = span->items[i].y;
					fz_concat(&trm, &tm, ctm);
					fz_bound_glyph(ctx, span->font, span->items[i].gid, &trm, &gbox);
					fz_union_rect(bbox, &gbox);
				}
			}

		}
	}

	if (!fz_is_empty_rect(bbox))
	{
		if (stroke)
			fz_adjust_rect_for_stroke(ctx, bbox, stroke, ctm);

		/* Compensate for the glyph cache limited positioning precision */
		bbox->x0 -= 1;
		bbox->y0 -= 1;
		bbox->x1 += 1;
		bbox->y1 += 1;
	}

	return bbox;
}

fz_text *
fz_clone_text(fz_context *ctx, const fz_text *text)
{
	fz_text *new_text;
	fz_text_span *span;
	fz_text_span **tail;

	new_text = fz_malloc_struct(ctx, fz_text);
	new_text->refs = 1;
	span = text->head;
	tail = &new_text->head;

	fz_var(span);

	fz_try(ctx)
	{
		while (span != NULL)
		{
			fz_text_span *new_span = fz_malloc_struct(ctx, fz_text_span);
			*tail = new_span;
			tail = &new_span->next;
			new_text->tail = new_span;
			new_span->font = fz_keep_font(ctx, span->font);
			new_span->trm = span->trm;
			new_span->wmode = span->wmode;
			new_span->len = span->len;
			new_span->cap = span->len;
			new_span->items = fz_malloc(ctx, span->len * sizeof(*span->items));
			memcpy(new_span->items, span->items, span->len * sizeof(*span->items));
			span = span->next;

		}
	}
	fz_catch(ctx)
	{
		span = new_text->head;
		while (span != NULL)
		{
			fz_text_span *next = span->next;
			fz_drop_font(ctx, span->font);
			fz_free(ctx, span->items);
			fz_free(ctx, span);
			span = next;
		}
		fz_free(ctx, new_text);
		fz_rethrow(ctx);
	}

	return new_text;
}
