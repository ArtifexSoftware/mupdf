// Copyright (C) 2004-2021 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 1305 Grant Avenue - Suite 200, Novato,
// CA 94945, U.S.A., +1(415)492-9861, for further information.

#include "mupdf/fitz.h"
#include "mupdf/ucdn.h"

#include <string.h>
#include <limits.h>
#include <assert.h>

/* Enumerate marked selection */

static float dist2(float a, float b)
{
	return a * a + b * b;
}

static float hdist(fz_point *dir, fz_point *a, fz_point *b)
{
	float dx = b->x - a->x;
	float dy = b->y - a->y;
	return fz_abs(dx * dir->x + dy * dir->y);
}

static float vdist(fz_point *dir, fz_point *a, fz_point *b)
{
	float dx = b->x - a->x;
	float dy = b->y - a->y;
	return fz_abs(dx * dir->y + dy * dir->x);
}

static int line_length(fz_stext_line *line)
{
	fz_stext_char *ch;
	int n = 0;
	for (ch = line->first_char; ch; ch = ch->next)
		++n;
	return n;
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

static int find_closest_in_line(fz_stext_line *line, int idx, fz_point p)
{
	fz_stext_char *ch;
	float closest_dist = 1e30f;
	int closest_idx = idx;
	int dirn = 0;

	if (line->dir.x > line->dir.y)
	{
		if (p.y < line->bbox.y0)
			return idx;
		if (p.y > line->bbox.y1)
			return idx + line_length(line);
	}
	else
	{
		if (p.x < line->bbox.x0)
			return idx + line_length(line);
		if (p.x > line->bbox.x1)
			return idx;
	}

	for (ch = line->first_char; ch; ch = ch->next)
	{
		float mid_x = (ch->quad.ul.x + ch->quad.ur.x + ch->quad.ll.x + ch->quad.lr.x) / 4;
		float mid_y = (ch->quad.ul.y + ch->quad.ur.y + ch->quad.ll.y + ch->quad.lr.y) / 4;
		float this_dist = dist2(p.x - mid_x, p.y - mid_y);

		dirn = direction_from_bidi_class(ucdn_get_bidi_class(ch->c), dirn);

		if (this_dist < closest_dist)
		{
			closest_dist = this_dist;
			if (dirn == -1)
			{
				/* R2L */
				if (line->dir.x > line->dir.y)
					closest_idx = (p.x < mid_x) ? idx+1 : idx;
				else
					closest_idx = (p.y < mid_y) ? idx+1 : idx;
			}
			else
			{
				/* Neutral or L2R */
				if (line->dir.x > line->dir.y)
					closest_idx = (p.x < mid_x) ? idx : idx+1;
				else
					closest_idx = (p.y < mid_y) ? idx : idx+1;
			}
		}
		++idx;
	}
	return closest_idx;
}

static int find_closest_in_page(fz_stext_page *page, fz_point p)
{
	fz_stext_block *block;
	fz_stext_line *line;
	fz_stext_line *closest_line = NULL;
	int closest_idx = 0;
	float closest_dist = 1e30f;
	float this_dist;
	int idx = 0;

	for (block = page->first_block; block; block = block->next)
	{
		if (block->type != FZ_STEXT_BLOCK_TEXT)
			continue;
		for (line = block->u.t.first_line; line; line = line->next)
		{
			fz_rect box = line->bbox;
			if (p.x >= box.x0 && p.x <= box.x1)
			{
				if (p.y < box.y0)
					this_dist = dist2(box.y0 - p.y, 0);
				else if (p.y > box.y1)
					this_dist = dist2(p.y - box.y1, 0);
				else
					this_dist = 0;
			}
			else if (p.y >= box.y0 && p.y <= box.y1)
			{
				if (p.x < box.x0)
					this_dist = dist2(box.x0 - p.x, 0);
				else if (p.x > box.x1)
					this_dist = dist2(p.x - box.x1, 0);
				else
					this_dist = 0;
			}
			else
			{
				float dul = dist2(p.x - box.x0, p.y - box.y0);
				float dur = dist2(p.x - box.x1, p.y - box.y0);
				float dll = dist2(p.x - box.x0, p.y - box.y1);
				float dlr = dist2(p.x - box.x1, p.y - box.y1);
				this_dist = fz_min(fz_min(dul, dur), fz_min(dll, dlr));
			}
			if (this_dist < closest_dist)
			{
				closest_dist = this_dist;
				closest_line = line;
				closest_idx = idx;
			}
			idx += line_length(line);
		}
	}

	if (closest_line)
		return find_closest_in_line(closest_line, closest_idx, p);
	return 0;
}

struct callbacks
{
	void (*on_char)(fz_context *ctx, void *arg, fz_stext_line *ln, fz_stext_char *ch);
	void (*on_line)(fz_context *ctx, void *arg, fz_stext_line *ln);
	void *arg;
};

static void
fz_enumerate_selection(fz_context *ctx, fz_stext_page *page, fz_point a, fz_point b, struct callbacks *cb)
{
	fz_stext_block *block;
	fz_stext_line *line;
	fz_stext_char *ch;
	int idx, start, end;
	int inside;

	start = find_closest_in_page(page, a);
	end = find_closest_in_page(page, b);

	if (start > end)
		idx = start, start = end, end = idx;

	if (start == end)
		return;

	inside = 0;
	idx = 0;
	for (block = page->first_block; block; block = block->next)
	{
		if (block->type != FZ_STEXT_BLOCK_TEXT)
			continue;
		for (line = block->u.t.first_line; line; line = line->next)
		{
			for (ch = line->first_char; ch; ch = ch->next)
			{
				if (!inside)
					if (idx == start)
						inside = 1;
				if (inside)
					cb->on_char(ctx, cb->arg, line, ch);
				if (++idx == end)
					return;
			}
			if (inside)
				cb->on_line(ctx, cb->arg, line);
		}
	}
}

fz_quad
fz_snap_selection(fz_context *ctx, fz_stext_page *page, fz_point *a, fz_point *b, int mode)
{
	fz_stext_block *block;
	fz_stext_line *line;
	fz_stext_char *ch;
	fz_quad handles;
	int idx, start, end;
	int pc;

	start = find_closest_in_page(page, *a);
	end = find_closest_in_page(page, *b);

	if (start > end)
		idx = start, start = end, end = idx;

	handles.ll = handles.ul = *a;
	handles.lr = handles.ur = *b;

	idx = 0;
	for (block = page->first_block; block; block = block->next)
	{
		if (block->type != FZ_STEXT_BLOCK_TEXT)
			continue;
		for (line = block->u.t.first_line; line; line = line->next)
		{
			pc = '\n';
			for (ch = line->first_char; ch; ch = ch->next)
			{
				if (idx <= start)
				{
					if (mode == FZ_SELECT_CHARS
						|| (mode == FZ_SELECT_WORDS && (pc == ' ' || pc == '\n'))
						|| (mode == FZ_SELECT_LINES && (pc == '\n')))
					{
						handles.ll = ch->quad.ll;
						handles.ul = ch->quad.ul;
						*a = ch->origin;
					}
				}
				if (idx >= end)
				{
					if (mode == FZ_SELECT_CHARS
						|| (mode == FZ_SELECT_WORDS && (ch->c == ' ')))
					{
						handles.lr = ch->quad.ll;
						handles.ur = ch->quad.ul;
						*b = ch->origin;
						return handles;
					}
					if (!ch->next)
					{
						handles.lr = ch->quad.lr;
						handles.ur = ch->quad.ur;
						*b = ch->quad.lr;
						return handles;
					}
				}
				pc = ch->c;
				++idx;
			}
		}
	}

	return handles;
}

/* Highlight selection */

struct highlight
{
	int len, cap;
	fz_quad *box;
	float hfuzz, vfuzz;
};

static void on_highlight_char(fz_context *ctx, void *arg, fz_stext_line *line, fz_stext_char *ch)
{
	struct highlight *hits = arg;
	float vfuzz = ch->size * hits->vfuzz;
	float hfuzz = ch->size * hits->hfuzz;

	if (hits->len > 0)
	{
		fz_quad *end = &hits->box[hits->len-1];
		float llh = hdist(&line->dir, &end->lr, &ch->quad.ll);
		float llv = vdist(&line->dir, &end->lr, &ch->quad.ll);
		float ulh = hdist(&line->dir, &end->ur, &ch->quad.ul);
		float ulv = vdist(&line->dir, &end->ur, &ch->quad.ul);
		float lrh = hdist(&line->dir, &end->ll, &ch->quad.lr);
		float lrv = vdist(&line->dir, &end->ll, &ch->quad.lr);
		float urh = hdist(&line->dir, &end->ul, &ch->quad.ur);
		float urv = vdist(&line->dir, &end->ul, &ch->quad.ur);

		if (lrh + lrv + urh + urv < llh + llv + ulh + ulv)
		{
			/* Merge to the right, if at all. */
			if (lrh < hfuzz
				&& lrv < vfuzz
				&& urh < hfuzz
				&& urv < vfuzz)
			{
				end->ul = ch->quad.ul;
				end->ll = ch->quad.ll;
				return;
			}
		}
		else
		{
			/* Merge to the left, if at all */
			if (llh < hfuzz
				&& llv < vfuzz
				&& ulh < hfuzz
				&& ulv < vfuzz)
			{
				end->ur = ch->quad.ur;
				end->lr = ch->quad.lr;
				return;
			}
		}
	}

	if (hits->len < hits->cap)
		hits->box[hits->len++] = ch->quad;
}

static void on_highlight_line(fz_context *ctx, void *arg, fz_stext_line *line)
{
}

int
fz_highlight_selection(fz_context *ctx, fz_stext_page *page, fz_point a, fz_point b, fz_quad *quads, int max_quads)
{
	struct callbacks cb;
	struct highlight hits;

	hits.len = 0;
	hits.cap = max_quads;
	hits.box = quads;
	hits.hfuzz = 0.5f; /* merge large gaps */
	hits.vfuzz = 0.1f;

	cb.on_char = on_highlight_char;
	cb.on_line = on_highlight_line;
	cb.arg = &hits;

	fz_enumerate_selection(ctx, page, a, b, &cb);

	return hits.len;
}

/* Copy selection */

static void on_copy_char(fz_context *ctx, void *arg, fz_stext_line *line, fz_stext_char *ch)
{
	fz_buffer *buffer = arg;
	int c = ch->c;
	if (c < 32)
		c = FZ_REPLACEMENT_CHARACTER;
	fz_append_rune(ctx, buffer, c);
}

static void on_copy_line_crlf(fz_context *ctx, void *arg, fz_stext_line *line)
{
	fz_buffer *buffer = arg;
	fz_append_byte(ctx, buffer, '\r');
	fz_append_byte(ctx, buffer, '\n');
}

static void on_copy_line_lf(fz_context *ctx, void *arg, fz_stext_line *line)
{
	fz_buffer *buffer = arg;
	fz_append_byte(ctx, buffer, '\n');
}

char *
fz_copy_selection(fz_context *ctx, fz_stext_page *page, fz_point a, fz_point b, int crlf)
{
	struct callbacks cb;
	fz_buffer *buffer;
	unsigned char *s;

	buffer = fz_new_buffer(ctx, 1024);
	fz_try(ctx)
	{
		cb.on_char = on_copy_char;
		cb.on_line = crlf ? on_copy_line_crlf : on_copy_line_lf;
		cb.arg = buffer;

		fz_enumerate_selection(ctx, page, a, b, &cb);
		fz_terminate_buffer(ctx, buffer);
	}
	fz_catch(ctx)
	{
		fz_drop_buffer(ctx, buffer);
		fz_rethrow(ctx);
	}
	fz_buffer_extract(ctx, buffer, &s); /* take over the data */
	fz_drop_buffer(ctx, buffer);
	return (char*)s;
}

char *
fz_copy_rectangle(fz_context *ctx, fz_stext_page *page, fz_rect area, int crlf)
{
	fz_stext_block *block;
	fz_stext_line *line;
	fz_stext_char *ch;
	fz_buffer *buffer;
	unsigned char *s;

	int need_new_line = 0;

	buffer = fz_new_buffer(ctx, 1024);
	fz_try(ctx)
	{
		for (block = page->first_block; block; block = block->next)
		{
			if (block->type != FZ_STEXT_BLOCK_TEXT)
				continue;
			for (line = block->u.t.first_line; line; line = line->next)
			{
				int line_had_text = 0;
				for (ch = line->first_char; ch; ch = ch->next)
				{
					fz_rect r = fz_rect_from_quad(ch->quad);
					if (!fz_is_empty_rect(fz_intersect_rect(r, area)))
					{
						line_had_text = 1;
						if (need_new_line)
						{
							fz_append_string(ctx, buffer, crlf ? "\r\n" : "\n");
							need_new_line = 0;
						}
						fz_append_rune(ctx, buffer, ch->c < 32 ? FZ_REPLACEMENT_CHARACTER : ch->c);
					}
				}
				if (line_had_text)
					need_new_line = 1;
			}
		}
		fz_terminate_buffer(ctx, buffer);
	}
	fz_catch(ctx)
	{
		fz_drop_buffer(ctx, buffer);
		fz_rethrow(ctx);
	}

	fz_buffer_extract(ctx, buffer, &s); /* take over the data */
	fz_drop_buffer(ctx, buffer);
	return (char*)s;
}

/* String search */

static inline int canon(int c)
{
	// Map full-width ASCII forms to ASCII:
	// U+FF01 .. U+FF5E => U+0021 .. U+007E
	if (c >= 0xFF01 && c <= 0xFF5E)
		c = c - 0xFF01 + 0x21;

	if (c == 0xA0 || c == 0x2028 || c == 0x2029)
		return ' ';
	if (c == '\r' || c == '\n' || c == '\t')
		return ' ';

	return fz_toupper(c);
}

static inline int chartocanon(int *c, const char *s)
{
	int n = fz_chartorune(c, s);
	*c = canon(*c);
	return n;
}

static const char *match_string(const char *h, const char *n)
{
	int hc, nc;
	const char *e = h;
	h += chartocanon(&hc, h);
	n += chartocanon(&nc, n);
	while (hc == nc)
	{
		e = h;
		if (hc == ' ')
			do
				h += chartocanon(&hc, h);
			while (hc == ' ');
		else
			h += chartocanon(&hc, h);
		if (nc == ' ')
			do
				n += chartocanon(&nc, n);
			while (nc == ' ');
		else
			n += chartocanon(&nc, n);
	}
	return nc == 0 ? e : NULL;
}

static const char *find_string(const char *s, const char *needle, const char **endp)
{
	const char *end;
	while (*s)
	{
		end = match_string(s, needle);
		if (end)
			return *endp = end, s;
		++s;
	}
	return *endp = NULL, NULL;
}

static void add_hit_char(fz_context *ctx, struct highlight *hits, int *hit_mark, fz_stext_line *line, fz_stext_char *ch, int is_at_start)
{
	float vfuzz = ch->size * hits->vfuzz;
	float hfuzz = ch->size * hits->hfuzz;

	if (hits->len > 0 && !is_at_start)
	{
		fz_quad *end = &hits->box[hits->len-1];
		if (hdist(&line->dir, &end->lr, &ch->quad.ll) < hfuzz
			&& vdist(&line->dir, &end->lr, &ch->quad.ll) < vfuzz
			&& hdist(&line->dir, &end->ur, &ch->quad.ul) < hfuzz
			&& vdist(&line->dir, &end->ur, &ch->quad.ul) < vfuzz)
		{
			end->ur = ch->quad.ur;
			end->lr = ch->quad.lr;
			return;
		}
	}

	if (hits->len < hits->cap)
	{
		if (hit_mark)
			hit_mark[hits->len] = is_at_start;
		hits->box[hits->len] = ch->quad;
		hits->len++;
	}
}

int
fz_search_stext_page(fz_context *ctx, fz_stext_page *page, const char *needle, int *hit_mark, fz_quad *quads, int max_quads)
{
	struct highlight hits;
	fz_stext_block *block;
	fz_stext_line *line;
	fz_stext_char *ch;
	fz_buffer *buffer;
	const char *haystack, *begin, *end;
	int c, inside;

	if (strlen(needle) == 0)
		return 0;

	hits.len = 0;
	hits.cap = max_quads;
	hits.box = quads;
	hits.hfuzz = 0.2f; /* merge kerns but not large gaps */
	hits.vfuzz = 0.1f;

	buffer = fz_new_buffer_from_stext_page(ctx, page);
	fz_try(ctx)
	{
		haystack = fz_string_from_buffer(ctx, buffer);
		begin = find_string(haystack, needle, &end);
		if (!begin)
			goto no_more_matches;

		inside = 0;
		for (block = page->first_block; block; block = block->next)
		{
			if (block->type != FZ_STEXT_BLOCK_TEXT)
				continue;
			for (line = block->u.t.first_line; line; line = line->next)
			{
				for (ch = line->first_char; ch; ch = ch->next)
				{
try_new_match:
					if (!inside)
					{
						if (haystack >= begin)
							inside = 1;
					}
					if (inside)
					{
						if (haystack < end)
						{
							add_hit_char(ctx, &hits, hit_mark, line, ch, haystack == begin);
						}
						else
						{
							inside = 0;
							begin = find_string(haystack, needle, &end);
							if (!begin)
								goto no_more_matches;
							else
								goto try_new_match;
						}
					}
					haystack += fz_chartorune(&c, haystack);
				}
				assert(*haystack == '\n');
				++haystack;
			}
			assert(*haystack == '\n');
			++haystack;
		}
no_more_matches:;
	}
	fz_always(ctx)
		fz_drop_buffer(ctx, buffer);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return hits.len;
}
