#include "mupdf/fitz.h"

#include <string.h>
#include <limits.h>
#include <stdio.h>

static inline int fz_tolower(int c)
{
	/* TODO: proper unicode case folding */
	/* TODO: character equivalence (a matches ä, etc) */
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	return c;
}

static inline int iswhite(int c)
{
	return c == ' ' || c == '\r' || c == '\n' || c == '\t' || c == 0xA0 || c == 0x2028 || c == 0x2029;
}

int fz_stext_char_count(fz_context *ctx, fz_stext_page *page)
{
	fz_stext_block *block;
	fz_stext_line *line;
	fz_stext_char *ch;
	int len = 0;

	for (block = page->first_block; block; block = block->next)
	{
		if (block->type != FZ_STEXT_BLOCK_TEXT)
			continue;
		for (line = block->u.t.first_line; line; line = line->next)
		{
			for (ch = line->first_char; ch; ch = ch->next)
				++len;
			++len; /* pseudo-newline */
		}
	}

	return len;
}

const fz_stext_char *fz_stext_char_at(fz_context *ctx, fz_stext_page *page, int idx)
{
	static const fz_stext_char space = { ' ', {0,0}, {0,0,0,0}, 0, NULL, NULL };
	static const fz_stext_char zero = { '\0', {0,0}, {0,0,0,0}, 0, NULL, NULL };
	fz_stext_block *block;
	fz_stext_line *line;
	fz_stext_char *ch;
	int ofs = 0;

	for (block = page->first_block; block; block = block->next)
	{
		if (block->type != FZ_STEXT_BLOCK_TEXT)
			continue;
		for (line = block->u.t.first_line; line; line = line->next)
		{
			for (ch = line->first_char; ch; ch = ch->next)
			{
				if (ofs == idx)
					return ch;
				++ofs;
			}

			/* pseudo-newline */
			if (idx == ofs)
				return &space;
			++ofs;
		}
	}
	return &zero;
}

static inline int charat(fz_context *ctx, fz_stext_page *page, int idx)
{
	return fz_stext_char_at(ctx, page, idx)->c;
}

static fz_rect *bboxat(fz_context *ctx, fz_stext_page *page, int idx, fz_rect *bbox)
{
	/* FIXME: Nasty extra copy */
	*bbox = fz_stext_char_at(ctx, page, idx)->bbox;
	return bbox;
}

static int match_stext(fz_context *ctx, fz_stext_page *page, const char *s, int n)
{
	int orig = n;
	int c;
	while (*s)
	{
		s += fz_chartorune(&c, (char *)s);
		if (iswhite(c) && iswhite(charat(ctx, page, n)))
		{
			const char *s_next;

			/* Skip over whitespace in the document */
			do
				n++;
			while (iswhite(charat(ctx, page, n)));

			/* Skip over multiple whitespace in the search string */
			while (s_next = s + fz_chartorune(&c, (char *)s), iswhite(c))
				s = s_next;
		}
		else
		{
			if (fz_tolower(c) != fz_tolower(charat(ctx, page, n)))
				return 0;
			n++;
		}
	}
	return n - orig;
}

int
fz_search_stext_page(fz_context *ctx, fz_stext_page *text, const char *needle, fz_rect *hit_bbox, int hit_max)
{
	int pos, len, i, n, hit_count;

	if (strlen(needle) == 0)
		return 0;

	hit_count = 0;
	len = fz_stext_char_count(ctx, text);
	pos = 0;
	while (pos < len)
	{
		n = match_stext(ctx, text, needle, pos);
		if (n)
		{
			fz_rect linebox = fz_empty_rect;
			for (i = 0; i < n; i++)
			{
				fz_rect charbox;
				bboxat(ctx, text, pos + i, &charbox);
				if (!fz_is_empty_rect(&charbox))
				{
					if (charbox.y0 != linebox.y0 || fz_abs(charbox.x0 - linebox.x1) > 5)
					{
						if (!fz_is_empty_rect(&linebox) && hit_count < hit_max)
							hit_bbox[hit_count++] = linebox;
						linebox = charbox;
					}
					else
					{
						fz_union_rect(&linebox, &charbox);
					}
				}
			}
			if (!fz_is_empty_rect(&linebox) && hit_count < hit_max)
				hit_bbox[hit_count++] = linebox;
			pos += n;
		}
		else
		{
			pos += 1;
		}
	}

	return hit_count;
}

static float dist2(float a, float b)
{
	return a * a + b * b;
}

static int line_length(fz_stext_line *line)
{
	fz_stext_char *ch;
	int n = 0;
	for (ch = line->first_char; ch; ch = ch->next)
		++n;
	return n;
}

static int find_closest_in_line(fz_stext_line *line, int idx, fz_point p)
{
	fz_stext_char *ch;
	float closest_dist = 1e30;
	int closest_idx = idx;

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
		float mid_x = (ch->bbox.x0 + ch->bbox.x1) / 2;
		float mid_y = (ch->bbox.y0 + ch->bbox.y1) / 2;
		float this_dist = dist2(p.x - mid_x, p.y - mid_y);
		if (this_dist < closest_dist)
		{
			closest_dist = this_dist;
			if (line->dir.x > line->dir.y)
				closest_idx = (p.x < mid_x) ? idx : idx+1;
			else
				closest_idx = (p.y < mid_y) ? idx : idx+1;
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
	float closest_dist = 1e30;
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
	int hit_count;
	int inside;

	start = find_closest_in_page(page, a);
	end = find_closest_in_page(page, b);

	if (start > end)
		idx = start, start = end, end = idx;

	if (start == end)
		return;

	hit_count = 0;
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

struct highlight
{
	int len, cap;
	fz_rect *box;
};

static void on_highlight_char(fz_context *ctx, void *arg, fz_stext_line *line, fz_stext_char *ch)
{
	struct highlight *hits = arg;
	float vfuzz = ch->size * 0.1f;
	float hfuzz = ch->size * 0.5f;
	fz_rect bbox;

	if (line->dir.x > line->dir.y)
	{
		bbox.x0 = ch->bbox.x0;
		bbox.x1 = ch->bbox.x1;
		bbox.y0 = line->bbox.y0;
		bbox.y1 = line->bbox.y1;
	}
	else
	{
		bbox.x0 = line->bbox.x0;
		bbox.x1 = line->bbox.x1;
		bbox.y0 = ch->bbox.y0;
		bbox.y1 = ch->bbox.y1;
	}

	if (hits->len > 0)
	{
		fz_rect *end = &hits->box[hits->len-1];
		if (fz_abs(bbox.y0 - end->y0) < vfuzz && fz_abs(bbox.y1 - end->y1) < vfuzz)
		{
			if (bbox.x1 < end->x0)
			{
				if (end->x0 - bbox.x1 < hfuzz)
				{
					end->x0 = bbox.x0;
					return;
				}
			}
			else if (bbox.x0 > end->x1)
			{
				if (bbox.x0 - end->x1 < hfuzz)
				{
					end->x1 = bbox.x1;
					return;
				}
			}
			else
			{
				end->x0 = fz_min(bbox.x0, end->x0);
				end->x1 = fz_max(bbox.x1, end->x1);
				return;
			}
		}
		if (fz_abs(bbox.x0 - end->x0) < vfuzz && fz_abs(bbox.x1 - end->x1) < vfuzz)
		{
			if (bbox.y1 < end->y0)
			{
				if (end->y0 - bbox.y1 < hfuzz)
				{
					end->y0 = bbox.y0;
					return;
				}
			}
			else if (bbox.y0 > end->y1)
			{
				if (bbox.y0 - end->y1 < hfuzz)
				{
					end->y1 = bbox.y1;
					return;
				}
			}
			else
			{
				end->y0 = fz_min(bbox.y0, end->y0);
				end->y1 = fz_max(bbox.y1, end->y1);
				return;
			}
		}
	}

	if (hits->len < hits->cap)
		hits->box[hits->len++] = bbox;
}

static void on_highlight_line(fz_context *ctx, void *arg, fz_stext_line *line)
{
}

int
fz_highlight_selection(fz_context *ctx, fz_stext_page *page, fz_point a, fz_point b, fz_rect *hit_bbox, int hit_max)
{
	struct callbacks cb;
	struct highlight hits;

	hits.len = 0;
	hits.cap = hit_max;
	hits.box = hit_bbox;

	cb.on_char = on_highlight_char;
	cb.on_line = on_highlight_line;
	cb.arg = &hits;

	fz_enumerate_selection(ctx, page, a, b, &cb);

	return hits.len;
}

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

	cb.on_char = on_copy_char;
	cb.on_line = crlf ? on_copy_line_crlf : on_copy_line_lf;
	cb.arg = buffer;

	fz_enumerate_selection(ctx, page, a, b, &cb);

	fz_terminate_buffer(ctx, buffer);
	fz_buffer_extract(ctx, buffer, &s); /* take over the data */
	fz_drop_buffer(ctx, buffer);
	return (char*)s;
}
