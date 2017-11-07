#include "mupdf/fitz.h"

#include <string.h>

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

int
fz_highlight_selection(fz_context *ctx, fz_stext_page *page, fz_rect rect, fz_rect *hit_bbox, int hit_max)
{
	fz_rect linebox;
	fz_stext_block *block;
	fz_stext_line *line;
	fz_stext_char *ch;
	int hit_count;

	float x0 = rect.x0;
	float x1 = rect.x1;
	float y0 = rect.y0;
	float y1 = rect.y1;

	hit_count = 0;

	for (block = page->first_block; block; block = block->next)
	{
		if (block->type != FZ_STEXT_BLOCK_TEXT)
			continue;
		for (line = block->u.t.first_line; line; line = line->next)
		{
			linebox = fz_empty_rect;
			for (ch = line->first_char; ch; ch = ch->next)
			{
				if (ch->bbox.x1 >= x0 && ch->bbox.x0 <= x1 && ch->bbox.y1 >= y0 && ch->bbox.y0 <= y1)
				{
					if (ch->bbox.y0 != linebox.y0 || fz_abs(ch->bbox.x0 - linebox.x1) > 5)
					{
						if (!fz_is_empty_rect(&linebox) && hit_count < hit_max)
							hit_bbox[hit_count++] = linebox;
						linebox = ch->bbox;
					}
					else
					{
						fz_union_rect(&linebox, &ch->bbox);
					}
				}
			}
			if (!fz_is_empty_rect(&linebox) && hit_count < hit_max)
				hit_bbox[hit_count++] = linebox;
		}
	}

	return hit_count;
}

char *
fz_copy_selection(fz_context *ctx, fz_stext_page *page, fz_rect rect)
{
	fz_buffer *buffer;
	int c, seen = 0;
	unsigned char *s;
	fz_stext_block *block;
	fz_stext_line *line;
	fz_stext_char *ch;

	float x0 = rect.x0;
	float x1 = rect.x1;
	float y0 = rect.y0;
	float y1 = rect.y1;

	buffer = fz_new_buffer(ctx, 1024);

	for (block = page->first_block; block; block = block->next)
	{
		if (block->type != FZ_STEXT_BLOCK_TEXT)
			continue;
		for (line = block->u.t.first_line; line; line = line->next)
		{
			if (seen)
			{
				fz_append_byte(ctx, buffer, '\n');
			}

			seen = 0;

			for (ch = line->first_char; ch; ch = ch->next)
			{
				c = ch->c;
				if (c < 32)
					c = FZ_REPLACEMENT_CHARACTER;
				if (ch->bbox.x1 >= x0 && ch->bbox.x0 <= x1 && ch->bbox.y1 >= y0 && ch->bbox.y0 <= y1)
				{
					fz_append_rune(ctx, buffer, c);
					seen = 1;
				}
			}

			seen = (seen && line == block->u.t.last_line);
		}
	}

	fz_terminate_buffer(ctx, buffer);
	fz_buffer_extract(ctx, buffer, &s); /* take over the data */
	fz_drop_buffer(ctx, buffer);
	return (char*)s;
}
