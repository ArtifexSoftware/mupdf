#include <fitz.h>

fz_error *
fz_newtext(fz_text **textp, fz_font *font)
{
	fz_text *text;

	text = *textp = fz_malloc(sizeof(fz_text));
	if (!text)
		return fz_outofmem;

	fz_initnode((fz_node*)text, FZ_NTEXT);

	text->font = font;
	text->trm = fz_identity();
	text->len = 0;
	text->cap = 0;
	text->els = nil;

	return nil;
}

void
fz_freetext(fz_text *text)
{
	fz_free(text->els);
	fz_free(text);
};

fz_rect
fz_boundtext(fz_text *text, fz_matrix ctm)
{
	/* fz_rect bounds = fz_boundglyph(text->font, text->els[0], ctm); */
	return FZ_INFRECT;
}

static fz_error *
growtext(fz_text *text, int n)
{
	int newcap;
	fz_textel *newels;

	while (text->len + n > text->cap)
	{
		newcap = text->cap + 36;
		newels = fz_realloc(text->els, sizeof (fz_textel) * newcap);
		if (!newels)
			return fz_outofmem;
		text->cap = newcap;
		text->els = newels;
	}

	return nil;
}

fz_error *
fz_addtext(fz_text *text, int g, float x, float y)
{
	if (growtext(text, 1) != nil)
		return fz_outofmem;
	text->els[text->len].g = g;
	text->els[text->len].x = x;
	text->els[text->len].y = y;
	text->len++;
	return nil;
}

