#include <fitz.h>

fz_error *
fz_newtextnode(fz_textnode **textp, fz_font *font)
{
	fz_textnode *text;

	text = *textp = fz_malloc(sizeof(fz_textnode));
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
fz_freetextnode(fz_textnode *text)
{
	fz_free(text->els);
}

fz_rect
fz_boundtextnode(fz_textnode *text, fz_matrix ctm)
{
	// FIXME convolve font bbox to all glyph x,y pairs
	/* fz_rect bounds = fz_boundglyph(text->font, text->els[0], ctm); */
	return fz_infiniterect();
}

static fz_error *
growtext(fz_textnode *text, int n)
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
fz_addtext(fz_textnode *text, int cid, float x, float y)
{
	if (growtext(text, 1) != nil)
		return fz_outofmem;
	text->els[text->len].cid = cid;
	text->els[text->len].x = x;
	text->els[text->len].y = y;
	text->len++;
	return nil;
}

