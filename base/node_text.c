#include <fitz.h>

fz_error *
fz_newtextnode(fz_textnode **textp, fz_font *font)
{
	fz_textnode *text;

	text = fz_malloc(sizeof(fz_textnode));
	if (!text)
		return fz_outofmem;

	fz_initnode((fz_node*)text, FZ_NTEXT);

	text->font = fz_keepfont(font);
	text->trm = fz_identity();
	text->len = 0;
	text->cap = 0;
	text->els = nil;

	*textp = text;
	return nil;
}

fz_error *
fz_clonetextnode(fz_textnode **textp, fz_textnode *oldtext)
{
	fz_textnode *text;

	text = *textp = fz_malloc(sizeof(fz_textnode));
	if (!text)
		return fz_outofmem;

	fz_initnode((fz_node*)text, FZ_NTEXT);

	text->font = fz_keepfont(oldtext->font);
	text->trm = oldtext->trm;
	text->len = oldtext->len;
	text->cap = oldtext->len;
	text->els = nil;

	text->els = fz_malloc(sizeof(fz_textel) * text->len);
	if (!text->els)
	{
		fz_dropfont(text->font);
		fz_free(text);
		return fz_outofmem;
	}

	memcpy(text->els, oldtext->els, sizeof(fz_textel) * text->len);

	*textp = text;
	return nil;
}

void
fz_droptextnode(fz_textnode *text)
{
	fz_dropfont(text->font);
	fz_free(text->els);
}

fz_rect
fz_boundtextnode(fz_textnode *text, fz_matrix ctm)
{
	fz_matrix trm;
	fz_rect bbox;
	fz_rect fbox;
	int i;

	if (text->len == 0)
		return fz_emptyrect;

	/* find bbox of glyph origins in ctm space */

	bbox.min.x = bbox.max.x = text->els[0].x;
	bbox.min.y = bbox.max.y = text->els[0].y;

	for (i = 1; i < text->len; i++)
	{
		bbox.min.x = MIN(bbox.min.x, text->els[i].x);
		bbox.min.y = MIN(bbox.min.y, text->els[i].y);
		bbox.max.x = MAX(bbox.max.x, text->els[i].x);
		bbox.max.y = MAX(bbox.max.y, text->els[i].y);
	}

	bbox = fz_transformaabb(ctm, bbox);

	/* find bbox of font in trm * ctm space */

	trm = fz_concat(text->trm, ctm);
	trm.e = 0;
	trm.f = 0;

	fbox.min.x = text->font->bbox.min.x * 0.001;
	fbox.min.y = text->font->bbox.min.y * 0.001;
	fbox.max.x = text->font->bbox.max.x * 0.001;
	fbox.max.y = text->font->bbox.max.y * 0.001;

	fbox = fz_transformaabb(trm, fbox);

	/* expand glyph origin bbox by font bbox */

	bbox.min.x += fbox.min.x;
	bbox.min.y += fbox.min.y;
	bbox.max.x += fbox.max.x;
	bbox.max.y += fbox.max.y;

	return bbox;
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

