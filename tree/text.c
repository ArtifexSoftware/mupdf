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
	fz_matrix trm;
	fz_point ul, ur, ll, lr;
	fz_rect bbox;
	fz_rect fbox;
	int i;

	if (text->len == 0)
		return fz_infiniterect();

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

	ll.x = bbox.min.x; ll.y = bbox.min.y; ll = fz_transformpoint(ctm, ll);
	ul.x = bbox.min.x; ul.y = bbox.max.y; ul = fz_transformpoint(ctm, ul);
	ur.x = bbox.max.x; ur.y = bbox.max.y; ur = fz_transformpoint(ctm, ur);
	lr.x = bbox.max.x; lr.y = bbox.min.y; lr = fz_transformpoint(ctm, lr);

	bbox.min.x = MIN4(ll.x, ul.x, ur.x, lr.x);
	bbox.min.y = MIN4(ll.y, ul.y, ur.y, lr.y);
	bbox.max.x = MAX4(ll.x, ul.x, ur.x, lr.x);
	bbox.max.y = MAX4(ll.y, ul.y, ur.y, lr.y);

	/* find bbox of font in trm * ctm space */

	trm = fz_concat(text->trm, ctm);
	trm.e = 0;
	trm.f = 0;

	fbox.min.x = text->font->bbox.min.x * 0.001;
	fbox.min.y = text->font->bbox.min.y * 0.001;
	fbox.max.x = text->font->bbox.max.x * 0.001;
	fbox.max.y = text->font->bbox.max.y * 0.001;

	ll.x = fbox.min.x; ll.y = fbox.min.y; ll = fz_transformpoint(trm, ll);
	ul.x = fbox.min.x; ul.y = fbox.max.y; ul = fz_transformpoint(trm, ul);
	ur.x = fbox.max.x; ur.y = fbox.max.y; ur = fz_transformpoint(trm, ur);
	lr.x = fbox.max.x; lr.y = fbox.min.y; lr = fz_transformpoint(trm, lr);

	fbox.min.x = MIN4(ll.x, ul.x, ur.x, lr.x);
	fbox.min.y = MIN4(ll.y, ul.y, ur.y, lr.y);
	fbox.max.x = MAX4(ll.x, ul.x, ur.x, lr.x);
	fbox.max.y = MAX4(ll.y, ul.y, ur.y, lr.y);

	bbox.min.x += MIN4(ll.x, ul.x, ur.x, lr.x);
	bbox.min.y += MIN4(ll.y, ul.y, ur.y, lr.y);
	bbox.max.x += MAX4(ll.x, ul.x, ur.x, lr.x);
	bbox.max.y += MAX4(ll.y, ul.y, ur.y, lr.y);

//	printf("text [ %g %g %g %g ]\n", bbox.min.x, bbox.min.y, bbox.max.x, bbox.max.y);

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

