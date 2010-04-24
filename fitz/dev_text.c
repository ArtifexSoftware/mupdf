#include "fitz.h"

#include <ft2build.h>
#include FT_FREETYPE_H

#if ((FREETYPE_MAJOR == 2) && (FREETYPE_MINOR == 1)) || \
	((FREETYPE_MAJOR == 2) && (FREETYPE_MINOR == 2)) || \
	((FREETYPE_MAJOR == 2) && (FREETYPE_MINOR == 3) && (FREETYPE_PATCH < 8))

int
FT_Get_Advance(FT_Face face, int gid, int masks, FT_Fixed *out)
{
	int fterr;
	fterr = FT_Load_Glyph(face, gid, masks | FT_LOAD_IGNORE_TRANSFORM);
	if (fterr)
		return fterr;
	*out = face->glyph->advance.x * 1024;
	return 0;
}

#else

#include FT_ADVANCES_H

#endif

typedef struct fz_textdevice_s fz_textdevice;

struct fz_textdevice_s
{
	fz_point point;
	fz_textspan *line;
};

fz_textspan *
fz_newtextspan(void)
{
	fz_textspan *line;
	line = fz_malloc(sizeof(fz_textspan));
	line->len = 0;
	line->cap = 0;
	line->text = nil;
	line->next = nil;
	return line;
}

void
fz_freetextspan(fz_textspan *line)
{
	if (line->next)
		fz_freetextspan(line->next);
	fz_free(line->text);
	fz_free(line);
}

static void
fz_addtextchar(fz_textspan *line, int c, fz_bbox bbox)
{
	if (line->len + 1 >= line->cap)
	{
		line->cap = line->cap ? (line->cap * 3) / 2 : 80;
		line->text = fz_realloc(line->text, sizeof(fz_textchar) * line->cap);
	}
	line->text[line->len].c = c;
	line->text[line->len].bbox = bbox;
	line->len ++;
}

void
fz_debugtextspan(fz_textspan *line)
{
	char buf[10];
	int c, n, k, i;

	for (i = 0; i < line->len; i++)
	{
		c = line->text[i].c;
		if (c < 128)
			putchar(c);
		else
		{
			n = runetochar(buf, &c);
			for (k = 0; k < n; k++)
				putchar(buf[k]);
		}
	}
	putchar('\n');

	if (line->next)
		fz_debugtextspan(line->next);
}

static void
fz_textextractline(fz_textspan **line, fz_text *text, fz_matrix ctm, fz_point *oldpt)
{
	fz_font *font = text->font;
	fz_matrix tm = text->trm;
	fz_matrix inv = fz_invertmatrix(text->trm);
	fz_matrix trm;
	float dx, dy;
	fz_rect rect;
	fz_point p;
	float adv;
	int i, fterr;

	if (font->ftface)
	{
		FT_Set_Transform(font->ftface, NULL, NULL);
		fterr = FT_Set_Char_Size(font->ftface, 64, 64, 72, 72);
		if (fterr)
			fz_warn("freetype set character size: %s", ft_errorstring(fterr));
	}

	for (i = 0; i < text->len; i++)
	{
		/* Get bbox in device space */
		tm.e = text->els[i].x;
		tm.f = text->els[i].y;
		trm = fz_concat(tm, ctm);

		rect.x0 = 0.0;
		rect.y0 = 0.0;
		rect.x1 = adv;
		rect.y1 = 1.0;
		rect = fz_transformrect(trm, rect);

		/* Get point in user space to perform heuristic space and newline tests */
		p.x = text->els[i].x;
		p.y = text->els[i].y;
		p = fz_transformpoint(inv, p);
		dx = oldpt->x - p.x;
		dy = oldpt->y - p.y;
		*oldpt = p;

		/* TODO: flip advance and test for vertical writing */
		if (fabs(dy) > 0.2)
		{
			fz_textspan *newline;
			newline = fz_newtextspan();
			(*line)->next = newline;
			*line = newline;
		}
		else if (fabs(dx) > 0.2)
		{
			/* TODO: improve the location of the invented space bbox */
			fz_bbox bbox = fz_roundrect(rect);
			bbox.x1 = bbox.x0;
			bbox.y1 = bbox.y0;
			fz_addtextchar(*line, ' ', bbox);
		}

		/* Update oldpt for advance width */
		if (font->ftface)
		{
			FT_Fixed ftadv;
			fterr = FT_Get_Advance(font->ftface, text->els[i].gid,
				FT_LOAD_NO_BITMAP | FT_LOAD_NO_HINTING,
				&ftadv);
			if (fterr)
				fz_warn("freetype get advance (gid %d): %s", text->els[i].gid, ft_errorstring(fterr));
			adv = ftadv / 65536.0;
			oldpt->x += adv;
		}
		else
		{
			adv = font->t3widths[text->els[i].gid];
			oldpt->x += adv;
		}

		fz_addtextchar(*line, text->els[i].ucs, fz_roundrect(rect));
	}
}

static void
fz_textfilltext(void *user, fz_text *text, fz_matrix ctm,
	fz_colorspace *colorspace, float *color, float alpha)
{
	fz_textdevice *tdev = user;
	fz_textextractline(&tdev->line, text, ctm, &tdev->point);
}

static void
fz_textignoretext(void *user, fz_text *text, fz_matrix ctm)
{
	fz_textdevice *tdev = user;
	fz_textextractline(&tdev->line, text, ctm, &tdev->point);
}

static void
fz_textfreeuser(void *user)
{
	fz_textdevice *tdev = user;
	fz_free(tdev);
}

fz_device *
fz_newtextdevice(fz_textspan *root)
{
	fz_textdevice *tdev = fz_malloc(sizeof(fz_textdevice));
	tdev->line = root;
	tdev->point.x = -1;
	tdev->point.y = -1;

	fz_device *dev = fz_newdevice(tdev);
	dev->freeuser = fz_textfreeuser;
	dev->filltext = fz_textfilltext;
	dev->ignoretext = fz_textignoretext;
	return dev;
}
