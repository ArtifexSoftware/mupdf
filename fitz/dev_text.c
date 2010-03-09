#include "fitz.h"

#include <ft2build.h>
#include FT_FREETYPE_H

#if ((FREETYPE_MAJOR == 2) && (FREETYPE_MINOR == 1)) || \
	((FREETYPE_MAJOR == 2) && (FREETYPE_MINOR == 2)) || \
	((FREETYPE_MAJOR == 2) && (FREETYPE_MINOR == 3) && (FREETYPE_PATCH < 8))

int FT_Get_Advance(FT_Face face, int gid, int masks, FT_Fixed *out)
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
	fz_textline *line;
};

fz_textline *
fz_newtextline(void)
{
	fz_textline *line;
	line = fz_malloc(sizeof(fz_textline));
	line->len = 0;
	line->cap = 0;
	line->text = nil;
	line->next = nil;
	return line;
}

void
fz_freetextline(fz_textline *line)
{
	if (line->next)
		fz_freetextline(line->next);
	fz_free(line->text);
	fz_free(line);
}

static void
fz_addtextchar(fz_textline *line, int x, int y, int c)
{
	if (line->len + 1 >= line->cap)
	{
		line->cap = line->cap ? (line->cap * 3) / 2 : 80;
		line->text = fz_realloc(line->text, sizeof(fz_textchar) * line->cap);
	}
	line->text[line->len].x = x;
	line->text[line->len].y = y;
	line->text[line->len].c = c;
	line->len ++;
}

void
fz_debugtextline(fz_textline *line)
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
		fz_debugtextline(line->next);
}

static void
fz_textextractline(fz_textline **line, fz_text *text, fz_point *oldpt)
{
	fz_font *font = text->font;
	fz_matrix ctm = text->ctm;
	fz_matrix tm = text->trm;
	fz_matrix inv = fz_invertmatrix(text->trm);
	fz_matrix trm;
	float dx, dy;
	fz_point p;
	float adv;
	int i, x, y, fterr;

	if (font->ftface)
	{
		FT_Set_Transform(font->ftface, NULL, NULL);
		fterr = FT_Set_Char_Size(font->ftface, 64, 64, 72, 72);
		if (fterr)
			fz_warn("freetype set character size: %s", ft_errorstring(fterr));
	}

	for (i = 0; i < text->len; i++)
	{
		tm.e = text->els[i].x;
		tm.f = text->els[i].y;
		trm = fz_concat(tm, ctm);
		x = trm.e;
		y = trm.f;
		trm.e = 0;
		trm.f = 0;

		p.x = text->els[i].x;
		p.y = text->els[i].y;
		p = fz_transformpoint(inv, p);
		dx = oldpt->x - p.x;
		dy = oldpt->y - p.y;
		*oldpt = p;

		/* TODO: flip advance and test for vertical writing */

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

		if (fabs(dy) > 0.2)
		{
			fz_textline *newline;
			newline = fz_newtextline();
			(*line)->next = newline;
			*line = newline;
		}
		else if (fabs(dx) > 0.2)
		{
			fz_addtextchar(*line, x, y, ' ');
		}

		fz_addtextchar(*line, x, y, text->els[i].ucs);
	}
}

void fz_textfilltext(void *user, fz_text *text, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_textdevice *tdev = user;
	fz_textextractline(&tdev->line, text, &tdev->point);
}

void fz_textignoretext(void *user, fz_text *text)
{
	fz_textdevice *tdev = user;
	fz_textextractline(&tdev->line, text, &tdev->point);
}

fz_device *fz_newtextdevice(fz_textline *root)
{
	fz_textdevice *tdev = fz_malloc(sizeof(fz_textdevice));
	tdev->line = root;
	tdev->point.x = -1;
	tdev->point.y = -1;

	fz_device *dev = fz_newdevice(tdev);

	dev->filltext = fz_textfilltext;
	dev->ignoretext = fz_textignoretext;

	return dev;
}

void fz_freetextdevice(fz_device *dev)
{
	fz_textdevice *tdev = dev->user;
	fz_free(tdev);
	fz_free(dev);
}