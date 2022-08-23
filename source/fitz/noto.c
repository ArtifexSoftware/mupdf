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

/*
	Base 14 PDF fonts from URW.
	Noto fonts from Google.
	Source Han Serif from Adobe for CJK.
	DroidSansFallback from Android for CJK.
	Charis SIL from SIL.

	Define TOFU to only include the Base14 and CJK fonts.

	Define TOFU_CJK_LANG to skip Source Han Serif per-language fonts.
	Define TOFU_CJK_EXT to skip DroidSansFallbackFull (and the above).
	Define TOFU_CJK to skip DroidSansFallback (and the above).

	Define TOFU_NOTO to skip ALL non-CJK noto fonts.
	Define TOFU_SYMBOL to skip symbol fonts.
	Define TOFU_EMOJI to skip emoji/extended symbol font.

	Define TOFU_SIL to skip the SIL fonts (warning: makes EPUB documents ugly).
	Define TOFU_BASE14 to skip the Base 14 fonts (warning: makes PDF unusable).
*/

#ifdef NOTO_SMALL
#define TOFU_CJK_EXT
#define TOFU_SYMBOL
#define TOFU_EMOJI
#define TOFU_SIL
#endif

#ifdef NO_CJK
#define TOFU_CJK
#endif

#ifdef TOFU
#define TOFU_NOTO
#define TOFU_SIL
#endif

#ifdef TOFU_NOTO
#define TOFU_SYMBOL
#define TOFU_EMOJI
#endif

/* This historic script has an unusually large font (2MB), so we skip it by default. */
#ifndef NOTO_TANGUT
#define NOTO_TANGUT 0
#endif

/* Define some extra scripts for special fonts. */
enum
{
	MUPDF_SCRIPT_MUSIC = UCDN_LAST_SCRIPT+1,
	MUPDF_SCRIPT_MATH,
	MUPDF_SCRIPT_SYMBOLS,
	MUPDF_SCRIPT_SYMBOLS2,
	MUPDF_SCRIPT_EMOJI,
	MUPDF_SCRIPT_CJKV
};

enum
{
	BOLD = 1,
	ITALIC = 2
};

typedef struct
{
	const unsigned char *data;
#ifdef HAVE_OBJCOPY
	const unsigned char *start;
	const unsigned char *end;
#define INBUILT_SIZE(e) (e->end - e->start)
#else
	const unsigned int *size;
#define INBUILT_SIZE(e) (*e->size)
#endif
	char name[48];
	int script;
	int lang;
	int order;
	int subfont;
	int attr;
} font_entry;

#define END_OF_DATA -2
#define ANY_SCRIPT -1
#define ANY_ORDER -1
#define NO_SUBFONT -1
#define REGULAR 0
#define CJKV_LANG -1

/* First, declare all the fonts. */
#ifdef HAVE_OBJCOPY
#define FONT(FORGE,NAME,NAME2,SCRIPT,LANG,ORDER,SUBFONT,ATTR) \
extern unsigned char _binary_resources_fonts_##FORGE##_##NAME##_start; \
extern unsigned char _binary_resources_fonts_##FORGE##_##NAME##_end;
#else
#define FONT(FORGE,NAME,NAME2,SCRIPT,LANG,ORDER,SUBFONT,ATTR) \
extern unsigned char _binary_##NAME[];\
unsigned int _binary_##NAME##_size;
#endif
#define ALIAS(FORGE,NAME,NAME2,SCRIPT,LANG,ORDER,SUBFONT,ATTR)
#define EMPTY(SCRIPT)

#include "font-table.h"

#undef FONT
#undef ALIAS
#undef EMPTY

/* Now the actual list. */
#ifdef HAVE_OBJCOPY
#define FONT_DATA(FORGE,NAME) &_binary_resources_fonts_##FORGE##_##NAME##_start
#define FONT_SIZE(FORGE,NAME) &_binary_resources_fonts_##FORGE##_##NAME##_start, &_binary_resources_fonts_##FORGE##_##NAME##_end
#define EMPTY(SCRIPT) { NULL, NULL, NULL, "", SCRIPT, FZ_LANG_UNSET, ANY_ORDER, NO_SUBFONT },
#else
#define FONT_DATA(FORGE,NAME) _binary_##NAME
#define FONT_SIZE(FORCE,NAME) &_binary_##NAME##_size
#define EMPTY(SCRIPT) { NULL, 0, "", SCRIPT, FZ_LANG_UNSET, ANY_ORDER, NO_SUBFONT },
#endif

#define FONT(FORGE,NAME,NAME2,SCRIPT,LANG,ORDER,SUBFONT,ATTR) { FONT_DATA(FORGE, NAME), FONT_SIZE(FORGE, NAME), NAME2, SCRIPT, LANG, ORDER, SUBFONT, ATTR },
#define ALIAS(FORGE,NAME,NAME2,SCRIPT,LANG,ORDER,SUBFONT,ATTR) { FONT_DATA(FORGE, NAME), FONT_SIZE(FORGE, NAME), NAME2, SCRIPT, LANG, ORDER, SUBFONT, ATTR },
static font_entry inbuilt_fonts[] =
{
#include "font-table.h"
	{ NULL,
#ifdef HAVE_OBJCOPY
	NULL, NULL,
#else
	0,
#endif
	"", END_OF_DATA, FZ_LANG_UNSET, ANY_ORDER, NO_SUBFONT }
};

#undef FONT
#undef ALIAS
#undef EMPTY
#undef FONT_DATA
#undef FONT_SIZE

static const unsigned char *
search_by_script_lang(int *size, int *subfont, int script, int language, int order)
{
	/* Search in the inbuilt font table. */
	font_entry *e;

	if (subfont)
		*subfont = 0;

	for (e = inbuilt_fonts; e->script != END_OF_DATA; e++)
	{
		if (script != ANY_SCRIPT && e->script != script)
			continue;
		if (e->lang != language)
			continue;
		if (order != ANY_ORDER && e->order != order && e->order != ANY_ORDER)
			continue;
		*size = INBUILT_SIZE(e);
		if (subfont && e->subfont != NO_SUBFONT)
			*subfont = e->subfont;
		return e->data;
	}

	return *size = 0, NULL;
}

static int
font_name_match(const char *ref, const char *needle, int with_attr)
{
	while (1)
	{
		int r;
		int n;

		/* Skip over unimportant chars in both source and needle */
		do
		{
			r = *ref++;
		}
		while (r == ' ' || r == '-' || r == '_');

		do
		{
			n = *needle++;
		}
		while (n == ' ' || n == '-' || n == '_');

		if (r == 0 && n == 0)
			return 1; /* Match! */

		/* Compare case insensitively */
		if (r >= 'a' && r <= 'z')
			r += 'A'-'a';
		if (n >= 'a' && n <= 'z')
			n += 'A'-'a';

		if (r == n)
			continue;

		/* If we ran out of needle, check for us almost matching */
		if (n == 0)
		{
			if (r == 'R' && !fz_strcasecmp(ref, "egular"))
				return 1;
			/* If with_attr, then we'll skip */
			if (with_attr)
			{
				if (r == 'B' && !fz_strncasecmp(ref, "old", 3))
					ref += 3, r = *ref++;
				if (r == 'O' && !fz_strncasecmp(ref, "blique", 6))
					ref += 6, r = *ref++;
				if (r == 'I' && !fz_strncasecmp(ref, "talic", 5))
					ref += 5, r = *ref++;
				if (r == 'R' && !fz_strncasecmp(ref, "oman", 4))
					ref += 4, r = *ref++;
				if (r == 0)
					return 1;
			}
		}
		/* If we get here, match has failed. */
		break;
	}

	return 0;
}

static const unsigned char *
search_by_name(int *size, const char *name, int with_attr, int attr)
{
	/* Search in the inbuilt font table. */
	font_entry *e;

	for (e = inbuilt_fonts; e->script != END_OF_DATA; e++)
	{
		if (with_attr && attr != e->attr)
			continue;
		if (font_name_match(e->name, name, with_attr))
		{
			*size = INBUILT_SIZE(e);
			return e->data;
		}
	}

	return *size = 0, NULL;
}

const char *base14_names[] =
{
	"Courier",
	"Courier-Oblique",
	"Courier-Bold",
	"Courier-BoldOblique",
	"Helvetica",
	"Helvetica-Oblique",
	"Helvetica-Bold",
	"Helvetica-BoldOblique",
	"Times-Roman",
	"Times-Italic",
	"Times-Bold",
	"Times-BoldItalic",
	"Symbol",
	"ZapfDingbats"
};

const unsigned char *
fz_lookup_base14_font(fz_context *ctx, const char *name, int *size)
{
	/* We want to insist on the base14 name matching exactly,
	 * so we check that here first, before we look in the font table
	 * to see if we actually have data. */
	unsigned int i;

	for (i = 0; i < nelem(base14_names); i++)
	{
		if (!strcmp(name, base14_names[i]))
			return search_by_name(size, name, 0, 0);
	}

	*size = 0;
	return NULL;
}

const unsigned char *
fz_lookup_builtin_font(fz_context *ctx, const char *name, int is_bold, int is_italic, int *size)
{
	return search_by_name(size, name, 1, (is_bold ? BOLD : 0) | (is_italic ? ITALIC : 0));
}

const unsigned char *
fz_lookup_cjk_font(fz_context *ctx, int ordering, int *size, int *subfont)
{
	return search_by_script_lang(size, subfont, MUPDF_SCRIPT_CJKV, CJKV_LANG, ordering);
}

int
fz_lookup_cjk_ordering_by_language(const char *name)
{
	if (!strcmp(name, "zh-Hant")) return FZ_ADOBE_CNS;
	if (!strcmp(name, "zh-TW")) return FZ_ADOBE_CNS;
	if (!strcmp(name, "zh-HK")) return FZ_ADOBE_CNS;
	if (!strcmp(name, "zh-Hans")) return FZ_ADOBE_GB;
	if (!strcmp(name, "zh-CN")) return FZ_ADOBE_GB;
	if (!strcmp(name, "ja")) return FZ_ADOBE_JAPAN;
	if (!strcmp(name, "ko")) return FZ_ADOBE_KOREA;
	return -1;
}

const unsigned char *
fz_lookup_cjk_font_by_language(fz_context *ctx, const char *lang, int *size, int *subfont)
{
	int ordering = fz_lookup_cjk_ordering_by_language(lang);
	if (ordering >= 0)
		return fz_lookup_cjk_font(ctx, ordering, size, subfont);
	return *size = 0, *subfont = 0, NULL;
}

const unsigned char *
fz_lookup_noto_font(fz_context *ctx, int script, int language, int *size, int *subfont)
{
	*subfont = 0;

	switch (script)
	{
	case UCDN_SCRIPT_HANGUL:
		return fz_lookup_cjk_font(ctx, FZ_ADOBE_KOREA, size, subfont);
	case UCDN_SCRIPT_HIRAGANA:
	case UCDN_SCRIPT_KATAKANA:
		return fz_lookup_cjk_font(ctx, FZ_ADOBE_JAPAN, size, subfont);
	case UCDN_SCRIPT_BOPOMOFO:
		return fz_lookup_cjk_font(ctx, FZ_ADOBE_CNS, size, subfont);
	case UCDN_SCRIPT_HAN:
		switch (language)
		{
		case FZ_LANG_ja: return fz_lookup_cjk_font(ctx, FZ_ADOBE_JAPAN, size, subfont);
		case FZ_LANG_ko: return fz_lookup_cjk_font(ctx, FZ_ADOBE_KOREA, size, subfont);
		case FZ_LANG_zh_Hans: return fz_lookup_cjk_font(ctx, FZ_ADOBE_GB, size, subfont);
		default:
		case FZ_LANG_zh_Hant: return fz_lookup_cjk_font(ctx, FZ_ADOBE_CNS, size, subfont);
		}

	case UCDN_SCRIPT_BRAILLE: break; /* no dedicated font; fallback to NotoSansSymbols will cover this */

	default:
		return search_by_script_lang(size, subfont, script, language, ANY_ORDER);
	}

	return *size = 0, NULL;
}

const unsigned char *
fz_lookup_noto_math_font(fz_context *ctx, int *size)
{
	return search_by_script_lang(size, NULL, MUPDF_SCRIPT_MATH, FZ_LANG_UNSET, ANY_ORDER);
}

const unsigned char *
fz_lookup_noto_music_font(fz_context *ctx, int *size)
{
	return search_by_script_lang(size, NULL, MUPDF_SCRIPT_MUSIC, FZ_LANG_UNSET, ANY_ORDER);
}

const unsigned char *
fz_lookup_noto_symbol1_font(fz_context *ctx, int *size)
{
	return search_by_script_lang(size, NULL, MUPDF_SCRIPT_SYMBOLS, FZ_LANG_UNSET, ANY_ORDER);
}

const unsigned char *
fz_lookup_noto_symbol2_font(fz_context *ctx, int *size)
{
	return search_by_script_lang(size, NULL, MUPDF_SCRIPT_SYMBOLS2, FZ_LANG_UNSET, ANY_ORDER);
}

const unsigned char *
fz_lookup_noto_emoji_font(fz_context *ctx, int *size)
{
	return search_by_script_lang(size, NULL, MUPDF_SCRIPT_EMOJI, FZ_LANG_UNSET, ANY_ORDER);
}
