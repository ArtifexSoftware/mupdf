#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include "../fitz/font-imp.h"
#include "../fitz/fitz-imp.h"

#include <assert.h>

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_ADVANCES_H
#ifdef FT_FONT_FORMATS_H
#include FT_FONT_FORMATS_H
#else
#include FT_XFREE86_H
#endif
#include FT_TRUETYPE_TABLES_H

#ifndef FT_SFNT_HEAD
#define FT_SFNT_HEAD ft_sfnt_head
#endif

static void pdf_load_font_descriptor(fz_context *ctx, pdf_document *doc, pdf_font_desc *fontdesc, pdf_obj *dict,
	const char *collection, const char *basefont, int iscidfont);

static const char *base_font_names[][10] =
{
	{ "Courier", "CourierNew", "CourierNewPSMT", NULL },
	{ "Courier-Bold", "CourierNew,Bold", "Courier,Bold",
		"CourierNewPS-BoldMT", "CourierNew-Bold", NULL },
	{ "Courier-Oblique", "CourierNew,Italic", "Courier,Italic",
		"CourierNewPS-ItalicMT", "CourierNew-Italic", NULL },
	{ "Courier-BoldOblique", "CourierNew,BoldItalic", "Courier,BoldItalic",
		"CourierNewPS-BoldItalicMT", "CourierNew-BoldItalic", NULL },
	{ "Helvetica", "ArialMT", "Arial", NULL },
	{ "Helvetica-Bold", "Arial-BoldMT", "Arial,Bold", "Arial-Bold",
		"Helvetica,Bold", NULL },
	{ "Helvetica-Oblique", "Arial-ItalicMT", "Arial,Italic", "Arial-Italic",
		"Helvetica,Italic", "Helvetica-Italic", NULL },
	{ "Helvetica-BoldOblique", "Arial-BoldItalicMT",
		"Arial,BoldItalic", "Arial-BoldItalic",
		"Helvetica,BoldItalic", "Helvetica-BoldItalic", NULL },
	{ "Times-Roman", "TimesNewRomanPSMT", "TimesNewRoman",
		"TimesNewRomanPS", NULL },
	{ "Times-Bold", "TimesNewRomanPS-BoldMT", "TimesNewRoman,Bold",
		"TimesNewRomanPS-Bold", "TimesNewRoman-Bold", NULL },
	{ "Times-Italic", "TimesNewRomanPS-ItalicMT", "TimesNewRoman,Italic",
		"TimesNewRomanPS-Italic", "TimesNewRoman-Italic", NULL },
	{ "Times-BoldItalic", "TimesNewRomanPS-BoldItalicMT",
		"TimesNewRoman,BoldItalic", "TimesNewRomanPS-BoldItalic",
		"TimesNewRoman-BoldItalic", NULL },
	{ "Symbol", "Symbol,Italic", "Symbol,Bold", "Symbol,BoldItalic",
		"SymbolMT", "SymbolMT,Italic", "SymbolMT,Bold", "SymbolMT,BoldItalic", NULL },
	{ "ZapfDingbats", NULL }
};

const unsigned char *
pdf_lookup_substitute_font(fz_context *ctx, int mono, int serif, int bold, int italic, int *len)
{
	if (mono) {
		if (bold) {
			if (italic) return fz_lookup_base14_font(ctx, "Courier-BoldOblique", len);
			else return fz_lookup_base14_font(ctx, "Courier-Bold", len);
		} else {
			if (italic) return fz_lookup_base14_font(ctx, "Courier-Oblique", len);
			else return fz_lookup_base14_font(ctx, "Courier", len);
		}
	} else if (serif) {
		if (bold) {
			if (italic) return fz_lookup_base14_font(ctx, "Times-BoldItalic", len);
			else return fz_lookup_base14_font(ctx, "Times-Bold", len);
		} else {
			if (italic) return fz_lookup_base14_font(ctx, "Times-Italic", len);
			else return fz_lookup_base14_font(ctx, "Times-Roman", len);
		}
	} else {
		if (bold) {
			if (italic) return fz_lookup_base14_font(ctx, "Helvetica-BoldOblique", len);
			else return fz_lookup_base14_font(ctx, "Helvetica-Bold", len);
		} else {
			if (italic) return fz_lookup_base14_font(ctx, "Helvetica-Oblique", len);
			else return fz_lookup_base14_font(ctx, "Helvetica", len);
		}
	}
}

static int is_dynalab(char *name)
{
	if (strstr(name, "HuaTian"))
		return 1;
	if (strstr(name, "MingLi"))
		return 1;
	if ((strstr(name, "DF") == name) || strstr(name, "+DF"))
		return 1;
	if ((strstr(name, "DLC") == name) || strstr(name, "+DLC"))
		return 1;
	return 0;
}

static int strcmp_ignore_space(const char *a, const char *b)
{
	while (1)
	{
		while (*a == ' ')
			a++;
		while (*b == ' ')
			b++;
		if (*a != *b)
			return 1;
		if (*a == 0)
			return *a != *b;
		if (*b == 0)
			return *a != *b;
		a++;
		b++;
	}
}

static const char *clean_font_name(const char *fontname)
{
	int i, k;
	for (i = 0; i < nelem(base_font_names); i++)
		for (k = 0; base_font_names[i][k]; k++)
			if (!strcmp_ignore_space(base_font_names[i][k], fontname))
				return base_font_names[i][0];
	return fontname;
}

static int is_builtin_font(fz_context *ctx, fz_font *font)
{
	int size;
	unsigned char *data;
	if (!font->buffer)
		return 0;
	fz_buffer_storage(ctx, font->buffer, &data);
	return fz_lookup_base14_font(ctx, clean_font_name(font->name), &size) == data;
}

/*
 * FreeType and Rendering glue
 */

enum { UNKNOWN, TYPE1, TRUETYPE };

static int ft_kind(FT_Face face)
{
#ifdef FT_FONT_FORMATS_H
	const char *kind = FT_Get_Font_Format(face);
#else
	const char *kind = FT_Get_X11_Font_Format(face);
#endif
	if (!strcmp(kind, "TrueType")) return TRUETYPE;
	if (!strcmp(kind, "Type 1")) return TYPE1;
	if (!strcmp(kind, "CFF")) return TYPE1;
	if (!strcmp(kind, "CID Type 1")) return TYPE1;
	return UNKNOWN;
}

static int ft_font_file_kind(FT_Face face)
{
#ifdef FT_FONT_FORMATS_H
	const char *kind = FT_Get_Font_Format(face);
#else
	const char *kind = FT_Get_X11_Font_Format(face);
#endif
	if (!strcmp(kind, "TrueType")) return 2;
	if (!strcmp(kind, "Type 1")) return 1;
	if (!strcmp(kind, "CFF")) return 3;
	if (!strcmp(kind, "CID Type 1")) return 1;
	return 0;
}

static int ft_char_index(FT_Face face, int cid)
{
	int gid = FT_Get_Char_Index(face, cid);
	if (gid == 0)
		gid = FT_Get_Char_Index(face, 0xf000 + cid);

	/* some chinese fonts only ship the similarly looking 0x2026 */
	if (gid == 0 && cid == 0x22ef)
		gid = FT_Get_Char_Index(face, 0x2026);

	return gid;
}

static int ft_name_index(FT_Face face, const char *name)
{
	int code = FT_Get_Name_Index(face, (char*)name);
	if (code == 0)
	{
		int unicode = pdf_lookup_agl(name);
		if (unicode)
		{
			const char **dupnames = pdf_lookup_agl_duplicates(unicode);
			while (*dupnames)
			{
				code = FT_Get_Name_Index(face, (char*)*dupnames);
				if (code)
					break;
				dupnames++;
			}
			if (code == 0)
			{
				char buf[10];
				sprintf(buf, "uni%04X", unicode);
				code = FT_Get_Name_Index(face, buf);
			}
		}
	}
	return code;
}

static int ft_cid_to_gid(pdf_font_desc *fontdesc, int cid)
{
	if (fontdesc->to_ttf_cmap)
	{
		cid = pdf_lookup_cmap(fontdesc->to_ttf_cmap, cid);

		/* vertical presentation forms */
		if (fontdesc->font->flags.ft_substitute && fontdesc->wmode)
		{
			switch (cid)
			{
			case 0x0021: cid = 0xFE15; break; /* ! */
			case 0x0028: cid = 0xFE35; break; /* ( */
			case 0x0029: cid = 0xFE36; break; /* ) */
			case 0x002C: cid = 0xFE10; break; /* , */
			case 0x003A: cid = 0xFE13; break; /* : */
			case 0x003B: cid = 0xFE14; break; /* ; */
			case 0x003F: cid = 0xFE16; break; /* ? */
			case 0x005B: cid = 0xFE47; break; /* [ */
			case 0x005D: cid = 0xFE48; break; /* ] */
			case 0x005F: cid = 0xFE33; break; /* _ */
			case 0x007B: cid = 0xFE37; break; /* { */
			case 0x007D: cid = 0xFE38; break; /* } */
			case 0x2013: cid = 0xFE32; break; /* EN DASH */
			case 0x2014: cid = 0xFE31; break; /* EM DASH */
			case 0x2025: cid = 0xFE30; break; /* TWO DOT LEADER */
			case 0x2026: cid = 0xFE19; break; /* HORIZONTAL ELLIPSIS */
			case 0x3001: cid = 0xFE11; break; /* IDEOGRAPHIC COMMA */
			case 0x3002: cid = 0xFE12; break; /* IDEOGRAPHIC FULL STOP */
			case 0x3008: cid = 0xFE3F; break; /* OPENING ANGLE BRACKET */
			case 0x3009: cid = 0xFE40; break; /* CLOSING ANGLE BRACKET */
			case 0x300A: cid = 0xFE3D; break; /* LEFT DOUBLE ANGLE BRACKET */
			case 0x300B: cid = 0xFE3E; break; /* RIGHT DOUBLE ANGLE BRACKET */
			case 0x300C: cid = 0xFE41; break; /* LEFT CORNER BRACKET */
			case 0x300D: cid = 0xFE42; break; /* RIGHT CORNER BRACKET */
			case 0x300E: cid = 0xFE43; break; /* LEFT WHITE CORNER BRACKET */
			case 0x300F: cid = 0xFE44; break; /* RIGHT WHITE CORNER BRACKET */
			case 0x3010: cid = 0xFE3B; break; /* LEFT BLACK LENTICULAR BRACKET */
			case 0x3011: cid = 0xFE3C; break; /* RIGHT BLACK LENTICULAR BRACKET */
			case 0x3014: cid = 0xFE39; break; /* LEFT TORTOISE SHELL BRACKET */
			case 0x3015: cid = 0xFE3A; break; /* RIGHT TORTOISE SHELL BRACKET */
			case 0x3016: cid = 0xFE17; break; /* LEFT WHITE LENTICULAR BRACKET */
			case 0x3017: cid = 0xFE18; break; /* RIGHT WHITE LENTICULAR BRACKET */

			case 0xFF01: cid = 0xFE15; break; /* FULLWIDTH EXCLAMATION MARK */
			case 0xFF08: cid = 0xFE35; break; /* FULLWIDTH LEFT PARENTHESIS */
			case 0xFF09: cid = 0xFE36; break; /* FULLWIDTH RIGHT PARENTHESIS */
			case 0xFF0C: cid = 0xFE10; break; /* FULLWIDTH COMMA */
			case 0xFF1A: cid = 0xFE13; break; /* FULLWIDTH COLON */
			case 0xFF1B: cid = 0xFE14; break; /* FULLWIDTH SEMICOLON */
			case 0xFF1F: cid = 0xFE16; break; /* FULLWIDTH QUESTION MARK */
			case 0xFF3B: cid = 0xFE47; break; /* FULLWIDTH LEFT SQUARE BRACKET */
			case 0xFF3D: cid = 0xFE48; break; /* FULLWIDTH RIGHT SQUARE BRACKET */
			case 0xFF3F: cid = 0xFE33; break; /* FULLWIDTH LOW LINE */
			case 0xFF5B: cid = 0xFE37; break; /* FULLWIDTH LEFT CURLY BRACKET */
			case 0xFF5D: cid = 0xFE38; break; /* FULLWIDTH RIGHT CURLY BRACKET */

			case 0x30FC: cid = 0xFE31; break; /* KATAKANA-HIRAGANA PROLONGED SOUND MARK */
			case 0xFF0D: cid = 0xFE31; break; /* FULLWIDTH HYPHEN-MINUS */
			}
		}

		return ft_char_index(fontdesc->font->ft_face, cid);
	}

	if (fontdesc->cid_to_gid && (size_t)cid < fontdesc->cid_to_gid_len && cid >= 0)
		return fontdesc->cid_to_gid[cid];

	return cid;
}

int
pdf_font_cid_to_gid(fz_context *ctx, pdf_font_desc *fontdesc, int cid)
{
	if (fontdesc->font->ft_face)
		return ft_cid_to_gid(fontdesc, cid);
	return cid;
}

static int ft_width(fz_context *ctx, pdf_font_desc *fontdesc, int cid)
{
	int mask = FT_LOAD_NO_SCALE | FT_LOAD_NO_HINTING | FT_LOAD_NO_BITMAP | FT_LOAD_IGNORE_TRANSFORM;
	int gid = ft_cid_to_gid(fontdesc, cid);
	FT_Fixed adv;
	int fterr;
	FT_Face face = fontdesc->font->ft_face;
	FT_UShort units_per_EM;

	fterr = FT_Get_Advance(face, gid, mask, &adv);
	if (fterr)
	{
		fz_warn(ctx, "freetype advance glyph (gid %d): %s", gid, ft_error_string(fterr));
		return 0;
	}
	units_per_EM = face->units_per_EM;
	if (units_per_EM == 0)
		units_per_EM = 2048;

	return adv * 1000 / units_per_EM;
}

static const struct { int code; const char *name; } mre_diff_table[] =
{
	{ 173, "notequal" },
	{ 176, "infinity" },
	{ 178, "lessequal" },
	{ 179, "greaterequal" },
	{ 182, "partialdiff" },
	{ 183, "summation" },
	{ 184, "product" },
	{ 185, "pi" },
	{ 186, "integral" },
	{ 189, "Omega" },
	{ 195, "radical" },
	{ 197, "approxequal" },
	{ 198, "Delta" },
	{ 215, "lozenge" },
	{ 219, "Euro" },
	{ 240, "apple" },
};

static int lookup_mre_code(const char *name)
{
	int i;
	for (i = 0; i < nelem(mre_diff_table); ++i)
		if (!strcmp(name, mre_diff_table[i].name))
			return mre_diff_table[i].code;
	for (i = 0; i < 256; i++)
		if (pdf_mac_roman[i] && !strcmp(name, pdf_mac_roman[i]))
			return i;
	return -1;
}

/*
 * Load font files.
 */

static void
pdf_load_builtin_font(fz_context *ctx, pdf_font_desc *fontdesc, const char *fontname, int has_descriptor)
{
	FT_Face face;
	const char *clean_name = clean_font_name(fontname);

	fontdesc->font = fz_load_system_font(ctx, fontname, 0, 0, !has_descriptor);
	if (!fontdesc->font)
	{
		const unsigned char *data;
		int len;

		data = fz_lookup_base14_font(ctx, clean_name, &len);
		if (!data)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find builtin font: '%s'", fontname);

		fontdesc->font = fz_new_font_from_memory(ctx, fontname, data, len, 0, 1);
		fontdesc->font->flags.is_serif = !!strstr(clean_name, "Times");
	}

	if (!strcmp(clean_name, "Symbol") || !strcmp(clean_name, "ZapfDingbats"))
		fontdesc->flags |= PDF_FD_SYMBOLIC;

	face = fontdesc->font->ft_face;
	fontdesc->ascent = 1000.0f * face->ascender / face->units_per_EM;
	fontdesc->descent = 1000.0f * face->descender / face->units_per_EM;
}

static void
pdf_load_substitute_font(fz_context *ctx, pdf_font_desc *fontdesc, const char *fontname, int mono, int serif, int bold, int italic)
{
	fontdesc->font = fz_load_system_font(ctx, fontname, bold, italic, 0);
	if (!fontdesc->font)
	{
		const unsigned char *data;
		int len;

		data = pdf_lookup_substitute_font(ctx, mono, serif, bold, italic, &len);
		if (!data)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find substitute font");

		fontdesc->font = fz_new_font_from_memory(ctx, fontname, data, len, 0, 1);
		fontdesc->font->flags.fake_bold = bold && !fontdesc->font->flags.is_bold;
		fontdesc->font->flags.fake_italic = italic && !fontdesc->font->flags.is_italic;

		fontdesc->font->flags.is_mono = mono;
		fontdesc->font->flags.is_serif = serif;
		fontdesc->font->flags.is_bold = bold;
		fontdesc->font->flags.is_italic = italic;
	}

	fontdesc->font->flags.ft_substitute = 1;
	fontdesc->font->flags.ft_stretch = 1;
}

static void
pdf_load_substitute_cjk_font(fz_context *ctx, pdf_font_desc *fontdesc, const char *fontname, int ros, int serif)
{
	fontdesc->font = fz_load_system_cjk_font(ctx, fontname, ros, serif);
	if (!fontdesc->font)
	{
		const unsigned char *data;
		int size;
		int subfont;

		data = fz_lookup_cjk_font(ctx, ros, &size, &subfont);
		if (!data)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find builtin CJK font");

		/* A glyph bbox cache is too big for CJK fonts. */
		fontdesc->font = fz_new_font_from_memory(ctx, fontname, data, size, subfont, 0);
	}

	fontdesc->font->flags.ft_substitute = 1;
	fontdesc->font->flags.ft_stretch = 0;
}

static void
pdf_load_system_font(fz_context *ctx, pdf_font_desc *fontdesc, const char *fontname, const char *collection)
{
	int bold = 0;
	int italic = 0;
	int serif = 0;
	int mono = 0;

	if (strstr(fontname, "Bold"))
		bold = 1;
	if (strstr(fontname, "Italic"))
		italic = 1;
	if (strstr(fontname, "Oblique"))
		italic = 1;

	if (fontdesc->flags & PDF_FD_FIXED_PITCH)
		mono = 1;
	if (fontdesc->flags & PDF_FD_SERIF)
		serif = 1;
	if (fontdesc->flags & PDF_FD_ITALIC)
		italic = 1;
	if (fontdesc->flags & PDF_FD_FORCE_BOLD)
		bold = 1;

	if (collection)
	{
		if (!strcmp(collection, "Adobe-CNS1"))
			pdf_load_substitute_cjk_font(ctx, fontdesc, fontname, FZ_ADOBE_CNS, serif);
		else if (!strcmp(collection, "Adobe-GB1"))
			pdf_load_substitute_cjk_font(ctx, fontdesc, fontname, FZ_ADOBE_GB, serif);
		else if (!strcmp(collection, "Adobe-Japan1"))
			pdf_load_substitute_cjk_font(ctx, fontdesc, fontname, FZ_ADOBE_JAPAN, serif);
		else if (!strcmp(collection, "Adobe-Korea1"))
			pdf_load_substitute_cjk_font(ctx, fontdesc, fontname, FZ_ADOBE_KOREA, serif);
		else
		{
			if (strcmp(collection, "Adobe-Identity") != 0)
				fz_warn(ctx, "unknown cid collection: %s", collection);
			pdf_load_substitute_font(ctx, fontdesc, fontname, mono, serif, bold, italic);
		}
	}
	else
	{
		pdf_load_substitute_font(ctx, fontdesc, fontname, mono, serif, bold, italic);
	}
}

static void
pdf_load_embedded_font(fz_context *ctx, pdf_document *doc, pdf_font_desc *fontdesc, const char *fontname, pdf_obj *stmref)
{
	fz_buffer *buf;

	buf = pdf_load_stream(ctx, stmref);
	fz_try(ctx)
		fontdesc->font = fz_new_font_from_buffer(ctx, fontname, buf, 0, 1);
	fz_always(ctx)
		fz_drop_buffer(ctx, buf);
	fz_catch(ctx)
		fz_rethrow(ctx);

	fontdesc->size += fz_buffer_storage(ctx, buf, NULL);
	fontdesc->is_embedded = 1;
}

/*
 * Create and destroy
 */

pdf_font_desc *
pdf_keep_font(fz_context *ctx, pdf_font_desc *fontdesc)
{
	return fz_keep_storable(ctx, &fontdesc->storable);
}

void
pdf_drop_font(fz_context *ctx, pdf_font_desc *fontdesc)
{
	fz_drop_storable(ctx, &fontdesc->storable);
}

static void
pdf_drop_font_imp(fz_context *ctx, fz_storable *fontdesc_)
{
	pdf_font_desc *fontdesc = (pdf_font_desc *)fontdesc_;

	fz_drop_font(ctx, fontdesc->font);
	pdf_drop_cmap(ctx, fontdesc->encoding);
	pdf_drop_cmap(ctx, fontdesc->to_ttf_cmap);
	pdf_drop_cmap(ctx, fontdesc->to_unicode);
	fz_free(ctx, fontdesc->cid_to_gid);
	fz_free(ctx, fontdesc->cid_to_ucs);
	fz_free(ctx, fontdesc->hmtx);
	fz_free(ctx, fontdesc->vmtx);
	fz_free(ctx, fontdesc);
}

pdf_font_desc *
pdf_new_font_desc(fz_context *ctx)
{
	pdf_font_desc *fontdesc;

	fontdesc = fz_malloc_struct(ctx, pdf_font_desc);
	FZ_INIT_STORABLE(fontdesc, 1, pdf_drop_font_imp);
	fontdesc->size = sizeof(pdf_font_desc);

	fontdesc->font = NULL;

	fontdesc->flags = 0;
	fontdesc->italic_angle = 0;
	fontdesc->ascent = 800;
	fontdesc->descent = -200;
	fontdesc->cap_height = 800;
	fontdesc->x_height = 500;
	fontdesc->missing_width = 0;

	fontdesc->encoding = NULL;
	fontdesc->to_ttf_cmap = NULL;
	fontdesc->cid_to_gid_len = 0;
	fontdesc->cid_to_gid = NULL;

	fontdesc->to_unicode = NULL;
	fontdesc->cid_to_ucs_len = 0;
	fontdesc->cid_to_ucs = NULL;

	fontdesc->wmode = 0;

	fontdesc->hmtx_cap = 0;
	fontdesc->vmtx_cap = 0;
	fontdesc->hmtx_len = 0;
	fontdesc->vmtx_len = 0;
	fontdesc->hmtx = NULL;
	fontdesc->vmtx = NULL;

	fontdesc->dhmtx.lo = 0x0000;
	fontdesc->dhmtx.hi = 0xFFFF;
	fontdesc->dhmtx.w = 1000;

	fontdesc->dvmtx.lo = 0x0000;
	fontdesc->dvmtx.hi = 0xFFFF;
	fontdesc->dvmtx.x = 0;
	fontdesc->dvmtx.y = 880;
	fontdesc->dvmtx.w = -1000;

	fontdesc->is_embedded = 0;

	return fontdesc;
}

/*
 * Simple fonts (Type1 and TrueType)
 */

static FT_CharMap
select_type1_cmap(FT_Face face)
{
	int i;
	for (i = 0; i < face->num_charmaps; i++)
		if (face->charmaps[i]->platform_id == 7)
			return face->charmaps[i];
	if (face->num_charmaps > 0)
		return face->charmaps[0];
	return NULL;
}

static FT_CharMap
select_truetype_cmap(FT_Face face, int symbolic)
{
	int i;

	/* First look for a Microsoft symbolic cmap, if applicable */
	if (symbolic)
	{
		for (i = 0; i < face->num_charmaps; i++)
			if (face->charmaps[i]->platform_id == 3 && face->charmaps[i]->encoding_id == 0)
				return face->charmaps[i];
	}

	/* Then look for a Microsoft Unicode cmap */
	for (i = 0; i < face->num_charmaps; i++)
		if (face->charmaps[i]->platform_id == 3 && face->charmaps[i]->encoding_id == 1)
			if (FT_Get_CMap_Format(face->charmaps[i]) != -1)
				return face->charmaps[i];

	/* Finally look for an Apple MacRoman cmap */
	for (i = 0; i < face->num_charmaps; i++)
		if (face->charmaps[i]->platform_id == 1 && face->charmaps[i]->encoding_id == 0)
			if (FT_Get_CMap_Format(face->charmaps[i]) != -1)
				return face->charmaps[i];

	if (face->num_charmaps > 0)
		if (FT_Get_CMap_Format(face->charmaps[0]) != -1)
			return face->charmaps[0];
	return NULL;
}

static FT_CharMap
select_unknown_cmap(FT_Face face)
{
	if (face->num_charmaps > 0)
		return face->charmaps[0];
	return NULL;
}

static pdf_font_desc *
pdf_load_simple_font_by_name(fz_context *ctx, pdf_document *doc, pdf_obj *dict, const char *basefont)
{
	pdf_obj *descriptor;
	pdf_obj *encoding;
	pdf_obj *widths;
	unsigned short *etable = NULL;
	pdf_font_desc *fontdesc = NULL;
	pdf_obj *subtype;
	FT_Face face;
	FT_CharMap cmap;
	int symbolic;
	int kind;
	int glyph;

	const char *estrings[256];
	char ebuffer[256][32];
	int i, k, n;
	int fterr;
	int has_lock = 0;

	fz_var(fontdesc);
	fz_var(etable);
	fz_var(has_lock);

	/* Load font file */
	fz_try(ctx)
	{
		fontdesc = pdf_new_font_desc(ctx);

		descriptor = pdf_dict_get(ctx, dict, PDF_NAME(FontDescriptor));
		if (descriptor)
			pdf_load_font_descriptor(ctx, doc, fontdesc, descriptor, NULL, basefont, 0);
		else
			pdf_load_builtin_font(ctx, fontdesc, basefont, 0);

		/* Some chinese documents mistakenly consider WinAnsiEncoding to be codepage 936 */
		if (descriptor && pdf_is_string(ctx, pdf_dict_get(ctx, descriptor, PDF_NAME(FontName))) &&
			!pdf_dict_get(ctx, dict, PDF_NAME(ToUnicode)) &&
			pdf_name_eq(ctx, pdf_dict_get(ctx, dict, PDF_NAME(Encoding)), PDF_NAME(WinAnsiEncoding)) &&
			pdf_dict_get_int(ctx, descriptor, PDF_NAME(Flags)) == 4)
		{
			char *cp936fonts[] = {
				"\xCB\xCE\xCC\xE5", "SimSun,Regular",
				"\xBA\xDA\xCC\xE5", "SimHei,Regular",
				"\xBF\xAC\xCC\xE5_GB2312", "SimKai,Regular",
				"\xB7\xC2\xCB\xCE_GB2312", "SimFang,Regular",
				"\xC1\xA5\xCA\xE9", "SimLi,Regular",
				NULL
			};
			for (i = 0; cp936fonts[i]; i += 2)
				if (!strcmp(basefont, cp936fonts[i]))
					break;
			if (cp936fonts[i])
			{
				fz_warn(ctx, "workaround for S22PDF lying about chinese font encodings");
				pdf_drop_font(ctx, fontdesc);
				fontdesc = NULL;
				fontdesc = pdf_new_font_desc(ctx);
				pdf_load_font_descriptor(ctx, doc, fontdesc, descriptor, "Adobe-GB1", cp936fonts[i+1], 0);
				fontdesc->encoding = pdf_load_system_cmap(ctx, "GBK-EUC-H");
				fontdesc->to_unicode = pdf_load_system_cmap(ctx, "Adobe-GB1-UCS2");
				fontdesc->to_ttf_cmap = pdf_load_system_cmap(ctx, "Adobe-GB1-UCS2");

				goto skip_encoding;
			}
		}

		face = fontdesc->font->ft_face;
		kind = ft_kind(face);

		/* Encoding */

		symbolic = fontdesc->flags & 4;

		if (kind == TYPE1)
			cmap = select_type1_cmap(face);
		else if (kind == TRUETYPE)
			cmap = select_truetype_cmap(face, symbolic);
		else
			cmap = select_unknown_cmap(face);

		if (cmap)
		{
			fterr = FT_Set_Charmap(face, cmap);
			if (fterr)
				fz_warn(ctx, "freetype could not set cmap: %s", ft_error_string(fterr));
		}
		else
			fz_warn(ctx, "freetype could not find any cmaps");

		etable = fz_malloc_array(ctx, 256, sizeof(unsigned short));
		fontdesc->size += 256 * sizeof(unsigned short);
		for (i = 0; i < 256; i++)
		{
			estrings[i] = NULL;
			etable[i] = 0;
		}

		encoding = pdf_dict_get(ctx, dict, PDF_NAME(Encoding));
		if (encoding)
		{
			if (pdf_is_name(ctx, encoding))
				pdf_load_encoding(estrings, pdf_to_name(ctx, encoding));

			if (pdf_is_dict(ctx, encoding))
			{
				pdf_obj *base, *diff, *item;

				base = pdf_dict_get(ctx, encoding, PDF_NAME(BaseEncoding));
				if (pdf_is_name(ctx, base))
					pdf_load_encoding(estrings, pdf_to_name(ctx, base));
				else if (!fontdesc->is_embedded && !symbolic)
					pdf_load_encoding(estrings, "StandardEncoding");

				diff = pdf_dict_get(ctx, encoding, PDF_NAME(Differences));
				if (pdf_is_array(ctx, diff))
				{
					n = pdf_array_len(ctx, diff);
					k = 0;
					for (i = 0; i < n; i++)
					{
						item = pdf_array_get(ctx, diff, i);
						if (pdf_is_int(ctx, item))
							k = pdf_to_int(ctx, item);
						if (pdf_is_name(ctx, item) && k >= 0 && k < nelem(estrings))
							estrings[k++] = pdf_to_name(ctx, item);
					}
				}
			}
		}
		else if (!fontdesc->is_embedded && !symbolic)
			pdf_load_encoding(estrings, "StandardEncoding");

		/* start with the builtin encoding */
		for (i = 0; i < 256; i++)
			etable[i] = ft_char_index(face, i);

		fz_lock(ctx, FZ_LOCK_FREETYPE);
		has_lock = 1;

		/* built-in and substitute fonts may be a different type than what the document expects */
		subtype = pdf_dict_get(ctx, dict, PDF_NAME(Subtype));
		if (pdf_name_eq(ctx, subtype, PDF_NAME(Type1)))
			kind = TYPE1;
		else if (pdf_name_eq(ctx, subtype, PDF_NAME(MMType1)))
			kind = TYPE1;
		else if (pdf_name_eq(ctx, subtype, PDF_NAME(TrueType)))
			kind = TRUETYPE;
		else if (pdf_name_eq(ctx, subtype, PDF_NAME(CIDFontType0)))
			kind = TYPE1;
		else if (pdf_name_eq(ctx, subtype, PDF_NAME(CIDFontType2)))
			kind = TRUETYPE;

		/* encode by glyph name where we can */
		if (kind == TYPE1)
		{
			for (i = 0; i < 256; i++)
			{
				if (estrings[i])
				{
					glyph = ft_name_index(face, estrings[i]);
					if (glyph > 0)
						etable[i] = glyph;
				}
			}
		}

		/* encode by glyph name where we can */
		if (kind == TRUETYPE)
		{
			/* Unicode cmap */
			if (!symbolic && face->charmap && face->charmap->platform_id == 3)
			{
				for (i = 0; i < 256; i++)
				{
					if (estrings[i])
					{
						int unicode = pdf_lookup_agl(estrings[i]);
						if (unicode > 0)
							glyph = ft_char_index(face, unicode);
						else
							glyph = ft_name_index(face, estrings[i]);
						if (glyph > 0)
							etable[i] = glyph;
					}
				}
			}

			/* MacRoman cmap */
			else if (!symbolic && face->charmap && face->charmap->platform_id == 1)
			{
				for (i = 0; i < 256; i++)
				{
					if (estrings[i])
					{
						int mrcode = lookup_mre_code(estrings[i]);
						if (mrcode > 0)
							glyph = ft_char_index(face, mrcode);
						else
							glyph = ft_name_index(face, estrings[i]);
						if (glyph > 0)
							etable[i] = glyph;
					}
				}
			}

			/* Symbolic cmap */
			else if (!face->charmap || face->charmap->encoding != FT_ENCODING_MS_SYMBOL)
			{
				for (i = 0; i < 256; i++)
				{
					if (estrings[i])
					{
						glyph = ft_name_index(face, estrings[i]);
						if (glyph > 0)
							etable[i] = glyph;
					}
				}
			}
		}

		/* try to reverse the glyph names from the builtin encoding */
		for (i = 0; i < 256; i++)
		{
			if (etable[i] && !estrings[i])
			{
				if (FT_HAS_GLYPH_NAMES(face))
				{
					fterr = FT_Get_Glyph_Name(face, etable[i], ebuffer[i], 32);
					if (fterr)
						fz_warn(ctx, "freetype get glyph name (gid %d): %s", etable[i], ft_error_string(fterr));
					if (ebuffer[i][0])
						estrings[i] = ebuffer[i];
				}
				else
				{
					estrings[i] = (char*) pdf_win_ansi[i]; /* discard const */
				}
			}
		}

		/* symbolic Type 1 fonts with an implicit encoding and non-standard glyph names */
		if (kind == TYPE1 && symbolic)
		{
			for (i = 0; i < 256; i++)
				if (etable[i] && estrings[i] && !pdf_lookup_agl(estrings[i]))
					estrings[i] = (char*) pdf_standard[i];
		}

		fz_unlock(ctx, FZ_LOCK_FREETYPE);
		has_lock = 0;

		fontdesc->encoding = pdf_new_identity_cmap(ctx, 0, 1);
		fontdesc->size += pdf_cmap_size(ctx, fontdesc->encoding);
		fontdesc->cid_to_gid_len = 256;
		fontdesc->cid_to_gid = etable;

		fz_try(ctx)
		{
			pdf_load_to_unicode(ctx, doc, fontdesc, estrings, NULL, pdf_dict_get(ctx, dict, PDF_NAME(ToUnicode)));
		}
		fz_catch(ctx)
		{
			fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
			fz_warn(ctx, "cannot load ToUnicode CMap");
		}

	skip_encoding:

		/* Widths */

		pdf_set_default_hmtx(ctx, fontdesc, fontdesc->missing_width);

		widths = pdf_dict_get(ctx, dict, PDF_NAME(Widths));
		if (widths)
		{
			int first, last;

			first = pdf_dict_get_int(ctx, dict, PDF_NAME(FirstChar));
			last = pdf_dict_get_int(ctx, dict, PDF_NAME(LastChar));

			if (first < 0 || last > 255 || first > last)
				first = last = 0;

			for (i = 0; i < last - first + 1; i++)
			{
				int wid = pdf_array_get_int(ctx, widths, i);
				pdf_add_hmtx(ctx, fontdesc, i + first, i + first, wid);
			}
		}
		else
		{
			for (i = 0; i < 256; i++)
				pdf_add_hmtx(ctx, fontdesc, i, i, ft_width(ctx, fontdesc, i));
		}

		pdf_end_hmtx(ctx, fontdesc);
	}
	fz_catch(ctx)
	{
		if (has_lock)
			fz_unlock(ctx, FZ_LOCK_FREETYPE);
		if (fontdesc && etable != fontdesc->cid_to_gid)
			fz_free(ctx, etable);
		pdf_drop_font(ctx, fontdesc);
		fz_rethrow(ctx);
	}
	return fontdesc;
}

static pdf_font_desc *
pdf_load_simple_font(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	const char *basefont = pdf_to_name(ctx, pdf_dict_get(ctx, dict, PDF_NAME(BaseFont)));
	return pdf_load_simple_font_by_name(ctx, doc, dict, basefont);
}

static int
hail_mary_make_hash_key(fz_context *ctx, fz_store_hash *hash, void *key_)
{
	hash->u.pi.i = 0;
	hash->u.pi.ptr = NULL;
	return 1;
}

static void *
hail_mary_keep_key(fz_context *ctx, void *key)
{
	return key;
}

static void
hail_mary_drop_key(fz_context *ctx, void *key)
{
}

static int
hail_mary_cmp_key(fz_context *ctx, void *k0, void *k1)
{
	return k0 == k1;
}

static void
hail_mary_format_key(fz_context *ctx, char *s, int n, void *key_)
{
	fz_strlcpy(s, "(hail mary font)", n);
}

static int hail_mary_store_key; /* Dummy */

static const fz_store_type hail_mary_store_type =
{
	hail_mary_make_hash_key,
	hail_mary_keep_key,
	hail_mary_drop_key,
	hail_mary_cmp_key,
	hail_mary_format_key,
	NULL
};

pdf_font_desc *
pdf_load_hail_mary_font(fz_context *ctx, pdf_document *doc)
{
	pdf_font_desc *fontdesc;
	pdf_font_desc *existing;

	if ((fontdesc = fz_find_item(ctx, pdf_drop_font_imp, &hail_mary_store_key, &hail_mary_store_type)) != NULL)
	{
		return fontdesc;
	}

	/* FIXME: Get someone with a clue about fonts to fix this */
	fontdesc = pdf_load_simple_font_by_name(ctx, doc, NULL, "Helvetica");

	existing = fz_store_item(ctx, &hail_mary_store_key, fontdesc, fontdesc->size, &hail_mary_store_type);
	assert(existing == NULL);
	(void)existing; /* Silence warning in release builds */

	return fontdesc;
}

/*
 * CID Fonts
 */

static pdf_font_desc *
load_cid_font(fz_context *ctx, pdf_document *doc, pdf_obj *dict, pdf_obj *encoding, pdf_obj *to_unicode)
{
	pdf_obj *widths;
	pdf_obj *descriptor;
	pdf_font_desc *fontdesc = NULL;
	pdf_cmap *cmap;
	FT_Face face;
	char collection[256];
	const char *basefont;
	int i, k, fterr;
	pdf_obj *cidtogidmap;
	pdf_obj *obj;
	int dw;

	fz_var(fontdesc);

	fz_try(ctx)
	{
		/* Get font name and CID collection */

		basefont = pdf_to_name(ctx, pdf_dict_get(ctx, dict, PDF_NAME(BaseFont)));

		{
			pdf_obj *cidinfo;
			const char *reg, *ord;

			cidinfo = pdf_dict_get(ctx, dict, PDF_NAME(CIDSystemInfo));
			if (!cidinfo)
				fz_throw(ctx, FZ_ERROR_SYNTAX, "cid font is missing info");

			reg = pdf_dict_get_string(ctx, cidinfo, PDF_NAME(Registry), NULL);
			ord = pdf_dict_get_string(ctx, cidinfo, PDF_NAME(Ordering), NULL);
			fz_snprintf(collection, sizeof collection, "%s-%s", reg, ord);
		}

		/* Encoding */

		if (pdf_is_name(ctx, encoding))
		{
			cmap = pdf_load_system_cmap(ctx, pdf_to_name(ctx, encoding));
		}
		else if (pdf_is_indirect(ctx, encoding))
		{
			cmap = pdf_load_embedded_cmap(ctx, doc, encoding);
		}
		else
		{
			fz_throw(ctx, FZ_ERROR_SYNTAX, "font missing encoding");
		}

		/* Load font file */

		fontdesc = pdf_new_font_desc(ctx);

		fontdesc->encoding = cmap;
		fontdesc->size += pdf_cmap_size(ctx, fontdesc->encoding);

		pdf_set_font_wmode(ctx, fontdesc, pdf_cmap_wmode(ctx, fontdesc->encoding));

		descriptor = pdf_dict_get(ctx, dict, PDF_NAME(FontDescriptor));
		if (!descriptor)
			fz_throw(ctx, FZ_ERROR_SYNTAX, "missing font descriptor");
		pdf_load_font_descriptor(ctx, doc, fontdesc, descriptor, collection, basefont, 1);

		face = fontdesc->font->ft_face;

		/* Apply encoding */

		cidtogidmap = pdf_dict_get(ctx, dict, PDF_NAME(CIDToGIDMap));
		if (pdf_is_stream(ctx, cidtogidmap))
		{
			fz_buffer *buf;
			size_t z, len;
			unsigned char *data;

			buf = pdf_load_stream(ctx, cidtogidmap);

			len = fz_buffer_storage(ctx, buf, &data);
			fontdesc->cid_to_gid_len = len / 2;
			fontdesc->cid_to_gid = fz_malloc_array(ctx, fontdesc->cid_to_gid_len, sizeof(unsigned short));
			fontdesc->size += fontdesc->cid_to_gid_len * sizeof(unsigned short);
			for (z = 0; z < fontdesc->cid_to_gid_len; z++)
				fontdesc->cid_to_gid[z] = (data[z * 2] << 8) + data[z * 2 + 1];

			fz_drop_buffer(ctx, buf);
		}
		else if (cidtogidmap && !pdf_name_eq(ctx, PDF_NAME(Identity), cidtogidmap))
		{
			fz_warn(ctx, "ignoring unknown CIDToGIDMap entry");
		}

		/* if font is external, cidtogidmap should not be identity */
		/* so we map from cid to unicode and then map that through the (3 1) */
		/* unicode cmap to get a glyph id */
		else if (fontdesc->font->flags.ft_substitute)
		{
			fterr = FT_Select_Charmap(face, ft_encoding_unicode);
			if (fterr)
				fz_throw(ctx, FZ_ERROR_GENERIC, "no unicode cmap when emulating CID font: %s", ft_error_string(fterr));

			if (!strcmp(collection, "Adobe-CNS1"))
				fontdesc->to_ttf_cmap = pdf_load_system_cmap(ctx, "Adobe-CNS1-UCS2");
			else if (!strcmp(collection, "Adobe-GB1"))
				fontdesc->to_ttf_cmap = pdf_load_system_cmap(ctx, "Adobe-GB1-UCS2");
			else if (!strcmp(collection, "Adobe-Japan1"))
				fontdesc->to_ttf_cmap = pdf_load_system_cmap(ctx, "Adobe-Japan1-UCS2");
			else if (!strcmp(collection, "Adobe-Japan2"))
				fontdesc->to_ttf_cmap = pdf_load_system_cmap(ctx, "Adobe-Japan2-UCS2");
			else if (!strcmp(collection, "Adobe-Korea1"))
				fontdesc->to_ttf_cmap = pdf_load_system_cmap(ctx, "Adobe-Korea1-UCS2");
		}

		pdf_load_to_unicode(ctx, doc, fontdesc, NULL, collection, to_unicode);

		/* If we have an identity encoding, we're supposed to use the glyph ids directly.
		 * If we only have a substitute font, that won't work.
		 * Make a last ditch attempt by using
		 * the ToUnicode table if it exists to map via the substitute font's cmap. */
		if (strstr(fontdesc->encoding->cmap_name, "Identity-") && fontdesc->font->flags.ft_substitute)
		{
			fz_warn(ctx, "non-embedded font using identity encoding: %s", basefont);
			if (fontdesc->to_unicode && !fontdesc->to_ttf_cmap)
				fontdesc->to_ttf_cmap = pdf_keep_cmap(ctx, fontdesc->to_unicode);
		}

		/* Horizontal */

		dw = 1000;
		obj = pdf_dict_get(ctx, dict, PDF_NAME(DW));
		if (obj)
			dw = pdf_to_int(ctx, obj);
		pdf_set_default_hmtx(ctx, fontdesc, dw);

		widths = pdf_dict_get(ctx, dict, PDF_NAME(W));
		if (widths)
		{
			int c0, c1, w, n, m;

			n = pdf_array_len(ctx, widths);
			for (i = 0; i < n; )
			{
				c0 = pdf_array_get_int(ctx, widths, i);
				obj = pdf_array_get(ctx, widths, i + 1);
				if (pdf_is_array(ctx, obj))
				{
					m = pdf_array_len(ctx, obj);
					for (k = 0; k < m; k++)
					{
						w = pdf_array_get_int(ctx, obj, k);
						pdf_add_hmtx(ctx, fontdesc, c0 + k, c0 + k, w);
					}
					i += 2;
				}
				else
				{
					c1 = pdf_to_int(ctx, obj);
					w = pdf_array_get_int(ctx, widths, i + 2);
					pdf_add_hmtx(ctx, fontdesc, c0, c1, w);
					i += 3;
				}
			}
		}

		pdf_end_hmtx(ctx, fontdesc);

		/* Vertical */

		if (pdf_cmap_wmode(ctx, fontdesc->encoding) == 1)
		{
			int dw2y = 880;
			int dw2w = -1000;

			obj = pdf_dict_get(ctx, dict, PDF_NAME(DW2));
			if (obj)
			{
				dw2y = pdf_array_get_int(ctx, obj, 0);
				dw2w = pdf_array_get_int(ctx, obj, 1);
			}

			pdf_set_default_vmtx(ctx, fontdesc, dw2y, dw2w);

			widths = pdf_dict_get(ctx, dict, PDF_NAME(W2));
			if (widths)
			{
				int c0, c1, w, x, y, n;

				n = pdf_array_len(ctx, widths);
				for (i = 0; i < n; )
				{
					c0 = pdf_array_get_int(ctx, widths, i);
					obj = pdf_array_get(ctx, widths, i + 1);
					if (pdf_is_array(ctx, obj))
					{
						int m = pdf_array_len(ctx, obj);
						for (k = 0; k * 3 < m; k ++)
						{
							w = pdf_array_get_int(ctx, obj, k * 3 + 0);
							x = pdf_array_get_int(ctx, obj, k * 3 + 1);
							y = pdf_array_get_int(ctx, obj, k * 3 + 2);
							pdf_add_vmtx(ctx, fontdesc, c0 + k, c0 + k, x, y, w);
						}
						i += 2;
					}
					else
					{
						c1 = pdf_to_int(ctx, obj);
						w = pdf_array_get_int(ctx, widths, i + 2);
						x = pdf_array_get_int(ctx, widths, i + 3);
						y = pdf_array_get_int(ctx, widths, i + 4);
						pdf_add_vmtx(ctx, fontdesc, c0, c1, x, y, w);
						i += 5;
					}
				}
			}

			pdf_end_vmtx(ctx, fontdesc);
		}
	}
	fz_catch(ctx)
	{
		pdf_drop_font(ctx, fontdesc);
		fz_rethrow(ctx);
	}

	return fontdesc;
}

static pdf_font_desc *
pdf_load_type0_font(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	pdf_obj *dfonts;
	pdf_obj *dfont;
	pdf_obj *subtype;
	pdf_obj *encoding;
	pdf_obj *to_unicode;

	dfonts = pdf_dict_get(ctx, dict, PDF_NAME(DescendantFonts));
	if (!dfonts)
		fz_throw(ctx, FZ_ERROR_SYNTAX, "cid font is missing descendant fonts");

	dfont = pdf_array_get(ctx, dfonts, 0);

	subtype = pdf_dict_get(ctx, dfont, PDF_NAME(Subtype));
	encoding = pdf_dict_get(ctx, dict, PDF_NAME(Encoding));
	to_unicode = pdf_dict_get(ctx, dict, PDF_NAME(ToUnicode));

	if (pdf_is_name(ctx, subtype) && pdf_name_eq(ctx, subtype, PDF_NAME(CIDFontType0)))
		return load_cid_font(ctx, doc, dfont, encoding, to_unicode);
	if (pdf_is_name(ctx, subtype) && pdf_name_eq(ctx, subtype, PDF_NAME(CIDFontType2)))
		return load_cid_font(ctx, doc, dfont, encoding, to_unicode);
	fz_throw(ctx, FZ_ERROR_SYNTAX, "unknown cid font type");
}

/*
 * FontDescriptor
 */

static void
pdf_load_font_descriptor(fz_context *ctx, pdf_document *doc, pdf_font_desc *fontdesc, pdf_obj *dict,
	const char *collection, const char *basefont, int iscidfont)
{
	pdf_obj *obj1, *obj2, *obj3, *obj;
	const char *fontname;
	FT_Face face;

	/* Prefer BaseFont; don't bother with FontName */
	fontname = basefont;

	fontdesc->flags = pdf_dict_get_int(ctx, dict, PDF_NAME(Flags));
	fontdesc->italic_angle = pdf_dict_get_real(ctx, dict, PDF_NAME(ItalicAngle));
	fontdesc->ascent = pdf_dict_get_real(ctx, dict, PDF_NAME(Ascent));
	fontdesc->descent = pdf_dict_get_real(ctx, dict, PDF_NAME(Descent));
	fontdesc->cap_height = pdf_dict_get_real(ctx, dict, PDF_NAME(CapHeight));
	fontdesc->x_height = pdf_dict_get_real(ctx, dict, PDF_NAME(XHeight));
	fontdesc->missing_width = pdf_dict_get_real(ctx, dict, PDF_NAME(MissingWidth));

	obj1 = pdf_dict_get(ctx, dict, PDF_NAME(FontFile));
	obj2 = pdf_dict_get(ctx, dict, PDF_NAME(FontFile2));
	obj3 = pdf_dict_get(ctx, dict, PDF_NAME(FontFile3));
	obj = obj1 ? obj1 : obj2 ? obj2 : obj3;

	if (pdf_is_indirect(ctx, obj))
	{
		fz_try(ctx)
		{
			pdf_load_embedded_font(ctx, doc, fontdesc, fontname, obj);
		}
		fz_catch(ctx)
		{
			fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
			fz_warn(ctx, "ignored error when loading embedded font; attempting to load system font");
			if (!iscidfont && fontname != clean_font_name(fontname))
				pdf_load_builtin_font(ctx, fontdesc, fontname, 1);
			else
				pdf_load_system_font(ctx, fontdesc, fontname, collection);
		}
	}
	else
	{
		if (!iscidfont && fontname != clean_font_name(fontname))
			pdf_load_builtin_font(ctx, fontdesc, fontname, 1);
		else
			pdf_load_system_font(ctx, fontdesc, fontname, collection);
	}

	/* Check for DynaLab fonts that must use hinting */
	face = fontdesc->font->ft_face;
	if (ft_kind(face) == TRUETYPE)
	{
		/* FreeType's own 'tricky' font detection needs a bit of help */
		if (is_dynalab(fontdesc->font->name))
			face->face_flags |= FT_FACE_FLAG_TRICKY;

		if (fontdesc->ascent == 0.0f)
			fontdesc->ascent = 1000.0f * face->ascender / face->units_per_EM;

		if (fontdesc->descent == 0.0f)
			fontdesc->descent = 1000.0f * face->descender / face->units_per_EM;
	}
}

static void
pdf_make_width_table(fz_context *ctx, pdf_font_desc *fontdesc)
{
	fz_font *font = fontdesc->font;
	int i, k, n, cid, gid;

	n = 0;
	for (i = 0; i < fontdesc->hmtx_len; i++)
	{
		for (k = fontdesc->hmtx[i].lo; k <= fontdesc->hmtx[i].hi; k++)
		{
			cid = pdf_lookup_cmap(fontdesc->encoding, k);
			gid = pdf_font_cid_to_gid(ctx, fontdesc, cid);
			if (gid > n)
				n = gid;
		}
	}

	font->width_count = n + 1;
	font->width_table = fz_malloc_array(ctx, font->width_count, sizeof(int));
	memset(font->width_table, 0, font->width_count * sizeof(int));
	fontdesc->size += font->width_count * sizeof(int);

	font->width_default = fontdesc->dhmtx.w;
	for (i = 0; i < font->width_count; i++)
		font->width_table[i] = -1;

	for (i = 0; i < fontdesc->hmtx_len; i++)
	{
		for (k = fontdesc->hmtx[i].lo; k <= fontdesc->hmtx[i].hi; k++)
		{
			cid = pdf_lookup_cmap(fontdesc->encoding, k);
			gid = pdf_font_cid_to_gid(ctx, fontdesc, cid);
			if (gid >= 0 && gid < font->width_count)
				font->width_table[gid] = fz_maxi(fontdesc->hmtx[i].w, font->width_table[gid]);
		}
	}

	for (i = 0; i < font->width_count; i++)
		if (font->width_table[i] == -1)
			font->width_table[i] = font->width_default;
}

pdf_font_desc *
pdf_load_font(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, pdf_obj *dict)
{
	pdf_obj *subtype;
	pdf_obj *dfonts;
	pdf_obj *charprocs;
	pdf_font_desc *fontdesc = NULL;
	int type3 = 0;

	if (pdf_obj_marked(ctx, dict))
		fz_throw(ctx, FZ_ERROR_SYNTAX, "Recursive Type3 font definition.");

	if ((fontdesc = pdf_find_item(ctx, pdf_drop_font_imp, dict)) != NULL)
	{
		return fontdesc;
	}

	subtype = pdf_dict_get(ctx, dict, PDF_NAME(Subtype));
	dfonts = pdf_dict_get(ctx, dict, PDF_NAME(DescendantFonts));
	charprocs = pdf_dict_get(ctx, dict, PDF_NAME(CharProcs));

	if (pdf_name_eq(ctx, subtype, PDF_NAME(Type0)))
		fontdesc = pdf_load_type0_font(ctx, doc, dict);
	else if (pdf_name_eq(ctx, subtype, PDF_NAME(Type1)))
		fontdesc = pdf_load_simple_font(ctx, doc, dict);
	else if (pdf_name_eq(ctx, subtype, PDF_NAME(MMType1)))
		fontdesc = pdf_load_simple_font(ctx, doc, dict);
	else if (pdf_name_eq(ctx, subtype, PDF_NAME(TrueType)))
		fontdesc = pdf_load_simple_font(ctx, doc, dict);
	else if (pdf_name_eq(ctx, subtype, PDF_NAME(Type3)))
	{
		fontdesc = pdf_load_type3_font(ctx, doc, rdb, dict);
		type3 = 1;
	}
	else if (charprocs)
	{
		fz_warn(ctx, "unknown font format, guessing type3.");
		fontdesc = pdf_load_type3_font(ctx, doc, rdb, dict);
		type3 = 1;
	}
	else if (dfonts)
	{
		fz_warn(ctx, "unknown font format, guessing type0.");
		fontdesc = pdf_load_type0_font(ctx, doc, dict);
	}
	else
	{
		fz_warn(ctx, "unknown font format, guessing type1 or truetype.");
		fontdesc = pdf_load_simple_font(ctx, doc, dict);
	}

	pdf_mark_obj(ctx, dict);
	fz_try(ctx)
	{
		/* Create glyph width table for stretching substitute fonts and text extraction. */
		pdf_make_width_table(ctx, fontdesc);

		/* Load CharProcs */
		if (type3)
			pdf_load_type3_glyphs(ctx, doc, fontdesc);

		pdf_store_item(ctx, dict, fontdesc, fontdesc->size);
	}
	fz_always(ctx)
		pdf_unmark_obj(ctx, dict);
	fz_catch(ctx)
	{
		pdf_drop_font(ctx, fontdesc);
		fz_rethrow(ctx);
	}

	return fontdesc;
}

void
pdf_print_font(fz_context *ctx, fz_output *out, pdf_font_desc *fontdesc)
{
	int i;

	fz_write_printf(ctx, out, "fontdesc {\n");

	if (fontdesc->font->ft_face)
		fz_write_printf(ctx, out, "\tfreetype font\n");
	if (fontdesc->font->t3procs)
		fz_write_printf(ctx, out, "\ttype3 font\n");

	fz_write_printf(ctx, out, "\twmode %d\n", fontdesc->wmode);
	fz_write_printf(ctx, out, "\tDW %d\n", fontdesc->dhmtx.w);

	fz_write_printf(ctx, out, "\tW {\n");
	for (i = 0; i < fontdesc->hmtx_len; i++)
		fz_write_printf(ctx, out, "\t\t<%04x> <%04x> %d\n",
			fontdesc->hmtx[i].lo, fontdesc->hmtx[i].hi, fontdesc->hmtx[i].w);
	fz_write_printf(ctx, out, "\t}\n");

	if (fontdesc->wmode)
	{
		fz_write_printf(ctx, out, "\tDW2 [%d %d]\n", fontdesc->dvmtx.y, fontdesc->dvmtx.w);
		fz_write_printf(ctx, out, "\tW2 {\n");
		for (i = 0; i < fontdesc->vmtx_len; i++)
			fz_write_printf(ctx, out, "\t\t<%04x> <%04x> %d %d %d\n", fontdesc->vmtx[i].lo, fontdesc->vmtx[i].hi,
				fontdesc->vmtx[i].x, fontdesc->vmtx[i].y, fontdesc->vmtx[i].w);
		fz_write_printf(ctx, out, "\t}\n");
	}
}

/* Font creation */

static pdf_obj*
pdf_add_font_file(fz_context *ctx, pdf_document *doc, fz_font *font)
{
	fz_buffer *buf = font->buffer;
	pdf_obj *obj = NULL;
	pdf_obj *ref = NULL;

	fz_var(obj);
	fz_var(ref);

	/* Check for substitute fonts */
	if (font->flags.ft_substitute)
		return NULL;

	fz_try(ctx)
	{
		size_t len = fz_buffer_storage(ctx, buf, NULL);
		obj = pdf_new_dict(ctx, doc, 3);
		pdf_dict_put_int(ctx, obj, PDF_NAME(Length1), (int)len);
		switch (ft_font_file_kind(font->ft_face))
		{
		case 1:
			/* TODO: these may not be the correct values, but I doubt it matters */
			pdf_dict_put_int(ctx, obj, PDF_NAME(Length2), len);
			pdf_dict_put_int(ctx, obj, PDF_NAME(Length3), 0);
			break;
		case 2:
			break;
		case 3:
			if (FT_Get_Sfnt_Table(font->ft_face, FT_SFNT_HEAD))
				pdf_dict_put(ctx, obj, PDF_NAME(Subtype), PDF_NAME(OpenType));
			else
				pdf_dict_put(ctx, obj, PDF_NAME(Subtype), PDF_NAME(Type1C));
			break;
		}
		ref = pdf_add_object(ctx, doc, obj);
		pdf_update_stream(ctx, doc, ref, buf, 0);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, obj);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, ref);
		fz_rethrow(ctx);
	}
	return ref;
}

static void
pdf_add_font_descriptor(fz_context *ctx, pdf_document *doc, pdf_obj *fobj, fz_font *font)
{
	FT_Face face = font->ft_face;
	pdf_obj *fdobj = NULL;
	pdf_obj *fileref;
	fz_rect bbox;

	fdobj = pdf_new_dict(ctx, doc, 10);
	fz_try(ctx)
	{
		pdf_dict_put(ctx, fdobj, PDF_NAME(Type), PDF_NAME(FontDescriptor));
		pdf_dict_put_name(ctx, fdobj, PDF_NAME(FontName), font->name);

		bbox.x0 = font->bbox.x0 * 1000;
		bbox.y0 = font->bbox.y0 * 1000;
		bbox.x1 = font->bbox.x1 * 1000;
		bbox.y1 = font->bbox.y1 * 1000;
		pdf_dict_put_rect(ctx, fdobj, PDF_NAME(FontBBox), bbox);

		pdf_dict_put_int(ctx, fdobj, PDF_NAME(ItalicAngle), 0);
		pdf_dict_put_int(ctx, fdobj, PDF_NAME(Ascent), face->ascender * 1000.0f / face->units_per_EM);
		pdf_dict_put_int(ctx, fdobj, PDF_NAME(Descent), face->descender * 1000.0f / face->units_per_EM);
		pdf_dict_put_int(ctx, fdobj, PDF_NAME(StemV), 80);
		pdf_dict_put_int(ctx, fdobj, PDF_NAME(Flags), PDF_FD_NONSYMBOLIC);

		fileref = pdf_add_font_file(ctx, doc, font);
		if (fileref)
		{
			switch (ft_font_file_kind(face))
			{
			default:
			case 1: pdf_dict_put_drop(ctx, fdobj, PDF_NAME(FontFile), fileref); break;
			case 2: pdf_dict_put_drop(ctx, fdobj, PDF_NAME(FontFile2), fileref); break;
			case 3: pdf_dict_put_drop(ctx, fdobj, PDF_NAME(FontFile3), fileref); break;
			}
		}

		pdf_dict_put_drop(ctx, fobj, PDF_NAME(FontDescriptor), pdf_add_object(ctx, doc, fdobj));
	}
	fz_always(ctx)
		pdf_drop_obj(ctx, fdobj);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void
pdf_add_simple_font_widths(fz_context *ctx, pdf_document *doc, pdf_obj *fobj, fz_font *font, const char * const encoding[])
{
	int width_table[256];
	pdf_obj *widths;
	int i, first, last;

	first = 0;
	last = 0;

	for (i = 0; i < 256; ++i)
	{
		int glyph = 0;
		if (encoding[i])
		{
			glyph = ft_name_index(font->ft_face, encoding[i]);
			if (glyph == 0)
				glyph = ft_char_index(font->ft_face, pdf_lookup_agl(encoding[i]));
		}
		if (glyph > 0)
		{
			if (!first)
				first = i;
			last = i;
			width_table[i] = fz_advance_glyph(ctx, font, glyph, 0) * 1000;
		}
		else
			width_table[i] = 0;
	}

	widths = pdf_new_array(ctx, doc, last - first + 1);
	pdf_dict_put_drop(ctx, fobj, PDF_NAME(Widths), widths);
	for (i = first; i <= last; ++i)
		pdf_array_push_int(ctx, widths, width_table[i]);
	pdf_dict_put_int(ctx, fobj, PDF_NAME(FirstChar), first);
	pdf_dict_put_int(ctx, fobj, PDF_NAME(LastChar), last);
}

static void
pdf_add_cid_system_info(fz_context *ctx, pdf_document *doc, pdf_obj *fobj, const char *reg, const char *ord, int supp)
{
	pdf_obj *csi = pdf_dict_put_dict(ctx, fobj, PDF_NAME(CIDSystemInfo), 3);
	pdf_dict_put_string(ctx, csi, PDF_NAME(Registry), reg, strlen(reg));
	pdf_dict_put_string(ctx, csi, PDF_NAME(Ordering), ord, strlen(ord));
	pdf_dict_put_int(ctx, csi, PDF_NAME(Supplement), supp);
}

/* Different states of starting, same width as last, or consecutive glyph */
enum { FW_START, FW_SAME, FW_RUN };

/* ToDo: Ignore the default sized characters */
static void
pdf_add_cid_font_widths(fz_context *ctx, pdf_document *doc, pdf_obj *fobj, fz_font *font)
{
	FT_Face face = font->ft_face;
	pdf_obj *run_obj = NULL;
	pdf_obj *fw;
	int curr_code;
	int prev_code;
	int curr_size;
	int prev_size;
	int first_code;
	int new_first_code;
	int state = FW_START;
	int new_state = FW_START;
	int publish = 0;

	fz_var(run_obj);

	fw = pdf_add_new_array(ctx, doc, 10);
	fz_try(ctx)
	{
		prev_code = 0;
		prev_size = fz_advance_glyph(ctx, font, 0, 0) * 1000;
		first_code = prev_code;

		while (prev_code < face->num_glyphs)
		{
			curr_code = prev_code + 1;
			curr_size = fz_advance_glyph(ctx, font, curr_code, 0) * 1000;

			switch (state)
			{
			case FW_SAME:
				if (curr_size != prev_size)
				{
					/* End of same widths for consecutive ids. Current will
					 * be pushed as prev. below during next iteration */
					publish = 1;
					if (curr_code < face->num_glyphs)
						run_obj = pdf_new_array(ctx, doc, 10);
					new_state = FW_RUN;
					/* And the new first code is our current code */
					new_first_code = curr_code;
				}
				break;
			case FW_RUN:
				if (curr_size == prev_size)
				{
					/* Same width, so start a new same entry starting with
					 * the previous code. i.e. the prev size is not put
					 * in the run */
					publish = 1;
					new_state = FW_SAME;
					new_first_code = prev_code;
				}
				else
				{
					/* Add prev size to run_obj */
					pdf_array_push_int(ctx, run_obj, prev_size);
				}
				break;
			case FW_START:
				/* Starting fresh. Determine our state */
				if (curr_size == prev_size)
				{
					state = FW_SAME;
				}
				else
				{
					run_obj = pdf_new_array(ctx, doc, 10);
					pdf_array_push_int(ctx, run_obj, prev_size);
					state = FW_RUN;
				}
				new_first_code = prev_code;
				break;
			}

			if (publish || curr_code == face->num_glyphs)
			{
				switch (state)
				{
				case FW_SAME:
					/* Add three entries. First cid, last cid and width */
					pdf_array_push_int(ctx, fw, first_code);
					pdf_array_push_int(ctx, fw, prev_code);
					pdf_array_push_int(ctx, fw, prev_size);
					break;
				case FW_RUN:
					if (pdf_array_len(ctx, run_obj) > 0)
					{
						pdf_array_push_int(ctx, fw, first_code);
						pdf_array_push(ctx, fw, run_obj);
					}
					pdf_drop_obj(ctx, run_obj);
					run_obj = NULL;
					break;
				case FW_START:
					/* Lone wolf. Not part of a consecutive run */
					pdf_array_push_int(ctx, fw, prev_code);
					pdf_array_push_int(ctx, fw, prev_code);
					pdf_array_push_int(ctx, fw, prev_size);
					break;
				}

				if (curr_code < face->num_glyphs)
				{
					state = new_state;
					first_code = new_first_code;
					publish = 0;
				}
			}

			prev_size = curr_size;
			prev_code = curr_code;
		}

		if (font->width_table != NULL)
			pdf_dict_put_int(ctx, fobj, PDF_NAME(DW), font->width_default);
		if (pdf_array_len(ctx, fw) > 0)
			pdf_dict_put(ctx, fobj, PDF_NAME(W), fw);
	}
	fz_always(ctx)
		pdf_drop_obj(ctx, fw);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

/* Descendant font construction used for CID font creation from ttf or Adobe type1 */
static pdf_obj*
pdf_add_descendant_cid_font(fz_context *ctx, pdf_document *doc, fz_font *font)
{
	FT_Face face = font->ft_face;
	pdf_obj *fobj, *fref;
	const char *ps_name;

	fobj = pdf_new_dict(ctx, doc, 3);
	fz_try(ctx)
	{
		pdf_dict_put(ctx, fobj, PDF_NAME(Type), PDF_NAME(Font));
		switch (ft_kind(face))
		{
		case TYPE1: pdf_dict_put(ctx, fobj, PDF_NAME(Subtype), PDF_NAME(CIDFontType0)); break;
		case TRUETYPE: pdf_dict_put(ctx, fobj, PDF_NAME(Subtype), PDF_NAME(CIDFontType2)); break;
		}

		pdf_add_cid_system_info(ctx, doc, fobj, "Adobe", "Identity", 0);

		ps_name = FT_Get_Postscript_Name(face);
		if (ps_name)
			pdf_dict_put_name(ctx, fobj, PDF_NAME(BaseFont), ps_name);
		else
			pdf_dict_put_name(ctx, fobj, PDF_NAME(BaseFont), font->name);

		pdf_add_font_descriptor(ctx, doc, fobj, font);

		/* We may have a cid font already with width info in source font and no cmap in the ft face */
		pdf_add_cid_font_widths(ctx, doc, fobj, font);

		fref = pdf_add_object(ctx, doc, fobj);
	}
	fz_always(ctx)
		pdf_drop_obj(ctx, fobj);
	fz_catch(ctx)
		fz_rethrow(ctx);
	return fref;
}

static int next_range(int *table, int size, int k)
{
	int n;
	for (n = 1; k + n < size; ++n)
	{
		if ((k & 0xFF00) != ((k+n) & 0xFF00)) /* high byte changes */
			break;
		if (table[k] + n != table[k+n])
			break;
	}
	return n;
}

/* Create the ToUnicode CMap. */
static void
pdf_add_to_unicode(fz_context *ctx, pdf_document *doc, pdf_obj *fobj, fz_font *font)
{
	FT_Face face = font->ft_face;
	fz_buffer *buf;

	int *table;
	int num_seq = 0;
	int num_chr = 0;
	int n, k;

	/* Populate reverse cmap table */
	{
		FT_ULong ucs;
		FT_UInt gid;

		table = fz_calloc(ctx, face->num_glyphs, sizeof *table);
		fz_lock(ctx, FZ_LOCK_FREETYPE);
		ucs = FT_Get_First_Char(face, &gid);
		while (gid > 0)
		{
			if (gid < (FT_ULong)face->num_glyphs && face->num_glyphs > 0)
				table[gid] = ucs;
			ucs = FT_Get_Next_Char(face, ucs, &gid);
		}
		fz_unlock(ctx, FZ_LOCK_FREETYPE);
	}

	for (k = 0; k < face->num_glyphs; k += n)
	{
		n = next_range(table, face->num_glyphs, k);
		if (n > 1)
			++num_seq;
		else if (table[k] > 0)
			++num_chr;
	}

	/* No mappings available... */
	if (num_seq + num_chr == 0)
	{
		fz_warn(ctx, "cannot create ToUnicode mapping for %s", font->name);
		fz_free(ctx, table);
		return;
	}

	buf = fz_new_buffer(ctx, 0);
	fz_try(ctx)
	{
		/* Header boiler plate */
		fz_append_string(ctx, buf, "/CIDInit /ProcSet findresource begin\n");
		fz_append_string(ctx, buf, "12 dict begin\n");
		fz_append_string(ctx, buf, "begincmap\n");
		fz_append_string(ctx, buf, "/CIDSystemInfo <</Registry(Adobe)/Ordering(UCS)/Supplement 0>> def\n");
		fz_append_string(ctx, buf, "/CMapName /Adobe-Identity-UCS def\n");
		fz_append_string(ctx, buf, "/CMapType 2 def\n");
		fz_append_string(ctx, buf, "1 begincodespacerange\n");
		fz_append_string(ctx, buf, "<0000> <FFFF>\n");
		fz_append_string(ctx, buf, "endcodespacerange\n");

		/* Note to have a valid CMap, the number of entries in table set can
		 * not exceed 100, so we have to break into multiple tables. Also, note
		 * that to reduce the file size we should be looking for sequential
		 * ranges. Per Adobe technical note #5411, we can't have a range
		 * cross a boundary where the high order byte changes */

		/* First the ranges */
		if (num_seq > 0)
		{
			int count = 0;
			if (num_seq > 100)
			{
				fz_append_string(ctx, buf, "100 beginbfrange\n");
				num_seq -= 100;
			}
			else
				fz_append_printf(ctx, buf, "%d beginbfrange\n", num_seq);
			for (k = 0; k < face->num_glyphs; k += n)
			{
				n = next_range(table, face->num_glyphs, k);
				if (n > 1)
				{
					if (count == 100)
					{
						fz_append_string(ctx, buf, "endbfrange\n");
						if (num_seq > 100)
						{
							fz_append_string(ctx, buf, "100 beginbfrange\n");
							num_seq -= 100;
						}
						else
							fz_append_printf(ctx, buf, "%d beginbfrange\n", num_seq);
						count = 0;
					}
					fz_append_printf(ctx, buf, "<%04x> <%04x> <%04x>\n", k, k+n-1, table[k]);
					++count;
				}
			}
			fz_append_string(ctx, buf, "endbfrange\n");
		}

		/* Then the singles */
		if (num_chr > 0)
		{
			int count = 0;
			if (num_chr > 100)
			{
				fz_append_string(ctx, buf, "100 beginbfchar\n");
				num_chr -= 100;
			}
			else
				fz_append_printf(ctx, buf, "%d beginbfchar\n", num_chr);
			for (k = 0; k < face->num_glyphs; k += n)
			{
				n = next_range(table, face->num_glyphs, k);
				if (n == 1 && table[k] > 0)
				{
					if (count == 100)
					{
						fz_append_string(ctx, buf, "endbfchar\n");
						if (num_chr > 100)
						{
							fz_append_string(ctx, buf, "100 beginbfchar\n");
							num_chr -= 100;
						}
						else
							fz_append_printf(ctx, buf, "%d beginbfchar\n", num_chr);
						count = 0;
					}
					fz_append_printf(ctx, buf, "<%04x> <%04x>\n", k, table[k]);
					++count;
				}
			}
			fz_append_string(ctx, buf, "endbfchar\n");
		}

		/* Trailer boiler plate */
		fz_append_string(ctx, buf, "endcmap\n");
		fz_append_string(ctx, buf, "CMapName currentdict /CMap defineresource pop\n");
		fz_append_string(ctx, buf, "end\nend\n");

		pdf_dict_put_drop(ctx, fobj, PDF_NAME(ToUnicode), pdf_add_stream(ctx, doc, buf, NULL, 0));
	}
	fz_always(ctx)
	{
		fz_free(ctx, table);
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);
}

/* Creates CID font with Identity-H CMap and a ToUnicode CMap that is created by
 * using the TTF cmap table "backwards" to go from the GID to a Unicode value.
 * We can possibly get width information that may have been embedded in
 * the PDF /W array (or W2 if vertical text) */
pdf_obj *
pdf_add_cid_font(fz_context *ctx, pdf_document *doc, fz_font *font)
{
	pdf_obj *fobj = NULL;
	pdf_obj *fref = NULL;
	pdf_obj *dfonts = NULL;
	unsigned char digest[16];

	fref = pdf_find_font_resource(ctx, doc, PDF_CID_FONT_RESOURCE, 0, font, digest);
	if (fref)
		return fref;

	fobj = pdf_add_new_dict(ctx, doc, 10);
	fz_try(ctx)
	{
		pdf_dict_put(ctx, fobj, PDF_NAME(Type), PDF_NAME(Font));
		pdf_dict_put(ctx, fobj, PDF_NAME(Subtype), PDF_NAME(Type0));
		pdf_dict_put_name(ctx, fobj, PDF_NAME(BaseFont), font->name);
		pdf_dict_put(ctx, fobj, PDF_NAME(Encoding), PDF_NAME(Identity_H));
		pdf_add_to_unicode(ctx, doc, fobj, font);

		dfonts = pdf_dict_put_array(ctx, fobj, PDF_NAME(DescendantFonts), 1);
		pdf_array_push_drop(ctx, dfonts, pdf_add_descendant_cid_font(ctx, doc, font));

		fref = pdf_insert_font_resource(ctx, doc, digest, fobj);
	}
	fz_always(ctx)
		pdf_drop_obj(ctx, fobj);
	fz_catch(ctx)
		fz_rethrow(ctx);
	return fref;
}

/* Create simple (8-bit encoding) fonts */

static void
pdf_add_simple_font_encoding_imp(fz_context *ctx, pdf_document *doc, pdf_obj *font, const char *glyph_names[])
{
	pdf_obj *enc, *diff;
	int i, last;

	enc = pdf_dict_put_dict(ctx, font, PDF_NAME(Encoding), 2);
	pdf_dict_put(ctx, enc, PDF_NAME(BaseEncoding), PDF_NAME(WinAnsiEncoding));
	diff = pdf_dict_put_array(ctx, enc, PDF_NAME(Differences), 129);
	last = 0;
	for (i = 128; i < 256; ++i)
	{
		const char *glyph = glyph_names[i];
		if (glyph)
		{
			if (last != i-1)
				pdf_array_push_int(ctx, diff, i);
			last = i;
			pdf_array_push_name(ctx, diff, glyph);
		}
	}
}

static void
pdf_add_simple_font_encoding(fz_context *ctx, pdf_document *doc, pdf_obj *fobj, int encoding)
{
	switch (encoding)
	{
	default:
	case PDF_SIMPLE_ENCODING_LATIN:
		pdf_dict_put(ctx, fobj, PDF_NAME(Encoding), PDF_NAME(WinAnsiEncoding));
		break;
	case PDF_SIMPLE_ENCODING_GREEK:
		pdf_add_simple_font_encoding_imp(ctx, doc, fobj, pdf_glyph_name_from_iso8859_7);
		break;
	case PDF_SIMPLE_ENCODING_CYRILLIC:
		pdf_add_simple_font_encoding_imp(ctx, doc, fobj, pdf_glyph_name_from_koi8u);
		break;
	}
}

pdf_obj *
pdf_add_simple_font(fz_context *ctx, pdf_document *doc, fz_font *font, int encoding)
{
	FT_Face face = font->ft_face;
	pdf_obj *fobj = NULL;
	pdf_obj *fref = NULL;
	const char **enc;
	unsigned char digest[16];

	fref = pdf_find_font_resource(ctx, doc, PDF_SIMPLE_FONT_RESOURCE, encoding, font, digest);
	if (fref)
		return fref;

	switch (encoding)
	{
	default: enc = pdf_win_ansi; break;
	case PDF_SIMPLE_ENCODING_LATIN: enc = pdf_win_ansi; break;
	case PDF_SIMPLE_ENCODING_GREEK: enc = pdf_glyph_name_from_iso8859_7; break;
	case PDF_SIMPLE_ENCODING_CYRILLIC: enc = pdf_glyph_name_from_koi8u; break;
	}

	fobj = pdf_add_new_dict(ctx, doc, 10);
	fz_try(ctx)
	{
		pdf_dict_put(ctx, fobj, PDF_NAME(Type), PDF_NAME(Font));
		switch (ft_kind(face))
		{
		case TYPE1: pdf_dict_put(ctx, fobj, PDF_NAME(Subtype), PDF_NAME(Type1)); break;
		case TRUETYPE: pdf_dict_put(ctx, fobj, PDF_NAME(Subtype), PDF_NAME(TrueType)); break;
		}

		if (!is_builtin_font(ctx, font))
		{
			const char *ps_name = FT_Get_Postscript_Name(face);
			if (!ps_name)
				ps_name = font->name;
			pdf_dict_put_name(ctx, fobj, PDF_NAME(BaseFont), ps_name);
			pdf_add_simple_font_encoding(ctx, doc, fobj, encoding);
			pdf_add_simple_font_widths(ctx, doc, fobj, font, enc);
			pdf_add_font_descriptor(ctx, doc, fobj, font);
		}
		else
		{
			pdf_dict_put_name(ctx, fobj, PDF_NAME(BaseFont), clean_font_name(font->name));
			pdf_add_simple_font_encoding(ctx, doc, fobj, encoding);
			if (encoding != PDF_SIMPLE_ENCODING_LATIN)
				pdf_add_simple_font_widths(ctx, doc, fobj, font, enc);
		}

		fref = pdf_insert_font_resource(ctx, doc, digest, fobj);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, fobj);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);
	return fref;
}

int
pdf_font_writing_supported(fz_font *font)
{
	if (font->ft_face == NULL)
		return 0;

	if (ft_kind(font->ft_face) == TYPE1 || ft_kind(font->ft_face) == TRUETYPE)
	{
		return 1;
	}
	return 0;
}

/* Add a non-embedded UTF16-encoded CID-font for the CJK scripts: CNS1, GB1, Japan1, or Korea1 */
pdf_obj *
pdf_add_cjk_font(fz_context *ctx, pdf_document *doc, fz_font *fzfont, int script, int wmode, int serif)
{
	pdf_obj *fref, *font, *subfont, *fontdesc;
	pdf_obj *dfonts;
	fz_rect bbox = { -200, -200, 1200, 1200 };
	unsigned char digest[16];
	int flags;

	const char *basefont, *encoding, *ordering;
	int supplement;

	switch (script)
	{
	default:
		script = FZ_ADOBE_CNS;
		/* fall through */
	case FZ_ADOBE_CNS: /* traditional chinese */
		basefont = serif ? "Ming" : "Fangti";
		encoding = wmode ? "UniCNS-UTF16-V" : "UniCNS-UTF16-H";
		ordering = "CNS1";
		supplement = 7;
		break;
	case FZ_ADOBE_GB: /* simplified chinese */
		basefont = serif ? "Song" : "Heiti";
		encoding = wmode ? "UniGB-UTF16-V" : "UniGB-UTF16-H";
		ordering = "GB1";
		supplement = 5;
		break;
	case FZ_ADOBE_JAPAN:
		basefont = serif ? "Mincho" : "Gothic";
		encoding = wmode ? "UniJIS-UTF16-V" : "UniJIS-UTF16-H";
		ordering = "Japan1";
		supplement = 6;
		break;
	case FZ_ADOBE_KOREA:
		basefont = serif ? "Batang" : "Dotum";
		encoding = wmode ? "UniKS-UTF16-V" : "UniKS-UTF16-H";
		ordering = "Korea1";
		supplement = 2;
		break;
	}

	flags = PDF_FD_SYMBOLIC;
	if (serif)
		flags |= PDF_FD_SERIF;

	fref = pdf_find_font_resource(ctx, doc, PDF_CJK_FONT_RESOURCE, script, fzfont, digest);
	if (fref)
		return fref;

	font = pdf_add_new_dict(ctx, doc, 5);
	fz_try(ctx)
	{
		pdf_dict_put(ctx, font, PDF_NAME(Type), PDF_NAME(Font));
		pdf_dict_put(ctx, font, PDF_NAME(Subtype), PDF_NAME(Type0));
		pdf_dict_put_name(ctx, font, PDF_NAME(BaseFont), basefont);
		pdf_dict_put_name(ctx, font, PDF_NAME(Encoding), encoding);
		dfonts = pdf_dict_put_array(ctx, font, PDF_NAME(DescendantFonts), 1);
		pdf_array_push_drop(ctx, dfonts, subfont = pdf_add_new_dict(ctx, doc, 5));
		{
			pdf_dict_put(ctx, subfont, PDF_NAME(Type), PDF_NAME(Font));
			pdf_dict_put(ctx, subfont, PDF_NAME(Subtype), PDF_NAME(CIDFontType0));
			pdf_dict_put_name(ctx, subfont, PDF_NAME(BaseFont), basefont);
			pdf_add_cid_system_info(ctx, doc, subfont, "Adobe", ordering, supplement);
			fontdesc = pdf_add_new_dict(ctx, doc, 8);
			pdf_dict_put_drop(ctx, subfont, PDF_NAME(FontDescriptor), fontdesc);
			{
				pdf_dict_put(ctx, fontdesc, PDF_NAME(Type), PDF_NAME(FontDescriptor));
				pdf_dict_put_text_string(ctx, fontdesc, PDF_NAME(FontName), basefont);
				pdf_dict_put_rect(ctx, fontdesc, PDF_NAME(FontBBox), bbox);
				pdf_dict_put_int(ctx, fontdesc, PDF_NAME(Flags), flags);
				pdf_dict_put_int(ctx, fontdesc, PDF_NAME(ItalicAngle), 0);
				pdf_dict_put_int(ctx, fontdesc, PDF_NAME(Ascent), 1000);
				pdf_dict_put_int(ctx, fontdesc, PDF_NAME(Descent), -200);
				pdf_dict_put_int(ctx, fontdesc, PDF_NAME(StemV), 80);
			}
		}

		fref = pdf_insert_font_resource(ctx, doc, digest, font);
	}
	fz_always(ctx)
		pdf_drop_obj(ctx, font);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return fref;
}
