#include "mupdf/pdf.h"

/*
	Which fonts are embedded is based on a few preprocessor definitions.

	The base 14 fonts are always embedded.
	For font substitution we embed DroidSans which has good glyph coverage.
	For CJK font substitution we embed DroidSansFallback.

	Set NOCJK to skip all CJK support (this also omits embedding the CJK CMaps)
	Set NOCJKFONT to skip the embedded CJK font.
	Set NOCJKFULL to embed a smaller CJK font without CJK Extension A support.

	Set NODROIDFONT to use the base 14 fonts as substitute fonts.
*/

#ifdef NOCJK
#define NOCJKFONT
#endif

#include "gen_font_base14.h"

#ifndef NODROIDFONT
#include "gen_font_droid.h"
#endif

#ifndef NOCJKFONT
#ifndef NOCJKFULL
#include "gen_font_cjk_full.h"
#else
#include "gen_font_cjk.h"
#endif
#endif

unsigned char *
pdf_lookup_builtin_font(const char *name, unsigned int *len)
{
	if (!strcmp("Courier", name)) {
		*len = sizeof pdf_font_NimbusMon_Reg;
		return (unsigned char*) pdf_font_NimbusMon_Reg;
	}
	if (!strcmp("Courier-Bold", name)) {
		*len = sizeof pdf_font_NimbusMon_Bol;
		return (unsigned char*) pdf_font_NimbusMon_Bol;
	}
	if (!strcmp("Courier-Oblique", name)) {
		*len = sizeof pdf_font_NimbusMon_Obl;
		return (unsigned char*) pdf_font_NimbusMon_Obl;
	}
	if (!strcmp("Courier-BoldOblique", name)) {
		*len = sizeof pdf_font_NimbusMon_BolObl;
		return (unsigned char*) pdf_font_NimbusMon_BolObl;
	}
	if (!strcmp("Helvetica", name)) {
		*len = sizeof pdf_font_NimbusSan_Reg;
		return (unsigned char*) pdf_font_NimbusSan_Reg;
	}
	if (!strcmp("Helvetica-Bold", name)) {
		*len = sizeof pdf_font_NimbusSan_Bol;
		return (unsigned char*) pdf_font_NimbusSan_Bol;
	}
	if (!strcmp("Helvetica-Oblique", name)) {
		*len = sizeof pdf_font_NimbusSan_Ita;
		return (unsigned char*) pdf_font_NimbusSan_Ita;
	}
	if (!strcmp("Helvetica-BoldOblique", name)) {
		*len = sizeof pdf_font_NimbusSan_BolIta;
		return (unsigned char*) pdf_font_NimbusSan_BolIta;
	}
	if (!strcmp("Times-Roman", name)) {
		*len = sizeof pdf_font_NimbusRom_Reg;
		return (unsigned char*) pdf_font_NimbusRom_Reg;
	}
	if (!strcmp("Times-Bold", name)) {
		*len = sizeof pdf_font_NimbusRom_Med;
		return (unsigned char*) pdf_font_NimbusRom_Med;
	}
	if (!strcmp("Times-Italic", name)) {
		*len = sizeof pdf_font_NimbusRom_Ita;
		return (unsigned char*) pdf_font_NimbusRom_Ita;
	}
	if (!strcmp("Times-BoldItalic", name)) {
		*len = sizeof pdf_font_NimbusRom_MedIta;
		return (unsigned char*) pdf_font_NimbusRom_MedIta;
	}
	if (!strcmp("Symbol", name)) {
		*len = sizeof pdf_font_StandardSymL;
		return (unsigned char*) pdf_font_StandardSymL;
	}
	if (!strcmp("ZapfDingbats", name)) {
		*len = sizeof pdf_font_Dingbats;
		return (unsigned char*) pdf_font_Dingbats;
	}
	*len = 0;
	return NULL;
}

unsigned char *
pdf_lookup_substitute_font(int mono, int serif, int bold, int italic, unsigned int *len)
{
#ifdef NODROIDFONT
	if (mono) {
		if (bold) {
			if (italic) return pdf_lookup_builtin_font("Courier-BoldOblique", len);
			else return pdf_lookup_builtin_font("Courier-Bold", len);
		} else {
			if (italic) return pdf_lookup_builtin_font("Courier-Oblique", len);
			else return pdf_lookup_builtin_font("Courier", len);
		}
	} else if (serif) {
		if (bold) {
			if (italic) return pdf_lookup_builtin_font("Times-BoldItalic", len);
			else return pdf_lookup_builtin_font("Times-Bold", len);
		} else {
			if (italic) return pdf_lookup_builtin_font("Times-Italic", len);
			else return pdf_lookup_builtin_font("Times-Roman", len);
		}
	} else {
		if (bold) {
			if (italic) return pdf_lookup_builtin_font("Helvetica-BoldOblique", len);
			else return pdf_lookup_builtin_font("Helvetica-Bold", len);
		} else {
			if (italic) return pdf_lookup_builtin_font("Helvetica-Oblique", len);
			else return pdf_lookup_builtin_font("Helvetica", len);
		}
	}
#else
	if (mono) {
		*len = sizeof pdf_font_DroidSansMono;
		return (unsigned char*) pdf_font_DroidSansMono;
	} else {
		*len = sizeof pdf_font_DroidSans;
		return (unsigned char*) pdf_font_DroidSans;
	}
#endif
}

unsigned char *
pdf_lookup_substitute_cjk_font(int ros, int serif, unsigned int *len)
{
#ifndef NOCJKFONT
#ifndef NOCJKFULL
	*len = sizeof pdf_font_DroidSansFallbackFull;
	return (unsigned char*) pdf_font_DroidSansFallbackFull;
#else
	*len = sizeof pdf_font_DroidSansFallback;
	return (unsigned char*) pdf_font_DroidSansFallback;
#endif
#else
	*len = 0;
	return NULL;
#endif
}
