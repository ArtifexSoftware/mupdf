#include "mupdf/pdf.h"

/*
	Which fonts are embedded is based on a few preprocessor definitions.

	The base 14 fonts are always embedded.
	For CJK font substitution we embed DroidSansFallback.

	Set NOCJK to skip all CJK support (this also omits embedding the CJK CMaps)
	Set NOCJKFONT to skip the embedded CJK font.
	Set NOCJKFULL to embed a smaller CJK font without CJK Extension A support.
*/

#ifdef NOCJK
#define NOCJKFONT
#endif

#include "gen_font_base14.h"

#ifndef NOCJKFONT
#ifndef NOCJKFULL
#include "gen_font_cjk_full.h"
#else
#include "gen_font_cjk.h"
#endif
#endif

unsigned char *
pdf_lookup_builtin_font(fz_context *ctx, const char *name, unsigned int *len)
{
	if (!strcmp("Courier", name)) {
		*len = sizeof pdf_font_NimbusMono_Regular;
		return (unsigned char*) pdf_font_NimbusMono_Regular;
	}
	if (!strcmp("Courier-Bold", name)) {
		*len = sizeof pdf_font_NimbusMono_Bold;
		return (unsigned char*) pdf_font_NimbusMono_Bold;
	}
	if (!strcmp("Courier-Oblique", name)) {
		*len = sizeof pdf_font_NimbusMono_Oblique;
		return (unsigned char*) pdf_font_NimbusMono_Oblique;
	}
	if (!strcmp("Courier-BoldOblique", name)) {
		*len = sizeof pdf_font_NimbusMono_BoldOblique;
		return (unsigned char*) pdf_font_NimbusMono_BoldOblique;
	}
	if (!strcmp("Helvetica", name)) {
		*len = sizeof pdf_font_NimbusSanL_Reg;
		return (unsigned char*) pdf_font_NimbusSanL_Reg;
	}
	if (!strcmp("Helvetica-Bold", name)) {
		*len = sizeof pdf_font_NimbusSanL_Bol;
		return (unsigned char*) pdf_font_NimbusSanL_Bol;
	}
	if (!strcmp("Helvetica-Oblique", name)) {
		*len = sizeof pdf_font_NimbusSanL_RegIta;
		return (unsigned char*) pdf_font_NimbusSanL_RegIta;
	}
	if (!strcmp("Helvetica-BoldOblique", name)) {
		*len = sizeof pdf_font_NimbusSanL_BolIta;
		return (unsigned char*) pdf_font_NimbusSanL_BolIta;
	}
	if (!strcmp("Times-Roman", name)) {
		*len = sizeof pdf_font_NimbusRomNo9L_Reg;
		return (unsigned char*) pdf_font_NimbusRomNo9L_Reg;
	}
	if (!strcmp("Times-Bold", name)) {
		*len = sizeof pdf_font_NimbusRomNo9L_Med;
		return (unsigned char*) pdf_font_NimbusRomNo9L_Med;
	}
	if (!strcmp("Times-Italic", name)) {
		*len = sizeof pdf_font_NimbusRomNo9L_RegIta;
		return (unsigned char*) pdf_font_NimbusRomNo9L_RegIta;
	}
	if (!strcmp("Times-BoldItalic", name)) {
		*len = sizeof pdf_font_NimbusRomNo9L_MedIta;
		return (unsigned char*) pdf_font_NimbusRomNo9L_MedIta;
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
pdf_lookup_substitute_font(fz_context *ctx, int mono, int serif, int bold, int italic, unsigned int *len)
{
	if (mono) {
		if (bold) {
			if (italic) return pdf_lookup_builtin_font(ctx, "Courier-BoldOblique", len);
			else return pdf_lookup_builtin_font(ctx, "Courier-Bold", len);
		} else {
			if (italic) return pdf_lookup_builtin_font(ctx, "Courier-Oblique", len);
			else return pdf_lookup_builtin_font(ctx, "Courier", len);
		}
	} else if (serif) {
		if (bold) {
			if (italic) return pdf_lookup_builtin_font(ctx, "Times-BoldItalic", len);
			else return pdf_lookup_builtin_font(ctx, "Times-Bold", len);
		} else {
			if (italic) return pdf_lookup_builtin_font(ctx, "Times-Italic", len);
			else return pdf_lookup_builtin_font(ctx, "Times-Roman", len);
		}
	} else {
		if (bold) {
			if (italic) return pdf_lookup_builtin_font(ctx, "Helvetica-BoldOblique", len);
			else return pdf_lookup_builtin_font(ctx, "Helvetica-Bold", len);
		} else {
			if (italic) return pdf_lookup_builtin_font(ctx, "Helvetica-Oblique", len);
			else return pdf_lookup_builtin_font(ctx, "Helvetica", len);
		}
	}
}

unsigned char *
pdf_lookup_substitute_cjk_font(fz_context *ctx, int ros, int serif, int wmode, unsigned int *len, int *index)
{
#ifndef NOCJKFONT
#ifndef NOCJKFULL
	*index = wmode;
	*len = sizeof pdf_font_DroidSansFallbackFull;
	return (unsigned char*) pdf_font_DroidSansFallbackFull;
#else
	*index = wmode;
	*len = sizeof pdf_font_DroidSansFallback;
	return (unsigned char*) pdf_font_DroidSansFallback;
#endif
#else
	*len = 0;
	return NULL;
#endif
}
