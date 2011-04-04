#include "fitz.h"
#include "mupdf.h"

extern const unsigned char pdf_font_Dingbats_cff_buf[];
extern const unsigned int pdf_font_Dingbats_cff_len;
extern const unsigned char pdf_font_NimbusMonL_Bold_cff_buf[];
extern const unsigned int pdf_font_NimbusMonL_Bold_cff_len;
extern const unsigned char pdf_font_NimbusMonL_BoldObli_cff_buf[];
extern const unsigned int pdf_font_NimbusMonL_BoldObli_cff_len;
extern const unsigned char pdf_font_NimbusMonL_Regu_cff_buf[];
extern const unsigned int pdf_font_NimbusMonL_Regu_cff_len;
extern const unsigned char pdf_font_NimbusMonL_ReguObli_cff_buf[];
extern const unsigned int pdf_font_NimbusMonL_ReguObli_cff_len;
extern const unsigned char pdf_font_NimbusRomNo9L_Medi_cff_buf[];
extern const unsigned int pdf_font_NimbusRomNo9L_Medi_cff_len;
extern const unsigned char pdf_font_NimbusRomNo9L_MediItal_cff_buf[];
extern const unsigned int pdf_font_NimbusRomNo9L_MediItal_cff_len;
extern const unsigned char pdf_font_NimbusRomNo9L_Regu_cff_buf[];
extern const unsigned int pdf_font_NimbusRomNo9L_Regu_cff_len;
extern const unsigned char pdf_font_NimbusRomNo9L_ReguItal_cff_buf[];
extern const unsigned int pdf_font_NimbusRomNo9L_ReguItal_cff_len;
extern const unsigned char pdf_font_NimbusSanL_Bold_cff_buf[];
extern const unsigned int pdf_font_NimbusSanL_Bold_cff_len;
extern const unsigned char pdf_font_NimbusSanL_BoldItal_cff_buf[];
extern const unsigned int pdf_font_NimbusSanL_BoldItal_cff_len;
extern const unsigned char pdf_font_NimbusSanL_Regu_cff_buf[];
extern const unsigned int pdf_font_NimbusSanL_Regu_cff_len;
extern const unsigned char pdf_font_NimbusSanL_ReguItal_cff_buf[];
extern const unsigned int pdf_font_NimbusSanL_ReguItal_cff_len;
extern const unsigned char pdf_font_StandardSymL_cff_buf[];
extern const unsigned int pdf_font_StandardSymL_cff_len;

#ifndef NOCJK
extern const unsigned char pdf_font_DroidSansFallback_ttf_buf[];
extern const unsigned int pdf_font_DroidSansFallback_ttf_len;
#endif

enum
{
	FD_FIXED_PITCH = 1 << 0,
	FD_SERIF = 1 << 1,
	FD_SYMBOLIC = 1 << 2,
	FD_SCRIPT = 1 << 3,
	FD_NONSYMBOLIC = 1 << 5,
	FD_ITALIC = 1 << 6,
	FD_ALL_CAP = 1 << 16,
	FD_SMALL_CAP = 1 << 17,
	FD_FORCE_BOLD = 1 << 18
};

enum { CNS, GB, Japan, Korea };
enum { MINCHO, GOTHIC };

static const struct {
	const char *name;
	const unsigned char *cff;
	const unsigned int *len;
} base_fonts[] = {
	{ "Courier",
		pdf_font_NimbusMonL_Regu_cff_buf,
		&pdf_font_NimbusMonL_Regu_cff_len },
	{ "Courier-Bold",
		pdf_font_NimbusMonL_Bold_cff_buf,
		&pdf_font_NimbusMonL_Bold_cff_len },
	{ "Courier-Oblique",
		pdf_font_NimbusMonL_ReguObli_cff_buf,
		&pdf_font_NimbusMonL_ReguObli_cff_len },
	{ "Courier-BoldOblique",
		pdf_font_NimbusMonL_BoldObli_cff_buf,
		&pdf_font_NimbusMonL_BoldObli_cff_len },
	{ "Helvetica",
		pdf_font_NimbusSanL_Regu_cff_buf,
		&pdf_font_NimbusSanL_Regu_cff_len },
	{ "Helvetica-Bold",
		pdf_font_NimbusSanL_Bold_cff_buf,
		&pdf_font_NimbusSanL_Bold_cff_len },
	{ "Helvetica-Oblique",
		pdf_font_NimbusSanL_ReguItal_cff_buf,
		&pdf_font_NimbusSanL_ReguItal_cff_len },
	{ "Helvetica-BoldOblique",
		pdf_font_NimbusSanL_BoldItal_cff_buf,
		&pdf_font_NimbusSanL_BoldItal_cff_len },
	{ "Times-Roman",
		pdf_font_NimbusRomNo9L_Regu_cff_buf,
		&pdf_font_NimbusRomNo9L_Regu_cff_len },
	{ "Times-Bold",
		pdf_font_NimbusRomNo9L_Medi_cff_buf,
		&pdf_font_NimbusRomNo9L_Medi_cff_len },
	{ "Times-Italic",
		pdf_font_NimbusRomNo9L_ReguItal_cff_buf,
		&pdf_font_NimbusRomNo9L_ReguItal_cff_len },
	{ "Times-BoldItalic",
		pdf_font_NimbusRomNo9L_MediItal_cff_buf,
		&pdf_font_NimbusRomNo9L_MediItal_cff_len },
	{ "Symbol",
		pdf_font_StandardSymL_cff_buf,
		&pdf_font_StandardSymL_cff_len },
	{ "ZapfDingbats",
		pdf_font_Dingbats_cff_buf,
		&pdf_font_Dingbats_cff_len },
	{ NULL, NULL, NULL }
};

fz_error
pdf_load_builtin_font(pdf_font_desc *fontdesc, char *fontname)
{
	fz_error error;
	unsigned char *data;
	unsigned int len;
	int i;

	for (i = 0; base_fonts[i].name; i++)
		if (!strcmp(fontname, base_fonts[i].name))
			goto found;

	return fz_throw("cannot find font: '%s'", fontname);

found:
	pdf_log_font("load builtin font %s\n", fontname);

	data = (unsigned char *) base_fonts[i].cff;
	len = *base_fonts[i].len;

	error = fz_new_font_from_memory(&fontdesc->font, data, len, 0);
	if (error)
		return fz_rethrow(error, "cannot load freetype font from buffer");

	fz_strlcpy(fontdesc->font->name, fontname, sizeof fontdesc->font->name);

	if (!strcmp(fontname, "Symbol") || !strcmp(fontname, "ZapfDingbats"))
		fontdesc->flags |= FD_SYMBOLIC;

	return fz_okay;
}

static fz_error
load_system_cid_font(pdf_font_desc *fontdesc, int ros, int kind)
{
#ifndef NOCJK
	fz_error error;
	/*
	We only have one builtin fallback font.
	We'd really like to have one for each combination of ROS and Kind.
	*/
	pdf_log_font("loading builtin CJK font\n");
	error = fz_new_font_from_memory(&fontdesc->font,
		(unsigned char *)pdf_font_DroidSansFallback_ttf_buf,
		pdf_font_DroidSansFallback_ttf_len, 0);
	if (error)
		return fz_rethrow(error, "cannot load builtin CJK font");
	fontdesc->font->ft_substitute = 1; /* substitute font */
	return fz_okay;
#else
	return fz_throw("no builtin CJK font file");
#endif
}

fz_error
pdf_load_system_font(pdf_font_desc *fontdesc, char *fontname, char *collection)
{
	fz_error error;
	char *name;

	int isbold = 0;
	int isitalic = 0;
	int isserif = 0;
	int isscript = 0;
	int isfixed = 0;

	if (strstr(fontname, "Bold"))
		isbold = 1;
	if (strstr(fontname, "Italic"))
		isitalic = 1;
	if (strstr(fontname, "Oblique"))
		isitalic = 1;

	if (fontdesc->flags & FD_FIXED_PITCH)
		isfixed = 1;
	if (fontdesc->flags & FD_SERIF)
		isserif = 1;
	if (fontdesc->flags & FD_ITALIC)
		isitalic = 1;
	if (fontdesc->flags & FD_SCRIPT)
		isscript = 1;
	if (fontdesc->flags & FD_FORCE_BOLD)
		isbold = 1;

	pdf_log_font("fixed-%d serif-%d italic-%d script-%d bold-%d\n",
		isfixed, isserif, isitalic, isscript, isbold);

	if (collection)
	{
		int kind;

		if (isserif)
			kind = MINCHO;
		else
			kind = GOTHIC;

		if (!strcmp(collection, "Adobe-CNS1"))
			return load_system_cid_font(fontdesc, CNS, kind);
		else if (!strcmp(collection, "Adobe-GB1"))
			return load_system_cid_font(fontdesc, GB, kind);
		else if (!strcmp(collection, "Adobe-Japan1"))
			return load_system_cid_font(fontdesc, Japan, kind);
		else if (!strcmp(collection, "Adobe-Japan2"))
			return load_system_cid_font(fontdesc, Japan, kind);
		else if (!strcmp(collection, "Adobe-Korea1"))
			return load_system_cid_font(fontdesc, Korea, kind);

		fz_warn("unknown cid collection: %s", collection);
	}

	else if (isfixed)
	{
		if (isitalic) {
			if (isbold) name = "Courier-BoldOblique";
			else name = "Courier-Oblique";
		}
		else {
			if (isbold) name = "Courier-Bold";
			else name = "Courier";
		}
	}

	else if (isserif)
	{
		if (isitalic) {
			if (isbold) name = "Times-BoldItalic";
			else name = "Times-Italic";
		}
		else {
			if (isbold) name = "Times-Bold";
			else name = "Times-Roman";
		}
	}

	else
	{
		if (isitalic) {
			if (isbold) name = "Helvetica-BoldOblique";
			else name = "Helvetica-Oblique";
		}
		else {
			if (isbold) name = "Helvetica-Bold";
			else name = "Helvetica";
		}
	}

	error = pdf_load_builtin_font(fontdesc, name);
	if (error)
		return fz_throw("cannot load builtin substitute font: %s", name);

	/* it's a substitute font: override the metrics */
	fontdesc->font->ft_substitute = 1;

	return fz_okay;
}

fz_error
pdf_load_embedded_font(pdf_font_desc *fontdesc, pdf_xref *xref, fz_obj *stmref)
{
	fz_error error;
	fz_buffer *buf;

	pdf_log_font("load embedded font\n");

	error = pdf_load_stream(&buf, xref, fz_to_num(stmref), fz_to_gen(stmref));
	if (error)
		return fz_rethrow(error, "cannot load font stream (%d %d R)", fz_to_num(stmref), fz_to_gen(stmref));

	error = fz_new_font_from_memory(&fontdesc->font, buf->data, buf->len, 0);
	if (error)
	{
		fz_drop_buffer(buf);
		return fz_rethrow(error, "cannot load embedded font (%d %d R)", fz_to_num(stmref), fz_to_gen(stmref));
	}

	/* save the buffer so we can free it later */
	fontdesc->font->ft_data = buf->data;
	fontdesc->font->ft_size = buf->len;
	fz_free(buf); /* only free the fz_buffer struct, not the contained data */

	fontdesc->isembedded = 1;

	return fz_okay;
}
