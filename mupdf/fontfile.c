#include <fitz.h>
#include <mupdf.h>

#include <mupdf/base14.h>

#include <ft2build.h>
#include FT_FREETYPE_H

static FT_Library ftlib = nil;

enum
{
    FD_FIXED = 1 << 0,
    FD_SERIF = 1 << 1,
    FD_SYMBOLIC = 1 << 2,
    FD_SCRIPT = 1 << 3,
    FD_NONSYMBOLIC = 1 << 5,
    FD_ITALIC = 1 << 6,
    FD_ALLCAP = 1 << 16,
    FD_SMALLCAP = 1 << 17,
	FD_FORCEBOLD = 1 << 18
};

static char *basenames[15] =
{
    "Courier", 
    "Courier-Bold", 
    "Courier-Oblique",
    "Courier-BoldOblique",
    "Helvetica",
    "Helvetica-Bold",
    "Helvetica-Oblique",
    "Helvetica-BoldOblique",
    "Times-Roman",
    "Times-Bold",
    "Times-Italic",
    "Times-BoldItalic",
    "Symbol", 
    "ZapfDingbats",
	"Chancery"
};

static struct { char *collection; char *serif; char *gothic; } cidfonts[5] =
{
	{ "Adobe-CNS1", "MOESung-Regular", "MOEKai-Regular" },
	{ "Adobe-GB1", "gkai00mp", "gbsn00lp" },
	{ "Adobe-Japan1", "WadaMin-Regular", "WadaMaruGo-Regular" },
	{ "Adobe-Japan2", "WadaMin-RegularH", "WadaMaruGo-RegularH" },
	{ "Adobe-Korea1", "Munhwa-Regular", "MunhwaGothic-Regular" },
};

static void loadfontdata(int i, unsigned char **d, unsigned int *l)
{
	switch (i)
	{
	case  0: *d=NimbusMonL_Regu_cff;*l=NimbusMonL_Regu_cff_len;break;
	case  1: *d=NimbusMonL_Bold_cff;*l=NimbusMonL_Bold_cff_len;break;
	case  2: *d=NimbusMonL_ReguObli_cff;*l=NimbusMonL_ReguObli_cff_len;break;
	case  3: *d=NimbusMonL_BoldObli_cff;*l=NimbusMonL_BoldObli_cff_len;break;
	case  4: *d=NimbusSanL_Regu_cff;*l=NimbusSanL_Regu_cff_len;break;
	case  5: *d=NimbusSanL_Bold_cff;*l=NimbusSanL_Bold_cff_len;break;
	case  6: *d=NimbusSanL_ReguItal_cff;*l=NimbusSanL_ReguItal_cff_len;break;
	case  7: *d=NimbusSanL_BoldItal_cff;*l=NimbusSanL_BoldItal_cff_len;break;
	case  8: *d=NimbusRomNo9L_Regu_cff;*l=NimbusRomNo9L_Regu_cff_len;break;
	case  9: *d=NimbusRomNo9L_Medi_cff;*l=NimbusRomNo9L_Medi_cff_len;break;
	case 10: *d=NimbusRomNo9L_ReguItal_cff;*l=NimbusRomNo9L_ReguItal_cff_len;break;
	case 11: *d=NimbusRomNo9L_MediItal_cff;*l=NimbusRomNo9L_MediItal_cff_len;break;
	case 12: *d=StandardSymL_cff;*l=StandardSymL_cff_len;break;
	case 13: *d=Dingbats_cff;*l=Dingbats_cff_len;break;
	default: *d=URWChanceryL_MediItal_cff;*l=URWChanceryL_MediItal_cff_len;break;
	}
}

static fz_error *initfontlibs(void)
{
	int fterr;
	int maj, min, pat;

	if (ftlib)
		return nil;

	fterr = FT_Init_FreeType(&ftlib);
	if (fterr)
		return fz_throw("freetype failed initialisation: 0x%x", fterr);

	FT_Library_Version(ftlib, &maj, &min, &pat);
	if (maj == 2 && min == 1 && pat < 7)
		return fz_throw("freetype version too old: %d.%d.%d", maj, min, pat);

	return nil;
}

fz_error *
pdf_loadbuiltinfont(pdf_font *font, char *fontname)
{
	fz_error *error;
	unsigned char *data;
	unsigned int len;
	FT_Error e;
	int i;

	error = initfontlibs();
	if (error)
		return error;

	for (i = 0; i < 15; i++)
		if (!strcmp(fontname, basenames[i]))
			goto found;

	return fz_throw("font not found: %s", fontname);

found:
	loadfontdata(i, &data, &len);

	e = FT_New_Memory_Face(ftlib, data, len, 0, (FT_Face*)&font->ftface);
	if (e)
		return fz_throw("freetype: could not load font: 0x%x", e);

	return nil;
}

static fz_error *
loadcidfont(pdf_font *font, char *filename)
{
	char path[1024];
	char *fontdir;
	int e;

printf("  load system cid font '%s'\n", filename);

	fontdir = getenv("FONTDIR");
	if (!fontdir)
		return fz_throw("ioerror: FONTDIR environment not set");

	strlcpy(path, fontdir, sizeof path);
	strlcat(path, "/", sizeof path);
	strlcat(path, filename, sizeof path);
	strlcat(path, ".cid.cff", sizeof path);

	if (access(path, R_OK))
		return fz_throw("ioerror: could not access file '%s'", path);

	e = FT_New_Face(ftlib, path, 0, (FT_Face*)&font->ftface);
	if (e)
		return fz_throw("freetype: could not load font: 0x%x", e);

	return nil;
}

fz_error *
pdf_loadsystemfont(pdf_font *font, char *fontname, char *collection)
{
	fz_error *error;
	char *name;
	int i;

	int isbold = 0;
	int isitalic = 0;
	int isserif = 0;
	int isscript = 0;
	int isfixed = 0;

	error = initfontlibs();
	if (error)
		return error;

	font->substitute = 1;

	if (strstr(fontname, "Bold"))
		isbold = 1;
	if (strstr(fontname, "Italic"))
		isitalic = 1;
	if (strstr(fontname, "Oblique"))
		isitalic = 1;

	if (font->flags & FD_FIXED)
		isfixed = 1;
	if (font->flags & FD_SERIF)
		isserif = 1;
	if (font->flags & FD_ITALIC)
		isitalic = 1;
	if (font->flags & FD_SCRIPT)
		isscript = 1;
	if (font->flags & FD_FORCEBOLD)
		isbold = 1;

	if (collection)
	{
		char buf[256];
		char *env;
printf("  find cid font %s (%d)\n", collection, isserif);

		snprintf(buf, sizeof buf, "%s_%s", strstr(collection, "-") + 1, isserif ? "S" : "G");
		env = getenv(buf);
		if (env)
			return loadcidfont(font, env);

		for (i = 0; i < 5; i++)
		{
			if (!strcmp(collection, cidfonts[i].collection))
			{
				if (isserif)
					return loadcidfont(font, cidfonts[i].serif);
				else
					return loadcidfont(font, cidfonts[i].gothic);
			}
		}

		fz_warn("unknown cid collection: %s", collection);
	}

	if (isscript)
		name = "Chancery";

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

printf("  loading substitute font %s\n", name);

	return pdf_loadbuiltinfont(font, name);
}

fz_error *
pdf_loadembeddedfont(pdf_font *font, pdf_xref *xref, fz_obj *stmref)
{
	fz_error *error;
	int fterr;
	FT_Face face;
	fz_buffer *buf;

	error = initfontlibs();
	if (error)
		return error;

	error = pdf_loadstream(&buf, xref, fz_tonum(stmref), fz_togen(stmref));
	if (error)
		return error;

	fterr = FT_New_Memory_Face(ftlib, buf->rp, buf->wp - buf->rp, 0, &face);

	if (fterr) {
		fz_free(buf);
		return fz_throw("freetype could not load embedded font: 0x%x", fterr);
	}

	font->ftface = face;
	font->fontdata = buf;

	return nil;
}

