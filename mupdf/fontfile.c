#include <fitz.h>
#include <mupdf.h>

#include <ft2build.h>
#include FT_FREETYPE_H
#include <fontconfig/fontconfig.h>

static FT_Library ftlib = nil;
static FcConfig *fclib = nil;

static char *basenames[14] =
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
    "ZapfDingbats"
};

static char *basepatterns[14] =
{
    "Courier,Nimbus Mono L,Courier New:style=Regular,Roman",
    "Courier,Nimbus Mono L,Courier New:style=Bold",
    "Courier,Nimbus Mono L,Courier New:style=Oblique,Italic",
    "Courier,Nimbus Mono L,Courier New:style=BoldOblique,BoldItalic",
    "Helvetica,Nimbus Sans L,Arial:style=Regular,Roman",
    "Helvetica,Nimbus Sans L,Arial:style=Bold",
    "Helvetica,Nimbus Sans L,Arial:style=Oblique,Italic",
    "Helvetica,Nimbus Sans L,Arial:style=BoldOblique,BoldItalic",
    "Times,Nimbus Roman No9 L,Times New Roman:style=Regular,Roman",
    "Times,Nimbus Roman No9 L,Times New Roman:style=Bold,Medium",
    "Times,Nimbus Roman No9 L,Times New Roman:style=Italic,Regular Italic",
    "Times,Nimbus Roman No9 L,Times New Roman:style=BoldItalic,Medium Italic",
    "Standard Symbols L,Symbol",
    "Zapf Dingbats,Dingbats"
};

static fz_error *initfontlibs(void)
{
	int fterr;

	if (ftlib)
		return nil;

	fterr = FT_Init_FreeType(&ftlib);
	if (fterr)
		return fz_throw("freetype failed initialisation: 0x%x", fterr);

	fclib = FcInitLoadConfigAndFonts();
	if (!fclib)
		return fz_throw("fontconfig failed initialisation");

	return nil;
}

fz_error *
pdf_loadbuiltinfont(void **fontp, char *pattern)
{
	fz_error *error;
	FcResult fcerr;
	int fterr;

	FcPattern *searchpat;
	FcPattern *matchpat;
	FT_Face face;
	char *file;

	error = initfontlibs();
	if (error)
		return error;

	fcerr = FcResultMatch;
	searchpat = FcNameParse(pattern);
	FcDefaultSubstitute(searchpat);
	FcConfigSubstitute(fclib, searchpat, FcMatchPattern);

	matchpat = FcFontMatch(fclib, searchpat, &fcerr);
	if (fcerr != FcResultMatch)
		return fz_throw("fontconfig could not find font %s", pattern);

	fcerr = FcPatternGetString(matchpat, "file", 0, (FcChar8**)&file);
	if (fcerr != FcResultMatch)
		return fz_throw("fontconfig could not find font %s", pattern);

	fterr = FT_New_Face(ftlib, file, 0, &face);
	if (fterr)
		return fz_throw("freetype could not load font file '%s': 0x%x", file, fterr);

	FcPatternDestroy(matchpat);
	FcPatternDestroy(searchpat);

	*fontp = face;

	return nil;
}

fz_error *
pdf_loadsystemfont(void **fontp, char *basefont, char *collection)
{
	fz_error *error;
	FcResult fcerr;
	int fterr;

	char fontname[200];
	FcPattern *searchpat;
	FcPattern *matchpat;
	FT_Face face;
	char *style;
	char *file;

	error = initfontlibs();
	if (error)
		return error;

	/* parse windows-style font name descriptors Font,Style or Font-Style */
	strlcpy(fontname, basefont, sizeof fontname);

	style = strchr(fontname, ',');
	if (style) {
		*style++ = 0;
	}
	else {
		style = strchr(fontname, '-');
		if (style)
			*style++ = 0;
	}

	searchpat = FcPatternCreate();
	if (!searchpat)
		return fz_outofmem;

	error = fz_outofmem;

	if (!FcPatternAddString(searchpat, FC_FAMILY, fontname))
		goto cleanup;
	if (collection)
		if (!FcPatternAddString(searchpat, FC_FAMILY, collection))
			goto cleanup;
	if (style)
		if (!FcPatternAddString(searchpat, FC_STYLE, style))
			goto cleanup;
	if (!FcPatternAddBool(searchpat, FC_OUTLINE, 1))
		goto cleanup;

file = FcNameUnparse(searchpat);
printf("  system font pattern %s\n", file);
free(file);

	fcerr = FcResultMatch;
	FcDefaultSubstitute(searchpat);
	FcConfigSubstitute(fclib, searchpat, FcMatchPattern);

	matchpat = FcFontMatch(fclib, searchpat, &fcerr);
	if (fcerr != FcResultMatch)
		return fz_throw("fontconfig could not find font %s", basefont);

	fcerr = FcPatternGetString(matchpat, "file", 0, (FcChar8**)&file);
	if (fcerr != FcResultMatch)
		return fz_throw("fontconfig could not find font %s", basefont);

printf("  system font file %s\n", file);

	fterr = FT_New_Face(ftlib, file, 0, &face);
	if (fterr) {
		FcPatternDestroy(matchpat);
		FcPatternDestroy(searchpat);
		return fz_throw("freetype could not load font file '%s': 0x%x", file, fterr);
	}

	FcPatternDestroy(matchpat);
	FcPatternDestroy(searchpat);

	*fontp = face;

	return nil;

cleanup:
	FcPatternDestroy(searchpat);
	return error;
}

fz_error *
pdf_loadembeddedfont(void **fontp, pdf_xref *xref, fz_obj *stmref)
{
	fz_error *error;
	int fterr;
	FT_Face face;
	fz_buffer *buf;

	error = initfontlibs();
	if (error)
		return error;

	error = pdf_readstream(&buf, xref, stmref);
	if (error)
		return error;

	fterr = FT_New_Memory_Face(ftlib, buf->rp, buf->wp - buf->rp, 0, &face);

	if (fterr) {
		fz_free(buf);
		return fz_throw("freetype could not load embedded font: 0x%x", fterr);
	}

	*fontp = face;

	/* TODO: figure out how to free 'buf' when the FT_Face is freed */

	return nil;
}

fz_error *
pdf_loadfontdescriptor(void **facep, pdf_xref *xref, fz_obj *desc, char *collection)
{
	fz_error *error;
	fz_obj *obj1, *obj2, *obj3, *obj;
	char *fontname;

	error = pdf_resolve(&desc, xref);
	if (error)
		return error;

	fontname = fz_toname(fz_dictgets(desc, "FontName"));

	obj1 = fz_dictgets(desc, "FontFile");
	obj2 = fz_dictgets(desc, "FontFile2");
	obj3 = fz_dictgets(desc, "FontFile3");
	obj = obj1 ? obj1 : obj2 ? obj2 : obj3;

	if (fz_isindirect(obj))
	{
		error = pdf_loadembeddedfont(facep, xref, obj);
		if (error)
			goto cleanup;
	}
	else
	{
		error = pdf_loadsystemfont(facep, fontname, collection);
		if (error)
			goto cleanup;
	}

	fz_dropobj(desc);

	return nil;

cleanup:
	fz_dropobj(desc);
	return error;
}

