#include <fitz.h>
#include <mupdf.h>

/*
 * TODO: substitution fonts when no exact match is found.
 * base on a) cid system info and b) fontdescriptor flags
 */

#include <ft2build.h>
#include FT_FREETYPE_H
#include <freetype/internal/ftobjs.h>

static char *basefontnames[14][7] =
{
	{ "Courier", "CourierNew", "CourierNewPSMT", 0 },
	{ "Courier-Bold", "CourierNew,Bold", "Courier,Bold",
		"CourierNewPS-BoldMT", "CourierNew-Bold", 0 },
	{ "Courier-Oblique", "CourierNew,Italic", "Courier,Italic",
		"CourierNewPS-ItalicMT", "CourierNew-Italic", 0 },
	{ "Courier-BoldOblique", "CourierNew,BoldItalic", "Courier,BoldItalic",
		"CourierNewPS-BoldItalicMT", "CourierNew-BoldItalic", 0 },
	{ "Helvetica", "ArialMT", "Arial", 0 },
	{ "Helvetica-Bold", "Arial-BoldMT", "Arial,Bold", "Arial-Bold",
		"Helvetica,Bold", 0 },
	{ "Helvetica-Oblique", "Arial-ItalicMT", "Arial,Italic", "Arial-Italic",
		"Helvetica,Italic", "Helvetica-Italic", 0 },
	{ "Helvetica-BoldOblique", "Arial-BoldItalicMT",
		"Arial,BoldItalic", "Arial-BoldItalic",
		"Helvetica,BoldItalic", "Helvetica-BoldItalic", 0 },
	{ "Times-Roman", "TimesNewRomanPSMT", "TimesNewRoman",
		"TimesNewRomanPS", 0 },
	{ "Times-Bold", "TimesNewRomanPS-BoldMT", "TimesNewRoman,Bold",
		"TimesNewRomanPS-Bold", "TimesNewRoman-Bold", 0 },
	{ "Times-Italic", "TimesNewRomanPS-ItalicMT", "TimesNewRoman,Italic",
		"TimesNewRomanPS-Italic", "TimesNewRoman-Italic", 0 },
	{ "Times-BoldItalic", "TimesNewRomanPS-BoldItalicMT",
		"TimesNewRoman,BoldItalic", "TimesNewRomanPS-BoldItalic",
		"TimesNewRoman-BoldItalic", 0 },
	{ "Symbol", 0 },
	{ "ZapfDingbats", 0 }
};

/*
 * FreeType and Rendering glue
 */

enum { UNKNOWN, TYPE1, CFF, TRUETYPE, CID };

static int ftkind(FT_Face face)
{
	const char *kind = face->driver->clazz->root.module_name;
printf("  type %s\n", kind);
	if (!strcmp(kind, "type1"))
		return TYPE1;
	if (!strcmp(kind, "cff"))
		return CFF;
	if (!strcmp(kind, "truetype"))
		return TRUETYPE;
	if (!strcmp(kind, "t1cid"))
		return CID;
	return UNKNOWN;
}

static int ftwidth(pdf_font *font, int cid)
{
	int e;
	if (font->cidtogid)
		cid = font->cidtogid[cid];
	e = FT_Load_Glyph(font->ftface, cid,
			FT_LOAD_NO_HINTING | FT_LOAD_NO_BITMAP | FT_LOAD_IGNORE_TRANSFORM);
	if (e)
		return 0;
	return ((FT_Face)font->ftface)->glyph->advance.x;
}

static fz_error *
ftrender(fz_glyph *glyph, fz_font *fzfont, int cid, fz_matrix trm)
{
	pdf_font *font = (pdf_font*)fzfont;
	FT_Face face = font->ftface;
	FT_Matrix m;
	FT_Vector v;
	FT_Error fterr;
	int gid;

	if (font->cidtogid)
		gid = font->cidtogid[cid];
	else
		gid = cid;

	if (font->substitute && fzfont->wmode == 0)
	{
		fz_hmtx subw;
		int realw;
		float scale;

		FT_Set_Char_Size(face, 1000, 1000, 72, 72);

		fterr = FT_Load_Glyph(font->ftface, gid,
					FT_LOAD_NO_HINTING | FT_LOAD_NO_BITMAP | FT_LOAD_IGNORE_TRANSFORM);
		if (fterr)
			return fz_throw("freetype failed to load glyph: 0x%x", fterr);

		realw = ((FT_Face)font->ftface)->glyph->advance.x;
		subw = fz_gethmtx(fzfont, cid);
		if (realw)
			scale = (float) subw.w / realw;
		else
			scale = 1.0;

		trm = fz_concat(fz_scale(scale, 1.0), trm);

		FT_Set_Char_Size(face, 64, 64, 72, 72);
	}

	glyph->w = 0;
	glyph->h = 0;
	glyph->lsb = 0;
	glyph->top = 0;
	glyph->bitmap = nil;

	m.xx = trm.a * 65536;
	m.yx = trm.b * 65536;
	m.xy = trm.c * 65536;
	m.yy = trm.d * 65536;
	v.x = trm.e * 64;
	v.y = trm.f * 64;

	FT_Set_Char_Size(face, 64, 64, 72, 72);
	FT_Set_Transform(face, &m, &v);

	fterr = FT_Load_Glyph(face, gid, FT_LOAD_NO_BITMAP | FT_LOAD_NO_HINTING);
	if (fterr)
		return fz_throw("freetype failed to load glyph: 0x%x", fterr);

	fterr = FT_Render_Glyph(face->glyph, ft_render_mode_normal);
	if (fterr)
		return fz_throw("freetype failed to render glyph: 0x%x", fterr);

	glyph->w = face->glyph->bitmap.width;
	glyph->h = face->glyph->bitmap.rows;
	glyph->lsb = face->glyph->bitmap_left;
	glyph->top = face->glyph->bitmap_top;
	glyph->bitmap = face->glyph->bitmap.buffer;

	return nil;
}

/*
 * Basic encoding tables
 */

static char *cleanfontname(char *fontname)
{
	int i, k;
	for (i = 0; i < 14; i++)
		for (k = 0; basefontnames[i][k]; k++)
			if (!strcmp(basefontnames[i][k], fontname))
				return basefontnames[i][0];
	return fontname;
}

static int mrecode(char *name)
{
	int i;
	for (i = 0; i < 256; i++)
		if (pdf_macroman[i] && !strcmp(name, pdf_macroman[i]))
			return i;
	return -1;
}

/*
 * Create and destroy
 */

static void ftdropfont(fz_font *font)
{
	pdf_font *pfont = (pdf_font*)font;
	if (pfont->encoding)
		fz_dropcmap(pfont->encoding);
	if (pfont->tounicode)
		fz_dropcmap(pfont->tounicode);
	fz_free(pfont->cidtogid);
	fz_free(pfont->cidtoucs);
	if (pfont->ftface)
		FT_Done_Face((FT_Face)pfont->ftface);
	if (pfont->fontdata)
		fz_dropbuffer(pfont->fontdata);
}

pdf_font *
pdf_newfont(char *name)
{
	pdf_font *font;
	int i;

	font = fz_malloc(sizeof (pdf_font));
	if (!font)
		return nil;

	fz_initfont((fz_font*)font, name);
	font->super.render = ftrender;
	font->super.drop = (void(*)(fz_font*)) ftdropfont;

	font->ftface = nil;
	font->substitute = 0;

	font->flags = 0;
	font->italicangle = 0;
	font->ascent = 0;
    font->descent = 0;
    font->capheight = 0;
    font->xheight = 0;
    font->missingwidth = 0;

	font->encoding = nil;
	font->ncidtogid = 0;
	font->cidtogid = nil;

	font->tounicode = nil;
	font->ncidtoucs = 0;
	font->cidtoucs = nil;

	font->filename = nil;
	font->fontdata = nil;

	for (i = 0; i < 256; i++)
		font->charprocs[i] = nil;

	return font;
}

/*
 * Simple fonts (Type1 and TrueType)
 */

static fz_error *
loadsimplefont(pdf_font **fontp, pdf_xref *xref, fz_obj *dict)
{
	fz_error *error;
	fz_obj *descriptor = nil;
	fz_obj *encoding = nil;
	fz_obj *widths = nil;
	fz_obj *tounicode = nil;
	unsigned short *etable = nil;
	unsigned short *utable = nil;
	pdf_font *font;
	FT_Face face;
	FT_CharMap cmap;
	int kind;
	int symbolic;

	char *basefont;
	char *estrings[256];
	int i, k, n, e;

	basefont = fz_toname(fz_dictgets(dict, "BaseFont"));
	basefont = cleanfontname(basefont);

	/*
	 * Load font file
	 */

printf("loading simple font %s\n", basefont);

	font = *fontp = pdf_newfont(basefont);
	if (!font)
		return fz_outofmem;

	descriptor = fz_dictgets(dict, "FontDescriptor");
	if (descriptor)
		error = pdf_loadfontdescriptor(font, xref, descriptor, nil);
	else
		error = pdf_loadbuiltinfont(font, basefont);
	if (error)
		goto cleanup;

	face = font->ftface;
	kind = ftkind(face);

	symbolic = font->flags & 4;

	fz_setfontbbox((fz_font*)font,
		face->bbox.xMin, face->bbox.yMin,
		face->bbox.xMax, face->bbox.yMax);

	/*
	 * Encoding
	 */

	if (face->num_charmaps > 0)
		cmap = face->charmaps[0];
	else
		cmap = nil;

	for (i = 0; i < face->num_charmaps; i++)
	{
		FT_CharMap test = face->charmaps[i];

		if (kind == CFF || kind == TYPE1)
		{
			if (test->platform_id == 7)
				cmap = test;
		}

		if (kind == TRUETYPE)
		{
			if (test->platform_id == 1 && test->encoding_id == 0)
				cmap = test;
			if (test->platform_id == 3 && test->encoding_id == 1)
				cmap = test;
		}
	}

	if (cmap)
	{
		e = FT_Set_Charmap(face, cmap);
		if (e)
		{
			error = fz_throw("freetype could not set cmap: 0x%x", e);
			goto cleanup;
		}
	}
	else
		fz_warn("freetype could not find any cmaps");

	etable = fz_malloc(sizeof(unsigned short) * 256);
	if (!etable)
		goto cleanup;

	for (i = 0; i < 256; i++)
	{
		estrings[i] = nil;
		etable[i] = 0;
	}

	encoding = fz_dictgets(dict, "Encoding");
	if (encoding && !(kind == TRUETYPE && symbolic))
	{
		error = pdf_resolve(&encoding, xref);
		if (error)
			goto cleanup;

		if (fz_isname(encoding))
			pdf_loadencoding(estrings, fz_toname(encoding));

		if (fz_isdict(encoding))
		{
			fz_obj *base, *diff, *item;

			base = fz_dictgets(encoding, "BaseEncoding");
			if (fz_isname(base))
				pdf_loadencoding(estrings, fz_toname(base));

			diff = fz_dictgets(encoding, "Differences");
			if (fz_isarray(diff))
			{
				n = fz_arraylen(diff);
				k = 0;
				for (i = 0; i < n; i++)
				{
					item = fz_arrayget(diff, i);
					if (fz_isint(item))
						k = fz_toint(item);
					if (fz_isname(item))
						estrings[k++] = fz_toname(item);
					if (k < 0) k = 0;
					if (k > 255) k = 255;
				}
			}
		}

		if (kind == TYPE1 || kind == CFF)
		{
			for (i = 0; i < 256; i++)
				if (estrings[i])
					etable[i] = FT_Get_Name_Index(face, estrings[i]);
				else
					etable[i] = FT_Get_Char_Index(face, i);
		}

		if (kind == TRUETYPE)
		{
			/* Unicode cmap */
			if (face->charmap->platform_id == 3)
			{
printf("  winansi cmap\n");
				for (i = 0; i < 256; i++)
					if (estrings[i])
					{
						k = pdf_lookupagl(estrings[i]);
						if (k == -1)
							etable[i] = FT_Get_Name_Index(face, estrings[i]);
						else
							etable[i] = FT_Get_Char_Index(face, k);
					}
					else
						etable[i] = FT_Get_Char_Index(face, i);
			}

			/* MacRoman cmap */
			else if (face->charmap->platform_id == 1)
			{
printf("  macroman cmap\n");
				for (i = 0; i < 256; i++)
					if (estrings[i])
					{
						k = mrecode(estrings[i]);
						if (k <= 0)
							etable[i] = FT_Get_Name_Index(face, estrings[i]);
						else
							etable[i] = FT_Get_Char_Index(face, k);
					}
					else
						etable[i] = FT_Get_Char_Index(face, i);
			}

			/* Symbolic cmap */
			else
			{
printf("  symbolic cmap\n");
				for (i = 0; i < 256; i++)
					etable[i] = FT_Get_Char_Index(face, i);
			}
		}

		fz_dropobj(encoding);
	}

	else
	{
printf("  builtin encoding\n");
		for (i = 0; i < 256; i++)
			etable[i] = FT_Get_Char_Index(face, i);
	}

	error = pdf_makeidentitycmap(&font->encoding, 0, 1);
	if (error)
		goto cleanup;

	font->ncidtogid = 256;
	font->cidtogid = etable;

	/*
	 * ToUnicode
	 */

	utable = fz_malloc(sizeof(unsigned short) * 256);
	if (!utable)
		goto cleanup;

	for (i = 0; i < 256; i++)
		if (estrings[i])
			utable[i] = pdf_lookupagl(estrings[i]);
		else
			utable[i] = i;

	tounicode = fz_dictgets(dict, "ToUnicode");
	if (fz_isindirect(tounicode))
	{
printf("  load tounicode cmap for simple font\n");
	}

	font->ncidtoucs = 256;
	font->cidtoucs = utable;

	/*
	 * Widths
	 */

	fz_setdefaulthmtx((fz_font*)font, font->missingwidth);

	widths = fz_dictgets(dict, "Widths");
	if (widths)
	{
		int first, last;

		error = pdf_resolve(&widths, xref);
		if (error)
			goto cleanup;

		first = fz_toint(fz_dictgets(dict, "FirstChar"));
		last = fz_toint(fz_dictgets(dict, "LastChar"));

printf("  widths vector %d to %d\n", first, last);

		if (first < 0 || last > 255 || first > last)
			first = last = 0;

		for (i = 0; i < last - first + 1; i++)
		{
			int wid = fz_toint(fz_arrayget(widths, i));
			error = fz_addhmtx((fz_font*)font, i + first, i + first, wid);
			if (error)
				goto cleanup;
		}

		fz_dropobj(widths);
	}
	else
	{
printf("  builtin widths\n");
		FT_Set_Char_Size(face, 1000, 1000, 72, 72);
		for (i = 0; i < 256; i++)
		{
			error = fz_addhmtx((fz_font*)font, i, i, ftwidth(font, i));
			if (error)
				goto cleanup;
		}
	}

	error = fz_endhmtx((fz_font*)font);
	if (error)
		goto cleanup;

	FT_Set_Char_Size(face, 64, 64, 72, 72);

printf("\n");

	return nil;

cleanup:
	fz_free(utable);
	fz_free(etable);
	if (widths)
		fz_dropobj(widths);
	fz_dropfont((fz_font*)font);
	*fontp = nil;
	return error;
}

/*
 * CID Fonts
 */

static fz_error *
loadcidfont(pdf_font **fontp, pdf_xref *xref, fz_obj *dict, fz_obj *encoding)
{
	fz_error *error;
	fz_obj *widths = nil;
	fz_obj *descriptor;
	pdf_font *font;
	FT_Face face;
	int kind;
	char collection[256];
	char *basefont;
	int i, k;

	/*
	 * Get font name and CID collection
	 */

	basefont = fz_toname(fz_dictgets(dict, "BaseFont"));

printf("loading cid font %s\n", basefont);

	{
		fz_obj *cidinfo;
		fz_obj *obj;
		char tmpstr[64];
		int tmplen;

		cidinfo = fz_dictgets(dict, "CIDSystemInfo");

		error = pdf_resolve(&cidinfo, xref);
		if (error)
			return error;

		obj = fz_dictgets(cidinfo, "Registry");
		tmplen = MIN(sizeof tmpstr - 1, fz_tostringlen(obj));
		memcpy(tmpstr, fz_tostringbuf(obj), tmplen);
		tmpstr[tmplen] = '\0';
		strlcpy(collection, tmpstr, sizeof collection);

		strlcat(collection, "-", sizeof collection);

		obj = fz_dictgets(cidinfo, "Ordering");
		tmplen = MIN(sizeof tmpstr - 1, fz_tostringlen(obj));
		memcpy(tmpstr, fz_tostringbuf(obj), tmplen);
		tmpstr[tmplen] = '\0';
		strlcat(collection, tmpstr, sizeof collection);

		fz_dropobj(cidinfo);
	}

printf("  collection %s\n", collection);

	/*
	 * Load font file
	 */

	font = *fontp = pdf_newfont(basefont);
	if (!font)
		return fz_outofmem;

	descriptor = fz_dictgets(dict, "FontDescriptor");
	if (descriptor)
		error = pdf_loadfontdescriptor(font, xref, descriptor, collection);
	else
		error = fz_throw("syntaxerror: missing font descriptor");
	if (error)
		goto cleanup;

	face = font->ftface;
	kind = ftkind(face);

	fz_setfontbbox((fz_font*)font,
		face->bbox.xMin, face->bbox.yMin,
		face->bbox.xMax, face->bbox.yMax);

	/*
	 * Encoding
	 */

	if (fz_isname(encoding))
	{
printf("  external CMap %s\n", fz_toname(encoding));
		if (!strcmp(fz_toname(encoding), "Identity-H"))
			error = pdf_makeidentitycmap(&font->encoding, 0, 2);
		else if (!strcmp(fz_toname(encoding), "Identity-V"))
			error = pdf_makeidentitycmap(&font->encoding, 1, 2);
		else
			error = pdf_loadsystemcmap(&font->encoding, fz_toname(encoding));
	}
	else if (fz_isindirect(encoding))
	{
printf("  embedded CMap\n");
		error = pdf_loadembeddedcmap(&font->encoding, xref, encoding);
	}
	else
	{
		error = fz_throw("syntaxerror: font missing encoding");
	}
	if (error)
		goto cleanup;

	fz_setfontwmode((fz_font*)font, fz_getwmode(font->encoding));

	if (kind == TRUETYPE)
	{
		fz_obj *cidtogidmap;

		cidtogidmap = fz_dictgets(dict, "CIDToGIDMap");
		if (fz_isindirect(cidtogidmap))
		{
			unsigned short *map;
			fz_buffer *buf;
			int len;

			error = pdf_loadstream(&buf, xref, fz_tonum(cidtogidmap), fz_togen(cidtogidmap));
			if (error)
				goto cleanup;

			len = (buf->wp - buf->rp) / 2;

			map = fz_malloc(len * sizeof(unsigned short));
			if (!map) {
				fz_dropbuffer(buf);
				error = fz_outofmem;
				goto cleanup;
			}

printf("  cidtogidmap %d\n", len / 2);

			for (i = 0; i < len; i++)
				map[i] = (buf->rp[i * 2] << 8) + buf->rp[i * 2 + 1];

			font->ncidtogid = len;
			font->cidtogid = map;

			fz_dropbuffer(buf);
		}

		/* TODO: if truetype font is external, cidtogidmap should not be identity */
		/* we should map the cid to another encoding represented by a 'cmap' table */
		/* cids: Adobe-CNS1 Adobe-GB1 Adobe-Japan1 Adobe-Japan2 Adobe-Korea1 */
    	/* cmap: Big5 Johab PRC  ShiftJIS Unicode Wansung */
		/* win:  3,4  3,6   3,3  3,2      3,1     3,5 */
	}

	/*
	 * ToUnicode
	 */

	if (fz_dictgets(dict, "ToUnicode"))
		printf("  load tounicode for cid-font");

	if (!strcmp(collection, "Adobe-CNS1"))
		error = pdf_loadsystemcmap(&font->tounicode, "Adobe-CNS1-UCS2");
	else if (!strcmp(collection, "Adobe-GB1"))
		error = pdf_loadsystemcmap(&font->tounicode, "Adobe-GB1-UCS2");
	else if (!strcmp(collection, "Adobe-Japan1"))
		error = pdf_loadsystemcmap(&font->tounicode, "Adobe-Japan1-UCS2");
	else if (!strcmp(collection, "Adobe-Japan2"))
		error = pdf_loadsystemcmap(&font->tounicode, "Adobe-Japan2-UCS2");
	else if (!strcmp(collection, "Adobe-Korea1"))
		error = pdf_loadsystemcmap(&font->tounicode, "Adobe-Korea1-UCS2");
	else
	{
		printf("  unknown character collection\n");
		error = nil;
	}
	if (error)
		goto cleanup;

	/*
	 * Horizontal
	 */

	fz_setdefaulthmtx((fz_font*)font, fz_toint(fz_dictgets(dict, "DW")));

	widths = fz_dictgets(dict, "W");
	if (widths)
	{
		int c0, c1, w;
		fz_obj *obj;

		error = pdf_resolve(&widths, xref);
		if (error)
			goto cleanup;

		for (i = 0; i < fz_arraylen(widths); )
		{
			c0 = fz_toint(fz_arrayget(widths, i));
			obj = fz_arrayget(widths, i + 1);
			if (fz_isarray(obj))
			{
				for (k = 0; k < fz_arraylen(obj); k++)
				{
					w = fz_toint(fz_arrayget(obj, k));
					error = fz_addhmtx((fz_font*)font, c0 + k, c0 + k, w);
					if (error)
						goto cleanup;
				}
				i += 2;
			}
			else
			{
				c1 = fz_toint(obj);
				w = fz_toint(fz_arrayget(widths, i + 2));
				error = fz_addhmtx((fz_font*)font, c0, c1, w);
				if (error)
					goto cleanup;
				i += 3;
			}
		}

		fz_dropobj(widths);
	}

	error = fz_endhmtx((fz_font*)font);
	if (error)
		goto cleanup;

	/*
	 * Vertical
	 */

	if (fz_getwmode(font->encoding) == 1)
	{
		fz_obj *obj;
		int dw2y = 880;
		int dw2w = -1000;

		obj = fz_dictgets(dict, "DW2");
		if (obj)
		{
			dw2y = fz_toint(fz_arrayget(obj, 0));
			dw2w = fz_toint(fz_arrayget(obj, 1));
		}

		fz_setdefaultvmtx((fz_font*)font, dw2y, dw2w);

		widths = fz_dictgets(dict, "W2");
		if (widths)
		{
			int c0, c1, w, x, y, k;

			error = pdf_resolve(&widths, xref);
			if (error)
				goto cleanup;

			for (i = 0; i < fz_arraylen(widths); )
			{
				c0 = fz_toint(fz_arrayget(widths, i));
				obj = fz_arrayget(widths, i + 1);
				if (fz_isarray(obj))
				{
					for (k = 0; k < fz_arraylen(obj); k += 3)
					{
						w = fz_toint(fz_arrayget(obj, k + 0));
						x = fz_toint(fz_arrayget(obj, k + 1));
						y = fz_toint(fz_arrayget(obj, k + 2));
						error = fz_addvmtx((fz_font*)font, c0 + k, c0 + k, x, y, w);
						if (error)
							goto cleanup;
					}
					i += 2;
				}
				else
				{
					c1 = fz_toint(obj);
					w = fz_toint(fz_arrayget(widths, i + 2));
					x = fz_toint(fz_arrayget(widths, i + 3));
					y = fz_toint(fz_arrayget(widths, i + 4));
					error = fz_addvmtx((fz_font*)font, c0, c1, x, y, w);
					if (error)
						goto cleanup;
					i += 5;
				}
			}

			fz_dropobj(widths);
		}

		error = fz_endvmtx((fz_font*)font);
		if (error)
			goto cleanup;
	}

	FT_Set_Char_Size(face, 64, 64, 72, 72);

printf("\n");

	return nil;

cleanup:
	if (widths)
		fz_dropobj(widths);
	fz_dropfont((fz_font*)font);
	*fontp = nil;
	return error;
}

static fz_error *
loadtype0(pdf_font **fontp, pdf_xref *xref, fz_obj *dict)
{
	fz_error *error;
	fz_obj *dfonts;
	fz_obj *dfont;
	fz_obj *subtype;
	fz_obj *encoding;

	dfonts = fz_dictgets(dict, "DescendantFonts");
	error = pdf_resolve(&dfonts, xref);
	if (error)
		return error;

	dfont = fz_arrayget(dfonts, 0);
	error = pdf_resolve(&dfont, xref);
	if (error)
		return fz_dropobj(dfonts), error;

	encoding = fz_dictgets(dict, "Encoding");
	subtype = fz_dictgets(dfont, "Subtype");

	if (!strcmp(fz_toname(subtype), "CIDFontType0"))
		error = loadcidfont(fontp, xref, dfont, encoding);
	else if (!strcmp(fz_toname(subtype), "CIDFontType2"))
		error = loadcidfont(fontp, xref, dfont, encoding);
	else
		error = fz_throw("syntaxerror: unknown cid font type");

	fz_dropobj(dfont);
	fz_dropobj(dfonts);

	if (error)
		return error;

	return nil;
}

/*
 * FontDescriptor
 */

fz_error *
pdf_loadfontdescriptor(pdf_font *font, pdf_xref *xref, fz_obj *desc, char *collection)
{
	fz_error *error;
	fz_obj *obj1, *obj2, *obj3, *obj;
	char *fontname;

	error = pdf_resolve(&desc, xref);
	if (error)
		return error;

	fontname = fz_toname(fz_dictgets(desc, "FontName"));

	font->flags = fz_toint(fz_dictgets(desc, "Flags"));
	font->italicangle = fz_toreal(fz_dictgets(desc, "ItalicAngle"));
	font->ascent = fz_toreal(fz_dictgets(desc, "Ascent"));
	font->descent = fz_toreal(fz_dictgets(desc, "Descent"));
	font->capheight = fz_toreal(fz_dictgets(desc, "CapHeight"));
	font->xheight = fz_toreal(fz_dictgets(desc, "XHeight"));
	font->missingwidth = fz_toreal(fz_dictgets(desc, "MissingWidth"));

	obj1 = fz_dictgets(desc, "FontFile");
	obj2 = fz_dictgets(desc, "FontFile2");
	obj3 = fz_dictgets(desc, "FontFile3");
	obj = obj1 ? obj1 : obj2 ? obj2 : obj3;

	if (fz_isindirect(obj))
	{
		error = pdf_loadembeddedfont(font, xref, obj);
		if (error)
			goto cleanup;
	}
	else
	{
		error = pdf_loadsystemfont(font, fontname, collection);
		if (error)
			goto cleanup;
	}

	fz_dropobj(desc);

	return nil;

cleanup:
	fz_dropobj(desc);
	return error;
}

fz_error *
pdf_loadfont(pdf_font **fontp, pdf_xref *xref, fz_obj *dict)
{
	char *subtype = fz_toname(fz_dictgets(dict, "Subtype"));
	if (!strcmp(subtype, "Type0"))
		return loadtype0(fontp, xref, dict);
	if (!strcmp(subtype, "Type1") || !strcmp(subtype, "MMType1"))
		return loadsimplefont(fontp, xref, dict);
	else if (!strcmp(subtype, "TrueType"))
		return loadsimplefont(fontp, xref, dict);
	else if (!strcmp(subtype, "Type3"))
		return pdf_loadtype3font(fontp, xref, dict);
	else
		return fz_throw("unimplemented: %s fonts", subtype);
}

