#include <fitz.h>
#include <mupdf.h>

#include <ft2build.h>
#include FT_FREETYPE_H
#include <freetype/internal/ftobjs.h>

#include "fontenc.h"
#include "fontagl.h"

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

static int ftwidth(FT_Face face, int gid)
{
	int e;
	e = FT_Load_Glyph(face, gid,
			FT_LOAD_NO_HINTING | FT_LOAD_NO_BITMAP | FT_LOAD_IGNORE_TRANSFORM);
	if (e)
		return 0;
	return face->glyph->advance.x;
}

static fz_error *
ftrender(fz_glyph *glyph, fz_font *font, int gid, fz_matrix trm)
{
	FT_Face face = ((pdf_font*)font)->ftface;
	FT_Matrix m;
	FT_Vector v;
	FT_Error fterr;

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

static char *cleanfontname(char *fontname)
{
	int i, k;
	for (i = 0; i < 14; i++)
		for (k = 0; basefontnames[i][k]; k++)
			if (!strcmp(basefontnames[i][k], fontname))
				return basefontnames[i][0];
	return fontname;
}

static void loadencoding(char **estrings, char *encoding)
{
	char **bstrings = nil;
	int i;

	if (!strcmp(encoding, "MacRomanEncoding"))
		bstrings = macroman;
	if (!strcmp(encoding, "MacExpertEncoding"))
		bstrings = macexpert;
	if (!strcmp(encoding, "WinAnsiEncoding"))
		bstrings = winansi;

	if (bstrings)
		for (i = 0; i < 256; i++)
			estrings[i] = bstrings[i];
}

static int aglcode(char *name)
{
	int l = 0;
	int r = adobeglyphlen;

	while (l <= r)
	{
		int m = (l + r) >> 1;
		int c = strcmp(name, adobeglyphlist[m].name);
		if (c < 0)
			r = m - 1;
		else if (c > 0)
			l = m + 1;
		else
			return adobeglyphlist[m].code;
	}

	if (strstr(name, "uni") == name)
		return strtol(name + 3, 0, 16);

	if (strstr(name, "u") == name)
		return strtol(name + 1, 0, 16);

	return -1;
}

static int mrecode(char *name)
{
	int i;
	for (i = 0; i < 256; i++)
		if (macroman[i] && !strcmp(name, macroman[i]))
			return i;
	return -1;
}

static int cidtogid(pdf_font *font, int cid)
{
	if (font->cidtogidmap)
	{
		if (cid >= 0 && cid < font->cidtogidlen)
			return font->cidtogidmap[cid];
		return 0;
	}
	return cid;
}

static void ftfreefont(fz_font *font)
{
	pdf_font *pfont = (pdf_font*)font;
	if (pfont->encoding)
		fz_freecmap(pfont->encoding);
}

static pdf_font *
newfont(char *name)
{
	pdf_font *font;

	font = fz_malloc(sizeof (pdf_font));
	if (!font)
		return nil;

	fz_initfont((fz_font*)font, name);
	font->super.render = ftrender;
	font->super.free = (void(*)(fz_font*)) ftfreefont;

	font->ftface = nil;
	font->encoding = nil;
	font->cidtogidlen = 0;
	font->cidtogidmap = nil;

	return font;
}

static fz_error *
loadsimplefont(pdf_font **fontp, pdf_xref *xref, fz_obj *dict)
{
	fz_error *error;
	fz_obj *descriptor = nil;
	fz_obj *encoding = nil;
	fz_obj *widths = nil;
	pdf_font *font;
	FT_Face face;
	FT_CharMap cmap;
	int kind;

	char *basefont;
	char *estrings[256];
	int etable[256];
	int i, k, n, e;

	basefont = fz_toname(fz_dictgets(dict, "BaseFont"));
	basefont = cleanfontname(basefont);

	/*
	 * Load font file
	 */

printf("loading simple font %s\n", basefont);

	font = *fontp = newfont(basefont);
	if (!font)
		return fz_outofmem;

	descriptor = fz_dictgets(dict, "FontDescriptor");
	if (descriptor)
		error = pdf_loadfontdescriptor(&font->ftface, xref, descriptor, nil);
	else
		error = pdf_loadsystemfont(&font->ftface, basefont, nil);
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

	if (!cmap)
	{
		error = fz_throw("freetype could not find any cmaps");
		goto cleanup;
	}

	e = FT_Set_Charmap(face, cmap);
	if (e)
	{
		error = fz_throw("freetype could not set cmap: 0x%x", e);
		goto cleanup;
	}

	for (i = 0; i < 256; i++)
	{
		estrings[i] = _notdef;
		etable[i] = 0;
	}

	encoding = fz_dictgets(dict, "Encoding");
	if (encoding)
	{
		error = pdf_resolve(&encoding, xref);
		if (error)
			goto cleanup;


		if (fz_isname(encoding))
			loadencoding(estrings, fz_toname(encoding));

		if (fz_isdict(encoding))
		{
			fz_obj *base, *diff, *item;

			base = fz_dictgets(encoding, "BaseEncoding");
			if (fz_isname(base))
				loadencoding(estrings, fz_toname(base));


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
				for (i = 0; i < 256; i++)
					if (estrings[i])
					{
						k = aglcode(estrings[i]);
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
				for (i = 0; i < 256; i++)
					etable[i] = FT_Get_Char_Index(face, i);
			}
		}

		encoding = fz_dropobj(encoding);
	}

	else
	{
		for (i = 0; i < 256; i++)
			etable[i] = FT_Get_Char_Index(face, i);
	}

	error = fz_newcmap(&font->encoding);
	if (error)
		goto cleanup;

	error = fz_addcodespacerange(font->encoding, 0x00, 0xff, 1);
	if (error)
		goto cleanup;

	error = fz_setcidlookup(font->encoding, etable);
	if (error)
		goto cleanup;

	/*
	 * Widths
	 */

	/* FIXME should set defaulthmtx to MissingWidth in FontDescriptor */

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
			int gid = etable[i + first];
			int wid = fz_toint(fz_arrayget(widths, i));
			if (gid >= 0)
			{
				error = fz_addhmtx((fz_font*)font, gid, wid);
				if (error)
					goto cleanup;
			}
		}

		widths = fz_dropobj(widths);
	}
	else
	{
printf("  builtin widths\n");
		FT_Set_Char_Size(face, 1000, 1000, 72, 72);
		for (i = 0; i < 256; i++)
		{
			int gid = etable[i];
			if (gid >= 0)
			{
				error = fz_addhmtx((fz_font*)font, gid, ftwidth(face, gid));
				if (error)
					goto cleanup;
			}
		}
	}

	error = fz_endhmtx((fz_font*)font);
	if (error)
		goto cleanup;

	FT_Set_Char_Size(face, 64, 64, 72, 72);

printf("\n");

fz_debugfont((fz_font*)font);

	return nil;

cleanup:
	if (widths)
		fz_dropobj(widths);
	fz_freefont((fz_font*)font);
	*fontp = nil;
	return error;
}

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

	font = *fontp = newfont(basefont);
	if (!font)
		return fz_outofmem;

	descriptor = fz_dictgets(dict, "FontDescriptor");
	if (descriptor)
		error = pdf_loadfontdescriptor(&font->ftface, xref, descriptor, collection);
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
			error = pdf_makeidentitycmap(&font->encoding, 0);
		else if (!strcmp(fz_toname(encoding), "Identity-V"))
			error = pdf_makeidentitycmap(&font->encoding, 1);
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
			fz_buffer *buf;
			int len;

			error = pdf_loadstream(&buf, xref, fz_tonum(cidtogidmap), fz_togen(cidtogidmap));
			if (error)
				goto cleanup;

			len = buf->wp - buf->rp;

			font->cidtogidlen = len / 2;
			font->cidtogidmap = fz_malloc((len / 2) * sizeof(int));
			if (!font->cidtogidmap) {
				fz_freebuffer(buf);
				error = fz_outofmem;
				goto cleanup;
			}

printf("  cidtogidmap %d\n", len / 2);

			for (i = 0; i < len / 2; i++)
				font->cidtogidmap[i] = (buf->rp[i * 2] << 8) + buf->rp[i * 2 + 1];

			fz_freebuffer(buf);
		}

		/* TODO: if truetype font is external, cidtogidmap should not be identity */
		/* we should map the cid to another encoding represented by a 'cmap' table */
		/* and then through that to a gid */
		/* cids: Adobe-CNS1 Adobe-GB1 Adobe-Japan1 Adobe-Japan2 Adobe-Korea1 */
    	/* cmap: Big5 Johab PRC  ShiftJIS Unicode Wansung */
		/* win:  3,4  3,6   3,3  3,2      3,1     3,5 */
	}

	/*
	 * Horizontal
	 */

	fz_setdefaulthmtx((fz_font*)font, fz_toint(fz_dictgets(dict, "DW")));

	widths = fz_dictgets(dict, "W");
	if (widths)
	{
		int c0, c1, w, gid;
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
					gid = cidtogid(font, c0 + k);
					error = fz_addhmtx((fz_font*)font, gid, w);
					if (error)
						goto cleanup;
				}
				i += 2;
			}
			else
			{
				c1 = fz_toint(obj);
				w = fz_toint(fz_arrayget(widths, i + 2));
				for (k = c0; k <= c1; k++)
				{
					gid = cidtogid(font, k);
					error = fz_addhmtx((fz_font*)font, gid, w);
					if (error)
						goto cleanup;
				}
				i += 3;
			}
		}

		widths = fz_dropobj(widths);
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
			int c0, c1, w, x, y, k, gid;

			error = pdf_resolve(&widths, xref);
			if (error)
				goto cleanup;

printf("  W2 ");
fz_debugobj(widths);
printf("\n");

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
						gid = cidtogid(font, c0 + k);
						error = fz_addvmtx((fz_font*)font, gid, x, y, w);
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
					for (k = c0; k <= c1; k++)
					{
						gid = cidtogid(font, c0);
						error = fz_addvmtx((fz_font*)font, gid, x, y, w);
						if (error)
							goto cleanup;
					}
					i += 5;
				}
			}

			widths = fz_dropobj(widths);
		}

		error = fz_endvmtx((fz_font*)font);
		if (error)
			goto cleanup;
	}

	FT_Set_Char_Size(face, 64, 64, 72, 72);

printf("\n");

fz_debugfont((fz_font*)font);

	return nil;

cleanup:
	if (widths)
		fz_dropobj(widths);
	fz_freefont((fz_font*)font);
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
	else
		return fz_throw("unimplemented: %s fonts", subtype);
}

