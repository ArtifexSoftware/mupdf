/* Copyright (C) 2006-2010 Artifex Software, Inc.
   All Rights Reserved.

   This software is provided AS-IS with no warranty, either express or
   implied.

   This software is distributed under license and may not be copied, modified
   or distributed except as expressly authorized under the terms of that
   license.  Refer to licensing information at http://www.artifex.com/
   or contact Artifex Software, Inc.,  7 Mt. Lassen  Drive - Suite A-134,
   San Rafael, CA  94903, U.S.A., +1(415)492-9861, for further information.
*/

/* XPS interpreter - general font functions */

#include "ghostxps.h"

static void xps_load_sfnt_cmap(xps_font_t *font);

/*
 * Big-endian memory accessor functions
 */

static inline int s16(byte *p)
{
	return (signed short)( (p[0] << 8) | p[1] );
}

static inline int u16(byte *p)
{
	return (p[0] << 8) | p[1];
}

static inline int u24(byte *p)
{
	return (p[0] << 16) | (p[1] << 8) | p[2];
}

static inline int u32(byte *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

xps_font_t *
xps_new_font(xps_context_t *ctx, byte *buf, int buflen, int index)
{
	xps_font_t *font;
	int code;

	font = xps_alloc(ctx, sizeof(xps_font_t));
	if (!font)
	{
		gs_throw(-1, "out of memory");
		return NULL;
	}

	font->data = buf;
	font->length = buflen;
	font->font = NULL;

	font->subfontid = index;
	font->cmaptable = 0;
	font->cmapsubcount = 0;
	font->cmapsubtable = 0;
	font->usepua = 0;

	font->cffdata = 0;
	font->cffend = 0;
	font->gsubrs = 0;
	font->subrs = 0;
	font->charstrings = 0;

	if (memcmp(font->data, "OTTO", 4) == 0)
		code = xps_init_postscript_font(ctx, font);
	else if (memcmp(font->data, "\0\1\0\0", 4) == 0)
		code = xps_init_truetype_font(ctx, font);
	else if (memcmp(font->data, "true", 4) == 0)
		code = xps_init_truetype_font(ctx, font);
	else if (memcmp(font->data, "ttcf", 4) == 0)
		code = xps_init_truetype_font(ctx, font);
	else
	{
		xps_free_font(ctx, font);
		gs_throw(-1, "not an opentype font");
		return NULL;
	}

	if (code < 0)
	{
		xps_free_font(ctx, font);
		gs_rethrow(-1, "cannot init font");
		return NULL;
	}

	xps_load_sfnt_cmap(font);

	return font;
}

void
xps_free_font(xps_context_t *ctx, xps_font_t *font)
{
	if (font->font)
	{
		gs_font_finalize(font->font);
		gs_free_object(ctx->memory, font->font, "font object");
	}
	xps_free(ctx, font);
}

/*
 * Find the offset and length of an SFNT table.
 * Return -1 if no table by the specified name is found.
 */

int
xps_find_sfnt_table(xps_font_t *font, const char *name, int *lengthp)
{
	int offset;
	int ntables;
	int i;

	if (font->length < 12)
		return -1;

	if (!memcmp(font->data, "ttcf", 4))
	{
		int nfonts = u32(font->data + 8);
		if (font->subfontid < 0 || font->subfontid >= nfonts)
		{
			gs_warn("Invalid subfont ID");
			return -1;
		}
		offset = u32(font->data + 12 + font->subfontid * 4);
	}
	else
	{
		offset = 0;
	}

	ntables = u16(font->data + offset + 4);
	if (font->length < offset + 12 + ntables * 16)
		return -1;

	for (i = 0; i < ntables; i++)
	{
		byte *entry = font->data + offset + 12 + i * 16;
		if (!memcmp(entry, name, 4))
		{
			if (lengthp)
				*lengthp = u32(entry + 12);
			return u32(entry + 8);
		}
	}

	return -1;
}

/*
 * Get the windows truetype font file name - position 4 in the name table.
 */
void
xps_load_sfnt_name(xps_font_t *font, char *namep)
{
	byte *namedata;
	int offset, length;
	int format, count, stringoffset;
	int i;

	strcpy(namep, "Unknown");

	offset = xps_find_sfnt_table(font, "name", &length);
	if (offset < 0 || length < 6)
	{
		gs_warn("cannot find name table");
		return;
	}

	namedata = font->data + offset;

	format = u16(namedata + 0);
	count = u16(namedata + 2);
	stringoffset = u16(namedata + 4);

	for (i = 0; i < count; i++)
	{
		byte *record = namedata + 6 + i * 12;
		int pid = u16(record + 0);
		int eid = u16(record + 2);
		int langid = u16(record + 4);
		int nameid = u16(record + 6);
		length = u16(record + 8);
		offset = u16(record + 10);

		/* Mac Roman English */
		if (pid == 1 && eid == 0 && langid == 0)
		{
			/* Full font name or postscript name */
			if (nameid == 4 || nameid == 6)
			{
				memcpy(namep, namedata + stringoffset + offset, length);
				namep[length] = 0;
			}
		}
	}
}

/*
 * Locate the 'cmap' table and count the number of subtables.
 */

static void
xps_load_sfnt_cmap(xps_font_t *font)
{
	byte *cmapdata;
	int offset, length;
	int nsubtables;

	offset = xps_find_sfnt_table(font, "cmap", &length);
	if (offset < 0 || length < 4)
	{
		gs_warn("cannot find cmap table");
		return;
	}

	cmapdata = font->data + offset;

	nsubtables = u16(cmapdata + 2);
	if (nsubtables < 0 || length < 4 + nsubtables * 8)
	{
		gs_warn("cannot find cmap sub-tables");
		return;
	}

	font->cmaptable = offset;
	font->cmapsubcount = nsubtables;
	font->cmapsubtable = 0;
}

/*
 * Return the number of cmap subtables.
 */

int
xps_count_font_encodings(xps_font_t *font)
{
	return font->cmapsubcount;
}

/*
 * Extract PlatformID and EncodingID for a cmap subtable.
 */

void
xps_identify_font_encoding(xps_font_t *font, int idx, int *pid, int *eid)
{
	byte *cmapdata, *entry;
	if (idx < 0 || idx >= font->cmapsubcount)
		return;
	cmapdata = font->data + font->cmaptable;
	entry = cmapdata + 4 + idx * 8;
	*pid = u16(entry + 0);
	*eid = u16(entry + 2);
}

/*
 * Select a cmap subtable for use with encoding functions.
 */

void
xps_select_font_encoding(xps_font_t *font, int idx)
{
	byte *cmapdata, *entry;
	int pid, eid;
	if (idx < 0 || idx >= font->cmapsubcount)
		return;
	cmapdata = font->data + font->cmaptable;
	entry = cmapdata + 4 + idx * 8;
	pid = u16(entry + 0);
	eid = u16(entry + 2);
	font->cmapsubtable = font->cmaptable + u32(entry + 4);
	font->usepua = (pid == 3 && eid == 0);
}

/*
 * Encode a character using the selected cmap subtable.
 * TODO: extend this to cover more cmap formats.
 */

static int
xps_encode_font_char_imp(xps_font_t *font, int code)
{
	byte *table;

	/* no cmap selected: return identity */
	if (font->cmapsubtable <= 0)
		return code;

	table = font->data + font->cmapsubtable;

	switch (u16(table))
	{
	case 0: /* Apple standard 1-to-1 mapping. */
		return table[code + 6];

	case 4: /* Microsoft/Adobe segmented mapping. */
		{
			int segCount2 = u16(table + 6);
			byte *endCount = table + 14;
			byte *startCount = endCount + segCount2 + 2;
			byte *idDelta = startCount + segCount2;
			byte *idRangeOffset = idDelta + segCount2;
			int i2;

			for (i2 = 0; i2 < segCount2 - 3; i2 += 2)
			{
				int delta, roff;
				int start = u16(startCount + i2);
				int glyph;

				if ( code < start )
					return 0;
				if ( code > u16(endCount + i2) )
					continue;
				delta = s16(idDelta + i2);
				roff = s16(idRangeOffset + i2);
				if ( roff == 0 )
				{
					return ( code + delta ) & 0xffff; /* mod 65536 */
					return 0;
				}
				glyph = u16(idRangeOffset + i2 + roff + ((code - start) << 1));
				return (glyph == 0 ? 0 : glyph + delta);
			}

			/*
			 * The TrueType documentation says that the last range is
			 * always supposed to end with 0xffff, so this shouldn't
			 * happen; however, in some real fonts, it does.
			 */
			return 0;
		}

	case 6: /* Single interval lookup. */
		{
			int firstCode = u16(table + 6);
			int entryCount = u16(table + 8);
			if ( code < firstCode || code >= firstCode + entryCount )
				return 0;
			return u16(table + 10 + ((code - firstCode) << 1));
		}

	case 10: /* Trimmed array (like 6) */
		{
			int startCharCode = u32(table + 12);
			int numChars = u32(table + 16);
			if ( code < startCharCode || code >= startCharCode + numChars )
				return 0;
			return u32(table + 20 + (code - startCharCode) * 4);
		}

	case 12: /* Segmented coverage. (like 4) */
		{
			int nGroups = u32(table + 12);
			byte *group = table + 16;
			int i;

			for (i = 0; i < nGroups; i++)
			{
				int startCharCode = u32(group + 0);
				int endCharCode = u32(group + 4);
				int startGlyphID = u32(group + 8);
				if ( code < startCharCode )
					return 0;
				if ( code <= endCharCode )
					return startGlyphID + (code - startCharCode);
				group += 12;
			}

			return 0;
		}

	case 2: /* High-byte mapping through table. */
	case 8: /* Mixed 16-bit and 32-bit coverage (like 2) */
	default:
		gs_warn1("unknown cmap format: %d\n", u16(table));
		return 0;
	}

	return 0;
}

int
xps_encode_font_char(xps_font_t *font, int code)
{
	int gid = xps_encode_font_char_imp(font, code);
	if (gid == 0 && font->usepua)
		gid = xps_encode_font_char_imp(font, 0xF000 | code);
	return gid;
}

/*
 * Get glyph metrics by parsing TTF tables manually.
 * XPS needs more and different metrics than postscript/ghostscript
 * use so the native ghostscript functions are not adequate.
 */

void
xps_measure_font_glyph(xps_context_t *ctx, xps_font_t *font, int gid, xps_glyph_metrics_t *mtx)
{

	int head, format, loca, glyf;
	int ofs, len;
	int idx, i, n;
	int hadv, vadv, vorg;
	int vtop, ymax, desc;
	int scale;

	/* some insane defaults */

	scale = 1000; /* units-per-em */
	hadv = 500;
	vadv = -1000;
	vorg = 1000;

	/*
	 * Horizontal metrics are easy.
	 */

	ofs = xps_find_sfnt_table(font, "hhea", &len);
	if (ofs < 0 || len < 2 * 18)
	{
		gs_warn("hhea table is too short");
		return;
	}

	vorg = s16(font->data + ofs + 4); /* ascender is default vorg */
	desc = s16(font->data + ofs + 6); /* descender */
	if (desc < 0)
		desc = -desc;
	n = u16(font->data + ofs + 17 * 2);

	ofs = xps_find_sfnt_table(font, "hmtx", &len);
	if (ofs < 0)
	{
		gs_warn("cannot find hmtx table");
		return;
	}

	idx = gid;
	if (idx > n - 1)
		idx = n - 1;

	hadv = u16(font->data + ofs + idx * 4);
	vadv = 0;

	/*
	 * Vertical metrics are hairy (with missing tables).
	 */

	head = xps_find_sfnt_table(font, "head", &len);
	if (head > 0)
	{
		scale = u16(font->data + head + 18); /* units per em */
	}

	ofs = xps_find_sfnt_table(font, "OS/2", &len);
	if (ofs > 0 && len > 70)
	{
		vorg = s16(font->data + ofs + 68); /* sTypoAscender */
		desc = s16(font->data + ofs + 70); /* sTypoDescender */
		if (desc < 0)
			desc = -desc;
	}

	ofs = xps_find_sfnt_table(font, "vhea", &len);
	if (ofs > 0 && len >= 2 * 18)
	{
		n = u16(font->data + ofs + 17 * 2);

		ofs = xps_find_sfnt_table(font, "vmtx", &len);
		if (ofs < 0)
		{
			gs_warn("cannot find vmtx table");
			return;
		}

		idx = gid;
		if (idx > n - 1)
			idx = n - 1;

		vadv = u16(font->data + ofs + idx * 4);
		vtop = u16(font->data + ofs + idx * 4 + 2);

		glyf = xps_find_sfnt_table(font, "glyf", &len);
		loca = xps_find_sfnt_table(font, "loca", &len);
		if (head > 0 && glyf > 0 && loca > 0)
		{
			format = u16(font->data + head + 50); /* indexToLocaFormat */

			if (format == 0)
				ofs = u16(font->data + loca + gid * 2) * 2;
			else
				ofs = u32(font->data + loca + gid * 4);

			ymax = u16(font->data + glyf + ofs + 8); /* yMax */

			vorg = ymax + vtop;
		}
	}

	ofs = xps_find_sfnt_table(font, "VORG", &len);
	if (ofs > 0)
	{
		vorg = u16(font->data + ofs + 6);
		n = u16(font->data + ofs + 6);
		for (i = 0; i < n; i++)
		{
			if (u16(font->data + ofs + 8 + 4 * i) == gid)
			{
				vorg = s16(font->data + ofs + 8 + 4 * i + 2);
				break;
			}
		}
	}

	if (vadv == 0)
		vadv = vorg + desc;

	mtx->hadv = hadv / (float) scale;
	mtx->vadv = vadv / (float) scale;
	mtx->vorg = vorg / (float) scale;
}
