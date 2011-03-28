#include "fitz.h"
#include "muxps.h"

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_ADVANCES_H

int
xps_count_font_encodings(fz_font *font)
{
	FT_Face face = font->ftface;
	return face->num_charmaps;
}

void
xps_identify_font_encoding(fz_font *font, int idx, int *pid, int *eid)
{
	FT_Face face = font->ftface;
	*pid = face->charmaps[idx]->platform_id;
	*eid = face->charmaps[idx]->encoding_id;
}

void
xps_select_font_encoding(fz_font *font, int idx)
{
	FT_Face face = font->ftface;
	FT_Set_Charmap(face, face->charmaps[idx]);
}

int
xps_encode_font_char(fz_font *font, int code)
{
	FT_Face face = font->ftface;
	int gid = FT_Get_Char_Index(face, code);
	if (gid == 0 && face->charmap->platform_id == 3 && face->charmap->encoding_id == 0)
		gid = FT_Get_Char_Index(face, 0xF000 | code);
	return gid;
}

void
xps_measure_font_glyph(xps_context_t *ctx, fz_font *font, int gid, xps_glyph_metrics_t *mtx)
{
	int mask = FT_LOAD_NO_BITMAP | FT_LOAD_NO_HINTING | FT_LOAD_IGNORE_TRANSFORM;
	FT_Fixed adv;

	FT_Set_Char_Size(font->ftface, 64, 64, 72, 72);
	FT_Get_Advance(font->ftface, gid, mask, &adv);
	mtx->hadv = adv / 65536.0f;
	mtx->vadv = -1000 / 1000.0f;
	mtx->vorg = 880 / 1000.0f;
}
