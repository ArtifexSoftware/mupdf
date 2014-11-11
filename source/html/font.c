#include "mupdf/html.h"
#include "mupdf/pdf.h" /* for pdf_lookup_substitute_font */

#include <ft2build.h>
#include FT_FREETYPE_H

static int ft_is_bold(FT_Face face)
{
	return face->style_flags & FT_STYLE_FLAG_BOLD;
}

static int ft_is_italic(FT_Face face)
{
	return face->style_flags & FT_STYLE_FLAG_ITALIC;
}

fz_font *
html_load_font(fz_context *ctx,
	const char *family, const char *variant, const char *style, const char *weight)
{
	unsigned char *data;
	unsigned int size;
	fz_font *font;

	int is_bold = !strcmp(weight, "bold");
	int is_italic = !strcmp(style, "italic");

	int is_mono = !strcmp(family, "monospace");
	int is_sans = !strcmp(family, "sans-serif");

	// TODO: keep a cache of loaded fonts

	data = pdf_lookup_substitute_font(is_mono, !is_sans, is_bold, is_italic, &size);

	font = fz_new_font_from_memory(ctx, family, data, size, 0, 1);
	font->ft_bold = is_bold && !ft_is_bold(font->ft_face);
	font->ft_italic = is_italic && !ft_is_italic(font->ft_face);

	return font;
}
