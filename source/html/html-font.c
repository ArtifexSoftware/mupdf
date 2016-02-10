#include "mupdf/html.h"

static const char *font_names[16] =
{
	"Times-Roman", "Times-Italic", "Times-Bold", "Times-BoldItalic",
	"Helvetica", "Helvetica-Oblique", "Helvetica-Bold", "Helvetica-BoldOblique",
	"Courier", "Courier-Oblique", "Courier-Bold", "Courier-BoldOblique",
	"Courier", "Courier-Oblique", "Courier-Bold", "Courier-BoldOblique",
};

fz_font *
fz_load_html_builtin_font(fz_context *ctx, fz_html_font_set *set, const char *family, int is_bold, int is_italic)
{
	int is_mono = !strcmp(family, "monospace");
	int is_sans = !strcmp(family, "sans-serif");
	int idx = is_mono * 8 + is_sans * 4 + is_bold * 2 + is_italic;
	if (!set->fonts[idx])
	{
		unsigned char *data;
		unsigned int size;

		data = fz_lookup_base14_font(ctx, font_names[idx], &size);
		if (!data)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot load html font: %s", font_names[idx]);
		set->fonts[idx] = fz_new_font_from_memory(ctx, font_names[idx], data, size, 0, 1);
		set->fonts[idx]->is_serif = !is_sans;
	}
	return set->fonts[idx];
}

fz_font *
fz_load_html_font(fz_context *ctx, fz_html_font_set *set, const char *family, int is_bold, int is_italic)
{
	fz_html_font_face *custom;

	for (custom = set->custom; custom; custom = custom->next)
	{
		if (!strcmp(family, custom->family) &&
				is_bold == custom->is_bold &&
				is_italic == custom->is_italic)
		{
			return custom->font;
		}
	}

	if (!strcmp(family, "monospace") ||
			!strcmp(family, "sans-serif") ||
			!strcmp(family, "serif"))
		return fz_load_html_builtin_font(ctx, set, family, is_bold, is_italic);

	return NULL;
}

void
fz_add_html_font_face(fz_context *ctx, fz_html_font_set *set,
	const char *family, int is_bold, int is_italic, const char *src,
	fz_font *font)
{
	fz_html_font_face *custom;

	custom = fz_malloc_struct(ctx, fz_html_font_face);
	custom->font = fz_keep_font(ctx, font);
	custom->src = fz_strdup(ctx, src);
	custom->family = fz_strdup(ctx, family);
	custom->is_bold = is_bold;
	custom->is_italic = is_italic;
	custom->next = set->custom;
	set->custom = custom;
}

fz_html_font_set *fz_new_html_font_set(fz_context *ctx)
{
	return fz_malloc_struct(ctx, fz_html_font_set);
}

void fz_drop_html_font_set(fz_context *ctx, fz_html_font_set *set)
{
	fz_html_font_face *font, *next;
	int i;

	font = set->custom;
	while (font)
	{
		next = font->next;
		fz_drop_font(ctx, font->font);
		fz_free(ctx, font->src);
		fz_free(ctx, font->family);
		fz_free(ctx, font);
		font = next;
	}

	for (i = 0; i < nelem(set->fonts); ++i)
		fz_drop_font(ctx, set->fonts[i]);

	fz_free(ctx, set);
}
