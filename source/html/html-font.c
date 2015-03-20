#include "mupdf/html.h"

unsigned char *pdf_lookup_builtin_font(fz_context *ctx, const char *name, unsigned int *len);

static const char *font_names[16] =
{
	"Times-Roman", "Times-Italic", "Times-Bold", "Times-BoldItalic",
	"Helvetica", "Helvetica-Oblique", "Helvetica-Bold", "Helvetica-BoldOblique",
	"Courier", "Courier-Oblique", "Courier-Bold", "Courier-BoldOblique",
	"Courier", "Courier-Oblique", "Courier-Bold", "Courier-BoldOblique",
};

fz_font *
fz_load_html_font(fz_context *ctx, fz_html_font_set *set,
	const char *family, const char *variant, const char *style, const char *weight)
{
	unsigned char *data;
	unsigned int size;

	int is_mono = !strcmp(family, "monospace");
	int is_sans = !strcmp(family, "sans-serif");
	int is_bold = !strcmp(weight, "bold") || !strcmp(weight, "bolder") || atoi(weight) > 400;
	int is_italic = !strcmp(style, "italic") || !strcmp(style, "oblique");

	int idx = is_mono * 8 + is_sans * 4 + is_bold * 2 + is_italic;
	if (!set->fonts[idx])
	{
		data = pdf_lookup_builtin_font(ctx, font_names[idx], &size);
		if (!data)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot load html font: %s", font_names[idx]);
		set->fonts[idx] = fz_new_font_from_memory(ctx, font_names[idx], data, size, 0, 1);
	}

	return set->fonts[idx];
}

fz_html_font_set *fz_new_html_font_set(fz_context *ctx)
{
	return fz_malloc_struct(ctx, fz_html_font_set);
}

void fz_drop_html_font_set(fz_context *ctx, fz_html_font_set *set)
{
	int i;
	for (i = 0; i < nelem(set->fonts); ++i)
		fz_drop_font(ctx, set->fonts[i]);
	fz_free(ctx, set);
}
