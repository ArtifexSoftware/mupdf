#include "mupdf/html.h"
#include "mupdf/pdf.h" /* for pdf_lookup_builtin_font */

static const char *font_names[16] = {
	"Times-Roman", "Times-Italic", "Times-Bold", "Times-BoldItalic",
	"Helvetica", "Helvetica-Oblique", "Helvetica-Bold", "Helvetica-BoldOblique",
	"Courier", "Courier-Oblique", "Courier-Bold", "Courier-BoldOblique",
	"Courier", "Courier-Oblique", "Courier-Bold", "Courier-BoldOblique",
};

fz_font *
html_load_font(fz_context *ctx, html_context *htx,
	const char *family, const char *variant, const char *style, const char *weight)
{
	unsigned char *data;
	unsigned int size;

	int is_mono = !strcmp(family, "monospace");
	int is_sans = !strcmp(family, "sans-serif");
	int is_bold = !strcmp(weight, "bold") || !strcmp(weight, "bolder") || atoi(weight) > 400;
	int is_italic = !strcmp(style, "italic") || !strcmp(style, "oblique");

	int idx = is_mono * 8 + is_sans * 4 + is_bold * 2 + is_italic;
	if (!htx->fonts[idx])
	{
		data = pdf_lookup_builtin_font(font_names[idx], &size);
		if (!data) {
		printf("data=%p idx=%d s=%s\n", data, idx, font_names[idx]);
			abort();
		}
		htx->fonts[idx] = fz_new_font_from_memory(ctx, font_names[idx], data, size, 0, 1);
	}

	return htx->fonts[idx];
}
