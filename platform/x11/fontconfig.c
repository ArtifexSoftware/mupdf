#include "mupdf/fitz.h"

#ifdef HAVE_FONTCONFIG

#include <fontconfig/fontconfig.h>

static FcConfig *config = NULL; /* TODO: move to fz_font_context as void* ? */

fz_buffer *fz_load_system_font_fc(fz_context *ctx, const char *fontname)
{
	char family[2048], *style;
	char *match_file, *match_family, *match_style;
	FcPattern *search = NULL;
	FcPattern *match = NULL;
	FcResult result;
	fz_stream *stm = NULL;
	fz_buffer *buf = NULL;

	if (!config)
	{
		config = FcInitLoadConfigAndFonts();
		if (!config)
		{
			fz_warn(ctx, "cannot initialize fontconfig");
			return NULL;
		}
	}

	/* Split font name into family and style */
	fz_strlcpy(family, fontname, sizeof family);
	style = strchr(family, ',');
	if (!style) style = strchr(family, '-');
	if (style) *style++ = 0;

	/* Create an FcPattern for matching the family and style */
	search = FcPatternCreate();
	FcPatternAddBool(search, FC_OUTLINE, 1);
	FcPatternAddString(search, FC_FAMILY, (FcChar8*)family);
	if (style) FcPatternAddString(search, FC_STYLE, (FcChar8*)style);
	FcDefaultSubstitute(search);
	FcConfigSubstitute(config, search, FcMatchPattern);

	/* Find a candidate */
	match = FcFontMatch(config, search, &result);
	if (result != FcResultMatch)
		goto error;

	result = FcPatternGetString(match, FC_FAMILY, 0, (FcChar8**)&match_family);
	if (result != FcResultMatch)
		goto error;
	result = FcPatternGetString(match, FC_STYLE, 0, (FcChar8**)&match_style);
	if (result != FcResultMatch)
		goto error;
	result = FcPatternGetString(match, FC_FILE, 0, (FcChar8**)&match_file);
	if (result != FcResultMatch)
		goto error;

	if (strcmp(family, match_family))
		goto error;
	if (style && strcmp(style, match_style))
		goto error;

	fprintf(stderr, "load system font family=%s style=%s %s\n", family, style?style:"", match_file);

	fz_var(stm);
	fz_var(buf);

	fz_try(ctx)
	{
		stm = fz_open_file(ctx, match_file);
		buf = fz_read_all(stm, 0);
	}
	fz_always(ctx)
	{
		fz_close(stm);
	}
	fz_catch(ctx)
	{
	}

	if (!buf) fz_warn(ctx, "cannot load system font: %s", fontname);
	FcPatternDestroy(search);
	FcPatternDestroy(match);
	return buf;
}

#endif
