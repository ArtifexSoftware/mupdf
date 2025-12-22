/*
 * Fuzzer for MuPDF font loading (TTF, OTF, CFF, Type1)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mupdf/fitz.h>

#define MAX_INPUT_SIZE (1 * 1024 * 1024)  /* 1MB limit */

static fz_context *ctx = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_font *font = NULL;
	fz_buffer *buf = NULL;

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(font);
	fz_var(buf);

	fz_try(ctx)
	{
		buf = fz_new_buffer_from_copied_data(ctx, data, size);

		/* Try loading as different font types */
		font = fz_new_font_from_buffer(ctx, NULL, buf, 0, 0);
		if (font)
		{
			/* Exercise font metrics */
			fz_font_ascender(ctx, font);
			fz_font_descender(ctx, font);

			/* Try to encode some glyphs */
			int gid;
			for (int i = 0; i < 256; i++)
			{
				gid = fz_encode_character(ctx, font, i);
				if (gid > 0)
				{
					fz_advance_glyph(ctx, font, gid, 0);
				}
			}
		}
	}
	fz_always(ctx)
	{
		fz_drop_font(ctx, font);
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
