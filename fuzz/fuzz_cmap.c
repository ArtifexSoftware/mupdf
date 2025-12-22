/*
 * Fuzzer for MuPDF CMap parsing (character mapping tables)
 * CMap files are used for CJK font encoding in PDFs
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mupdf/fitz.h>
#include <mupdf/pdf.h>

#define MAX_INPUT_SIZE (256 * 1024)  /* 256KB limit */

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
	fz_stream *stream = NULL;
	pdf_cmap *cmap = NULL;

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(stream);
	fz_var(cmap);

	fz_try(ctx)
	{
		stream = fz_open_memory(ctx, data, size);
		cmap = pdf_load_cmap(ctx, stream);

		if (cmap)
		{
			/* Exercise cmap lookup */
			for (int i = 0; i < 256; i++)
			{
				pdf_lookup_cmap(cmap, i);
			}

			/* Try some multi-byte lookups */
			pdf_lookup_cmap_full(cmap, 0x4E2D, NULL);  /* CJK character */
			pdf_lookup_cmap_full(cmap, 0x6587, NULL);
		}
	}
	fz_always(ctx)
	{
		pdf_drop_cmap(ctx, cmap);
		fz_drop_stream(ctx, stream);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
