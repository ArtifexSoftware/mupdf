/*
 * Fuzzer for MuPDF EPUB document parsing and rendering
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
	if (ctx)
		fz_register_document_handlers(ctx);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_stream *stream = NULL;
	fz_document *doc = NULL;
	fz_pixmap *pix = NULL;
	int i, n;

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(stream);
	fz_var(doc);
	fz_var(pix);

	fz_try(ctx)
	{
		stream = fz_open_memory(ctx, data, size);
		doc = fz_open_document_with_stream(ctx, "epub", stream);

		n = fz_count_pages(ctx, doc);
		for (i = 0; i < n && i < 3; i++)  /* Limit to 3 pages */
		{
			pix = fz_new_pixmap_from_page_number(ctx, doc, i, fz_identity, fz_device_rgb(ctx), 0);
			fz_drop_pixmap(ctx, pix);
			pix = NULL;
		}
	}
	fz_always(ctx)
	{
		fz_drop_pixmap(ctx, pix);
		fz_drop_document(ctx, doc);
		fz_drop_stream(ctx, stream);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
