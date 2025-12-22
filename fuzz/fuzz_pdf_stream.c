/*
 * Fuzzer for MuPDF PDF content stream interpretation
 * This targets the PDF glyph/content stream interpreter
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mupdf/fitz.h>
#include <mupdf/pdf.h>

#define MAX_INPUT_SIZE (256 * 1024)  /* 256KB limit */

static fz_context *ctx = NULL;
static pdf_document *doc = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
	if (ctx)
	{
		fz_register_document_handlers(ctx);
		fz_try(ctx)
		{
			doc = pdf_create_document(ctx);
		}
		fz_catch(ctx)
		{
			doc = NULL;
		}
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_buffer *buf = NULL;
	pdf_obj *resources = NULL;
	fz_device *dev = NULL;
	fz_cookie cookie = { 0 };

	if (size == 0 || size > MAX_INPUT_SIZE || doc == NULL)
		return 0;

	fz_var(buf);
	fz_var(resources);
	fz_var(dev);

	fz_try(ctx)
	{
		fz_matrix ctm = fz_identity;
		fz_rect bbox = fz_empty_rect;

		/* Create a buffer with the fuzz input as content stream */
		buf = fz_new_buffer_from_copied_data(ctx, data, size);

		/* Create minimal resources dictionary */
		resources = pdf_new_dict(ctx, doc, 4);

		/* Create a bbox device to consume the output */
		dev = fz_new_bbox_device(ctx, &bbox);

		/* Try to run the glyph stream (Type3 font charprocs) */
		pdf_run_glyph(ctx, doc, resources, buf, dev, ctm, NULL, NULL, NULL, NULL);
	}
	fz_always(ctx)
	{
		fz_close_device(ctx, dev);
		fz_drop_device(ctx, dev);
		pdf_drop_obj(ctx, resources);
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
