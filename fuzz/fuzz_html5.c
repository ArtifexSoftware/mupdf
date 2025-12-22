/*
 * Fuzzer for MuPDF HTML5 parsing
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mupdf/fitz.h>

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
	fz_buffer *buf = NULL;
	fz_xml *xml = NULL;

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(buf);
	fz_var(xml);

	fz_try(ctx)
	{
		buf = fz_new_buffer_from_copied_data(ctx, data, size);
		xml = fz_parse_xml_from_html5(ctx, buf);
	}
	fz_always(ctx)
	{
		fz_drop_xml(ctx, xml);
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
