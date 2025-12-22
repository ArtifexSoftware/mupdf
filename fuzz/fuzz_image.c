/*
 * Fuzzer for MuPDF image loading (PNG, JPEG, TIFF, BMP, GIF, PSD, PNM, etc.)
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
	fz_buffer *buf = NULL;
	fz_image *img = NULL;
	fz_pixmap *pix = NULL;

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(buf);
	fz_var(img);
	fz_var(pix);

	fz_try(ctx)
	{
		buf = fz_new_buffer_from_copied_data(ctx, data, size);
		img = fz_new_image_from_buffer(ctx, buf);
		if (img)
		{
			pix = fz_get_pixmap_from_image(ctx, img, NULL, NULL, NULL, NULL);
		}
	}
	fz_always(ctx)
	{
		fz_drop_pixmap(ctx, pix);
		fz_drop_image(ctx, img);
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
