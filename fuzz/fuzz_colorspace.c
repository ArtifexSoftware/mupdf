/*
 * Fuzzer for MuPDF color space handling
 * This targets ICC profile parsing and color conversion
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
	fz_colorspace *cs = NULL;
	fz_buffer *buf = NULL;

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(cs);
	fz_var(buf);

	fz_try(ctx)
	{
		buf = fz_new_buffer_from_copied_data(ctx, data, size);

		/* Try to load as ICC profile */
		cs = fz_new_icc_colorspace(ctx, FZ_COLORSPACE_NONE, 0, NULL, buf);

		if (cs)
		{
			/* Exercise color conversion */
			float src[FZ_MAX_COLORS] = {0};
			float dst[FZ_MAX_COLORS] = {0};
			int n = fz_colorspace_n(ctx, cs);

			for (int i = 0; i < n && i < FZ_MAX_COLORS; i++)
				src[i] = 0.5f;

			/* Convert to device RGB */
			fz_convert_color(ctx, cs, src, fz_device_rgb(ctx), dst, NULL, fz_default_color_params);
		}
	}
	fz_always(ctx)
	{
		fz_drop_colorspace(ctx, cs);
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
