/*
 * Fuzzer for MuPDF archive handling (ZIP, TAR)
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
	fz_stream *stream = NULL;
	fz_archive *arch = NULL;

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(stream);
	fz_var(arch);

	fz_try(ctx)
	{
		stream = fz_open_memory(ctx, data, size);
		arch = fz_open_archive_with_stream(ctx, stream);

		if (arch)
		{
			int count = fz_count_archive_entries(ctx, arch);
			for (int i = 0; i < count && i < 10; i++)  /* Limit entries */
			{
				const char *name = fz_list_archive_entry(ctx, arch, i);
				if (name)
				{
					fz_buffer *buf = fz_read_archive_entry(ctx, arch, name);
					fz_drop_buffer(ctx, buf);
				}
			}
		}
	}
	fz_always(ctx)
	{
		fz_drop_archive(ctx, arch);
		fz_drop_stream(ctx, stream);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
