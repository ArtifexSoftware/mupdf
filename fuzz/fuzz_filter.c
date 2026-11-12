// Copyright (C) 2025 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 39 Mesa Street, Suite 108A, San Francisco,
// CA 94129, USA, for further information.

/*
 * Fuzzer for MuPDF decompression filters
 * This targets FlateDecode, LZW, DCT, JBIG2, JPX and other filters
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mupdf/fitz.h>

#define MAX_INPUT_SIZE (512 * 1024)  /* 512KB limit */
#define MAX_OUTPUT_SIZE (4 * 1024 * 1024)  /* 4MB output limit */

static fz_context *ctx = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
	return 0;
}

static void test_filter(fz_context *ctx, const uint8_t *data, size_t size,
	fz_stream *(*open_filter)(fz_context *, fz_stream *))
{
	fz_stream *input = NULL;
	fz_stream *filter = NULL;
	unsigned char buf[4096];
	size_t total = 0;

	fz_var(input);
	fz_var(filter);

	fz_try(ctx)
	{
		input = fz_open_memory(ctx, data, size);
		filter = open_filter(ctx, input);
		input = NULL;  /* Filter takes ownership */

		/* Read until EOF or limit */
		while (total < MAX_OUTPUT_SIZE)
		{
			size_t n = fz_read(ctx, filter, buf, sizeof(buf));
			if (n == 0)
				break;
			total += n;
		}
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, filter);
		fz_drop_stream(ctx, input);
	}
	fz_catch(ctx)
	{
		/* Ignore errors */
	}
}

static fz_stream *open_flate(fz_context *ctx, fz_stream *chain)
{
	return fz_open_flated(ctx, chain, 15);
}

static fz_stream *open_lzw(fz_context *ctx, fz_stream *chain)
{
	return fz_open_lzwd(ctx, chain, 0, 9, 0, 1);
}

static fz_stream *open_rld(fz_context *ctx, fz_stream *chain)
{
	return fz_open_rld(ctx, chain);
}

static fz_stream *open_a85d(fz_context *ctx, fz_stream *chain)
{
	return fz_open_a85d(ctx, chain);
}

static fz_stream *open_ahxd(fz_context *ctx, fz_stream *chain)
{
	return fz_open_ahxd(ctx, chain);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	/* Use first byte to select filter type */
	uint8_t filter_type = data[0] % 5;
	data++;
	size--;

	if (size == 0)
		return 0;

	switch (filter_type)
	{
	case 0:
		test_filter(ctx, data, size, open_flate);
		break;
	case 1:
		test_filter(ctx, data, size, open_lzw);
		break;
	case 2:
		test_filter(ctx, data, size, open_rld);
		break;
	case 3:
		test_filter(ctx, data, size, open_a85d);
		break;
	case 4:
		test_filter(ctx, data, size, open_ahxd);
		break;
	}

	return 0;
}
