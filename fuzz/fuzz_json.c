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
 * Fuzzer for MuPDF JSON parsing
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
	fz_pool *pool = NULL;
	fz_json *json = NULL;
	char *str = NULL;

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(pool);
	fz_var(str);

	fz_try(ctx)
	{
		/* Null-terminate the input for JSON parsing */
		str = fz_malloc(ctx, size + 1);
		memcpy(str, data, size);
		str[size] = '\0';

		pool = fz_new_pool(ctx);
		json = fz_parse_json(ctx, pool, str);

		/* If parsing succeeded, try to serialize it back */
		if (json)
		{
			fz_buffer *buf = fz_new_buffer(ctx, 1024);
			fz_append_json(ctx, buf, json);
			fz_drop_buffer(ctx, buf);
		}
	}
	fz_always(ctx)
	{
		fz_drop_pool(ctx, pool);
		fz_free(ctx, str);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
