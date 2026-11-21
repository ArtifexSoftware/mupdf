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
 * Fuzzer for MuPDF structured text extraction from PDF
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
	fz_stext_page *stext = NULL;
	fz_stext_options opts = { 0 };
	int i, n;

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(stream);
	fz_var(doc);
	fz_var(stext);

	fz_try(ctx)
	{
		stream = fz_open_memory(ctx, data, size);
		doc = fz_open_document_with_stream(ctx, "pdf", stream);

		n = fz_count_pages(ctx, doc);
		for (i = 0; i < n && i < 3; i++)  /* Limit to 3 pages */
		{
			fz_page *page = fz_load_page(ctx, doc, i);
			stext = fz_new_stext_page_from_page(ctx, page, &opts);
			fz_drop_stext_page(ctx, stext);
			stext = NULL;
			fz_drop_page(ctx, page);
		}
	}
	fz_always(ctx)
	{
		fz_drop_stext_page(ctx, stext);
		fz_drop_document(ctx, doc);
		fz_drop_stream(ctx, stream);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
