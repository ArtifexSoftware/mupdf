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
 * Fuzzer for MuPDF PDF object parsing
 * This targets PDF array, dictionary, and indirect object parsing
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
		/* Create a minimal PDF document for parsing context */
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
	fz_stream *stream = NULL;
	pdf_lexbuf lexbuf;
	pdf_obj *obj = NULL;

	if (size == 0 || size > MAX_INPUT_SIZE || doc == NULL)
		return 0;

	memset(&lexbuf, 0, sizeof(lexbuf));

	fz_var(stream);
	fz_var(obj);

	fz_try(ctx)
	{
		pdf_lexbuf_init(ctx, &lexbuf, PDF_LEXBUF_SMALL);
		stream = fz_open_memory(ctx, data, size);

		/* Try parsing as different object types */

		/* Try as array */
		fz_try(ctx)
		{
			fz_seek(ctx, stream, 0, SEEK_SET);
			obj = pdf_parse_array(ctx, doc, stream, &lexbuf);
			pdf_drop_obj(ctx, obj);
			obj = NULL;
		}
		fz_catch(ctx) { }

		/* Try as dictionary */
		fz_try(ctx)
		{
			fz_seek(ctx, stream, 0, SEEK_SET);
			obj = pdf_parse_dict(ctx, doc, stream, &lexbuf);
			pdf_drop_obj(ctx, obj);
			obj = NULL;
		}
		fz_catch(ctx) { }

		/* Try as stream object */
		fz_try(ctx)
		{
			fz_seek(ctx, stream, 0, SEEK_SET);
			obj = pdf_parse_stm_obj(ctx, doc, stream, &lexbuf);
			pdf_drop_obj(ctx, obj);
			obj = NULL;
		}
		fz_catch(ctx) { }
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, obj);
		fz_drop_stream(ctx, stream);
		pdf_lexbuf_fin(ctx, &lexbuf);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
