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
 * Fuzzer for MuPDF font loading (TTF, OTF, CFF, Type1)
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
	fz_font *font = NULL;
	fz_buffer *buf = NULL;

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(font);
	fz_var(buf);

	fz_try(ctx)
	{
		buf = fz_new_buffer_from_copied_data(ctx, data, size);

		/* Try loading as different font types */
		font = fz_new_font_from_buffer(ctx, NULL, buf, 0, 0);
		if (font)
		{
			/* Exercise font metrics */
			fz_font_ascender(ctx, font);
			fz_font_descender(ctx, font);

			/* Try to encode some glyphs */
			int gid;
			for (int i = 0; i < 256; i++)
			{
				gid = fz_encode_character(ctx, font, i);
				if (gid > 0)
				{
					fz_advance_glyph(ctx, font, gid, 0);
				}
			}
		}
	}
	fz_always(ctx)
	{
		fz_drop_font(ctx, font);
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
