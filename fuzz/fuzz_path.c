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
 * Fuzzer for MuPDF path operations
 * This targets vector path construction and stroking
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mupdf/fitz.h>

#define MAX_INPUT_SIZE (64 * 1024)  /* 64KB limit */

static fz_context *ctx = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
	return 0;
}

/* Path operation types */
enum {
	OP_MOVETO = 0,
	OP_LINETO,
	OP_CURVETO,
	OP_CURVETOV,
	OP_CURVETOY,
	OP_CLOSEPATH,
	OP_RECTTO,
	OP_COUNT
};

/* Small pixmap dimensions for rasterization tests */
#define RASTER_WIDTH 64
#define RASTER_HEIGHT 64

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_path *path = NULL;
	fz_stroke_state *stroke = NULL;
	fz_pixmap *pix = NULL;
	fz_device *dev = NULL;
	fz_rect bounds;
	size_t i = 0;

	if (size < 4 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(path);
	fz_var(stroke);
	fz_var(pix);
	fz_var(dev);

	fz_try(ctx)
	{
		path = fz_new_path(ctx);
		stroke = fz_new_stroke_state(ctx);

		/* Configure stroke from first few bytes */
		stroke->linewidth = (data[i++] % 100) / 10.0f;
		stroke->miterlimit = (data[i++] % 100) / 10.0f + 1.0f;
		stroke->start_cap = data[i++] % 3;
		stroke->end_cap = data[i++] % 3;

		/* Build path from remaining data */
		while (i + 1 < size)
		{
			uint8_t op = data[i++] % OP_COUNT;
			float x, y, x2, y2, x3, y3;

			switch (op)
			{
			case OP_MOVETO:
				if (i + 2 > size) break;
				x = (float)(int8_t)data[i++];
				y = (float)(int8_t)data[i++];
				fz_moveto(ctx, path, x, y);
				break;

			case OP_LINETO:
				if (i + 2 > size) break;
				x = (float)(int8_t)data[i++];
				y = (float)(int8_t)data[i++];
				fz_lineto(ctx, path, x, y);
				break;

			case OP_CURVETO:
				if (i + 6 > size) break;
				x = (float)(int8_t)data[i++];
				y = (float)(int8_t)data[i++];
				x2 = (float)(int8_t)data[i++];
				y2 = (float)(int8_t)data[i++];
				x3 = (float)(int8_t)data[i++];
				y3 = (float)(int8_t)data[i++];
				fz_curveto(ctx, path, x, y, x2, y2, x3, y3);
				break;

			case OP_CURVETOV:
				if (i + 4 > size) break;
				x2 = (float)(int8_t)data[i++];
				y2 = (float)(int8_t)data[i++];
				x3 = (float)(int8_t)data[i++];
				y3 = (float)(int8_t)data[i++];
				fz_curvetov(ctx, path, x2, y2, x3, y3);
				break;

			case OP_CURVETOY:
				if (i + 4 > size) break;
				x = (float)(int8_t)data[i++];
				y = (float)(int8_t)data[i++];
				x3 = (float)(int8_t)data[i++];
				y3 = (float)(int8_t)data[i++];
				fz_curvetoy(ctx, path, x, y, x3, y3);
				break;

			case OP_CLOSEPATH:
				fz_closepath(ctx, path);
				break;

			case OP_RECTTO:
				if (i + 4 > size) break;
				x = (float)(int8_t)data[i++];
				y = (float)(int8_t)data[i++];
				x2 = (float)(uint8_t)data[i++];
				y2 = (float)(uint8_t)data[i++];
				fz_rectto(ctx, path, x, y, x + x2, y + y2);
				break;
			}
		}

		/* Exercise path operations */
		bounds = fz_bound_path(ctx, path, stroke, fz_identity);
		(void)bounds;

		/* Trim the path */
		fz_trim_path(ctx, path);

		/* Exercise the rasterizer by filling and stroking the path */
		pix = fz_new_pixmap(ctx, fz_device_rgb(ctx), RASTER_WIDTH, RASTER_HEIGHT, NULL, 1);
		fz_clear_pixmap_with_value(ctx, pix, 255);
		dev = fz_new_draw_device(ctx, fz_identity, pix);

		/* Fill the path */
		{
			float color[3] = { 0.5f, 0.5f, 0.5f };
			fz_fill_path(ctx, dev, path, 0, fz_identity,
			             fz_device_rgb(ctx), color, 1.0f, fz_default_color_params);
		}

		/* Stroke the path */
		{
			float color[3] = { 0.0f, 0.0f, 0.0f };
			fz_stroke_path(ctx, dev, path, stroke, fz_identity,
			               fz_device_rgb(ctx), color, 1.0f, fz_default_color_params);
		}

		fz_close_device(ctx, dev);
	}
	fz_always(ctx)
	{
		fz_drop_device(ctx, dev);
		fz_drop_pixmap(ctx, pix);
		fz_drop_stroke_state(ctx, stroke);
		fz_drop_path(ctx, path);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
