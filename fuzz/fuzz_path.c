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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_path *path = NULL;
	fz_stroke_state *stroke = NULL;
	fz_rect bounds;
	size_t i = 0;

	if (size < 4 || size > MAX_INPUT_SIZE)
		return 0;

	fz_var(path);
	fz_var(stroke);

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
	}
	fz_always(ctx)
	{
		fz_drop_stroke_state(ctx, stroke);
		fz_drop_path(ctx, path);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
