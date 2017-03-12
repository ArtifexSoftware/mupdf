#include "mupdf/fitz.h"

void
fz_save_gproof(fz_context *ctx, const char *pdf_file, fz_document *doc, const char *filename, int res,
				const char *print_profile, const char *display_profile)
{
	int i;
	int num_pages = fz_count_pages(ctx, doc);
	fz_output *out;
	fz_page *page = NULL;

	fz_var(page);

	if (num_pages <= 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Cannot write a 0 page GProof skeleton file");

	out = fz_new_output_with_path(ctx, filename, 0);

	fz_try(ctx)
	{
		/* File Signature: GPRO */
		fz_write_int32_le(ctx, out, 0x4f525047);

		/* Version = 1 */
		fz_write_byte(ctx, out, 1);
		fz_write_byte(ctx, out, 0);

		/* Resolution */
		fz_write_int32_le(ctx, out, res);

		/* Num Pages */
		fz_write_int32_le(ctx, out, num_pages);

		for (i = 0; i < num_pages; i++)
		{
			fz_rect rect;
			int w, h;

			page = fz_load_page(ctx, doc, i);
			fz_bound_page(ctx, page, &rect);
			fz_drop_page(ctx, page);
			page = NULL;

			/* Same lack of rounding as gs uses */
			w = (int)((rect.x1 - rect.x0) * res / 72.0);
			h = (int)((rect.y1 - rect.y0) * res / 72.0);
			fz_write_int32_le(ctx, out, w);
			fz_write_int32_le(ctx, out, h);
		}

		/* Filenames */
		fz_write_data(ctx, out, pdf_file, strlen(pdf_file)+1);
		fz_write_data(ctx, out, print_profile, strlen(print_profile) + 1);
		fz_write_data(ctx, out, display_profile, strlen(display_profile) + 1);
	}
	fz_always(ctx)
	{
		fz_drop_page(ctx, page);
		fz_drop_output(ctx, out);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}
