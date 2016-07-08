#include "mupdf/fitz.h"

#include <zlib.h>

typedef struct fz_cbz_writer_s fz_cbz_writer;

struct fz_cbz_writer_s
{
	fz_document_writer super;
	fz_draw_options options;
	fz_pixmap *pixmap;
	int count;
	fz_zip_writer *zip;
};

const char *fz_cbz_write_options_usage = "";

static fz_device *
cbz_begin_page(fz_context *ctx, fz_document_writer *wri_, const fz_rect *mediabox)
{
	fz_cbz_writer *wri = (fz_cbz_writer*)wri_;
	return fz_new_draw_device_with_options(ctx, &wri->options, mediabox, &wri->pixmap);
}

static void
cbz_end_page(fz_context *ctx, fz_document_writer *wri_, fz_device *dev)
{
	fz_cbz_writer *wri = (fz_cbz_writer*)wri_;
	fz_buffer *buffer;
	char name[40];

	fz_close_device(ctx, dev);
	fz_drop_device(ctx, dev);

	wri->count += 1;

	fz_snprintf(name, sizeof name, "p%04d.png", wri->count);

	buffer = fz_new_buffer_from_pixmap_as_png(ctx, wri->pixmap);
	fz_try(ctx)
		fz_write_zip_entry(ctx, wri->zip, name, buffer, 0);
	fz_always(ctx)
		fz_drop_buffer(ctx, buffer);
	fz_catch(ctx)
		fz_rethrow(ctx);

	fz_drop_pixmap(ctx, wri->pixmap);
	wri->pixmap = NULL;
}

static void
cbz_close_writer(fz_context *ctx, fz_document_writer *wri_)
{
	fz_cbz_writer *wri = (fz_cbz_writer*)wri_;
	fz_close_zip_writer(ctx, wri->zip);
}

static void
cbz_drop_writer(fz_context *ctx, fz_document_writer *wri_)
{
	fz_cbz_writer *wri = (fz_cbz_writer*)wri_;
	fz_drop_zip_writer(ctx, wri->zip);
	fz_drop_pixmap(ctx, wri->pixmap);
}

fz_document_writer *
fz_new_cbz_writer(fz_context *ctx, const char *path, const char *options)
{
	fz_cbz_writer *wri;

	wri = fz_malloc_struct(ctx, fz_cbz_writer);
	wri->super.begin_page = cbz_begin_page;
	wri->super.end_page = cbz_end_page;
	wri->super.close_writer = cbz_close_writer;
	wri->super.drop_writer = cbz_drop_writer;

	fz_try(ctx)
	{
		fz_parse_draw_options(ctx, &wri->options, options);
		wri->zip = fz_new_zip_writer(ctx, path ? path : "out.cbz");
	}
	fz_catch(ctx)
	{
		fz_free(ctx, wri);
		fz_rethrow(ctx);
	}

	return (fz_document_writer*)wri;
}
