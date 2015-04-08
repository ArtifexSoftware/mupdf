// Rendering a page of a PDF document to a PNG image in less than 100 lines.

// Compile a debug build of mupdf, then compile and run this example:
//
// gcc -g -o build/debug/example -Iinclude docs/example.c \
//	build/debug/libmupdf.a \
//	build/debug/libfreetype.a build/debug/libjbig2dec.a \
//	build/debug/libjpeg.a build/debug/libopenjpeg.a \
//	build/debug/libmujs.a \
//	build/debug/libz.a -lm
//
// build/debug/example /path/to/document.pdf 1 200 25

// Include the MuPDF header file.
#include <mupdf/fitz.h>

void
render(char *filename, int pagenumber, int zoom, int rotation)
{
	fz_context *ctx;
	fz_document *doc;
	int pagecount;
	fz_page *page;
	fz_matrix transform;
	fz_rect bounds;
	fz_irect bbox;
	fz_pixmap *pix;
	fz_device *dev;

	// Create a context to hold the exception stack and various caches.

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);

	// Register the default file types.

	fz_register_document_handlers(ctx);

	// Open the PDF, XPS or CBZ document.

	doc = fz_open_document(ctx, filename);

	// Retrieve the number of pages (not used in this example).

	pagecount = fz_count_pages(ctx, doc);

	// Load the page we want. Page numbering starts from zero.

	page = fz_load_page(ctx, doc, pagenumber - 1);

	// Calculate a transform to use when rendering. This transform
	// contains the scale and rotation. Convert zoom percentage to a
	// scaling factor. Without scaling the resolution is 72 dpi.

	fz_rotate(&transform, rotation);
	fz_pre_scale(&transform, zoom / 100.0f, zoom / 100.0f);

	// Take the page bounds and transform them by the same matrix that
	// we will use to render the page.

	fz_bound_page(ctx, page, &bounds);
	fz_transform_rect(&bounds, &transform);

	// Create a blank pixmap to hold the result of rendering. The
	// pixmap bounds used here are the same as the transformed page
	// bounds, so it will contain the entire page. The page coordinate
	// space has the origin at the top left corner and the x axis
	// extends to the right and the y axis extends down.

	fz_round_rect(&bbox, &bounds);
	pix = fz_new_pixmap_with_bbox(ctx, fz_device_rgb(ctx), &bbox);
	fz_clear_pixmap_with_value(ctx, pix, 0xff);

	// A page consists of a series of objects (text, line art, images,
	// gradients). These objects are passed to a device when the
	// interpreter runs the page. There are several devices, used for
	// different purposes:
	//
	//	draw device -- renders objects to a target pixmap.
	//
	//	text device -- extracts the text in reading order with styling
	//	information. This text can be used to provide text search.
	//
	//	list device -- records the graphic objects in a list that can
	//	be played back through another device. This is useful if you
	//	need to run the same page through multiple devices, without
	//	the overhead of parsing the page each time.

	// Create a draw device with the pixmap as its target.
	// Run the page with the transform.

	dev = fz_new_draw_device(ctx, pix);
	fz_run_page(ctx, page, dev, &transform, NULL);
	fz_drop_device(ctx, dev);

	// Save the pixmap to a file.

	fz_write_png(ctx, pix, "out.png", 0);

	// Clean up.

	fz_drop_pixmap(ctx, pix);
	fz_drop_page(ctx, page);
	fz_drop_document(ctx, doc);
	fz_drop_context(ctx);
}

int main(int argc, char **argv)
{
	char *filename = argc >= 2 ? argv[1] : "";
	int pagenumber = argc > 2 ? atoi(argv[2]) : 1;
	int zoom = argc > 3 ? atoi(argv[3]) : 100;
	int rotation = argc > 4 ? atoi(argv[4]) : 0;

	render(filename, pagenumber, zoom, rotation);

	return 0;
}
