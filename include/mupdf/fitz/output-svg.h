#ifndef MUPDF_FITZ_OUTPUT_SVG_H
#define MUPDF_FITZ_OUTPUT_SVG_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/device.h"
#include "mupdf/fitz/output.h"

enum {
	FZ_SVG_TEXT_AS_PATH = 0,
	FZ_SVG_TEXT_AS_TEXT = 1,
};

/*
	fz_new_svg_device: Create a device that outputs (single page)
		SVG files to the given output stream.

	output: The output stream to send the constructed SVG page to.

	page_width, page_height: The page dimensions to use (in points).

	text_format: How to emit text. One of the following values:
		FZ_SVG_TEXT_AS_TEXT: As <text> elements with possible layout errors and mismatching fonts.
		FZ_SVG_TEXT_AS_PATH: As <path> elements with exact visual appearance.

	reuse_images: Share image resources using <symbol> definitions.
*/
fz_device *fz_new_svg_device(fz_context *ctx, fz_output *out, float page_width, float page_height, int text_format, int reuse_images);

#endif
