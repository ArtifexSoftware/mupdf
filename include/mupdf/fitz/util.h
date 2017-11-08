#ifndef MUPDF_FITZ_UTIL_H
#define MUPDF_FITZ_UTIL_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/geometry.h"
#include "mupdf/fitz/document.h"
#include "mupdf/fitz/pixmap.h"
#include "mupdf/fitz/structured-text.h"
#include "mupdf/fitz/buffer.h"

/*
	fz_new_display_list_from_page: Create a display list with the contents of a page.
*/
fz_display_list *fz_new_display_list_from_page(fz_context *ctx, fz_page *page);
fz_display_list *fz_new_display_list_from_page_number(fz_context *ctx, fz_document *doc, int number);
fz_display_list *fz_new_display_list_from_page_contents(fz_context *ctx, fz_page *page);
fz_display_list *fz_new_display_list_from_annot(fz_context *ctx, fz_annot *annot);

/*
	fz_new_pixmap_from_page: Render the page to a pixmap using the transform and colorspace.
*/
fz_pixmap *fz_new_pixmap_from_display_list(fz_context *ctx, fz_display_list *list, const fz_matrix *ctm, fz_colorspace *cs, int alpha);
fz_pixmap *fz_new_pixmap_from_page(fz_context *ctx, fz_page *page, const fz_matrix *ctm, fz_colorspace *cs, int alpha);
fz_pixmap *fz_new_pixmap_from_page_number(fz_context *ctx, fz_document *doc, int number, const fz_matrix *ctm, fz_colorspace *cs, int alpha);

/*
	fz_new_pixmap_from_page_contents: Render the page contents without annotations.
*/
fz_pixmap *fz_new_pixmap_from_page_contents(fz_context *ctx, fz_page *page, const fz_matrix *ctm, fz_colorspace *cs, int alpha);

/*
	fz_new_pixmap_from_annot: Render an annotation suitable for blending on top of the opaque
	pixmap returned by fz_new_pixmap_from_page_contents.
*/
fz_pixmap *fz_new_pixmap_from_annot(fz_context *ctx, fz_annot *annot, const fz_matrix *ctm, fz_colorspace *cs, int alpha);

/*
	fz_new_stext_page_from_page: Extract structured text from a page.
*/
fz_stext_page *fz_new_stext_page_from_page(fz_context *ctx, fz_page *page, const fz_stext_options *options);
fz_stext_page *fz_new_stext_page_from_page_number(fz_context *ctx, fz_document *doc, int number, const fz_stext_options *options);
fz_stext_page *fz_new_stext_page_from_display_list(fz_context *ctx, fz_display_list *list, const fz_stext_options *options);

/*
	fz_new_buffer_from_stext_page: Convert structured text into plain text.
*/
fz_buffer *fz_new_buffer_from_stext_page(fz_context *ctx, fz_stext_page *text);
fz_buffer *fz_new_buffer_from_page(fz_context *ctx, fz_page *page, const fz_stext_options *options);
fz_buffer *fz_new_buffer_from_page_number(fz_context *ctx, fz_document *doc, int number, const fz_stext_options *options);
fz_buffer *fz_new_buffer_from_display_list(fz_context *ctx, fz_display_list *list, const fz_stext_options *options);

/*
	fz_search_page: Search for the 'needle' text on the page.
	Record the hits in the hit_bbox array and return the number of hits.
	Will stop looking once it has filled hit_max rectangles.
*/
int fz_search_page(fz_context *ctx, fz_page *page, const char *needle, fz_rect *hit_bbox, int hit_max);
int fz_search_page_number(fz_context *ctx, fz_document *doc, int number, const char *needle, fz_rect *hit_bbox, int hit_max);
int fz_search_display_list(fz_context *ctx, fz_display_list *list, const char *needle, fz_rect *hit_bbox, int hit_max);

/*
	Parse an SVG document into a display-list.
*/
fz_display_list *fz_new_display_list_from_svg(fz_context *ctx, fz_buffer *buf, float *w, float *h);

/*
	Create a scalable image from an SVG document.
*/
fz_image *fz_new_image_from_svg(fz_context *ctx, fz_buffer *buf);

/*
	Write image as a data URI (for HTML and SVG output).
*/
void fz_write_image_as_data_uri(fz_context *ctx, fz_output *out, fz_image *image);

#endif
