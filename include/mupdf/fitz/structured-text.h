#ifndef MUPDF_FITZ_STRUCTURED_TEXT_H
#define MUPDF_FITZ_STRUCTURED_TEXT_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/geometry.h"
#include "mupdf/fitz/font.h"
#include "mupdf/fitz/colorspace.h"
#include "mupdf/fitz/image.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/device.h"

/*
	Text extraction device: Used for searching, format conversion etc.

	(In development - Subject to change in future versions)
*/

typedef struct fz_stext_char_s fz_stext_char;
typedef struct fz_stext_line_s fz_stext_line;
typedef struct fz_stext_block_s fz_stext_block;
typedef struct fz_stext_page_s fz_stext_page;

/*
	FZ_STEXT_PRESERVE_LIGATURES: If this option is activated ligatures
	are passed through to the application in their original form. If
	this option is deactivated ligatures are expanded into their
	constituent parts, e.g. the ligature ffi is expanded into three
	separate characters f, f and i.

	FZ_STEXT_PRESERVE_WHITESPACE: If this option is activated whitespace
	is passed through to the application in its original form. If this
	option is deactivated any type of horizontal whitespace (including
	horizontal tabs) will be replaced with space characters of variable
	width.

	FZ_STEXT_PRESERVE_IMAGES: If this option is set, then images will
	be stored in the structured text structure. The default is to ignore
	all images.
*/
enum
{
	FZ_STEXT_PRESERVE_LIGATURES = 1,
	FZ_STEXT_PRESERVE_WHITESPACE = 2,
	FZ_STEXT_PRESERVE_IMAGES = 4,
};

/*
	A text page is a list of blocks, together with an overall bounding box.
*/
struct fz_stext_page_s
{
	fz_pool *pool;
	fz_rect mediabox;
	fz_stext_block *first_block, *last_block;
};

enum
{
	FZ_STEXT_BLOCK_TEXT = 0,
	FZ_STEXT_BLOCK_IMAGE = 1
};

/*
	A text block is a list of lines of text (typically a paragraph), or an image.
*/
struct fz_stext_block_s
{
	int type;
	fz_rect bbox;
	union {
		struct { fz_stext_line *first_line, *last_line; } t;
		struct { fz_matrix transform; fz_image *image; } i;
	} u;
	fz_stext_block *prev, *next;
};

/*
	A text line is a list of characters that share a common baseline.
*/
struct fz_stext_line_s
{
	int wmode; /* 0 for horizontal, 1 for vertical */
	fz_point dir; /* normalized direction of baseline */
	fz_rect bbox;
	fz_stext_char *first_char, *last_char;
	fz_stext_line *prev, *next;
};

/*
	A text char is a unicode character, the style in which is appears, and
	the point at which it is positioned.
*/
struct fz_stext_char_s
{
	int c;
	fz_point origin;
	fz_rect bbox;
	float size;
	fz_font *font;
	fz_stext_char *next;
};

extern const char *fz_stext_options_usage;

int fz_stext_char_count(fz_context *ctx, fz_stext_page *page);
const fz_stext_char *fz_stext_char_at(fz_context *ctx, fz_stext_page *page, int idx);

/*
	fz_new_stext_page: Create an empty text page.

	The text page is filled out by the text device to contain the blocks
	and lines of text on the page.

	mediabox: optional mediabox information.
*/
fz_stext_page *fz_new_stext_page(fz_context *ctx, const fz_rect *mediabox);
void fz_drop_stext_page(fz_context *ctx, fz_stext_page *page);

/*
	fz_print_stext_page_as_html: Output a page to a file in HTML (visual) format.
*/
void fz_print_stext_page_as_html(fz_context *ctx, fz_output *out, fz_stext_page *page);
void fz_print_stext_header_as_html(fz_context *ctx, fz_output *out);
void fz_print_stext_trailer_as_html(fz_context *ctx, fz_output *out);

/*
	fz_print_stext_page_as_xhtml: Output a page to a file in XHTML (semantic) format.
*/
void fz_print_stext_page_as_xhtml(fz_context *ctx, fz_output *out, fz_stext_page *page);
void fz_print_stext_header_as_xhtml(fz_context *ctx, fz_output *out);
void fz_print_stext_trailer_as_xhtml(fz_context *ctx, fz_output *out);

/*
	fz_print_stext_page_as_xml: Output a page to a file in XML format.
*/
void fz_print_stext_page_as_xml(fz_context *ctx, fz_output *out, fz_stext_page *page);

/*
	fz_print_stext_page_as_text: Output a page to a file in UTF-8 format.
*/
void fz_print_stext_page_as_text(fz_context *ctx, fz_output *out, fz_stext_page *page);

/*
	fz_search_stext_page: Search for occurrence of 'needle' in text page.

	Return the number of hits and store hit bboxes in the passed in array.

	NOTE: This is an experimental interface and subject to change without notice.
*/
int fz_search_stext_page(fz_context *ctx, fz_stext_page *text, const char *needle, fz_rect *hit_bbox, int hit_max);

/*
	fz_highlight_selection: Return a list of rectangles to highlight lines inside the selection points.
*/
int fz_highlight_selection(fz_context *ctx, fz_stext_page *page, fz_point a, fz_point b, fz_rect *hit_bbox, int hit_max);

/*
	fz_copy_selection: Return a newly allocated UTF-8 string with the text for a given selection.

	crlf: If true, write "\r\n" style line endings (otherwise "\n" only).
*/
char *fz_copy_selection(fz_context *ctx, fz_stext_page *page, fz_point a, fz_point b, int crlf);

/*
	struct fz_stext_options: Options for creating a pixmap and draw device.
*/
typedef struct fz_stext_options_s fz_stext_options;

struct fz_stext_options_s
{
	int flags;
};

/*
	fz_parse_stext_options: Parse stext device options from a comma separated key-value string.
*/
fz_stext_options *fz_parse_stext_options(fz_context *ctx, fz_stext_options *opts, const char *string);

/*
	fz_new_stext_device: Create a device to extract the text on a page.

	Gather the text on a page into blocks and lines.

	The reading order is taken from the order the text is drawn in the
	source file, so may not be accurate.

	page: The text page to which content should be added. This will
	usually be a newly created (empty) text page, but it can be one
	containing data already (for example when merging multiple pages,
	or watermarking).

	options: Options to configure the stext device.
*/
fz_device *fz_new_stext_device(fz_context *ctx, fz_stext_page *page, const fz_stext_options *options);

#endif
