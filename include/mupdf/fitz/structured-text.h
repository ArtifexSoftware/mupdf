// Copyright (C) 2004-2024 Artifex Software, Inc.
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

#ifndef MUPDF_FITZ_STRUCTURED_TEXT_H
#define MUPDF_FITZ_STRUCTURED_TEXT_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/types.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/geometry.h"
#include "mupdf/fitz/font.h"
#include "mupdf/fitz/image.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/device.h"
#include "mupdf/fitz/pool.h"

/**
	Simple text layout (for use with annotation editing primarily).
*/
typedef struct fz_layout_char
{
	float x, advance;
	const char *p; /* location in source text of character */
	struct fz_layout_char *next;
} fz_layout_char;

typedef struct fz_layout_line
{
	float x, y, font_size;
	const char *p; /* location in source text of start of line */
	fz_layout_char *text;
	struct fz_layout_line *next;
} fz_layout_line;

typedef struct
{
	fz_pool *pool;
	fz_matrix matrix;
	fz_matrix inv_matrix;
	fz_layout_line *head, **tailp;
	fz_layout_char **text_tailp;
} fz_layout_block;

/**
	Create a new layout block, with new allocation pool, zero
	matrices, and initialise linked pointers.
*/
fz_layout_block *fz_new_layout(fz_context *ctx);

/**
	Drop layout block. Free the pool, and linked blocks.

	Never throws exceptions.
*/
void fz_drop_layout(fz_context *ctx, fz_layout_block *block);

/**
	Add a new line to the end of the layout block.
*/
void fz_add_layout_line(fz_context *ctx, fz_layout_block *block, float x, float y, float h, const char *p);

/**
	Add a new char to the line at the end of the layout block.
*/
void fz_add_layout_char(fz_context *ctx, fz_layout_block *block, float x, float w, const char *p);

/**
	Text extraction device: Used for searching, format conversion etc.

	(In development - Subject to change in future versions)
*/

typedef struct fz_stext_char fz_stext_char;
typedef struct fz_stext_line fz_stext_line;
typedef struct fz_stext_block fz_stext_block;
typedef struct fz_stext_struct fz_stext_struct;
typedef struct fz_stext_grid_positions fz_stext_grid_positions;

/**
	FZ_STEXT_PRESERVE_LIGATURES: If this option is activated
	ligatures are passed through to the application in their
	original form. If this option is deactivated ligatures are
	expanded into their constituent parts, e.g. the ligature ffi is
	expanded into three separate characters f, f and i.

	FZ_STEXT_PRESERVE_WHITESPACE: If this option is activated
	whitespace is passed through to the application in its original
	form. If this option is deactivated any type of horizontal
	whitespace (including horizontal tabs) will be replaced with
	space characters of variable width.

	FZ_STEXT_PRESERVE_IMAGES: If this option is set, then images
	will be stored in the structured text structure. The default is
	to ignore all images.

	FZ_STEXT_INHIBIT_SPACES: If this option is set, we will not try
	to add missing space characters where there are large gaps
	between characters.

	FZ_STEXT_DEHYPHENATE: If this option is set, hyphens at the
	end of a line will be removed and the lines will be merged.

	FZ_STEXT_PRESERVE_SPANS: If this option is set, spans on the same line
	will not be merged. Each line will thus be a span of text with the same
	font, colour, and size.

	FZ_STEXT_CLIP: If this option is set, characters that would be entirely
	clipped away by the current clipping path (or, more accurate, the smallest
	bbox that contains the current clipping path) will be ignored. The
	clip path is guaranteed to be smaller then the page mediabox, hence
	this option subsumes an older, now deprecated, FZ_STEXT_MEDIABOX_CLIP
	option.

	FZ_STEXT_COLLECT_STRUCTURE: If this option is set, we will collect
	the structure as specified using begin/end_structure calls. This will
	change the returned stext structure from being a simple list of blocks
	into effectively being a 'tree' that should be walked in depth-first
	order.

	FZ_STEXT_COLLECT_VECTORS: If this option is set, we will collect
	details (currently just the bbox) of vector graphics. This is intended
	to be of use in segmentation analysis.

	FZ_STEXT_IGNORE_ACTUALTEXT: If this option is set, we will no longer
	replace text by the ActualText replacement specified in the document.

	FZ_STEXT_SEGMENT: If this option is set, we will attempt to segment
	the page into different regions. This will deliberately not do anything
	to pages with structure information present.
*/
enum
{
	FZ_STEXT_PRESERVE_LIGATURES = 1,
	FZ_STEXT_PRESERVE_WHITESPACE = 2,
	FZ_STEXT_PRESERVE_IMAGES = 4,
	FZ_STEXT_INHIBIT_SPACES = 8,
	FZ_STEXT_DEHYPHENATE = 16,
	FZ_STEXT_PRESERVE_SPANS = 32,
	FZ_STEXT_CLIP = 64,
	FZ_STEXT_USE_CID_FOR_UNKNOWN_UNICODE = 128,
	FZ_STEXT_COLLECT_STRUCTURE = 256,
	FZ_STEXT_ACCURATE_BBOXES = 512,
	FZ_STEXT_COLLECT_VECTORS = 1024,
	FZ_STEXT_IGNORE_ACTUALTEXT = 2048,
	FZ_STEXT_SEGMENT = 4096,

	/* An old, deprecated option. */
	FZ_STEXT_MEDIABOX_CLIP = FZ_STEXT_CLIP
};

/**
 *	A note on stext's handling of structure.
 *
 *	A PDF document can contain a structure tree. This gives the
 *	structure of a document in its entirety as a tree. e.g.
 *
 *	Tree			MCID	INDEX
 *	-------------------------------------
 *	DOC			0	0
 *	 TOC			1	0
 *	  TOC_ITEM		2	0
 *	  TOC_ITEM		3	1
 *	  TOC_ITEM		4	2
 *	  ...
 *	 STORY			100	1
 *	  SECTION		101	0
 *	   HEADING		102	0
 *	   SUBSECTION		103	1
 *	    PARAGRAPH		104	0
 *	    PARAGRAPH		105	1
 *	    PARAGRAPH		106	2
 *	   SUBSECTION		107	2
 *	    PARAGRAPH		108	0
 *	    PARAGRAPH		109	1
 *	    PARAGRAPH		110	2
 *	   ...
 *	  SECTION		200	1
 *      ...
 *
 *	Each different section of the tree is identified as part of an
 *	MCID by a number (this is a slight simplification, but makes the
 *	explanation easier).
 *
 *	The PDF document contains markings that say "Entering MCID 0"
 *	and "Leaving MCID 0". Any content within that region is therefore
 *	identified as appearing in that particular structural region.
 *
 *	This means that content can be sent in the document in a different
 *	order to which it appears 'logically' in the tree.
 *
 *	MuPDF converts this tree form into a nested series of calls to
 *	begin_structure and end_structure.
 *
 *	For instance, if the document started out with MCID 100, then
 *	we'd send:
 *		begin_structure("DOC")
 *		begin_structure("STORY")
 *
 *	The problem with this is that if we send:
 *		begin_structure("DOC")
 *		begin_structure("STORY")
 *		begin_structure("SECTION")
 *		begin_structure("SUBSECTION")
 *
 *	or
 *		begin_structure("DOC")
 *		begin_structure("STORY")
 *		begin_structure("SECTION")
 *		begin_structure("HEADING")
 *
 *	How do I know what order the SECTION and HEADING should appear in?
 *	Are they even in the same STORY? Or the same DOC?
 *
 *	Accordingly, every begin_structure is accompanied not only with the
 *	node type, but with an index. The index is the number of this node
 *	within this level of the tree. Hence:
 *
 *		begin_structure("DOC", 0)
 *		begin_structure("STORY", 0)
 *		begin_structure("SECTION", 0)
 *		begin_structure("HEADING", 0)
 *	and
 *		begin_structure("DOC", 0)
 *		begin_structure("STORY", 0)
 *		begin_structure("SECTION", 0)
 *		begin_structure("SUBSECTION", 1)
 *
 *	are now unambiguous in their describing of the tree.
 *
 *	MuPDF automatically sends the minimal end_structure/begin_structure
 *	pairs to move us between nodes in the tree.
 *
 *	In order to accomodate this information within the structured text
 *	data structures an additional block type is used. Previously a
 *	"page" was just a list of blocks, either text or images. e.g.
 *
 *	[BLOCK:TEXT] <-> [BLOCK:IMG] <-> [BLOCK:TEXT] <-> [BLOCK:TEXT] ...
 *
 *	We now introduce a new type of block, STRUCT, that turns this into
 *	a tree:
 *
 *	[BLOCK:TEXT] <-> [BLOCK:STRUCT(IDX=0)] <-> [BLOCK:TEXT] <-> ...
 *	                      /|\
 *	[STRUCT:TYPE=DOC] <----
 *	    |
 *	[BLOCK:TEXT] <-> [BLOCK:STRUCT(IDX=0)] <-> [BLOCK:TEXT] <-> ...
 *	                      /|\
 *	[STRUCT:TYPE=STORY] <--
 *	    |
 *	   ...
 *
 *	Rather than doing a simple linear traversal of the list to extract
 *	the logical data, a caller now has to do a depth-first traversal.
 */

/**
	A text page is a list of blocks, together with an overall
	bounding box.
*/
typedef struct
{
	fz_pool *pool;
	fz_rect mediabox;
	fz_stext_block *first_block;

	/* The following fields are only of use to the routines that
	 * build an fz_stext_page. They change during page construction
	 * and their meaning is subject to change. These values should
	 * not be used by anything outside of the stext device. */
	fz_stext_block *last_block;
	fz_stext_struct *last_struct;
} fz_stext_page;

enum
{
	FZ_STEXT_BLOCK_TEXT = 0,
	FZ_STEXT_BLOCK_IMAGE = 1,
	FZ_STEXT_BLOCK_STRUCT = 2,
	FZ_STEXT_BLOCK_VECTOR = 3,
	FZ_STEXT_BLOCK_GRID = 4
};

/**
	A text block is a list of lines of text (typically a paragraph),
	or an image.
*/
struct fz_stext_block
{
	int type;
	fz_rect bbox;
	union {
		struct { fz_stext_line *first_line, *last_line; } t;
		struct { fz_matrix transform; fz_image *image; } i;
		struct { fz_stext_struct *down; int index; } s;
		struct { uint8_t stroked; uint32_t argb; } v;
		struct { fz_stext_grid_positions *xs; fz_stext_grid_positions *ys; } b;
	} u;
	fz_stext_block *prev, *next;
};

/**
	A text line is a list of characters that share a common baseline.
*/
struct fz_stext_line
{
	int wmode; /* 0 for horizontal, 1 for vertical */
	fz_point dir; /* normalized direction of baseline */
	fz_rect bbox;
	fz_stext_char *first_char, *last_char;
	fz_stext_line *prev, *next;
};

/**
	A text char is a unicode character, the style in which is
	appears, and the point at which it is positioned.
*/
struct fz_stext_char
{
	int c; /* unicode character value */
	uint16_t bidi; /* even for LTR, odd for RTL - probably only needs 8 bits? */
	uint16_t flags;
	uint32_t argb; /* sRGB hex color (alpha in top 8 bits, then r, then g, then b in low bits) */
	fz_point origin;
	fz_quad quad;
	float size;
	fz_font *font;
	fz_stext_char *next;
};

enum
{
	FZ_STEXT_STRIKEOUT = 1,
	FZ_STEXT_UNDERLINE = 2,
	FZ_STEXT_SYNTHETIC = 4
};

/**
	When we are collecting the structure information from
	PDF structure trees/tags, we end up with a tree of
	nodes. The structure should be walked in depth-first
	traversal order to extract the content.

	An fz_stext_struct pointer can be NULL to indicate that
	we know there is a child there within the complete tree,
	but we don't know what it is yet.
*/
struct fz_stext_struct
{
	/* up points to the block that contains this fz_stext_struct. */
	fz_stext_block *up;
	/* parent points to the struct that has up as one of its children.
	 * parent is useful for doing depth first traversal without having
	 * to store the entire chain of structs in the iterator. */
	fz_stext_struct *parent;

	/* first_block points to the first child of this node (or NULL
	 * if there are none). */
	fz_stext_block *first_block;
	/* last_block points to the last child of this node (or NULL
	 * if there are none). */
	fz_stext_block *last_block;

	/* We have a set of 'standard' structure types. Every structure
	 * element should correspond to one of these. */
	fz_structure standard;
	/* Documents can use their own non-standard structure types, which
	 * are held as 'raw' strings. */
	char raw[1];
};

/* An example to show how fz_stext_blocks and fz_stext_structs interact:
 *
 *         [fz_stext_page]
 *             |
 *  first_block|
 *             |
 *            \|/
 *  [fz_stext_block:TEXT]<->[fz_stext_block:STRUCT]<->[fz_stext_block:IMG]
 *                           u.s.down|   /|\
 *                                   |    |
 *                                  \|/   |up
 *                             [fz_stext_struct]<---------.
 *                                |       |               |
 *                     first_block|       |last_block     |
 *         _______________________|       |               |
 *        |                               |               |
 *        |                               |               |
 *       \|/                             \|/              |
 *  [fz_stext_block:...]<->...<->[fz_stext_block:STRUCT]  |
 *                                  |  /|\                |
 *                          u.s.down|   |up               |
 *                                 \|/  |           parent|
 *                               [fz_stext_struct]--------'
 *                                  |   |
 *                       first_block|   |last_block
 *                                  :   :
 */

 struct fz_stext_grid_positions
 {
	int len;
	int max_uncertainty;
	struct {
		float pos;
		int uncertainty;
	} list[1];
 };

FZ_DATA extern const char *fz_stext_options_usage;

/**
	Create an empty text page.

	The text page is filled out by the text device to contain the
	blocks and lines of text on the page.

	mediabox: optional mediabox information.
*/
fz_stext_page *fz_new_stext_page(fz_context *ctx, fz_rect mediabox);
void fz_drop_stext_page(fz_context *ctx, fz_stext_page *page);

/**
	Output structured text to a file in HTML (visual) format.
*/
void fz_print_stext_page_as_html(fz_context *ctx, fz_output *out, fz_stext_page *page, int id);
void fz_print_stext_header_as_html(fz_context *ctx, fz_output *out);
void fz_print_stext_trailer_as_html(fz_context *ctx, fz_output *out);

/**
	Output structured text to a file in XHTML (semantic) format.
*/
void fz_print_stext_page_as_xhtml(fz_context *ctx, fz_output *out, fz_stext_page *page, int id);
void fz_print_stext_header_as_xhtml(fz_context *ctx, fz_output *out);
void fz_print_stext_trailer_as_xhtml(fz_context *ctx, fz_output *out);

/**
	Output structured text to a file in XML format.
*/
void fz_print_stext_page_as_xml(fz_context *ctx, fz_output *out, fz_stext_page *page, int id);

/**
	Output structured text to a file in JSON format.
*/
void fz_print_stext_page_as_json(fz_context *ctx, fz_output *out, fz_stext_page *page, float scale);

/**
	Output structured text to a file in plain-text UTF-8 format.
*/
void fz_print_stext_page_as_text(fz_context *ctx, fz_output *out, fz_stext_page *page);

/**
	Search for occurrence of 'needle' in text page.

	Return the number of quads and store hit quads in the passed in
	array.

	NOTE: This is an experimental interface and subject to change
	without notice.
*/
int fz_search_stext_page(fz_context *ctx, fz_stext_page *text, const char *needle, int *hit_mark, fz_quad *hit_bbox, int hit_max);

/**
	Callback function for use in searching.

	Called with the list of quads that correspond to a single hit.

	The callback should return with 0 to continue the search, or 1 to abort it.
	All other values are reserved at this point.
*/
typedef int (fz_search_callback_fn)(fz_context *ctx, void *opaque, int num_quads, fz_quad *hit_bbox);

/**
	Search for occurrence of 'needle' in text page.

	Call callback once for each hit. This callback will receive
	(potentially) multiple quads for each hit.

	Returns the number of hits - note that this is potentially
	different from (i.e. is not greater than) the number of quads
	as returned by the non callback API.

	NOTE: This is an experimental interface and subject to change
	without notice.
*/
int fz_search_stext_page_cb(fz_context *ctx, fz_stext_page *text, const char *needle, fz_search_callback_fn *cb, void *opaque);


/**
	Return a list of quads to highlight lines inside the selection
	points.
*/
int fz_highlight_selection(fz_context *ctx, fz_stext_page *page, fz_point a, fz_point b, fz_quad *quads, int max_quads);

enum
{
	FZ_SELECT_CHARS,
	FZ_SELECT_WORDS,
	FZ_SELECT_LINES,
};

fz_quad fz_snap_selection(fz_context *ctx, fz_stext_page *page, fz_point *ap, fz_point *bp, int mode);

/**
	Return a newly allocated UTF-8 string with the text for a given
	selection.

	crlf: If true, write "\r\n" style line endings (otherwise "\n"
	only).
*/
char *fz_copy_selection(fz_context *ctx, fz_stext_page *page, fz_point a, fz_point b, int crlf);

/**
	Return a newly allocated UTF-8 string with the text for a given
	selection rectangle.

	crlf: If true, write "\r\n" style line endings (otherwise "\n"
	only).
*/
char *fz_copy_rectangle(fz_context *ctx, fz_stext_page *page, fz_rect area, int crlf);

/**
	Options for creating structured text.
*/
typedef struct
{
	int flags;
	float scale;
} fz_stext_options;

/**
	Parse stext device options from a comma separated key-value
	string.
*/
fz_stext_options *fz_parse_stext_options(fz_context *ctx, fz_stext_options *opts, const char *string);

/**
	Perform segmentation analysis on an (unstructured) page to look for
	recursive subdivisions.

	Essentially this code attempts to split the page horizontally and/or
	vertically repeatedly into smaller and smaller "segments" (divisions).

	Returns 0 if no changes were made to the document.

	This is experimental code, and may change (or be removed) in future
	versions!
*/
int fz_segment_stext_page(fz_context *ctx, fz_stext_page *page);

/**
	Create a device to extract the text on a page.

	Gather the text on a page into blocks and lines.

	The reading order is taken from the order the text is drawn in
	the source file, so may not be accurate.

	page: The text page to which content should be added. This will
	usually be a newly created (empty) text page, but it can be one
	containing data already (for example when merging multiple
	pages, or watermarking).

	options: Options to configure the stext device.
*/
fz_device *fz_new_stext_device(fz_context *ctx, fz_stext_page *page, const fz_stext_options *options);

/**
	Create a device to OCR the text on the page.

	Renders the page internally to a bitmap that is then OCRd. Text
	is then forwarded onto the target device.

	target: The target device to receive the OCRd text.

	ctm: The transform to apply to the mediabox to get the size for
	the rendered page image. Also used to calculate the resolution
	for the page image. In general, this will be the same as the CTM
	that you pass to fz_run_page (or fz_run_display_list) to feed
	this device.

	mediabox: The mediabox (in points). Combined with the CTM to get
	the bounds of the pixmap used internally for the rendered page
	image.

	with_list: If with_list is false, then all non-text operations
	are forwarded instantly to the target device. This results in
	the target device seeing all NON-text operations, followed by
	all the text operations (derived from OCR).

	If with_list is true, then all the marking operations are
	collated into a display list which is then replayed to the
	target device at the end.

	language: NULL (for "eng"), or a pointer to a string to describe
	the languages/scripts that should be used for OCR (e.g.
	"eng,ara").

	datadir: NULL (for ""), or a pointer to a path string otherwise
	provided to Tesseract in the TESSDATA_PREFIX environment variable.

	progress: NULL, or function to be called periodically to indicate
	progress. Return 0 to continue, or 1 to cancel. progress_arg is
	returned as the void *. The int is a value between 0 and 100 to
	indicate progress.

	progress_arg: A void * value to be parrotted back to the progress
	function.
*/
fz_device *fz_new_ocr_device(fz_context *ctx, fz_device *target, fz_matrix ctm, fz_rect mediabox, int with_list, const char *language,
			const char *datadir, int (*progress)(fz_context *, void *, int), void *progress_arg);

fz_document *fz_open_reflowed_document(fz_context *ctx, fz_document *underdoc, const fz_stext_options *opts);


#endif
