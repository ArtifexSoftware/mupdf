#ifndef MUPDF_FITZ_OUTLINE_H
#define MUPDF_FITZ_OUTLINE_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/link.h"
#include "mupdf/fitz/output.h"

/* Outline */

/*
	fz_outline is a tree of the outline of a document (also known
	as table of contents).

	title: Title of outline item using UTF-8 encoding. May be NULL
	if the outline item has no text string.

	dest: Destination in the document to be displayed when this
	outline item is activated. May be FZ_LINK_NONE if the outline
	item does not have a destination.

	next: The next outline item at the same level as this outline
	item. May be NULL if no more outline items exist at this level.

	down: The outline items immediate children in the hierarchy.
	May be NULL if no children exist.
*/

typedef struct fz_outline_s fz_outline;

struct fz_outline_s
{
	int refs;
	char *title;
	fz_link_dest dest;
	fz_outline *next;
	fz_outline *down;
	int is_open;
};

/* fz_print_outline_xml: Print an outline to 'out' as XML. */
void fz_print_outline_xml(fz_context *ctx, fz_output *out, fz_outline *outline);

/* fz_print_outline: Print an outline to 'out' is plain text. */
void fz_print_outline(fz_context *ctx, fz_output *out, fz_outline *outline);

fz_outline *fz_new_outline(fz_context *ctx);
fz_outline *fz_keep_outline(fz_context *ctx, fz_outline *outline);
void fz_drop_outline(fz_context *ctx, fz_outline *outline);

#endif
