#ifndef MUPDF_FITZ_OUTLINE_H
#define MUPDF_FITZ_OUTLINE_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/link.h"
#include "mupdf/fitz/output.h"

/* Outline */

/**
	fz_outline is a tree of the outline of a document (also known
	as table of contents).

	title: Title of outline item using UTF-8 encoding. May be NULL
	if the outline item has no text string.

	uri: Destination in the document to be displayed when this
	outline item is activated. May be an internal or external
	link, or NULL if the outline item does not have a destination.

	page: The page number of an internal link, or -1 for external
	links or links with no destination.

	next: The next outline item at the same level as this outline
	item. May be NULL if no more outline items exist at this level.

	down: The outline items immediate children in the hierarchy.
	May be NULL if no children exist.
*/
typedef struct fz_outline
{
	int refs;
	char *title;
	char *uri;
	int page;
	float x, y;
	struct fz_outline *next;
	struct fz_outline *down;
	int is_open;
} fz_outline;

/**
	Create a new outline entry with zeroed fields for the caller
	to fill in.
*/
fz_outline *fz_new_outline(fz_context *ctx);

/**
	Increment the reference count. Returns the same pointer.

	Never throws exceptions.
*/
fz_outline *fz_keep_outline(fz_context *ctx, fz_outline *outline);

/**
	Decrements the reference count. When the reference point
	reaches zero, the outline is freed.

	When freed, it will drop linked	outline entries (next and down)
	too, thus a whole outline structure can be dropped by dropping
	the top entry.

	Never throws exceptions.
*/
void fz_drop_outline(fz_context *ctx, fz_outline *outline);

#endif
