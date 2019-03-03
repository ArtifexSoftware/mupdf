#ifndef MUPDF_FITZ_DOCUMENT_H
#define MUPDF_FITZ_DOCUMENT_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/geometry.h"
#include "mupdf/fitz/device.h"
#include "mupdf/fitz/transition.h"
#include "mupdf/fitz/link.h"
#include "mupdf/fitz/outline.h"
#include "mupdf/fitz/separation.h"

typedef struct fz_document_s fz_document;
typedef struct fz_document_handler_s fz_document_handler;
typedef struct fz_page_s fz_page;
typedef intptr_t fz_bookmark;

typedef enum
{
	FZ_PERMISSION_PRINT = 'p',
	FZ_PERMISSION_COPY = 'c',
	FZ_PERMISSION_EDIT = 'e',
	FZ_PERMISSION_ANNOTATE = 'n',
}
fz_permission;

/*
	Type for a function to be called when
	the reference count for the fz_document drops to 0. The
	implementation should release any resources held by the
	document. The actual document pointer will be freed by the
	caller.
*/
typedef void (fz_document_drop_fn)(fz_context *ctx, fz_document *doc);

/*
	Type for a function to be
	called to enquire whether the document needs a password
	or not. See fz_needs_password for more information.
*/
typedef int (fz_document_needs_password_fn)(fz_context *ctx, fz_document *doc);

/*
	Type for a function to be
	called to attempt to authenticate a password. See
	fz_authenticate_password for more information.
*/
typedef int (fz_document_authenticate_password_fn)(fz_context *ctx, fz_document *doc, const char *password);

/*
	Type for a function to be
	called to see if a document grants a certain permission. See
	fz_document_has_permission for more information.
*/
typedef int (fz_document_has_permission_fn)(fz_context *ctx, fz_document *doc, fz_permission permission);

/*
	Type for a function to be called to
	load the outlines for a document. See fz_document_load_outline
	for more information.
*/
typedef fz_outline *(fz_document_load_outline_fn)(fz_context *ctx, fz_document *doc);

/*
	Type for a function to be called to lay
	out a document. See fz_layout_document for more information.
*/
typedef void (fz_document_layout_fn)(fz_context *ctx, fz_document *doc, float w, float h, float em);

/*
	Type for a function to be called to
	resolve an internal link to a page number. See fz_resolve_link
	for more information.
*/
typedef int (fz_document_resolve_link_fn)(fz_context *ctx, fz_document *doc, const char *uri, float *xp, float *yp);

/*
	Type for a function to be called to
	count the number of pages in a document. See fz_count_pages for
	more information.
*/
typedef int (fz_document_count_pages_fn)(fz_context *ctx, fz_document *doc);

/*
	Type for a function to load a given
	page from a document. See fz_load_page for more information.
*/
typedef fz_page *(fz_document_load_page_fn)(fz_context *ctx, fz_document *doc, int number);

/*
	Type for a function to query
	a documents metadata. See fz_lookup_metadata for more
	information.
*/
typedef int (fz_document_lookup_metadata_fn)(fz_context *ctx, fz_document *doc, const char *key, char *buf, int size);

/*
	Return output intent color space if it exists
*/
typedef fz_colorspace* (fz_document_output_intent_fn)(fz_context *ctx, fz_document *doc);

/*
	Type for a function to make
	a bookmark. See fz_make_bookmark for more information.
*/
typedef fz_bookmark (fz_document_make_bookmark_fn)(fz_context *ctx, fz_document *doc, int page);

/*
	Type for a function to lookup
	a bookmark. See fz_lookup_bookmark for more information.
*/
typedef int (fz_document_lookup_bookmark_fn)(fz_context *ctx, fz_document *doc, fz_bookmark mark);

/*
	Type for a function to release all the
	resources held by a page. Called automatically when the
	reference count for that page reaches zero.
*/
typedef void (fz_page_drop_page_fn)(fz_context *ctx, fz_page *page);

/*
	Type for a function to return the
	bounding box of a page. See fz_bound_page for more
	information.
*/
typedef fz_rect (fz_page_bound_page_fn)(fz_context *ctx, fz_page *page);

/*
	Type for a function to run the
	contents of a page. See fz_run_page_contents for more
	information.
*/
typedef void (fz_page_run_page_fn)(fz_context *ctx, fz_page *page, fz_device *dev, fz_matrix transform, fz_cookie *cookie);

/*
	Type for a function to load the links
	from a page. See fz_load_links for more information.
*/
typedef fz_link *(fz_page_load_links_fn)(fz_context *ctx, fz_page *page);

/*
	Type for a function to
	obtain the details of how this page should be presented when
	in presentation mode. See fz_page_presentation for more
	information.
*/
typedef fz_transition *(fz_page_page_presentation_fn)(fz_context *ctx, fz_page *page, fz_transition *transition, float *duration);

/*
	Type for a function to enable/
	disable separations on a page. See fz_control_separation for
	more information.
*/
typedef void (fz_page_control_separation_fn)(fz_context *ctx, fz_page *page, int separation, int disable);

/*
	Type for a function to detect
	whether a given separation is enabled or disabled on a page.
	See FZ_SEPARATION_DISABLED for more information.
*/
typedef int (fz_page_separation_disabled_fn)(fz_context *ctx, fz_page *page, int separation);

/*
	Type for a function to retrieve
	details of separations on a page. See fz_get_separations
	for more information.
*/
typedef fz_separations *(fz_page_separations_fn)(fz_context *ctx, fz_page *page);

/*
	Type for a function to retrieve
	whether or not a given page uses overprint.
*/
typedef int (fz_page_uses_overprint_fn)(fz_context *ctx, fz_page *page);

/*
	Structure definition is public so other classes can
	derive from it. Do not access the members directly.
*/
struct fz_page_s
{
	int refs;
	int number; /* page number */
	fz_page_drop_page_fn *drop_page;
	fz_page_bound_page_fn *bound_page;
	fz_page_run_page_fn *run_page_contents;
	fz_page_run_page_fn *run_page_annots;
	fz_page_run_page_fn *run_page_widgets;
	fz_page_load_links_fn *load_links;
	fz_page_page_presentation_fn *page_presentation;
	fz_page_control_separation_fn *control_separation;
	fz_page_separation_disabled_fn *separation_disabled;
	fz_page_separations_fn *separations;
	fz_page_uses_overprint_fn *overprint;
	fz_page **prev, *next; /* linked list of currently open pages */
};

/*
	Structure definition is public so other classes can
	derive from it. Callers shoud not access the members
	directly, though implementations will need initialize
	functions directly.
*/
struct fz_document_s
{
	int refs;
	fz_document_drop_fn *drop_document;
	fz_document_needs_password_fn *needs_password;
	fz_document_authenticate_password_fn *authenticate_password;
	fz_document_has_permission_fn *has_permission;
	fz_document_load_outline_fn *load_outline;
	fz_document_layout_fn *layout;
	fz_document_make_bookmark_fn *make_bookmark;
	fz_document_lookup_bookmark_fn *lookup_bookmark;
	fz_document_resolve_link_fn *resolve_link;
	fz_document_count_pages_fn *count_pages;
	fz_document_load_page_fn *load_page;
	fz_document_lookup_metadata_fn *lookup_metadata;
	fz_document_output_intent_fn *get_output_intent;
	int did_layout;
	int is_reflowable;
	fz_page *open; /* linked list of currently open pages */
};

/*
	Function type to open a document from a
	file.

	filename: file to open

	Pointer to opened document. Throws exception in case of error.
*/
typedef fz_document *(fz_document_open_fn)(fz_context *ctx, const char *filename);

/*
	Function type to open a
	document from a file.

	stream: fz_stream to read document data from. Must be
	seekable for formats that require it.

	Pointer to opened document. Throws exception in case of error.
*/
typedef fz_document *(fz_document_open_with_stream_fn)(fz_context *ctx, fz_stream *stream);

/*
	Recognize a document type from
	a magic string.

	magic: string to recognise - typically a filename or mime
	type.

	Returns a number between 0 (not recognized) and 100
	(fully recognized) based on how certain the recognizer
	is that this is of the required type.
*/
typedef int (fz_document_recognize_fn)(fz_context *ctx, const char *magic);

struct fz_document_handler_s
{
	fz_document_recognize_fn *recognize;
	fz_document_open_fn *open;
	fz_document_open_with_stream_fn *open_with_stream;
	const char **extensions;
	const char **mimetypes;
};

void fz_register_document_handler(fz_context *ctx, const fz_document_handler *handler);

void fz_register_document_handlers(fz_context *ctx);

const fz_document_handler *fz_recognize_document(fz_context *ctx, const char *magic);

fz_document *fz_open_document(fz_context *ctx, const char *filename);

fz_document *fz_open_document_with_stream(fz_context *ctx, const char *magic, fz_stream *stream);

void *fz_new_document_of_size(fz_context *ctx, int size);
#define fz_new_derived_document(C,M) ((M*)Memento_label(fz_new_document_of_size(C, sizeof(M)), #M))

fz_document *fz_keep_document(fz_context *ctx, fz_document *doc);
void fz_drop_document(fz_context *ctx, fz_document *doc);

int fz_needs_password(fz_context *ctx, fz_document *doc);

int fz_authenticate_password(fz_context *ctx, fz_document *doc, const char *password);

fz_outline *fz_load_outline(fz_context *ctx, fz_document *doc);

int fz_is_document_reflowable(fz_context *ctx, fz_document *doc);

void fz_layout_document(fz_context *ctx, fz_document *doc, float w, float h, float em);

fz_bookmark fz_make_bookmark(fz_context *ctx, fz_document *doc, int page);

int fz_lookup_bookmark(fz_context *ctx, fz_document *doc, fz_bookmark mark);

int fz_count_pages(fz_context *ctx, fz_document *doc);

int fz_resolve_link(fz_context *ctx, fz_document *doc, const char *uri, float *xp, float *yp);

fz_page *fz_load_page(fz_context *ctx, fz_document *doc, int number);

fz_link *fz_load_links(fz_context *ctx, fz_page *page);

fz_page *fz_new_page_of_size(fz_context *ctx, int size);
#define fz_new_derived_page(CTX,TYPE) \
	((TYPE *)Memento_label(fz_new_page_of_size(CTX,sizeof(TYPE)),#TYPE))

fz_rect fz_bound_page(fz_context *ctx, fz_page *page);

void fz_run_page(fz_context *ctx, fz_page *page, fz_device *dev, fz_matrix transform, fz_cookie *cookie);

void fz_run_page_contents(fz_context *ctx, fz_page *page, fz_device *dev, fz_matrix transform, fz_cookie *cookie);
void fz_run_page_annots(fz_context *ctx, fz_page *page, fz_device *dev, fz_matrix transform, fz_cookie *cookie);
void fz_run_page_widgets(fz_context *ctx, fz_page *page, fz_device *dev, fz_matrix transform, fz_cookie *cookie);

fz_page *fz_keep_page(fz_context *ctx, fz_page *page);
void fz_drop_page(fz_context *ctx, fz_page *page);

fz_transition *fz_page_presentation(fz_context *ctx, fz_page *page, fz_transition *transition, float *duration);

int fz_has_permission(fz_context *ctx, fz_document *doc, fz_permission p);

int fz_lookup_metadata(fz_context *ctx, fz_document *doc, const char *key, char *buf, int size);

#define FZ_META_FORMAT "format"
#define FZ_META_ENCRYPTION "encryption"

#define FZ_META_INFO_AUTHOR "info:Author"
#define FZ_META_INFO_TITLE "info:Title"

fz_colorspace *fz_document_output_intent(fz_context *ctx, fz_document *doc);

fz_separations *fz_page_separations(fz_context *ctx, fz_page *page);

int fz_page_uses_overprint(fz_context *ctx, fz_page *page);

void fz_save_gproof(fz_context *ctx, const char *doc_filename, fz_document *doc, const char *filename, int res,
	const char *print_profile, const char *display_profile);

#endif
