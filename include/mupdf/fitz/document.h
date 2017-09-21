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

/*
	Document interface
*/
typedef struct fz_document_s fz_document;
typedef struct fz_document_handler_s fz_document_handler;
typedef struct fz_page_s fz_page;
typedef struct fz_annot_s fz_annot;
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
	fz_document_drop_fn: Type for a function to be called when
	the reference count for the fz_document drops to 0. The
	implementation should release any resources held by the
	document. The actual document pointer will be freed by the
	caller.
*/
typedef void (fz_document_drop_fn)(fz_context *ctx, fz_document *doc);

/*
	fz_document_needs_password_fn: Type for a function to be
	called to enquire whether the document needs a password
	or not. See fz_needs_password for more information.
*/
typedef int (fz_document_needs_password_fn)(fz_context *ctx, fz_document *doc);

/*
	fz_document_authenticate_password_fn: Type for a function to be
	called to attempt to authenticate a password. See
	fz_authenticate_password for more information.
*/
typedef int (fz_document_authenticate_password_fn)(fz_context *ctx, fz_document *doc, const char *password);

/*
	fz_document_has_permission_fn: Type for a function to be
	called to see if a document grants a certain permission. See
	fz_document_has_permission for more information.
*/
typedef int (fz_document_has_permission_fn)(fz_context *ctx, fz_document *doc, fz_permission permission);

/*
	fz_document_load_outline_fn: Type for a function to be called to
	load the outlines for a document. See fz_document_load_outline
	for more information.
*/
typedef fz_outline *(fz_document_load_outline_fn)(fz_context *ctx, fz_document *doc);

/*
	fz_document_layout_fn: Type for a function to be called to lay
	out a document. See fz_layout_document for more information.
*/
typedef void (fz_document_layout_fn)(fz_context *ctx, fz_document *doc, float w, float h, float em);

/*
	fz_document_resolve_link_fn: Type for a function to be called to
	resolve an internal link to a page number. See fz_resolve_link
	for more information.
*/
typedef int (fz_document_resolve_link_fn)(fz_context *ctx, fz_document *doc, const char *uri, float *xp, float *yp);

/*
	fz_document_count_pages_fn: Type for a function to be called to
	count the number of pages in a document. See fz_count_pages for
	more information.
*/
typedef int (fz_document_count_pages_fn)(fz_context *ctx, fz_document *doc);

/*
	fz_document_load_page_fn: Type for a function to load a given
	page from a document. See fz_load_page for more information.
*/
typedef fz_page *(fz_document_load_page_fn)(fz_context *ctx, fz_document *doc, int number);

/*
	fz_document_lookup_metadata_fn: Type for a function to query
	a documents metadata. See fz_lookup_metadata for more
	information.
*/
typedef int (fz_document_lookup_metadata_fn)(fz_context *ctx, fz_document *doc, const char *key, char *buf, int size);

/*
	fz_document_output_intent_fn: Return output intent color space if it exists
*/
typedef fz_colorspace* (fz_document_output_intent_fn)(fz_context *ctx, fz_document *doc);

/*
	fz_document_make_bookmark_fn: Type for a function to make
	a bookmark. See fz_make_bookmark for more information.
*/
typedef fz_bookmark (fz_document_make_bookmark_fn)(fz_context *ctx, fz_document *doc, int page);

/*
	fz_document_lookup_bookmark_fn: Type for a function to lookup
	a bookmark. See fz_lookup_bookmark for more information.
*/
typedef int (fz_document_lookup_bookmark_fn)(fz_context *ctx, fz_document *doc, fz_bookmark mark);

/*
	fz_page_drop_page_fn: Type for a function to release all the
	resources held by a page. Called automatically when the
	reference count for that page reaches zero.
*/
typedef void (fz_page_drop_page_fn)(fz_context *ctx, fz_page *page);

/*
	fz_page_bound_page_fn: Type for a function to return the
	bounding box of a page. See fz_bound_page for more
	information.
*/
typedef fz_rect *(fz_page_bound_page_fn)(fz_context *ctx, fz_page *page, fz_rect *);

/*
	fz_page_run_page_contents_fn: Type for a function to run the
	contents of a page. See fz_run_page_contents for more
	information.
*/
typedef void (fz_page_run_page_contents_fn)(fz_context *ctx, fz_page *page, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie);

/*
	fz_page_load_links_fn: Type for a function to load the links
	from a page. See fz_load_links for more information.
*/
typedef fz_link *(fz_page_load_links_fn)(fz_context *ctx, fz_page *page);

/*
	fz_page_first_annot_fn: Type for a function to load the
	annotations from a page. See fz_first_annot for more
	information.
*/
typedef fz_annot *(fz_page_first_annot_fn)(fz_context *ctx, fz_page *page);

/*
	fz_page_page_presentation_fn: Type for a function to
	obtain the details of how this page should be presented when
	in presentation mode. See fz_page_presentation for more
	information.
*/
typedef fz_transition *(fz_page_page_presentation_fn)(fz_context *ctx, fz_page *page, fz_transition *transition, float *duration);

/*
	fz_page_control_separation: Type for a function to enable/
	disable separations on a page. See fz_control_separation for
	more information.
*/
typedef void (fz_page_control_separation_fn)(fz_context *ctx, fz_page *page, int separation, int disable);

/*
	fz_page_separation_disabled_fn: Type for a function to detect
	whether a given separation is enabled or disabled on a page.
	See FZ_SEPARATION_DISABLED for more information.
*/
typedef int (fz_page_separation_disabled_fn)(fz_context *ctx, fz_page *page, int separation);

/*
	fz_page_separations_fn: Type for a function to retrieve
	details of separations on a page. See fz_get_separations
	for more information.
*/
typedef fz_separations *(fz_page_separations_fn)(fz_context *ctx, fz_page *page);

/*
	fz_page_uses_overprint_fn: Type for a function to retrieve
	whether or not a given page uses overprint.
*/
typedef int (fz_page_uses_overprint_fn)(fz_context *ctx, fz_page *page);

typedef void (fz_annot_drop_fn)(fz_context *ctx, fz_annot *annot);
typedef fz_annot *(fz_annot_next_fn)(fz_context *ctx, fz_annot *annot);
typedef fz_rect *(fz_annot_bound_fn)(fz_context *ctx, fz_annot *annot, fz_rect *rect);
typedef void (fz_annot_run_fn)(fz_context *ctx, fz_annot *annot, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie);

/*
	Structure definition is public so other classes can
	derive from it. Do not access the members directly.
*/
struct fz_annot_s
{
	int refs;
	fz_annot_drop_fn *drop_annot;
	fz_annot_bound_fn *bound_annot;
	fz_annot_run_fn *run_annot;
	fz_annot_next_fn *next_annot;
};

/*
	Structure definition is public so other classes can
	derive from it. Do not access the members directly.
*/
struct fz_page_s
{
	int refs;
	fz_page_drop_page_fn *drop_page;
	fz_page_bound_page_fn *bound_page;
	fz_page_run_page_contents_fn *run_page_contents;
	fz_page_load_links_fn *load_links;
	fz_page_first_annot_fn *first_annot;
	fz_page_page_presentation_fn *page_presentation;
	fz_page_control_separation_fn *control_separation;
	fz_page_separation_disabled_fn *separation_disabled;
	fz_page_separations_fn *separations;
	fz_page_uses_overprint_fn *overprint;
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
};

/*
	fz_document_open_fn: Function type to open a document from a
	file.

	filename: file to open

	Pointer to opened document. Throws exception in case of error.
*/
typedef fz_document *(fz_document_open_fn)(fz_context *ctx, const char *filename);

/*
	fz_document_open_with_stream_fn: Function type to open a
	document from a file.

	stream: fz_stream to read document data from. Must be
	seekable for formats that require it.

	Pointer to opened document. Throws exception in case of error.
*/
typedef fz_document *(fz_document_open_with_stream_fn)(fz_context *ctx, fz_stream *stream);

/*
	fz_document_recognize_fn: Recognize a document type from
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

/*
	fz_register_document_handler: Register a handler
	for a document type.

	handler: The handler to register.
*/
void fz_register_document_handler(fz_context *ctx, const fz_document_handler *handler);

/*
	fz_register_document_handler: Register handlers
	for all the standard document types supported in
	this build.
*/
void fz_register_document_handlers(fz_context *ctx);

/*
	fz_recognize_document: Given a magic find a document
	handler that can handle a document of this type.

	magic: Can be a file extension (including initial period) or
	a mimetype.
*/
const fz_document_handler *fz_recognize_document(fz_context *ctx, const char *magic);

/*
	fz_open_document: Open a PDF, XPS or CBZ document.

	Open a document file and read its basic structure so pages and
	objects can be located. MuPDF will try to repair broken
	documents (without actually changing the file contents).

	The returned fz_document is used when calling most other
	document related functions.

	filename: a path to a file as it would be given to open(2).
*/
fz_document *fz_open_document(fz_context *ctx, const char *filename);

/*
	fz_open_document_with_stream: Open a PDF, XPS or CBZ document.

	Open a document using the specified stream object rather than
	opening a file on disk.

	magic: a string used to detect document type; either a file name or mime-type.
*/
fz_document *fz_open_document_with_stream(fz_context *ctx, const char *magic, fz_stream *stream);

/*
	fz_new_document: Create and initialize a document struct.
*/
void *fz_new_document_of_size(fz_context *ctx, int size);

#define fz_new_derived_document(C,M) ((M*)Memento_label(fz_new_document_of_size(C, sizeof(M)), #M))

/*
	fz_keep_document: Keep a reference to an open document.
*/
fz_document *fz_keep_document(fz_context *ctx, fz_document *doc);

/*
	fz_drop_document: Release an open document.

	The resource store in the context associated with fz_document
	is emptied, and any allocations for the document are freed when
	the last reference is dropped.
*/
void fz_drop_document(fz_context *ctx, fz_document *doc);

/*
	fz_needs_password: Check if a document is encrypted with a
	non-blank password.
*/
int fz_needs_password(fz_context *ctx, fz_document *doc);

/*
	fz_authenticate_password: Test if the given password can
	decrypt the document.

	password: The password string to be checked. Some document
	specifications do not specify any particular text encoding, so
	neither do we.

	Returns 0 for failure to authenticate, non-zero for success.

	For PDF documents, further information can be given by examining
	the bits in the return code.

		Bit 0 => No password required
		Bit 1 => User password authenticated
		Bit 2 => Owner password authenticated
*/
int fz_authenticate_password(fz_context *ctx, fz_document *doc, const char *password);

/*
	fz_load_outline: Load the hierarchical document outline.

	Should be freed by fz_drop_outline.
*/
fz_outline *fz_load_outline(fz_context *ctx, fz_document *doc);

/*
	fz_is_document_reflowable: Is the document reflowable.

	Returns 1 to indicate reflowable documents, otherwise 0.
*/
int fz_is_document_reflowable(fz_context *ctx, fz_document *doc);

/*
	fz_layout_document: Layout reflowable document types.

	w, h: Page size in points.
	em: Default font size in points.
*/
void fz_layout_document(fz_context *ctx, fz_document *doc, float w, float h, float em);

/*
	Create a bookmark for the given page, which can be used to find the
	same location after the document has been laid out with different
	parameters.
*/
fz_bookmark fz_make_bookmark(fz_context *ctx, fz_document *doc, int page);

/*
	Find a bookmark and return its page number.
*/
int fz_lookup_bookmark(fz_context *ctx, fz_document *doc, fz_bookmark mark);

/*
	fz_count_pages: Return the number of pages in document

	May return 0 for documents with no pages.
*/
int fz_count_pages(fz_context *ctx, fz_document *doc);

/*
	fz_resolve_link: Resolve an internal link to a page number.

	xp, yp: Pointer to store coordinate of destination on the page.

	Returns -1 if the URI cannot be resolved.
*/
int fz_resolve_link(fz_context *ctx, fz_document *doc, const char *uri, float *xp, float *yp);

/*
	fz_load_page: Load a page.

	After fz_load_page is it possible to retrieve the size of the
	page using fz_bound_page, or to render the page using
	fz_run_page_*. Free the page by calling fz_drop_page.

	number: page number, 0 is the first page of the document.
*/
fz_page *fz_load_page(fz_context *ctx, fz_document *doc, int number);

/*
	fz_load_links: Load the list of links for a page.

	Returns a linked list of all the links on the page, each with
	its clickable region and link destination. Each link is
	reference counted so drop and free the list of links by
	calling fz_drop_link on the pointer return from fz_load_links.

	page: Page obtained from fz_load_page.
*/
fz_link *fz_load_links(fz_context *ctx, fz_page *page);

/*
	fz_new_page_of_size: Create and initialize a page struct.
*/
fz_page *fz_new_page_of_size(fz_context *ctx, int size);

#define fz_new_derived_page(CTX,TYPE) \
	((TYPE *)Memento_label(fz_new_page_of_size(CTX,sizeof(TYPE)),#TYPE))

/*
	fz_bound_page: Determine the size of a page at 72 dpi.

*/
fz_rect *fz_bound_page(fz_context *ctx, fz_page *page, fz_rect *rect);

/*
	fz_run_page: Run a page through a device.

	page: Page obtained from fz_load_page.

	dev: Device obtained from fz_new_*_device.

	transform: Transform to apply to page. May include for example
	scaling and rotation, see fz_scale, fz_rotate and fz_concat.
	Set to fz_identity if no transformation is desired.

	cookie: Communication mechanism between caller and library
	rendering the page. Intended for multi-threaded applications,
	while single-threaded applications set cookie to NULL. The
	caller may abort an ongoing rendering of a page. Cookie also
	communicates progress information back to the caller. The
	fields inside cookie are continually updated while the page is
	rendering.
*/
void fz_run_page(fz_context *ctx, fz_page *page, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie);

/*
	fz_run_page_contents: Run a page through a device. Just the main
	page content, without the annotations, if any.

	page: Page obtained from fz_load_page.

	dev: Device obtained from fz_new_*_device.

	transform: Transform to apply to page. May include for example
	scaling and rotation, see fz_scale, fz_rotate and fz_concat.
	Set to fz_identity if no transformation is desired.

	cookie: Communication mechanism between caller and library
	rendering the page. Intended for multi-threaded applications,
	while single-threaded applications set cookie to NULL. The
	caller may abort an ongoing rendering of a page. Cookie also
	communicates progress information back to the caller. The
	fields inside cookie are continually updated while the page is
	rendering.
*/
void fz_run_page_contents(fz_context *ctx, fz_page *page, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie);

/*
	fz_run_annot: Run an annotation through a device.

	page: Page obtained from fz_load_page.

	annot: an annotation.

	dev: Device obtained from fz_new_*_device.

	transform: Transform to apply to page. May include for example
	scaling and rotation, see fz_scale, fz_rotate and fz_concat.
	Set to fz_identity if no transformation is desired.

	cookie: Communication mechanism between caller and library
	rendering the page. Intended for multi-threaded applications,
	while single-threaded applications set cookie to NULL. The
	caller may abort an ongoing rendering of a page. Cookie also
	communicates progress information back to the caller. The
	fields inside cookie are continually updated while the page is
	rendering.
*/
void fz_run_annot(fz_context *ctx, fz_annot *annot, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie);

/*
	fz_keep_page: Keep a reference to a loaded page.
*/
fz_page *fz_keep_page(fz_context *ctx, fz_page *page);

/*
	fz_drop_page: Free a loaded page.
*/
void fz_drop_page(fz_context *ctx, fz_page *page);

/*
	fz_page_presentation: Get the presentation details for a given page.

	transition: A pointer to a transition struct to fill out.

	duration: A pointer to a place to set the page duration in seconds.
	Will be set to 0 if no transition is specified for the page.

	Returns: a pointer to the transition structure, or NULL if there is no
	transition specified for the page.
*/
fz_transition *fz_page_presentation(fz_context *ctx, fz_page *page, fz_transition *transition, float *duration);

/*
	fz_has_permission: Check permission flags on document.
*/
int fz_has_permission(fz_context *ctx, fz_document *doc, fz_permission p);

/*
	fz_lookup_metadata: Retrieve document meta data strings.

	doc: The document to query.

	key: Which meta data key to retrieve...

	Basic information:
		'format'	-- Document format and version.
		'encryption'	-- Description of the encryption used.

	From the document information dictionary:
		'info:Title'
		'info:Author'
		'info:Subject'
		'info:Keywords'
		'info:Creator'
		'info:Producer'
		'info:CreationDate'
		'info:ModDate'

	buf: The buffer to hold the results (a nul-terminated UTF-8 string).

	size: Size of 'buf'.

	Returns the size of the output string (may be larger than 'size' if
	the output was truncated), or -1 if the key is not recognized or found.
*/
int fz_lookup_metadata(fz_context *ctx, fz_document *doc, const char *key, char *buf, int size);

#define FZ_META_FORMAT "format"
#define FZ_META_ENCRYPTION "encryption"

#define FZ_META_INFO_AUTHOR "info:Author"
#define FZ_META_INFO_TITLE "info:Title"

/*
	Find the output intent colorspace if the document has defined one.
*/
fz_colorspace *fz_document_output_intent(fz_context *ctx, fz_document *doc);

/*
	fz_page_separations: Get the separations details for a page.
	This will be NULL, unless the format specifically supports
	separations (such as gproof, or PDF files). May be NULL even
	so, if there are no separations on a page.

	Returns a reference that must be dropped.
*/
fz_separations *fz_page_separations(fz_context *ctx, fz_page *page);

/*
	fz_page_uses_overprint: Find out whether a given page requests
	overprint.
*/
int fz_page_uses_overprint(fz_context *ctx, fz_page *page);

/*
	fz_save_gproof: Given a currently open document, create a
	gproof skeleton file from that document.

	doc_filename: The name of the currently opened document file.

	doc: The currently opened document.

	filename: The filename of the desired gproof file.

	res: The resolution at which proofing should be done.

	print_profile: The filename of the ICC profile for the printer we are proofing

	display_profile: The filename of the ICC profile for our display device
*/
void fz_save_gproof(fz_context *ctx, const char *doc_filename, fz_document *doc, const char *filename, int res,
	const char *print_profile, const char *display_profile);

#endif
