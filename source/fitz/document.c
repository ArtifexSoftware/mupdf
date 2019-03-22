#include "mupdf/fitz.h"
#include "fitz-imp.h"

#include <string.h>

enum
{
	FZ_DOCUMENT_HANDLER_MAX = 10
};

#define DEFW (450)
#define DEFH (600)
#define DEFEM (12)

struct fz_document_handler_context_s
{
	int refs;
	int count;
	const fz_document_handler *handler[FZ_DOCUMENT_HANDLER_MAX];
};

void fz_new_document_handler_context(fz_context *ctx)
{
	ctx->handler = fz_malloc_struct(ctx, fz_document_handler_context);
	ctx->handler->refs = 1;
}

fz_document_handler_context *fz_keep_document_handler_context(fz_context *ctx)
{
	if (!ctx || !ctx->handler)
		return NULL;
	return fz_keep_imp(ctx, ctx->handler, &ctx->handler->refs);
}

void fz_drop_document_handler_context(fz_context *ctx)
{
	if (!ctx)
		return;

	if (fz_drop_imp(ctx, ctx->handler, &ctx->handler->refs))
	{
		fz_free(ctx, ctx->handler);
		ctx->handler = NULL;
	}
}

/*
	Register a handler
	for a document type.

	handler: The handler to register.
*/
void fz_register_document_handler(fz_context *ctx, const fz_document_handler *handler)
{
	fz_document_handler_context *dc;
	int i;

	if (!handler)
		return;

	dc = ctx->handler;
	if (dc == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Document handler list not found");

	for (i = 0; i < dc->count; i++)
		if (dc->handler[i] == handler)
			return;

	if (dc->count >= FZ_DOCUMENT_HANDLER_MAX)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Too many document handlers");

	dc->handler[dc->count++] = handler;
}

/*
	Given a magic find a document
	handler that can handle a document of this type.

	magic: Can be a filename extension (including initial period) or
	a mimetype.
*/
const fz_document_handler *
fz_recognize_document(fz_context *ctx, const char *magic)
{
	fz_document_handler_context *dc;
	int i, best_score, best_i;
	const char *ext, *needle;

	dc = ctx->handler;
	if (dc->count == 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "No document handlers registered");

	ext = strrchr(magic, '.');
	if (ext)
		needle = ext + 1;
	else
		needle = magic;

	best_score = 0;
	best_i = -1;

	for (i = 0; i < dc->count; i++)
	{
		int score = 0;
		const char **entry;

		if (dc->handler[i]->recognize)
			score = dc->handler[i]->recognize(ctx, magic);

		if (!ext)
		{
			for (entry = &dc->handler[i]->mimetypes[0]; *entry; entry++)
				if (!fz_strcasecmp(needle, *entry) && score < 100)
				{
					score = 100;
					break;
				}
		}

		for (entry = &dc->handler[i]->extensions[0]; *entry; entry++)
			if (!fz_strcasecmp(needle, *entry) && score < 100)
			{
				score = 100;
				break;
			}

		if (best_score < score)
		{
			best_score = score;
			best_i = i;
		}
	}

	if (best_i < 0)
		return NULL;

	return dc->handler[best_i];
}

#if FZ_ENABLE_PDF
extern fz_document_handler pdf_document_handler;
#endif

/*
	Open a PDF, XPS or CBZ document.

	Open a document using the specified stream object rather than
	opening a file on disk.

	magic: a string used to detect document type; either a file name or mime-type.
*/
fz_document *
fz_open_document_with_stream(fz_context *ctx, const char *magic, fz_stream *stream)
{
	const fz_document_handler *handler;

	if (magic == NULL || stream == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no document to open");

	handler = fz_recognize_document(ctx, magic);
	if (!handler)
#if FZ_ENABLE_PDF
		handler = &pdf_document_handler;
#else
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find document handler for file type: %s", magic);
#endif

	return handler->open_with_stream(ctx, stream);
}

/*
	Open a PDF, XPS or CBZ document.

	Open a document file and read its basic structure so pages and
	objects can be located. MuPDF will try to repair broken
	documents (without actually changing the file contents).

	The returned fz_document is used when calling most other
	document related functions.

	filename: a path to a file as it would be given to open(2).
*/
fz_document *
fz_open_document(fz_context *ctx, const char *filename)
{
	const fz_document_handler *handler;
	fz_stream *file;
	fz_document *doc = NULL;

	if (filename == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no document to open");

	handler = fz_recognize_document(ctx, filename);
	if (!handler)
#if FZ_ENABLE_PDF
		handler = &pdf_document_handler;
#else
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find document handler for file: %s", filename);
#endif

	if (handler->open)
		return handler->open(ctx, filename);

	file = fz_open_file(ctx, filename);

	fz_try(ctx)
		doc = handler->open_with_stream(ctx, file);
	fz_always(ctx)
		fz_drop_stream(ctx, file);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return doc;
}

void *
fz_new_document_of_size(fz_context *ctx, int size)
{
	fz_document *doc = fz_calloc(ctx, 1, size);
	doc->refs = 1;
	return doc;
}

fz_document *
fz_keep_document(fz_context *ctx, fz_document *doc)
{
	return fz_keep_imp(ctx, doc, &doc->refs);
}

void
fz_drop_document(fz_context *ctx, fz_document *doc)
{
	if (fz_drop_imp(ctx, doc, &doc->refs))
	{
		if (doc->drop_document)
			doc->drop_document(ctx, doc);
		fz_free(ctx, doc);
	}
}

static void
fz_ensure_layout(fz_context *ctx, fz_document *doc)
{
	if (doc && doc->layout && !doc->did_layout)
	{
		doc->layout(ctx, doc, DEFW, DEFH, DEFEM);
		doc->did_layout = 1;
	}
}

/*
	Is the document reflowable.

	Returns 1 to indicate reflowable documents, otherwise 0.
*/
int
fz_is_document_reflowable(fz_context *ctx, fz_document *doc)
{
	return doc ? doc->is_reflowable : 0;
}

/*
	Create a bookmark for the given page, which can be used to find the
	same location after the document has been laid out with different
	parameters.
*/
fz_bookmark fz_make_bookmark(fz_context *ctx, fz_document *doc, int page)
{
	if (doc && doc->make_bookmark)
		return doc->make_bookmark(ctx, doc, page);
	return (fz_bookmark)page;
}

/*
	Find a bookmark and return its page number.
*/
int fz_lookup_bookmark(fz_context *ctx, fz_document *doc, fz_bookmark mark)
{
	if (doc && doc->lookup_bookmark)
		return doc->lookup_bookmark(ctx, doc, mark);
	return (int)mark;
}

/*
	Check if a document is encrypted with a
	non-blank password.
*/
int
fz_needs_password(fz_context *ctx, fz_document *doc)
{
	if (doc && doc->needs_password)
		return doc->needs_password(ctx, doc);
	return 0;
}

/*
	Test if the given password can
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
int
fz_authenticate_password(fz_context *ctx, fz_document *doc, const char *password)
{
	if (doc && doc->authenticate_password)
		return doc->authenticate_password(ctx, doc, password);
	return 1;
}

/*
	Check permission flags on document.
*/
int
fz_has_permission(fz_context *ctx, fz_document *doc, fz_permission p)
{
	if (doc && doc->has_permission)
		return doc->has_permission(ctx, doc, p);
	return 1;
}

/*
	Load the hierarchical document outline.

	Should be freed by fz_drop_outline.
*/
fz_outline *
fz_load_outline(fz_context *ctx, fz_document *doc)
{
	fz_ensure_layout(ctx, doc);
	if (doc && doc->load_outline)
		return doc->load_outline(ctx, doc);
	return NULL;
}

/*
	Resolve an internal link to a page number.

	xp, yp: Pointer to store coordinate of destination on the page.

	Returns -1 if the URI cannot be resolved.
*/
int
fz_resolve_link(fz_context *ctx, fz_document *doc, const char *uri, float *xp, float *yp)
{
	fz_ensure_layout(ctx, doc);
	if (xp) *xp = 0;
	if (yp) *yp = 0;
	if (doc && doc->resolve_link)
		return doc->resolve_link(ctx, doc, uri, xp, yp);
	return -1;
}

/*
	Layout reflowable document types.

	w, h: Page size in points.
	em: Default font size in points.
*/
void
fz_layout_document(fz_context *ctx, fz_document *doc, float w, float h, float em)
{
	if (doc && doc->layout)
	{
		doc->layout(ctx, doc, w, h, em);
		doc->did_layout = 1;
	}
}

/*
	Return the number of pages in document

	May return 0 for documents with no pages.
*/
int
fz_count_pages(fz_context *ctx, fz_document *doc)
{
	fz_ensure_layout(ctx, doc);
	if (doc && doc->count_pages)
		return doc->count_pages(ctx, doc);
	return 0;
}

/*
	Retrieve document meta data strings.

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
int
fz_lookup_metadata(fz_context *ctx, fz_document *doc, const char *key, char *buf, int size)
{
	if (buf && size > 0)
		buf[0] = 0;
	if (doc && doc->lookup_metadata)
		return doc->lookup_metadata(ctx, doc, key, buf, size);
	return -1;
}

/*
	Find the output intent colorspace if the document has defined one.
*/
fz_colorspace *
fz_document_output_intent(fz_context *ctx, fz_document *doc)
{
	if (doc && doc->get_output_intent)
		return doc->get_output_intent(ctx, doc);
	return NULL;
}

/*
	Load a page.

	After fz_load_page is it possible to retrieve the size of the
	page using fz_bound_page, or to render the page using
	fz_run_page_*. Free the page by calling fz_drop_page.

	number: page number, 0 is the first page of the document.
*/
fz_page *
fz_load_page(fz_context *ctx, fz_document *doc, int number)
{
	fz_page *page;

	fz_ensure_layout(ctx, doc);

	for (page = doc->open; page; page = page->next)
		if (page->number == number)
			return fz_keep_page(ctx, page);

	if (doc && doc->load_page)
	{
		page = doc->load_page(ctx, doc, number);
		page->number = number;

		/* Insert new page at the head of the list of open pages. */
		if ((page->next = doc->open) != NULL)
			doc->open->prev = &page->next;
		doc->open = page;
		page->prev = &doc->open;
		return page;
	}

	return NULL;
}

/*
	Load the list of links for a page.

	Returns a linked list of all the links on the page, each with
	its clickable region and link destination. Each link is
	reference counted so drop and free the list of links by
	calling fz_drop_link on the pointer return from fz_load_links.

	page: Page obtained from fz_load_page.
*/
fz_link *
fz_load_links(fz_context *ctx, fz_page *page)
{
	if (page && page->load_links)
		return page->load_links(ctx, page);
	return NULL;
}

/*
	Determine the size of a page at 72 dpi.
*/
fz_rect
fz_bound_page(fz_context *ctx, fz_page *page)
{
	if (page && page->bound_page)
		return page->bound_page(ctx, page);
	return fz_empty_rect;
}

/*
	Run a page through a device. Just the main
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
void
fz_run_page_contents(fz_context *ctx, fz_page *page, fz_device *dev, fz_matrix transform, fz_cookie *cookie)
{
	if (page && page->run_page_contents)
	{
		fz_try(ctx)
		{
			page->run_page_contents(ctx, page, dev, transform, cookie);
		}
		fz_catch(ctx)
		{
			dev->close_device = NULL; /* aborted run, don't warn about unclosed device */
			if (fz_caught(ctx) != FZ_ERROR_ABORT)
				fz_rethrow(ctx);
		}
	}
}

/*
	Run the annotations on a page through a device.
*/
void
fz_run_page_annots(fz_context *ctx, fz_page *page, fz_device *dev, fz_matrix transform, fz_cookie *cookie)
{
	if (page && page->run_page_annots)
	{
		fz_try(ctx)
		{
			page->run_page_annots(ctx, page, dev, transform, cookie);
		}
		fz_catch(ctx)
		{
			dev->close_device = NULL; /* aborted run, don't warn about unclosed device */
			if (fz_caught(ctx) != FZ_ERROR_ABORT)
				fz_rethrow(ctx);
		}
	}
}

/*
	Run the widgets on a page through a device.
*/
void
fz_run_page_widgets(fz_context *ctx, fz_page *page, fz_device *dev, fz_matrix transform, fz_cookie *cookie)
{
	if (page && page->run_page_widgets)
	{
		fz_try(ctx)
		{
			page->run_page_widgets(ctx, page, dev, transform, cookie);
		}
		fz_catch(ctx)
		{
			dev->close_device = NULL; /* aborted run, don't warn about unclosed device */
			if (fz_caught(ctx) != FZ_ERROR_ABORT)
				fz_rethrow(ctx);
		}
	}
}

/*
	Run a page through a device.

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
void
fz_run_page(fz_context *ctx, fz_page *page, fz_device *dev, fz_matrix transform, fz_cookie *cookie)
{
	fz_run_page_contents(ctx, page, dev, transform, cookie);
	fz_run_page_annots(ctx, page, dev, transform, cookie);
	fz_run_page_widgets(ctx, page, dev, transform, cookie);
}

fz_page *
fz_new_page_of_size(fz_context *ctx, int size)
{
	fz_page *page = Memento_label(fz_calloc(ctx, 1, size), "fz_page");
	page->refs = 1;
	return page;
}

fz_page *
fz_keep_page(fz_context *ctx, fz_page *page)
{
	return fz_keep_imp(ctx, page, &page->refs);
}

void
fz_drop_page(fz_context *ctx, fz_page *page)
{
	if (fz_drop_imp(ctx, page, &page->refs))
	{
		/* Remove page from the list of open pages */
		if (page->next != NULL)
			page->next->prev = page->prev;
		if (page->prev != NULL)
			*page->prev = page->next;

		if (page->drop_page)
			page->drop_page(ctx, page);

		fz_free(ctx, page);
	}
}

/*
	Get the presentation details for a given page.

	transition: A pointer to a transition struct to fill out.

	duration: A pointer to a place to set the page duration in seconds.
	Will be set to 0 if no transition is specified for the page.

	Returns: a pointer to the transition structure, or NULL if there is no
	transition specified for the page.
*/
fz_transition *
fz_page_presentation(fz_context *ctx, fz_page *page, fz_transition *transition, float *duration)
{
	float dummy;
	if (duration)
		*duration = 0;
	else
		duration = &dummy;
	if (page && page->page_presentation && page)
		return page->page_presentation(ctx, page, transition, duration);
	return NULL;
}

/*
	Get the separations details for a page.
	This will be NULL, unless the format specifically supports
	separations (such as gproof, or PDF files). May be NULL even
	so, if there are no separations on a page.

	Returns a reference that must be dropped.
*/
fz_separations *
fz_page_separations(fz_context *ctx, fz_page *page)
{
	if (page && page->separations)
		return page->separations(ctx, page);
	return NULL;
}

int fz_page_uses_overprint(fz_context *ctx, fz_page *page)
{
	if (page && page->overprint)
		return page->overprint(ctx, page);
	return 0;
}
