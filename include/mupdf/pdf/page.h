#ifndef MUPDF_PDF_PAGE_H
#define MUPDF_PDF_PAGE_H

#include "mupdf/pdf/interpret.h"

int pdf_lookup_page_number(fz_context *ctx, pdf_document *doc, pdf_obj *pageobj);
int pdf_count_pages(fz_context *ctx, pdf_document *doc);
pdf_obj *pdf_lookup_page_obj(fz_context *ctx, pdf_document *doc, int needle);
void pdf_load_page_tree(fz_context *ctx, pdf_document *doc);
void pdf_drop_page_tree(fz_context *ctx, pdf_document *doc);

/*
	pdf_lookup_anchor: Find the page number of a named destination.

	For use with looking up the destination page of a fragment
	identifier in hyperlinks: foo.pdf#bar or foo.pdf#page=5.
*/
int pdf_lookup_anchor(fz_context *ctx, pdf_document *doc, const char *name, float *xp, float *yp);

/*
	pdf_flatten_inheritable_page_items: Make page self sufficient.

	Copy any inheritable page keys into the actual page object, removing
	any dependencies on the page tree parents.
*/
void pdf_flatten_inheritable_page_items(fz_context *ctx, pdf_obj *page);

/*
	pdf_load_page: Load a page and its resources.

	Locates the page in the PDF document and loads the page and its
	resources. After pdf_load_page is it possible to retrieve the size
	of the page using pdf_bound_page, or to render the page using
	pdf_run_page_*.

	number: page number, where 0 is the first page of the document.
*/
pdf_page *pdf_load_page(fz_context *ctx, pdf_document *doc, int number);

void pdf_page_obj_transform(fz_context *ctx, pdf_obj *pageobj, fz_rect *page_mediabox, fz_matrix *page_ctm);
void pdf_page_transform(fz_context *ctx, pdf_page *page, fz_rect *mediabox, fz_matrix *ctm);
pdf_obj *pdf_page_resources(fz_context *ctx, pdf_page *page);
pdf_obj *pdf_page_contents(fz_context *ctx, pdf_page *page);
pdf_obj *pdf_page_group(fz_context *ctx, pdf_page *page);

/*
	pdf_page_separations: Get the separation details for a page.
*/
fz_separations *pdf_page_separations(fz_context *ctx, pdf_page *page);

fz_link *pdf_load_links(fz_context *ctx, pdf_page *page);

/*
	pdf_bound_page: Determine the size of a page.

	Determine the page size in user space units, taking page rotation
	into account. The page size is taken to be the crop box if it
	exists (visible area after cropping), otherwise the media box will
	be used (possibly including printing marks).
*/
fz_rect *pdf_bound_page(fz_context *ctx, pdf_page *page, fz_rect *);

/*
	pdf_run_page: Interpret a loaded page and render it on a device.

	page: A page loaded by pdf_load_page.

	dev: Device used for rendering, obtained from fz_new_*_device.

	ctm: A transformation matrix applied to the objects on the page,
	e.g. to scale or rotate the page contents as desired.
*/
void pdf_run_page(fz_context *ctx, pdf_page *page, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie);

/*
	pdf_run_page_with_usage: Interpret a loaded page and render it on a device.

	page: A page loaded by pdf_load_page.

	dev: Device used for rendering, obtained from fz_new_*_device.

	ctm: A transformation matrix applied to the objects on the page,
	e.g. to scale or rotate the page contents as desired.

	usage: The 'usage' for displaying the file (typically
	'View', 'Print' or 'Export'). NULL means 'View'.

	cookie: A pointer to an optional fz_cookie structure that can be used
	to track progress, collect errors etc.
*/
void pdf_run_page_with_usage(fz_context *ctx, pdf_document *doc, pdf_page *page, fz_device *dev, const fz_matrix *ctm, const char *usage, fz_cookie *cookie);

/*
	pdf_run_page_contents: Interpret a loaded page and render it on a device.
	Just the main page contents without the annotations

	page: A page loaded by pdf_load_page.

	dev: Device used for rendering, obtained from fz_new_*_device.

	ctm: A transformation matrix applied to the objects on the page,
	e.g. to scale or rotate the page contents as desired.
*/
void pdf_run_page_contents(fz_context *ctx, pdf_page *page, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie);

/*
	pdf_page_contents_process_fn: A function used for processing the
	cleaned page contents/resources gathered as part of
	pdf_clean_page_contents.

	buffer: A buffer holding the page contents.

	res: A pdf_obj holding the page resources.

	arg: An opaque arg specific to the particular function.
*/
typedef void (pdf_page_contents_process_fn)(fz_context *ctx, fz_buffer *buffer, pdf_obj *res, void *arg);

/*
	pdf_clean_page_contents: Clean a loaded pages rendering operations,
	with an optional post processing step.

	Firstly, this filters the PDF operators used to avoid (some cases
	of) repetition, and leaves the page in a balanced state with an
	unchanged top level matrix etc. At the same time, the resources
	used by the page contents are collected.

	Next, the resources themselves are cleaned (as appropriate) in the
	same way.

	Next, an optional post processing stage is called.

	Finally, the page contents and resources in the documents page tree
	are replaced by these processed versions.

	Annotations remain unaffected.

	page: A page loaded by pdf_load_page.

	cookie: A pointer to an optional fz_cookie structure that can be used
	to track progress, collect errors etc.
*/
void pdf_clean_page_contents(fz_context *ctx, pdf_document *doc, pdf_page *page, fz_cookie *cookie,
	pdf_page_contents_process_fn *proc, void *proc_arg, int ascii);

/*
	pdf_clean_annot_contents: Clean a loaded annotations rendering operations,
	with an optional post processing step.

	Each appearance stream in the annotation is processed.

	Firstly, this filters the PDF operators used to avoid (some cases
	of) repetition, and leaves the page in a balanced state with an
	unchanged top level matrix etc. At the same time, the resources
	used by the page contents are collected.

	Next, the resources themselves are cleaned (as appropriate) in the
	same way.

	Next, an optional post processing stage is called.

	Finally, the updated stream of operations is reinserted into the
	appearance stream.

	annot: An annotation loaded by pdf_load_annot.

	cookie: A pointer to an optional fz_cookie structure that can be used
	to track progress, collect errors etc.
*/
void pdf_clean_annot_contents(fz_context *ctx, pdf_document *doc, pdf_annot *annot, fz_cookie *cookie,
	pdf_page_contents_process_fn *proc, void *proc_arg, int ascii);

/*
	pdf_filter_page_contents: Performs the same task as
	pdf_clean_page_contents, but with an optional text filter
	function.

	text_filter: Function to assess whether a given character
	should be kept (return 0) or removed (return 1).

	after_text: Function called after each text object is closed
	to allow other output to be sent.

	arg: Opaque value to be passed to callback functions.
*/
void pdf_filter_page_contents(fz_context *ctx, pdf_document *doc, pdf_page *page, fz_cookie *cookie,
	pdf_page_contents_process_fn *proc_fn, pdf_text_filter_fn *text_filter, pdf_after_text_object_fn *after_text, void *arg, int ascii);

/*
	pdf_filter_annot_contents: Performs the same task as
	pdf_clean_annot_contents, but with an optional text filter
	function.

	text_filter: Function to assess whether a given character
	should be kept (return 0) or removed (return 1).

	after_text: Function called after each text object is closed
	to allow other output to be sent.

	arg: Opaque value to be passed to callback functions.
*/
void pdf_filter_annot_contents(fz_context *ctx, pdf_document *doc, pdf_annot *annot, fz_cookie *cookie,
	pdf_page_contents_process_fn *proc, pdf_text_filter_fn *text_filter, pdf_after_text_object_fn *after_text, void *arg, int ascii);

/*
	Presentation interface.
*/
fz_transition *pdf_page_presentation(fz_context *ctx, pdf_page *page, fz_transition *transition, float *duration);

/*
	Load default colorspaces for a page.
*/
fz_default_colorspaces *pdf_load_default_colorspaces(fz_context *ctx, pdf_document *doc, pdf_page *page);

/*
	Update default colorspaces for an xobject.
*/
fz_default_colorspaces *pdf_update_default_colorspaces(fz_context *ctx, fz_default_colorspaces *old_cs, pdf_obj *res);

/*
 * Page tree, pages and related objects
 */

struct pdf_page_s
{
	fz_page super;
	pdf_document *doc;
	pdf_obj *obj;

	int transparency;
	int overprint;
	int incomplete;

	fz_link *links;
	pdf_annot *annots, **annot_tailp;
};

enum
{
	PDF_PAGE_INCOMPLETE_CONTENTS = 1,
	PDF_PAGE_INCOMPLETE_ANNOTS = 2
};

#endif
