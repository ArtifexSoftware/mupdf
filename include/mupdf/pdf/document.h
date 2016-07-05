#ifndef MUPDF_PDF_DOCUMENT_H
#define MUPDF_PDF_DOCUMENT_H

typedef struct pdf_lexbuf_s pdf_lexbuf;
typedef struct pdf_lexbuf_large_s pdf_lexbuf_large;
typedef struct pdf_xref_s pdf_xref;
typedef struct pdf_crypt_s pdf_crypt;
typedef struct pdf_ocg_descriptor_s pdf_ocg_descriptor;

typedef struct pdf_page_s pdf_page;
typedef struct pdf_annot_s pdf_annot;
typedef struct pdf_widget_s pdf_widget;
typedef struct pdf_hotspot_s pdf_hotspot;
typedef struct pdf_js_s pdf_js;
typedef struct pdf_resource_tables_s pdf_resource_tables;

enum
{
	PDF_LEXBUF_SMALL = 256,
	PDF_LEXBUF_LARGE = 65536
};

struct pdf_lexbuf_s
{
	int size;
	int base_size;
	int len;
	fz_off_t i;
	float f;
	char *scratch;
	char buffer[PDF_LEXBUF_SMALL];
};

struct pdf_lexbuf_large_s
{
	pdf_lexbuf base;
	char buffer[PDF_LEXBUF_LARGE - PDF_LEXBUF_SMALL];
};

struct pdf_hotspot_s
{
	int num;
	int state;
};

/*
	Document event structures are mostly opaque to the app. Only the type
	is visible to the app.
*/
typedef struct pdf_doc_event_s pdf_doc_event;

/*
	pdf_doc_event_cb: the type of function via which the app receives
	document events.
*/
typedef void (pdf_doc_event_cb)(fz_context *ctx, pdf_document *doc, pdf_doc_event *event, void *data);

/*
	pdf_open_document: Open a PDF document.

	Open a PDF document by reading its cross reference table, so
	MuPDF can locate PDF objects inside the file. Upon an broken
	cross reference table or other parse errors MuPDF will restart
	parsing the file from the beginning to try to rebuild a
	(hopefully correct) cross reference table to allow further
	processing of the file.

	The returned pdf_document should be used when calling most
	other PDF functions. Note that it wraps the context, so those
	functions implicitly get access to the global state in
	context.

	filename: a path to a file as it would be given to open(2).
*/
pdf_document *pdf_open_document(fz_context *ctx, const char *filename);

/*
	pdf_open_document_with_stream: Opens a PDF document.

	Same as pdf_open_document, but takes a stream instead of a
	filename to locate the PDF document to open. Increments the
	reference count of the stream. See fz_open_file,
	fz_open_file_w or fz_open_fd for opening a stream, and
	fz_drop_stream for closing an open stream.
*/
pdf_document *pdf_open_document_with_stream(fz_context *ctx, fz_stream *file);

/*
	pdf_drop_document: Closes and frees an opened PDF document.

	The resource store in the context associated with pdf_document
	is emptied.

	Does not throw exceptions.
*/
void pdf_drop_document(fz_context *ctx, pdf_document *doc);

/*
	pdf_specifics: down-cast an fz_document to a pdf_document.
	Returns NULL if underlying document is not PDF
*/
pdf_document *pdf_specifics(fz_context *ctx, fz_document *doc);

/*
	pdf_document_from_fz_document,
	pdf_page_from_fz_page,
	pdf_annot_from_fz_annot:
		Down-cast generic fitz objects into pdf specific variants.
		Returns NULL if the objects are not from a PDF document.
*/
pdf_document *pdf_document_from_fz_document(fz_context *ctx, fz_document *ptr);
pdf_page *pdf_page_from_fz_page(fz_context *ctx, fz_page *ptr);
pdf_annot *pdf_annot_from_fz_annot(fz_context *ctx, fz_annot *ptr);

int pdf_needs_password(fz_context *ctx, pdf_document *doc);
int pdf_authenticate_password(fz_context *ctx, pdf_document *doc, const char *pw);

int pdf_has_permission(fz_context *ctx, pdf_document *doc, fz_permission p);
int pdf_lookup_metadata(fz_context *ctx, pdf_document *doc, const char *key, char *ptr, int size);

fz_outline *pdf_load_outline(fz_context *ctx, pdf_document *doc);

typedef struct pdf_ocg_entry_s pdf_ocg_entry;

struct pdf_ocg_entry_s
{
	int num;
	int state;
};

struct pdf_ocg_descriptor_s
{
	int len;
	pdf_ocg_entry *ocgs;
	pdf_obj *intent;
};

/*
	pdf_update_page: update a page for the sake of changes caused by a call
	to pdf_pass_event. pdf_update_page regenerates any appearance streams that
	are out of date, checks for cases where different appearance streams
	should be selected because of state changes, and records internally
	each annotation that has changed appearance. The list of changed annotations
	is then available via pdf_poll_changed_annot. Note that a call to
	pdf_pass_event for one page may lead to changes on any other, so an app
	should call pdf_update_page for every page it currently displays. Also
	it is important that the pdf_page object is the one used to last render
	the page. If instead the app were to drop the page and reload it then
	a call to pdf_update_page would not reliably be able to report all changed
	areas.
*/
void pdf_update_page(fz_context *ctx, pdf_document *doc, pdf_page *page);

/*
	Determine whether changes have been made since the
	document was opened or last saved.
*/
int pdf_has_unsaved_changes(fz_context *ctx, pdf_document *doc);

typedef struct pdf_signer_s pdf_signer;

/* Unsaved signature fields */
typedef struct pdf_unsaved_sig_s pdf_unsaved_sig;

struct pdf_unsaved_sig_s
{
	pdf_obj *field;
	int byte_range_start;
	int byte_range_end;
	int contents_start;
	int contents_end;
	pdf_signer *signer;
	pdf_unsaved_sig *next;
};

struct pdf_document_s
{
	fz_document super;

	fz_stream *file;

	int version;
	fz_off_t startxref;
	fz_off_t file_size;
	pdf_crypt *crypt;
	pdf_ocg_descriptor *ocg;
	pdf_hotspot hotspot;

	int max_xref_len;
	int num_xref_sections;
	int num_incremental_sections;
	int xref_base;
	int disallow_new_increments;
	pdf_xref *xref_sections;
	int *xref_index;
	int freeze_updates;
	int has_xref_streams;

	int page_count;

	int repair_attempted;

	/* State indicating which file parsing method we are using */
	int file_reading_linearly;
	fz_off_t file_length;

	pdf_obj *linear_obj; /* Linearized object (if used) */
	pdf_obj **linear_page_refs; /* Page objects for linear loading */
	int linear_page1_obj_num;

	/* The state for the pdf_progressive_advance parser */
	fz_off_t linear_pos;
	int linear_page_num;

	int hint_object_offset;
	int hint_object_length;
	int hints_loaded; /* Set to 1 after the hints loading has completed,
			   * whether successful or not! */
	/* Page n references shared object references:
	 *   hint_shared_ref[i]
	 * where
	 *      i = s to e-1
	 *	s = hint_page[n]->index
	 *	e = hint_page[n+1]->index
	 * Shared object reference r accesses objects:
	 *   rs to re-1
	 * where
	 *   rs = hint_shared[r]->number
	 *   re = hint_shared[r]->count + rs
	 * These are guaranteed to lie within the region starting at
	 * hint_shared[r]->offset of length hint_shared[r]->length
	 */
	struct
	{
		int number; /* Page object number */
		fz_off_t offset; /* Offset of page object */
		fz_off_t index; /* Index into shared hint_shared_ref */
	} *hint_page;
	int *hint_shared_ref;
	struct
	{
		int number; /* Object number of first object */
		fz_off_t offset; /* Offset of first object */
	} *hint_shared;
	int hint_obj_offsets_max;
	fz_off_t *hint_obj_offsets;

	int resources_localised;

	pdf_lexbuf_large lexbuf;

	pdf_annot *focus;
	pdf_obj *focus_obj;

	pdf_js *js;

	int recalculating;
	int dirty;

	void (*update_appearance)(fz_context *ctx, pdf_document *doc, pdf_annot *annot);

	pdf_doc_event_cb *event_cb;
	void *event_cb_data;

	int num_type3_fonts;
	int max_type3_fonts;
	fz_font **type3_fonts;

	pdf_resource_tables *resources;
};

/*
	PDF creation
*/

/*
	pdf_create_document: Create a blank PDF document
*/
pdf_document *pdf_create_document(fz_context *ctx);

/*
	Deep copy objects between documents.
*/
typedef struct pdf_graft_map_s pdf_graft_map;

pdf_graft_map *pdf_new_graft_map(fz_context *ctx, pdf_document *src);
void pdf_drop_graft_map(fz_context *ctx, pdf_graft_map *map);
pdf_obj *pdf_graft_object(fz_context *ctx, pdf_document *dst, pdf_document *src, pdf_obj *obj, pdf_graft_map *map);

/*
	pdf_page_write: Create a device that will record the
	graphical operations given to it into a sequence of
	pdf operations, together with a set of resources. This
	sequence/set pair can then be used as the basis for
	adding a page to the document (see pdf_add_page).

	doc: The document for which these are intended.

	mediabox: The bbox for the created page.

	presources: Pointer to a place to put the created
	resources dictionary.

	pcontents: Pointer to a place to put the created
	contents buffer.
*/
fz_device *pdf_page_write(fz_context *ctx, pdf_document *doc, const fz_rect *mediabox, pdf_obj **presources, fz_buffer **pcontents);

/*
	pdf_add_page: Create a pdf_obj within a document that
	represents a page, from a previously created resources
	dictionary and page content stream. This should then be
	inserted into the document using pdf_insert_page.

	After this call the page exists within the document
	structure, but is not actually ever displayed as it is
	not linked into the PDF page tree.

	doc: The document to which to add the page.

	mediabox: The mediabox for the page (should be identical
	to that used when creating the resources/contents).

	rotate: 0, 90, 180 or 270. The rotation to use for the
	page.

	resources: The resources dictionary for the new page
	(typically created by pdf_page_write).

	contents: The page contents for the new page (typically
	create by pdf_page_write).
*/
pdf_obj *pdf_add_page(fz_context *ctx, pdf_document *doc, const fz_rect *mediabox, int rotate, pdf_obj *resources, fz_buffer *contents);

/*
	pdf_insert_page: Insert a page previously created by
	pdf_add_page into the pages tree of the document.

	doc: The document to insert into.

	at: The page number to insert at. 0 inserts at the start.
	negative numbers, or INT_MAX insert at the end. Otherwise
	n inserts after page n.

	page: The page to insert.
*/
void pdf_insert_page(fz_context *ctx, pdf_document *doc, int at, pdf_obj *page);

/*
	pdf_delete_page: Delete a page from the page tree of
	a document. This does not remove the page contents
	or resources from the file.

	doc: The document to operate on.

	number: The page to remove (numbered from 0)
*/
void pdf_delete_page(fz_context *ctx, pdf_document *doc, int number);

/*
	pdf_delete_page_range: Delete a range of pages from the
	page tree of a document. This does not remove the page
	contents or resources from the file.

	doc: The document to operate on.

	start, end: The range of pages (numbered from 0)
	(inclusive, exclusive) to remove. If end is negative or
	greater than the number of pages in the document, it
	will be taken to be the end of the document.
*/
void pdf_delete_page_range(fz_context *ctx, pdf_document *doc, int start, int end);

/*
	pdf_finish_edit: Called after any editing operations
	on a document have completed, this will tidy up
	the document. For now this is restricted to
	rebalancing the page tree, but may be extended
	in future.
*/
void pdf_finish_edit(fz_context *ctx, pdf_document *doc);

int pdf_recognize(fz_context *doc, const char *magic);

typedef struct pdf_write_options_s pdf_write_options;

/*
	In calls to fz_save_document, the following options structure can be used
	to control aspects of the writing process. This structure may grow
	in future, and should be zero-filled to allow forwards compatibility.
*/
struct pdf_write_options_s
{
	int do_incremental; /* Write just the changed objects. */
	int do_pretty; /* Pretty-print dictionaries and arrays. */
	int do_ascii; /* ASCII hex encode binary streams. */
	int do_compress; /* Compress streams. */
	int do_compress_images; /* Compress (or leave compressed) image streams. */
	int do_compress_fonts; /* Compress (or leave compressed) font streams. */
	int do_decompress; /* Decompress streams (except when compressing images/fonts). */
	int do_garbage; /* Garbage collect objects before saving; 1=gc, 2=re-number, 3=de-duplicate. */
	int do_linear; /* Write linearised. */
	int do_clean; /* Sanitize content streams. */
	int continue_on_error; /* If set, errors are (optionally) counted and writing continues. */
	int *errors; /* Pointer to a place to store a count of errors */
};

/*
	Parse option string into a pdf_write_options struct.
	Matches the command line options to 'mutool clean':
		g: garbage collect
		d, i, f: expand all, fonts, images
		l: linearize
		a: ascii hex encode
		z: deflate
		s: sanitize content streams
*/
pdf_write_options *pdf_parse_write_options(fz_context *ctx, pdf_write_options *opts, const char *args);

/*
	pdf_has_unsaved_sigs: Returns true if there are digital signatures waiting to
	to updated on save.
*/
int pdf_has_unsaved_sigs(fz_context *ctx, pdf_document *doc);

/*
	pdf_write_document: Write out the document to an output stream with all changes finalised.

	This method will throw an error if pdf_has_unsaved_sigs.
*/
void pdf_write_document(fz_context *ctx, pdf_document *doc, fz_output *out, pdf_write_options *opts);

/*
	pdf_save_document: Write out the document to a file with all changes finalised.
*/
void pdf_save_document(fz_context *ctx, pdf_document *doc, const char *filename, pdf_write_options *opts);

/*
	pdf_can_be_saved_incrementally: Return true if the document can be saved
	incrementally. (e.g. it has not been repaired, and it is not encrypted)
*/
int pdf_can_be_saved_incrementally(fz_context *ctx, pdf_document *doc);

#endif
