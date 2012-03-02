#ifndef _MUPDF_H_
#define _MUPDF_H_

#include "fitz.h"

typedef struct pdf_document_s pdf_document;

/*
 * Dynamic objects.
 * The same type of objects as found in PDF and PostScript.
 * Used by the filters and the mupdf parser.
 */

typedef struct pdf_obj_s pdf_obj;

pdf_obj *pdf_new_null(fz_context *ctx);
pdf_obj *pdf_new_bool(fz_context *ctx, int b);
pdf_obj *pdf_new_int(fz_context *ctx, int i);
pdf_obj *pdf_new_real(fz_context *ctx, float f);
pdf_obj *fz_new_name(fz_context *ctx, char *str);
pdf_obj *pdf_new_string(fz_context *ctx, char *str, int len);
pdf_obj *pdf_new_indirect(fz_context *ctx, int num, int gen, void *doc);

pdf_obj *pdf_new_array(fz_context *ctx, int initialcap);
pdf_obj *pdf_new_dict(fz_context *ctx, int initialcap);
pdf_obj *pdf_copy_array(fz_context *ctx, pdf_obj *array);
pdf_obj *pdf_copy_dict(fz_context *ctx, pdf_obj *dict);

pdf_obj *pdf_keep_obj(pdf_obj *obj);
void pdf_drop_obj(pdf_obj *obj);

/* type queries */
int pdf_is_null(pdf_obj *obj);
int pdf_is_bool(pdf_obj *obj);
int pdf_is_int(pdf_obj *obj);
int pdf_is_real(pdf_obj *obj);
int pdf_is_name(pdf_obj *obj);
int pdf_is_string(pdf_obj *obj);
int pdf_is_array(pdf_obj *obj);
int pdf_is_dict(pdf_obj *obj);
int pdf_is_indirect(pdf_obj *obj);
int pdf_is_stream(pdf_document *doc, int num, int gen);

int pdf_objcmp(pdf_obj *a, pdf_obj *b);

/* dict marking and unmarking functions - to avoid infinite recursions */
int pdf_dict_marked(pdf_obj *obj);
int pdf_dict_mark(pdf_obj *obj);
void pdf_dict_unmark(pdf_obj *obj);

/* safe, silent failure, no error reporting on type mismatches */
int pdf_to_bool(pdf_obj *obj);
int pdf_to_int(pdf_obj *obj);
float pdf_to_real(pdf_obj *obj);
char *pdf_to_name(pdf_obj *obj);
char *pdf_to_str_buf(pdf_obj *obj);
pdf_obj *pdf_to_dict(pdf_obj *obj);
int pdf_to_str_len(pdf_obj *obj);
int pdf_to_num(pdf_obj *obj);
int pdf_to_gen(pdf_obj *obj);

int pdf_array_len(pdf_obj *array);
pdf_obj *pdf_array_get(pdf_obj *array, int i);
void pdf_array_put(pdf_obj *array, int i, pdf_obj *obj);
void pdf_array_push(pdf_obj *array, pdf_obj *obj);
void pdf_array_insert(pdf_obj *array, pdf_obj *obj);
int pdf_array_contains(pdf_obj *array, pdf_obj *obj);

int pdf_dict_len(pdf_obj *dict);
pdf_obj *pdf_dict_get_key(pdf_obj *dict, int idx);
pdf_obj *pdf_dict_get_val(pdf_obj *dict, int idx);
pdf_obj *pdf_dict_get(pdf_obj *dict, pdf_obj *key);
pdf_obj *pdf_dict_gets(pdf_obj *dict, char *key);
pdf_obj *pdf_dict_getsa(pdf_obj *dict, char *key, char *abbrev);
void fz_dict_put(pdf_obj *dict, pdf_obj *key, pdf_obj *val);
void pdf_dict_puts(pdf_obj *dict, char *key, pdf_obj *val);
void pdf_dict_del(pdf_obj *dict, pdf_obj *key);
void pdf_dict_dels(pdf_obj *dict, char *key);
void pdf_sort_dict(pdf_obj *dict);

int pdf_fprint_obj(FILE *fp, pdf_obj *obj, int tight);
void pdf_debug_obj(pdf_obj *obj);
void pdf_debug_ref(pdf_obj *obj);

fz_rect pdf_to_rect(fz_context *ctx, pdf_obj *array);

typedef struct pdf_xref_entry_s pdf_xref_entry;

struct pdf_xref_entry_s
{
	int ofs;	/* file offset / objstm object number */
	int gen;	/* generation / objstm index */
	int stm_ofs;	/* on-disk stream */
	pdf_obj *obj;	/* stored/cached object */
	int type;	/* 0=unset (f)ree i(n)use (o)bjstm */
};

pdf_obj *pdf_resolve_indirect(pdf_obj *ref);
pdf_obj *pdf_load_object(pdf_document *doc, int num, int gen);
void pdf_update_object(pdf_document *doc, int num, int gen, pdf_obj *newobj);

fz_buffer *pdf_load_raw_stream(pdf_document *doc, int num, int gen);
fz_buffer *pdf_load_stream(pdf_document *doc, int num, int gen);
fz_stream *pdf_open_raw_stream(pdf_document *doc, int num, int gen);
fz_stream *pdf_open_stream(pdf_document *doc, int num, int gen);

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
	fz_close for closing an open stream.
*/
pdf_document *pdf_open_document_with_stream(fz_stream *file);

/*
	pdf_close_document: Closes and frees an opened PDF document.

	The resource store in the context associated with pdf_document
	is emptied.

	Does not throw exceptions.
*/
void pdf_close_document(pdf_document *doc);

int pdf_needs_password(pdf_document *doc);
int pdf_authenticate_password(pdf_document *doc, char *pw);

fz_image *pdf_load_image(pdf_document *doc, pdf_obj *obj);

#endif /* _MUPDF_H_ */
