#ifndef MUPDF_PDF_CRYPT_H
#define MUPDF_PDF_CRYPT_H

/*
 * Encryption
 */

pdf_crypt *pdf_new_crypt(fz_context *ctx, pdf_obj *enc, pdf_obj *id);
void pdf_drop_crypt(fz_context *ctx, pdf_crypt *crypt);

void pdf_crypt_obj(fz_context *ctx, pdf_crypt *crypt, pdf_obj *obj, int num, int gen);
void pdf_crypt_buffer(fz_context *ctx, pdf_crypt *crypt, fz_buffer *buf, int num, int gen);
fz_stream *pdf_open_crypt(fz_context *ctx, fz_stream *chain, pdf_crypt *crypt, int num, int gen);
fz_stream *pdf_open_crypt_with_filter(fz_context *ctx, fz_stream *chain, pdf_crypt *crypt, pdf_obj *name, int num, int gen);

int pdf_crypt_version(fz_context *ctx, pdf_document *doc);
int pdf_crypt_revision(fz_context *ctx, pdf_document *doc);
char *pdf_crypt_method(fz_context *ctx, pdf_document *doc);
int pdf_crypt_length(fz_context *ctx, pdf_document *doc);
unsigned char *pdf_crypt_key(fz_context *ctx, pdf_document *doc);

void pdf_print_crypt(fz_context *ctx, fz_output *out, pdf_crypt *crypt);

void pdf_write_digest(fz_context *ctx, fz_output *out, pdf_obj *byte_range, int digest_offset, int digest_length, pdf_pkcs7_signer *signer);

/*
	User access permissions from PDF reference.
*/
enum
{
	PDF_PERM_PRINT = 1 << 2,
	PDF_PERM_MODIFY = 1 << 3,
	PDF_PERM_COPY = 1 << 4,
	PDF_PERM_ANNOTATE = 1 << 5,
	PDF_PERM_FORM = 1 << 8,
	PDF_PERM_ACCESSIBILITY = 1 << 9, /* deprecated in pdf 2.0 (this permission is always granted) */
	PDF_PERM_ASSEMBLE = 1 << 10,
	PDF_PERM_PRINT_HQ = 1 << 11,
};

/*
	pdf_document_permissions: access the detailed permissions flag.
*/
int pdf_document_permissions(fz_context *ctx, pdf_document *doc);

/*
	pdf_signature_widget_byte_range: retrieve the byte range for a signature widget
*/
int pdf_signature_widget_byte_range(fz_context *ctx, pdf_document *doc, pdf_widget *widget, fz_range *byte_range);

/*
	pdf_signature_widget_hash_bytes: retrieve an fz_stream to read the bytes hashed for the signature
*/
fz_stream *pdf_signature_widget_hash_bytes(fz_context *ctx, pdf_document *doc, pdf_widget *widget);

/*
	pdf_signature_widget_contents: retrieve the contents for a signature widget
*/
int pdf_signature_widget_contents(fz_context *ctx, pdf_document *doc, pdf_widget *widget, char **contents);

/*
	pdf_sign_signature: sign a signature form field
*/
void pdf_sign_signature(fz_context *ctx, pdf_document *doc, pdf_widget *widget, pdf_pkcs7_signer *signer);

void pdf_encrypt_data(fz_context *ctx, pdf_crypt *crypt, int num, int gen, void (*fmt_str_out)(fz_context *, void *, const unsigned char *, int), void *arg, const unsigned char *s, int n);

int pdf_encrypted_len(fz_context *ctx, pdf_crypt *crypt, int num, int gen, int len);

#endif
