#ifndef MUPDF_PDF_FIELD_H
#define MUPDF_PDF_FIELD_H

/* Field flags */
enum
{
	/* All fields */
	PDF_FIELD_IS_READ_ONLY = 1,
	PDF_FIELD_IS_REQUIRED = 1 << 1,
	PDF_FIELD_IS_NO_EXPORT = 1 << 2,

	/* Text fields */
	PDF_TX_FIELD_IS_MULTILINE = 1 << 12,
	PDF_TX_FIELD_IS_PASSWORD = 1 << 13,
	PDF_TX_FIELD_IS_COMB = 1 << 24,

	/* Button fields */
	PDF_BTN_FIELD_IS_NO_TOGGLE_TO_OFF = 1 << 14,
	PDF_BTN_FIELD_IS_RADIO = 1 << 15,
	PDF_BTN_FIELD_IS_PUSHBUTTON = 1 << 16,

	/* Choice fields */
	PDF_CH_FIELD_IS_COMBO = 1 << 17,
	PDF_CH_FIELD_IS_EDIT = 1 << 18,
	PDF_CH_FIELD_IS_SORT = 1 << 19,
	PDF_CH_FIELD_IS_MULTI_SELECT = 1 << 21,
};

int pdf_get_field_flags(fz_context *ctx, pdf_document *doc, pdf_obj *obj);
int pdf_field_type(fz_context *ctx, pdf_document *doc, pdf_obj *field);
void pdf_set_field_type(fz_context *ctx, pdf_document *doc, pdf_obj *obj, int type);
char *pdf_field_value(fz_context *ctx, pdf_document *doc, pdf_obj *field);
int pdf_field_set_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *text);
char *pdf_field_border_style(fz_context *ctx, pdf_document *doc, pdf_obj *field);
void pdf_field_set_border_style(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *text);
void pdf_field_set_button_caption(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *text);
void pdf_field_set_fill_color(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_obj *col);
void pdf_field_set_text_color(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_obj *col);
void pdf_signature_set_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_pkcs7_signer *signer);
int pdf_field_display(fz_context *ctx, pdf_document *doc, pdf_obj *field);
char *pdf_field_name(fz_context *ctx, pdf_document *doc, pdf_obj *field);
const char *pdf_field_label(fz_context *ctx, pdf_document *doc, pdf_obj *field);
void pdf_field_set_display(fz_context *ctx, pdf_document *doc, pdf_obj *field, int d);
pdf_obj *pdf_lookup_field(fz_context *ctx, pdf_obj *form, char *name);
void pdf_field_reset(fz_context *ctx, pdf_document *doc, pdf_obj *field);

#endif
