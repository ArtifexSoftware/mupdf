#ifndef MUPDF_PDF_FORM_H
#define MUPDF_PDF_FORM_H

/* Types of widget */
enum
{
	PDF_WIDGET_TYPE_NOT_WIDGET = -1,
	PDF_WIDGET_TYPE_PUSHBUTTON,
	PDF_WIDGET_TYPE_CHECKBOX,
	PDF_WIDGET_TYPE_RADIOBUTTON,
	PDF_WIDGET_TYPE_TEXT,
	PDF_WIDGET_TYPE_LISTBOX,
	PDF_WIDGET_TYPE_COMBOBOX,
	PDF_WIDGET_TYPE_SIGNATURE
};

/* Types of text widget content */
enum
{
	PDF_WIDGET_CONTENT_UNRESTRAINED,
	PDF_WIDGET_CONTENT_NUMBER,
	PDF_WIDGET_CONTENT_SPECIAL,
	PDF_WIDGET_CONTENT_DATE,
	PDF_WIDGET_CONTENT_TIME
};

pdf_widget *pdf_first_widget(fz_context *ctx, pdf_page *page);
pdf_widget *pdf_next_widget(fz_context *ctx, pdf_widget *previous);

pdf_widget *pdf_focused_widget(fz_context *ctx, pdf_document *doc);

int pdf_widget_type(fz_context *ctx, pdf_widget *widget);

fz_rect pdf_bound_widget(fz_context *ctx, pdf_widget *widget);

char *pdf_text_widget_text(fz_context *ctx, pdf_document *doc, pdf_widget *tw);
int pdf_text_widget_max_len(fz_context *ctx, pdf_document *doc, pdf_widget *tw);
int pdf_text_widget_content_type(fz_context *ctx, pdf_document *doc, pdf_widget *tw);
int pdf_text_widget_set_text(fz_context *ctx, pdf_document *doc, pdf_widget *tw, char *text);

int pdf_choice_widget_options(fz_context *ctx, pdf_document *doc, pdf_widget *tw, int exportval, const char *opts[]);
int pdf_choice_widget_is_multiselect(fz_context *ctx, pdf_document *doc, pdf_widget *tw);
int pdf_choice_widget_value(fz_context *ctx, pdf_document *doc, pdf_widget *tw, const char *opts[]);
void pdf_choice_widget_set_value(fz_context *ctx, pdf_document *doc, pdf_widget *tw, int n, const char *opts[]);

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

void pdf_form_calculate(fz_context *ctx, pdf_document *doc);

int pdf_field_type(fz_context *ctx, pdf_obj *field);
int pdf_field_flags(fz_context *ctx, pdf_obj *field);
char *pdf_field_name(fz_context *ctx, pdf_obj *field);
char *pdf_field_value(fz_context *ctx, pdf_obj *field);

char *pdf_field_border_style(fz_context *ctx, pdf_obj *field);
void pdf_field_set_border_style(fz_context *ctx, pdf_obj *field, const char *text);
void pdf_field_set_button_caption(fz_context *ctx, pdf_obj *field, const char *text);
void pdf_field_set_fill_color(fz_context *ctx, pdf_obj *field, pdf_obj *col);
void pdf_field_set_text_color(fz_context *ctx, pdf_obj *field, pdf_obj *col);
int pdf_field_display(fz_context *ctx, pdf_obj *field);
void pdf_field_set_display(fz_context *ctx, pdf_obj *field, int d);
const char *pdf_field_label(fz_context *ctx, pdf_obj *field);

int pdf_field_set_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *text, int ignore_trigger_events);
void pdf_signature_set_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_pkcs7_signer *signer);
void pdf_field_reset(fz_context *ctx, pdf_document *doc, pdf_obj *field);

pdf_obj *pdf_lookup_field(fz_context *ctx, pdf_obj *form, const char *name);

#endif
