#ifndef MUPDF_PDF_FORM_H
#define MUPDF_PDF_FORM_H

/* Types of widget */
enum pdf_widget_type
{
	PDF_WIDGET_TYPE_UNKNOWN,
	PDF_WIDGET_TYPE_BUTTON,
	PDF_WIDGET_TYPE_CHECKBOX,
	PDF_WIDGET_TYPE_COMBOBOX,
	PDF_WIDGET_TYPE_LISTBOX,
	PDF_WIDGET_TYPE_RADIOBUTTON,
	PDF_WIDGET_TYPE_SIGNATURE,
	PDF_WIDGET_TYPE_TEXT,
};

/* Types of text widget content */
enum pdf_widget_tx_format
{
	PDF_WIDGET_TX_FORMAT_NONE,
	PDF_WIDGET_TX_FORMAT_NUMBER,
	PDF_WIDGET_TX_FORMAT_SPECIAL,
	PDF_WIDGET_TX_FORMAT_DATE,
	PDF_WIDGET_TX_FORMAT_TIME
};

pdf_widget *pdf_keep_widget(fz_context *ctx, pdf_widget *widget);
void pdf_drop_widget(fz_context *ctx, pdf_widget *widget);
pdf_widget *pdf_first_widget(fz_context *ctx, pdf_page *page);
pdf_widget *pdf_next_widget(fz_context *ctx, pdf_widget *previous);
int pdf_update_widget(fz_context *ctx, pdf_widget *widget);

enum pdf_widget_type pdf_widget_type(fz_context *ctx, pdf_widget *widget);

fz_rect pdf_bound_widget(fz_context *ctx, pdf_widget *widget);

/*
	get the maximum number of
	characters permitted in a text widget
*/
int pdf_text_widget_max_len(fz_context *ctx, pdf_widget *tw);

/*
	get the type of content
	required by a text widget
*/
int pdf_text_widget_format(fz_context *ctx, pdf_widget *tw);

/*
	get the list of options for a list box or combo box.

	Returns the number of options and fills in their
	names within the supplied array. Should first be called with a
	NULL array to find out how big the array should be.  If exportval
	is true, then the export values will be returned and not the list
	values if there are export values present.
*/
int pdf_choice_widget_options(fz_context *ctx, pdf_widget *tw, int exportval, const char *opts[]);
int pdf_choice_widget_is_multiselect(fz_context *ctx, pdf_widget *tw);

/*
	get the value of a choice widget.

	Returns the number of options currently selected and fills in
	the supplied array with their strings. Should first be called
	with NULL as the array to find out how big the array need to
	be. The filled in elements should not be freed by the caller.
*/
int pdf_choice_widget_value(fz_context *ctx, pdf_widget *tw, const char *opts[]);

/*
	set the value of a choice widget.

	The caller should pass the number of options selected and an
	array of their names
*/
void pdf_choice_widget_set_value(fz_context *ctx, pdf_widget *tw, int n, const char *opts[]);

int pdf_choice_field_option_count(fz_context *ctx, pdf_obj *field);
const char *pdf_choice_field_option(fz_context *ctx, pdf_obj *field, int exportval, int i);

int pdf_widget_is_signed(fz_context *ctx, pdf_widget *widget);

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
	PDF_TX_FIELD_IS_FILE_SELECT = 1 << 20,
	PDF_TX_FIELD_IS_DO_NOT_SPELL_CHECK = 1 << 22,
	PDF_TX_FIELD_IS_DO_NOT_SCROLL = 1 << 23,
	PDF_TX_FIELD_IS_COMB = 1 << 24,
	PDF_TX_FIELD_IS_RICH_TEXT = 1 << 25,

	/* Button fields */
	PDF_BTN_FIELD_IS_NO_TOGGLE_TO_OFF = 1 << 14,
	PDF_BTN_FIELD_IS_RADIO = 1 << 15,
	PDF_BTN_FIELD_IS_PUSHBUTTON = 1 << 16,
	PDF_BTN_FIELD_IS_RADIOS_IN_UNISON = 1 << 25,

	/* Choice fields */
	PDF_CH_FIELD_IS_COMBO = 1 << 17,
	PDF_CH_FIELD_IS_EDIT = 1 << 18,
	PDF_CH_FIELD_IS_SORT = 1 << 19,
	PDF_CH_FIELD_IS_MULTI_SELECT = 1 << 21,
	PDF_CH_FIELD_IS_DO_NOT_SPELL_CHECK = 1 << 22,
	PDF_CH_FIELD_IS_COMMIT_ON_SEL_CHANGE = 1 << 26,
};

void pdf_calculate_form(fz_context *ctx, pdf_document *doc);
void pdf_reset_form(fz_context *ctx, pdf_document *doc, pdf_obj *fields, int exclude);

int pdf_field_type(fz_context *ctx, pdf_obj *field);
int pdf_field_flags(fz_context *ctx, pdf_obj *field);

/*
	Retrieve the name for a field as a C string that
	must be freed by the caller.
*/
char *pdf_field_name(fz_context *ctx, pdf_obj *field);
const char *pdf_field_value(fz_context *ctx, pdf_obj *field);

char *pdf_field_border_style(fz_context *ctx, pdf_obj *field);
void pdf_field_set_border_style(fz_context *ctx, pdf_obj *field, const char *text);
void pdf_field_set_button_caption(fz_context *ctx, pdf_obj *field, const char *text);
void pdf_field_set_fill_color(fz_context *ctx, pdf_obj *field, pdf_obj *col);
void pdf_field_set_text_color(fz_context *ctx, pdf_obj *field, pdf_obj *col);
int pdf_field_display(fz_context *ctx, pdf_obj *field);
void pdf_field_set_display(fz_context *ctx, pdf_obj *field, int d);
const char *pdf_field_label(fz_context *ctx, pdf_obj *field);
pdf_obj *pdf_button_field_on_state(fz_context *ctx, pdf_obj *field);

int pdf_set_field_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *text, int ignore_trigger_events);

/*
	Update the text of a text widget.

	The text is first validated by the Field/Keystroke event processing and accepted only if it passes.

	The function returns whether validation passed.
*/
int pdf_set_text_field_value(fz_context *ctx, pdf_widget *widget, const char *value);
int pdf_set_choice_field_value(fz_context *ctx, pdf_widget *widget, const char *value);

typedef struct
{
	char *cn;
	char *o;
	char *ou;
	char *email;
	char *c;
}
pdf_pkcs7_designated_name;

typedef enum
{
	PDF_SIGNATURE_ERROR_OKAY,
	PDF_SIGNATURE_ERROR_NO_SIGNATURES,
	PDF_SIGNATURE_ERROR_NO_CERTIFICATE,
	PDF_SIGNATURE_ERROR_DIGEST_FAILURE,
	PDF_SIGNATURE_ERROR_SELF_SIGNED,
	PDF_SIGNATURE_ERROR_SELF_SIGNED_IN_CHAIN,
	PDF_SIGNATURE_ERROR_NOT_TRUSTED,
	PDF_SIGNATURE_ERROR_UNKNOWN
} pdf_signature_error;

/* Increment the reference count for a signer object */
typedef pdf_pkcs7_signer *(pdf_pkcs7_keep_signer_fn)(fz_context *ctx, pdf_pkcs7_signer *signer);

/* Drop a reference for a signer object */
typedef void (pdf_pkcs7_drop_signer_fn)(fz_context *ctx, pdf_pkcs7_signer *signer);

/* Obtain the designated name information from a signer object */
typedef pdf_pkcs7_designated_name *(pdf_pkcs7_get_signing_name_fn)(fz_context *ctx, pdf_pkcs7_signer *signer);

/* Predict the size of the digest. The actual digest returned by create_digest will be no greater in size */
typedef size_t (pdf_pkcs7_max_digest_size_fn)(fz_context *ctx, pdf_pkcs7_signer *signer);

/* Create a signature based on ranges of bytes drawn from a stream */
typedef int (pdf_pkcs7_create_digest_fn)(fz_context *ctx, pdf_pkcs7_signer *signer, fz_stream *in, unsigned char *digest, size_t digest_len);

struct pdf_pkcs7_signer
{
	pdf_pkcs7_keep_signer_fn *keep;
	pdf_pkcs7_drop_signer_fn *drop;
	pdf_pkcs7_get_signing_name_fn *get_signing_name;
	pdf_pkcs7_max_digest_size_fn *max_digest_size;
	pdf_pkcs7_create_digest_fn *create_digest;
};

typedef struct pdf_pkcs7_verifier pdf_pkcs7_verifier;

typedef void (pdf_pkcs7_drop_verifier_fn)(fz_context *ctx, pdf_pkcs7_verifier *verifier);
typedef pdf_signature_error (pdf_pkcs7_check_certificate_fn)(fz_context *ctx, pdf_pkcs7_verifier *verifier, unsigned char *signature, size_t len);
typedef pdf_signature_error (pdf_pkcs7_check_digest_fn)(fz_context *ctx, pdf_pkcs7_verifier *verifier, fz_stream *in, unsigned char *signature, size_t len);
typedef pdf_pkcs7_designated_name *(pdf_pkcs7_get_signatory_fn)(fz_context *ctx, pdf_pkcs7_verifier *verifier, unsigned char *signature, size_t len);

struct pdf_pkcs7_verifier
{
	pdf_pkcs7_drop_verifier_fn *drop;
	pdf_pkcs7_check_certificate_fn *check_certificate;
	pdf_pkcs7_check_digest_fn *check_digest;
	pdf_pkcs7_get_signatory_fn *get_signatory;
};

int pdf_signature_is_signed(fz_context *ctx, pdf_document *doc, pdf_obj *field);
void pdf_signature_set_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_pkcs7_signer *signer, int64_t stime);

int pdf_count_signatures(fz_context *ctx, pdf_document *doc);

char *pdf_signature_error_description(pdf_signature_error err);

pdf_pkcs7_designated_name *pdf_signature_get_signatory(fz_context *ctx, pdf_pkcs7_verifier *verifier, pdf_document *doc, pdf_obj *signature);
void pdf_signature_drop_designated_name(fz_context *ctx, pdf_pkcs7_designated_name *name);
char *pdf_signature_format_designated_name(fz_context *ctx, pdf_pkcs7_designated_name *name);

pdf_signature_error pdf_check_digest(fz_context *ctx, pdf_pkcs7_verifier *verifier, pdf_document *doc, pdf_obj *signature);
pdf_signature_error pdf_check_certificate(fz_context *ctx, pdf_pkcs7_verifier *verifier, pdf_document *doc, pdf_obj *signature);

/*
	check a signature's certificate chain and digest

	This is a helper function defined to provide compatibility with older
	versions of mupdf
*/
int pdf_check_signature(fz_context *ctx, pdf_pkcs7_verifier *verifier, pdf_document *doc, pdf_obj *signature, char *ebuf, size_t ebufsize);

void pdf_drop_signer(fz_context *ctx, pdf_pkcs7_signer *signer);
void pdf_drop_verifier(fz_context *ctx, pdf_pkcs7_verifier *verifier);

void pdf_field_reset(fz_context *ctx, pdf_document *doc, pdf_obj *field);

pdf_obj *pdf_lookup_field(fz_context *ctx, pdf_obj *form, const char *name);

/* Form text field editing events: */

typedef struct
{
	const char *value;
	const char *change;
	int selStart, selEnd;
	int willCommit;
	char *newChange;
} pdf_keystroke_event;

int pdf_field_event_keystroke(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_keystroke_event *evt);
int pdf_field_event_validate(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *value);
void pdf_field_event_calculate(fz_context *ctx, pdf_document *doc, pdf_obj *field);
char *pdf_field_event_format(fz_context *ctx, pdf_document *doc, pdf_obj *field);

/* Call these to trigger actions from various UI events: */

void pdf_document_event_will_close(fz_context *ctx, pdf_document *doc);
void pdf_document_event_will_save(fz_context *ctx, pdf_document *doc);
void pdf_document_event_did_save(fz_context *ctx, pdf_document *doc);
void pdf_document_event_will_print(fz_context *ctx, pdf_document *doc);
void pdf_document_event_did_print(fz_context *ctx, pdf_document *doc);

void pdf_page_event_open(fz_context *ctx, pdf_page *page);
void pdf_page_event_close(fz_context *ctx, pdf_page *page);

void pdf_annot_event_enter(fz_context *ctx, pdf_annot *annot);
void pdf_annot_event_exit(fz_context *ctx, pdf_annot *annot);
void pdf_annot_event_down(fz_context *ctx, pdf_annot *annot);
void pdf_annot_event_up(fz_context *ctx, pdf_annot *annot);
void pdf_annot_event_focus(fz_context *ctx, pdf_annot *annot);
void pdf_annot_event_blur(fz_context *ctx, pdf_annot *annot);
void pdf_annot_event_page_open(fz_context *ctx, pdf_annot *annot);
void pdf_annot_event_page_close(fz_context *ctx, pdf_annot *annot);
void pdf_annot_event_page_visible(fz_context *ctx, pdf_annot *annot);
void pdf_annot_event_page_invisible(fz_context *ctx, pdf_annot *annot);

#endif
