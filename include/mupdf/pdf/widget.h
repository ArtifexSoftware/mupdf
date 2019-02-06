#ifndef MUPDF_PDF_WIDGET_H
#define MUPDF_PDF_WIDGET_H

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

#endif
