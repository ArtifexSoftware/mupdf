#ifndef MUPDF_PDF_JAVASCRIPT_H
#define MUPDF_PDF_JAVASCRIPT_H

typedef struct pdf_js_event_s
{
	pdf_obj *target;
	char *value;
	int rc;
} pdf_js_event;

void pdf_enable_js(fz_context *ctx, pdf_document *doc);
void pdf_disable_js(fz_context *ctx, pdf_document *doc);
int pdf_js_supported(fz_context *ctx, pdf_document *doc);
void pdf_drop_js(fz_context *ctx, pdf_js *js);

void pdf_js_setup_event(pdf_js *js, pdf_js_event *e);
pdf_js_event *pdf_js_get_event(pdf_js *js);
void pdf_js_execute(pdf_js *js, char *code);

#endif
