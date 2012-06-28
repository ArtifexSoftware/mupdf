#include "fitz-internal.h"
#include "mupdf-internal.h"


pdf_js *pdf_new_js(pdf_document *doc)
{
	static int x;

	return (pdf_js *)&x;
}

void pdf_drop_js(pdf_js *js)
{
}

void pdf_js_setup_event(pdf_js *js, pdf_obj *target)
{
}

char *pdf_js_getEventValue(pdf_js *js)
{
	return "";
}

void pdf_js_execute(pdf_js *js, char *code)
{
}

void pdf_js_execute_count(pdf_js *js, char *code, int count)
{
}
