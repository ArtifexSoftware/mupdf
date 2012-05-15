#include "fitz.h"
#include "mupdf-internal.h"

/*
	PDF is currently the only interactive format, so no need
	to indirect through function pointers.
*/

int fz_pass_event(fz_interactive *idoc, fz_page *page, fz_ui_event *ui_event)
{
	return pdf_pass_event((pdf_document*)idoc, (pdf_page*)page, ui_event);
}

fz_rect *fz_get_screen_update(fz_interactive *idoc)
{
	return pdf_get_screen_update((pdf_document*)idoc);
}

fz_widget *fz_get_focussed_widget(fz_interactive *idoc)
{
	return pdf_get_focussed_widget((pdf_document*)idoc);
}
