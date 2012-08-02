#include "fitz.h"
#include "mupdf-internal.h"

/*
	PDF is currently the only interactive format, so no need
	to indirect through function pointers.
*/

int fz_has_unsaved_changes(fz_interactive *idoc)
{
	return pdf_has_unsaved_changes((pdf_document*)idoc);
}

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

fz_widget *fz_first_widget(fz_interactive *idoc, fz_page *page)
{
	return pdf_first_widget((pdf_document*)idoc, (pdf_page*)page);
}

fz_widget *fz_next_widget(fz_interactive *idoc, fz_widget *previous)
{
	return pdf_next_widget(previous);
}

char *fz_widget_text_get_text(fz_interactive *idoc, fz_widget *tw)
{
	return pdf_widget_text_get_text((pdf_document *)idoc, tw);
}

int fz_widget_text_get_max_len(fz_interactive *idoc, fz_widget *tw)
{
	return pdf_widget_text_get_max_len((pdf_document *)idoc, tw);
}

int fz_widget_text_get_content_type(fz_interactive *idoc, fz_widget *tw)
{
	return pdf_widget_text_get_content_type((pdf_document *)idoc, tw);
}

void fz_widget_text_set_text(fz_interactive *idoc, fz_widget *tw, char *text)
{
	pdf_widget_text_set_text((pdf_document *)idoc, tw, text);
}

int fz_widget_choice_get_options(fz_interactive *idoc, fz_widget *tw, char *opts[])
{
	return pdf_widget_choice_get_options((pdf_document *)idoc, tw, opts);
}

int fz_widget_choice_is_multiselect(fz_interactive *idoc, fz_widget *tw)
{
	return pdf_widget_choice_is_multiselect((pdf_document *)idoc, tw);
}

int fz_widget_choice_get_value(fz_interactive *idoc, fz_widget *tw, char *opts[])
{
	return pdf_widget_choice_get_value((pdf_document *)idoc, tw, opts);
}

void fz_widget_choice_set_value(fz_interactive *idoc, fz_widget *tw, int n, char *opts[])
{
	pdf_widget_choice_set_value((pdf_document *)idoc, tw, n, opts);
}
