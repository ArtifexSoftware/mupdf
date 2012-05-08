#include "fitz-internal.h"
#include "mupdf-internal.h"

int pdf_pass_event(pdf_document *doc, pdf_page *page, fz_ui_event *ui_event)
{
	int changed = 0;

	switch (ui_event->etype)
	{
	case FZ_EVENT_TYPE_POINTER:
		{
			pdf_hotspot *hp = &doc->hotspot;
			fz_point  *pt = &(ui_event->event.pointer.pt);
			pdf_annot *annot;
			switch (ui_event->event.pointer.ptype)
			{
			case FZ_POINTER_DOWN:
				for (annot = page->annots; annot; annot = annot->next)
				{
					if (pt->x >= annot->pagerect.x0 && pt->x <= annot->pagerect.x1)
						if (pt->y >= annot->pagerect.y0 && pt->y <= annot->pagerect.y1)
							break;
				}

				if (annot)
				{
					hp->num = pdf_to_num(annot->obj);
					hp->gen = pdf_to_gen(annot->obj);
					hp->state = HOTSPOT_POINTER_DOWN;
					changed = 1;
				}
				break;

			case FZ_POINTER_UP:
				if (hp->state != 0)
					changed = 1;

				hp->num = 0;
				hp->gen = 0;
				hp->state = 0;
				break;
			}

		}
		break;
	}

	return changed;
}

fz_rect *pdf_get_screen_update(pdf_document *doc)
{
	return NULL;
}

fz_widget *pdf_get_focussed_widget(pdf_document *doc)
{
	return NULL;
}
