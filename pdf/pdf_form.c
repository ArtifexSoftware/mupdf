#include "fitz-internal.h"
#include "mupdf-internal.h"

enum
{
	Ff_NoToggleToOff = 1 << (15-1),
	Ff_Radio         = 1 << (16-1),
	Ff_Pushbutton    = 1 << (17-1),
	Ff_RadioInUnison = 1 << (26-1)
};

static char *get_annot_type(pdf_obj *obj)
{
	pdf_obj *type = NULL;

	while (!type && obj)
	{
		type = pdf_dict_gets(obj, "FT");

		if (!type)
			obj = pdf_dict_gets(obj, "Parent");
	}

	return type ? pdf_to_name(type)
				: NULL;
}

static int get_annot_field_flags(pdf_obj *obj)
{
	pdf_obj *flags = NULL;

	while (!flags && obj)
	{
		flags = pdf_dict_gets(obj, "Ff");

		if (!flags)
			obj = pdf_dict_gets(obj, "Parent");
	}

	return flags ? pdf_to_int(flags)
				 : 0;
}

static void toggle_check_box(pdf_document *doc, pdf_obj *obj)
{
	pdf_obj *as;

	as = pdf_dict_gets(obj, "AS");

	if (strcmp(pdf_to_name(as), "Off"))
	{
		/* "as" neither missing nor set to Off. Set it to Off. */
		pdf_obj *off = fz_new_name(doc->ctx, "Off");
		pdf_dict_puts(obj, "AS", off);
		pdf_drop_obj(off);
	}
	else
	{
	    pdf_obj *ap, *n, *key;
		int len, i;

		ap = pdf_dict_gets(obj, "AP");
		n = pdf_dict_gets(ap, "N");

		/* Look for a key that isn't "Off" */
		len = pdf_dict_len(n);
		for (i = 0; i < len; i++)
		{
			key = pdf_dict_get_key(n, i);
			if (pdf_is_name(key) && strcmp(pdf_to_name(key), "Off"))
			{
				pdf_dict_puts(obj, "AS", key);
				break;
			}
		}
	}

	/* FIXME: should probably update the V entry in the field dictionary too */
}

int pdf_pass_event(pdf_document *doc, pdf_page *page, fz_ui_event *ui_event)
{
	pdf_annot *annot;
	pdf_hotspot *hp = &doc->hotspot;
	fz_point  *pt = &(ui_event->event.pointer.pt);
	int changed = 0;

	for (annot = page->annots; annot; annot = annot->next)
	{
		if (pt->x >= annot->pagerect.x0 && pt->x <= annot->pagerect.x1)
			if (pt->y >= annot->pagerect.y0 && pt->y <= annot->pagerect.y1)
				break;
	}

	switch (ui_event->etype)
	{
	case FZ_EVENT_TYPE_POINTER:
		{
			switch (ui_event->event.pointer.ptype)
			{
			case FZ_POINTER_DOWN:
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

				if (annot)
				{
					char *atype = get_annot_type(annot->obj);
					int   flags = get_annot_field_flags(annot->obj);

					if (!strcmp(atype, "Btn"))
					{
						if ((flags & (Ff_Pushbutton | Ff_Radio)) == 0)
							toggle_check_box(doc, annot->obj);

						/* FIXME: treating radio buttons like check boxes, for now */
						if ((flags & (Ff_Pushbutton | Ff_Radio)) == Ff_Radio)
							toggle_check_box(doc, annot->obj);
					}
				}
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
