#include "fitz-internal.h"
#include "mupdf-internal.h"

enum
{
	Ff_NoToggleToOff = 1 << (15-1),
	Ff_Radio         = 1 << (16-1),
	Ff_Pushbutton    = 1 << (17-1),
	Ff_RadioInUnison = 1 << (26-1),
	Ff_Combo         = 1 << (18-1)
};

struct fz_widget_s
{
	pdf_document *doc;
	int           type;
	pdf_obj      *obj;
};

struct fz_widget_text_s
{
	fz_widget super;
	char     *text;
};

static pdf_obj *get_field_entry(pdf_obj *obj, char *key)
{
	pdf_obj *fobj = NULL;

	while (!fobj && obj)
	{
		fobj = pdf_dict_gets(obj, key);

		if (!fobj)
			obj = pdf_dict_gets(obj, "Parent");
	}

	return fobj;
}

static char *get_field_type_name(pdf_obj *obj)
{
	pdf_obj *type = get_field_entry(obj, "FT");

	return type ? pdf_to_name(type)
				: NULL;
}

static int get_field_flags(pdf_obj *obj)
{
	pdf_obj *flags = get_field_entry(obj, "Ff");

	return flags ? pdf_to_int(flags)
				 : 0;
}

static int get_field_type(pdf_obj *obj)
{
	char *type = get_field_type_name(obj);
	int   flags = get_field_flags(obj);

	if (!strcmp(type, "Btn"))
	{
		if (flags & Ff_Pushbutton)
			return FZ_WIDGET_TYPE_PUSHBUTTON;
		else if (flags & Ff_Radio)
			return FZ_WIDGET_TYPE_RADIOBUTTON;
		else
			return FZ_WIDGET_TYPE_CHECKBOX;
	}
	else if (!strcmp(type, "Tx"))
		return FZ_WIDGET_TYPE_TEXT;
	else if (!strcmp(type, "Ch"))
	{
		if (flags & Ff_Combo)
			return FZ_WIDGET_TYPE_COMBOBOX;
		else
			return FZ_WIDGET_TYPE_LISTBOX;
	}
	else
		return -1;
}

static fz_widget *new_widget(pdf_document *doc, pdf_obj *obj)
{
	fz_widget *widget = NULL;

	fz_try(doc->ctx)
	{
		int type = get_field_type(obj);

		switch(type)
		{
		case FZ_WIDGET_TYPE_TEXT:
			widget = &(fz_malloc_struct(doc->ctx, fz_widget_text)->super);
			break;
		default:
			widget = fz_malloc_struct(doc->ctx, fz_widget);
			break;
		}

		widget->doc  = doc;
		widget->type = type;
		widget->obj  = pdf_keep_obj(obj);
	}
	fz_catch(doc->ctx)
	{
		fz_warn(doc->ctx, "failed to load foccussed widget");
	}

	return widget;
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
				if (doc->focus)
				{
					fz_free_widget(doc->ctx, doc->focus);
					doc->focus = NULL;
				}

				if (annot)
				{
					doc->focus = new_widget(doc, annot->obj);
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
					switch(get_field_type(annot->obj))
					{
					case FZ_WIDGET_TYPE_RADIOBUTTON:
					case FZ_WIDGET_TYPE_CHECKBOX:
						/* FIXME: treating radio buttons like check boxes, for now */
						toggle_check_box(doc, annot->obj);
						changed = 1;
						break;
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
	return doc->focus;
}

void fz_free_widget(fz_context *ctx, fz_widget *widget)
{
	if (widget)
	{
		switch(widget->type)
		{
		case FZ_WIDGET_TYPE_TEXT:
			fz_free(ctx, ((fz_widget_text *)widget)->text);
			break;
		}

		pdf_drop_obj(widget->obj);
		fz_free(ctx, widget);
	}
}

int fz_widget_get_type(fz_widget *widget)
{
	return widget->type;
}

char *fz_widget_text_get_text(fz_widget_text *tw)
{
	pdf_document *doc = tw->super.doc;
	fz_context *ctx = doc->ctx;
	pdf_obj *vobj = get_field_entry(tw->super.obj, "V");
	int len = 0;
	char *buf = NULL;
	fz_buffer *strmbuf = NULL;

	fz_free(ctx, tw->text);
	tw->text = NULL;

	fz_var(strmbuf);
	fz_try(ctx)
	{
		if (pdf_is_string(vobj))
		{
			len = pdf_to_str_len(vobj);
			buf = pdf_to_str_buf(vobj);
		}
		else if (pdf_is_stream(doc, pdf_to_num(vobj), pdf_to_gen(vobj)))
		{
			strmbuf = pdf_load_stream(doc, pdf_to_num(vobj), pdf_to_gen(vobj));
			len = fz_buffer_storage(ctx, strmbuf, &buf);
		}

		if (buf)
		{
			tw->text = fz_malloc(ctx, len+1);
			memcpy(tw->text, buf, len);
			tw->text[len] = 0;
		}
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "failed allocation in fz_widget_text_get_text");
	}

	fz_drop_buffer(ctx, strmbuf);

	return tw->text;
}

void fz_widget_text_set_text(fz_widget_text *tw, char *text)
{
}
