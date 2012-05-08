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

static pdf_obj *get_inheritable(pdf_obj *obj, char *key)
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
	pdf_obj *type = get_inheritable(obj, "FT");

	return type ? pdf_to_name(type)
				: NULL;
}

static int get_field_flags(pdf_obj *obj)
{
	pdf_obj *flags = get_inheritable(obj, "Ff");

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

static int copy_da_with_size_check(fz_context *ctx, fz_buffer *fzbuf, char *da, int h)
{
	int tok, fontsize = h; /* Default to use if Tf defines size 0 */
	pdf_lexbuf lbuf;
	fz_stream *str = fz_open_memory(ctx, da, strlen(da));

	memset(lbuf.scratch, 0, sizeof(lbuf.scratch));
	lbuf.size = sizeof(lbuf.scratch);
	fz_try(ctx)
	{
		int last_tok_was_int = 0;
		int last_int_tok_val = 0;

		for (tok = pdf_lex(str, &lbuf); tok != PDF_TOK_EOF; tok = pdf_lex(str, &lbuf))
		{
			if (last_tok_was_int)
			{
				if (tok = PDF_TOK_NAME && !strcmp(lbuf.scratch, "Tf"))
				{
					/* Tf defines nonzero font size. Use defined value
					 * rather than the default */
					if(last_int_tok_val != 0)
						fontsize = last_int_tok_val;

					fz_buffer_printf(ctx, fzbuf, " %d", fontsize);
				}
				else
				{
					fz_buffer_printf(ctx, fzbuf, " %d", last_int_tok_val);
				}

				last_tok_was_int = 0;
			}

			if (tok == PDF_TOK_INT)
			{
				last_tok_was_int = 1;
				last_int_tok_val = lbuf.i;
			}
			else
			{
				fz_buffer_printf(ctx, fzbuf, " ");
				pdf_print_token(ctx, fzbuf, tok, &lbuf);
			}
		}
	}
	fz_always(ctx)
	{
		fz_close(str);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return fontsize;
}

fz_buffer *create_text_appearance(fz_context *ctx, fz_rect *bbox, char *da, char *text)
{
	int height, fontsize;
	fz_buffer *fzbuf;
	fz_rect rect;
	const char *fmt1 =
		"/Tx BMC"
		" q"
		" %1.2f %1.2f %1.2f %1.2f re"
		" W"
		" n"
		" BT";
	const char *fmt2 =
		" 2 %1.2f Td"
		" (%s) Tj"
		" ET"
		" Q"
		" EMC";

	rect = *bbox;

	if (rect.x1 - rect.x0 >= 2.0 && rect.y1 - rect.y0 >= 2.0)
	{
		rect.x0 += 1.0;
		rect.x1 -= 1.0;
		rect.y0 += 1.0;
		rect.y1 -= 1.0;
	}

	height = MAX(floor(bbox->y1 - bbox->y0 - 4.0), 1);

	fzbuf = fz_new_buffer(ctx, 0);
	fz_buffer_printf(ctx, fzbuf, fmt1, rect.x0, rect.y0, rect.x1 - rect.x0, rect.y1 - rect.y0);
	fontsize = copy_da_with_size_check(ctx, fzbuf, da, height);
	fz_buffer_printf(ctx, fzbuf, fmt2, (bbox->y1 - bbox->y0 - fontsize)/2, text);

	return fzbuf;
}

static fz_bbox measure_text(pdf_document *doc, pdf_obj *dr, fz_buffer *fzbuf)
{
	fz_context *ctx = doc->ctx;
	fz_device *dev = NULL;
	fz_bbox bbox = fz_empty_bbox;

	fz_try(ctx)
	{
		dev = fz_new_bbox_device(doc->ctx, &bbox);
		pdf_run_glyph(doc, dr, fzbuf, dev, fz_identity, NULL);
	}
	fz_always(ctx)
	{
		fz_free_device(dev);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return bbox;
}

static void update_text_appearance(pdf_document *doc, pdf_obj *obj, char *text)
{
	fz_context *ctx = doc->ctx;
	pdf_obj *ap, *n, *dr, *da;
	pdf_xobject *form = NULL;
	fz_buffer *fzbuf = NULL;

	fz_var(form);
	fz_var(fzbuf);

	fz_try(ctx)
	{
		dr = get_inheritable(obj, "DR");
		da = get_inheritable(obj, "DA");
		ap = pdf_dict_gets(obj, "AP");
		if (pdf_is_dict(ap))
		{
			n = pdf_dict_gets(ap, "N");

			if (pdf_is_stream(doc, pdf_to_num(n), pdf_to_gen(n)))
			{
				int i, len;
				form = pdf_load_xobject(doc, n);

				/* copy the default resources to the xobject */
				len = pdf_dict_len(dr);
				for (i = 0; i < len; i++)
				{
					pdf_obj *key = pdf_dict_get_key(dr, i);

					if (!pdf_dict_get(form->resources, key))
						fz_dict_put(form->resources, key, pdf_dict_get_val(dr, i));
				}

				fzbuf = create_text_appearance(ctx, &form->bbox, pdf_to_str_buf(da), text);
				pdf_xobject_set_contents(ctx, form, fzbuf);
			}
		}
	}
	fz_always(ctx)
	{
		pdf_drop_xobject(ctx, form);
		fz_drop_buffer(ctx, fzbuf);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "update_text_appearance failed");
	}
}

static void synthesize_text_widget(pdf_document *doc, pdf_obj *obj)
{
	fz_context *ctx = doc->ctx;
	pdf_obj *ap = NULL;
	fz_rect rect;
	pdf_obj *form = NULL;

	fz_var(form);
	fz_var(ap);
	fz_try(ctx)
	{
		rect = pdf_to_rect(ctx, pdf_dict_gets(obj, "Rect"));
		rect.x1 -= rect.x0;
		rect.y1 -= rect.y0;
		rect.x0 = rect.y0 = 0;
		form = pdf_new_xobject(doc, &rect);
		ap = pdf_new_dict(ctx, 1);
		pdf_dict_puts(ap, "N", form);
		pdf_dict_puts(obj, "AP", ap);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(form);
		pdf_drop_obj(ap);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

void pdf_synthesize_missing_appearance(pdf_document *doc, pdf_obj *obj)
{
	if (!pdf_dict_gets(obj, "AP"))
	{
		if (!strcmp(pdf_to_name(pdf_dict_gets(obj, "Subtype")), "Widget"))
		{
			switch(get_field_type(obj))
			{
			case FZ_WIDGET_TYPE_TEXT:
				synthesize_text_widget(doc, obj);
				break;
			}
		}
	}
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
	pdf_obj *vobj = get_inheritable(tw->super.obj, "V");
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
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, strmbuf);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "failed allocation in fz_widget_text_get_text");
	}

	return tw->text;
}

void fz_widget_text_set_text(fz_widget_text *tw, char *text)
{
	fz_context *ctx = tw->super.doc->ctx;

	fz_try(ctx)
	{
		update_text_appearance(tw->super.doc, tw->super.obj, text);
		fz_free(ctx, tw->text);
		tw->text = fz_strdup(ctx, text);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "fz_widget_text_set_text failed");
	}
}
