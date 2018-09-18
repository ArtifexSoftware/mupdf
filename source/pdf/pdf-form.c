#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>

/* Must be kept in sync with definitions in pdf_util.js */
enum
{
	Display_Visible,
	Display_Hidden,
	Display_NoPrint,
	Display_NoView
};

enum
{
	SigFlag_SignaturesExist = 1,
	SigFlag_AppendOnly = 2
};

static int pdf_field_dirties_document(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	int ff = pdf_get_field_flags(ctx, doc, field);
	if (ff & PDF_FIELD_IS_NO_EXPORT) return 0;
	if (ff & PDF_FIELD_IS_READ_ONLY) return 0;
	return 1;
}

/* Find the point in a field hierarchy where all descendants
 * share the same name */
static pdf_obj *find_head_of_field_group(fz_context *ctx, pdf_obj *obj)
{
	if (obj == NULL || pdf_dict_get(ctx, obj, PDF_NAME(T)))
		return obj;
	else
		return find_head_of_field_group(ctx, pdf_dict_get(ctx, obj, PDF_NAME(Parent)));
}

static void pdf_field_mark_dirty(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME(Kids));
	if (kids)
	{
		int i, n = pdf_array_len(ctx, kids);
		for (i = 0; i < n; i++)
			pdf_field_mark_dirty(ctx, doc, pdf_array_get(ctx, kids, i));
	}
	pdf_dirty_obj(ctx, field);
}

static void update_field_value(fz_context *ctx, pdf_document *doc, pdf_obj *obj, const char *text)
{
	pdf_obj *grp;

	if (!text)
		text = "";

	/* All fields of the same name should be updated, so
	 * set the value at the head of the group */
	grp = find_head_of_field_group(ctx, obj);
	if (grp)
		obj = grp;

	pdf_dict_put_text_string(ctx, obj, PDF_NAME(V), text);

	pdf_field_mark_dirty(ctx, doc, obj);
}

static pdf_obj *find_field(fz_context *ctx, pdf_obj *dict, char *name, int len)
{
	int i, n = pdf_array_len(ctx, dict);
	for (i = 0; i < n; i++)
	{
		pdf_obj *field = pdf_array_get(ctx, dict, i);
		const char *part = pdf_dict_get_text_string(ctx, field, PDF_NAME(T));
		if (strlen(part) == (size_t)len && !memcmp(part, name, len))
			return field;
	}
	return NULL;
}

pdf_obj *pdf_lookup_field(fz_context *ctx, pdf_obj *form, char *name)
{
	char *dot;
	char *namep;
	pdf_obj *dict = NULL;
	int len;

	/* Process the fully qualified field name which has
	* the partial names delimited by '.'. Pretend there
	* was a preceding '.' to simplify the loop */
	dot = name - 1;

	while (dot && form)
	{
		namep = dot + 1;
		dot = strchr(namep, '.');
		len = dot ? dot - namep : (int)strlen(namep);
		dict = find_field(ctx, form, namep, len);
		if (dot)
			form = pdf_dict_get(ctx, dict, PDF_NAME(Kids));
	}

	return dict;
}

static void reset_form_field(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	/* Set V to DV wherever DV is present, and delete V where DV is not.
	 * FIXME: we assume for now that V has not been set unequal
	 * to DV higher in the hierarchy than "field".
	 *
	 * At the bottom of the hierarchy we may find widget annotations
	 * that aren't also fields, but DV and V will not be present in their
	 * dictionaries, and attempts to remove V will be harmless. */
	pdf_obj *dv = pdf_dict_get(ctx, field, PDF_NAME(DV));
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME(Kids));

	if (dv)
		pdf_dict_put(ctx, field, PDF_NAME(V), dv);
	else
		pdf_dict_del(ctx, field, PDF_NAME(V));

	if (kids == NULL)
	{
		/* The leaves of the tree are widget annotations
		 * In some cases we need to update the appearance state;
		 * in others we need to mark the field as dirty so that
		 * the appearance stream will be regenerated. */
		switch (pdf_field_type(ctx, doc, field))
		{
		case PDF_WIDGET_TYPE_RADIOBUTTON:
		case PDF_WIDGET_TYPE_CHECKBOX:
			{
				pdf_obj *leafv = pdf_dict_get_inheritable(ctx, field, PDF_NAME(V));

				if (leafv)
					pdf_keep_obj(ctx, leafv);
				else
					leafv = PDF_NAME(Off);

				pdf_dict_put_drop(ctx, field, PDF_NAME(AS), leafv);
			}
			break;

		case PDF_WIDGET_TYPE_PUSHBUTTON:
			break;

		default:
			pdf_field_mark_dirty(ctx, doc, field);
			break;
		}
	}

	if (pdf_field_dirties_document(ctx, doc, field))
		doc->dirty = 1;
}

void pdf_field_reset(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME(Kids));

	reset_form_field(ctx, doc, field);

	if (kids)
	{
		int i, n = pdf_array_len(ctx, kids);

		for (i = 0; i < n; i++)
			pdf_field_reset(ctx, doc, pdf_array_get(ctx, kids, i));
	}
}

static void add_field_hierarchy_to_array(fz_context *ctx, pdf_obj *array, pdf_obj *field)
{
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME(Kids));
	pdf_obj *exclude = pdf_dict_get(ctx, field, PDF_NAME(Exclude));

	if (exclude)
		return;

	pdf_array_push(ctx, array, field);

	if (kids)
	{
		int i, n = pdf_array_len(ctx, kids);

		for (i = 0; i < n; i++)
			add_field_hierarchy_to_array(ctx, array, pdf_array_get(ctx, kids, i));
	}
}

/*
	When resetting or submitting a form, the fields to act upon are defined
	by an array of either field references or field names, plus a flag determining
	whether to act upon the fields in the array, or all fields other than those in
	the array. specified_fields interprets this information and produces the array
	of fields to be acted upon.
*/
static pdf_obj *specified_fields(fz_context *ctx, pdf_document *doc, pdf_obj *fields, int exclude)
{
	pdf_obj *form = pdf_dict_getl(ctx, pdf_trailer(ctx, doc), PDF_NAME(Root), PDF_NAME(AcroForm), PDF_NAME(Fields), NULL);
	int i, n;
	pdf_obj *result = pdf_new_array(ctx, doc, 0);

	fz_try(ctx)
	{
		/* The 'fields' array not being present signals that all fields
		* should be acted upon, so handle it using the exclude case - excluding none */
		if (exclude || !fields)
		{
			/* mark the fields we don't want to act upon */
			n = pdf_array_len(ctx, fields);
			for (i = 0; i < n; i++)
			{
				pdf_obj *field = pdf_array_get(ctx, fields, i);

				if (pdf_is_string(ctx, field))
					field = pdf_lookup_field(ctx, form, pdf_to_str_buf(ctx, field));

				if (field)
					pdf_dict_put(ctx, field, PDF_NAME(Exclude), PDF_NULL);
			}

			/* Act upon all unmarked fields */
			n = pdf_array_len(ctx, form);

			for (i = 0; i < n; i++)
				add_field_hierarchy_to_array(ctx, result, pdf_array_get(ctx, form, i));

			/* Unmark the marked fields */
			n = pdf_array_len(ctx, fields);

			for (i = 0; i < n; i++)
			{
				pdf_obj *field = pdf_array_get(ctx, fields, i);

				if (pdf_is_string(ctx, field))
					field = pdf_lookup_field(ctx, form, pdf_to_str_buf(ctx, field));

				if (field)
					pdf_dict_del(ctx, field, PDF_NAME(Exclude));
			}
		}
		else
		{
			n = pdf_array_len(ctx, fields);

			for (i = 0; i < n; i++)
			{
				pdf_obj *field = pdf_array_get(ctx, fields, i);

				if (pdf_is_string(ctx, field))
					field = pdf_lookup_field(ctx, form, pdf_to_str_buf(ctx, field));

				if (field)
					add_field_hierarchy_to_array(ctx, result, field);
			}
		}
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, result);
		fz_rethrow(ctx);
	}

	return result;
}

static void reset_form(fz_context *ctx, pdf_document *doc, pdf_obj *fields, int exclude)
{
	pdf_obj *sfields = specified_fields(ctx, doc, fields, exclude);

	fz_try(ctx)
	{
		int i, n = pdf_array_len(ctx, sfields);

		for (i = 0; i < n; i++)
			reset_form_field(ctx, doc, pdf_array_get(ctx, sfields, i));
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, sfields);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

void pdf_execute_action(fz_context *ctx, pdf_document *doc, pdf_obj *obj, pdf_obj *a)
{
	if (a)
	{
		pdf_obj *type = pdf_dict_get(ctx, a, PDF_NAME(S));

		if (pdf_name_eq(ctx, type, PDF_NAME(JavaScript)))
		{
			pdf_obj *js = pdf_dict_get(ctx, a, PDF_NAME(JS));
			if (js)
			{
				char *code = pdf_load_stream_or_string_as_utf8(ctx, js);
				fz_try(ctx)
				{
					pdf_js_execute(doc->js, code);
				}
				fz_always(ctx)
				{
					fz_free(ctx, code);
				}
				fz_catch(ctx)
				{
					fz_rethrow(ctx);
				}
			}
		}
		else if (pdf_name_eq(ctx, type, PDF_NAME(ResetForm)))
		{
			reset_form(ctx, doc, pdf_dict_get(ctx, a, PDF_NAME(Fields)), pdf_dict_get_int(ctx, a, PDF_NAME(Flags)) & 1);
		}
		else if (pdf_name_eq(ctx, type, PDF_NAME(Named)))
		{
			pdf_obj *name = pdf_dict_get(ctx, a, PDF_NAME(N));

			if (pdf_name_eq(ctx, name, PDF_NAME(Print)))
				pdf_event_issue_print(ctx, doc);
		}
	}
}

static void execute_action_chain(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	pdf_obj *a = pdf_dict_get(ctx, obj, PDF_NAME(A));
	pdf_js_event e;

	e.target = obj;
	e.value = "";
	pdf_js_setup_event(doc->js, &e);

	while (a)
	{
		pdf_execute_action(ctx, doc, obj, a);
		a = pdf_dict_get(ctx, a, PDF_NAME(Next));
	}
}

static void execute_additional_action(fz_context *ctx, pdf_document *doc, pdf_obj *obj, char *act)
{
	pdf_obj *a = pdf_dict_getp(ctx, obj, act);

	if (a)
	{
		pdf_js_event e;

		e.target = obj;
		e.value = "";
		pdf_js_setup_event(doc->js, &e);
		pdf_execute_action(ctx, doc, obj, a);
	}
}

static void check_off(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	pdf_dict_put(ctx, obj, PDF_NAME(AS), PDF_NAME(Off));
}

static void set_check(fz_context *ctx, pdf_document *doc, pdf_obj *chk, pdf_obj *name)
{
	pdf_obj *n = pdf_dict_getp(ctx, chk, "AP/N");
	pdf_obj *val;

	/* If name is a possible value of this check
	* box then use it, otherwise use "Off" */
	if (pdf_dict_get(ctx, n, name))
		val = name;
	else
		val = PDF_NAME(Off);

	pdf_dict_put(ctx, chk, PDF_NAME(AS), val);
}

/* Set the values of all fields in a group defined by a node
 * in the hierarchy */
static void set_check_grp(fz_context *ctx, pdf_document *doc, pdf_obj *grp, pdf_obj *val)
{
	pdf_obj *kids = pdf_dict_get(ctx, grp, PDF_NAME(Kids));

	if (kids == NULL)
	{
		set_check(ctx, doc, grp, val);
	}
	else
	{
		int i, n = pdf_array_len(ctx, kids);

		for (i = 0; i < n; i++)
			set_check_grp(ctx, doc, pdf_array_get(ctx, kids, i), val);
	}
}

static void recalculate(fz_context *ctx, pdf_document *doc)
{
	pdf_js_event e = {NULL, NULL};

	if (doc->recalculating)
		return;

	doc->recalculating = 1;

	fz_var(e);
	fz_try(ctx)
	{
		pdf_obj *co = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/AcroForm/CO");

		if (co && doc->js)
		{
			int i, n = pdf_array_len(ctx, co);

			for (i = 0; i < n; i++)
			{
				pdf_obj *field = pdf_array_get(ctx, co, i);
				pdf_obj *calc = pdf_dict_getp(ctx, field, "AA/C");

				if (calc)
				{
					pdf_js_event e;

					e.target = field;
					e.value = pdf_field_value(ctx, doc, field);
					pdf_js_setup_event(doc->js, &e);
					/* e.value has been copied. We can free it */
					fz_free(ctx, e.value);
					e.value = NULL;
					pdf_execute_action(ctx, doc, field, calc);
					/* A calculate action, updates event.value. We need
					* to place the value in the field */
					update_field_value(ctx, doc, field, pdf_js_get_event(doc->js)->value);
				}
			}
		}
	}
	fz_always(ctx)
	{
		fz_free(ctx, e.value);
		doc->recalculating = 0;
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void toggle_check_box(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	pdf_obj *as = pdf_dict_get(ctx, obj, PDF_NAME(AS));
	int ff = pdf_get_field_flags(ctx, doc, obj);
	int button_mask = PDF_BTN_FIELD_IS_RADIO | PDF_BTN_FIELD_IS_PUSHBUTTON;
	int radio = ((ff & button_mask) == PDF_BTN_FIELD_IS_RADIO);
	pdf_obj *val = NULL;
	pdf_obj *grp = radio ? pdf_dict_get(ctx, obj, PDF_NAME(Parent)) : find_head_of_field_group(ctx, obj);

	if (!grp)
		grp = obj;

	if (as && !pdf_name_eq(ctx, as, PDF_NAME(Off)))
	{
		/* AS neither missing nor set to Off. Set it to Off, unless
		 * this is a non-toggle-off radio button. */
		if (!(radio && (ff & PDF_BTN_FIELD_IS_NO_TOGGLE_TO_OFF)))
		{
			check_off(ctx, doc, obj);
			val = PDF_NAME(Off);
		}
	}
	else
	{
		pdf_obj *n, *key;
		int len, i;

		n = pdf_dict_getl(ctx, obj, PDF_NAME(AP), PDF_NAME(N), NULL);

		/* Look for an appearance state that isn't "Off" */
		len = pdf_dict_len(ctx, n);
		for (i = 0; i < len; i++)
		{
			key = pdf_dict_get_key(ctx, n, i);
			if (pdf_is_name(ctx, key) && !pdf_name_eq(ctx, key, PDF_NAME(Off)))
				val = key;
		}

		/* If we found no alternative value to Off then we have no value to use */
		if (!val)
			return;

		if (radio)
		{
			/* For radio buttons, first turn off all buttons in the group and
			 * then set the one that was clicked */
			pdf_obj *kids = pdf_dict_get(ctx, grp, PDF_NAME(Kids));

			len = pdf_array_len(ctx, kids);
			for (i = 0; i < len; i++)
				check_off(ctx, doc, pdf_array_get(ctx, kids, i));

			pdf_dict_put(ctx, obj, PDF_NAME(AS), val);
		}
		else
		{
			/* For check boxes, we have located the node of the field hierarchy
			 * below which all fields share a name with the clicked one. Set
			 * all to the same value. This may cause the group to act like
			 * radio buttons, if each have distinct "On" values */
			set_check_grp(ctx, doc, grp, val);
		}
	}

	if (val && grp)
	{
		pdf_dict_put(ctx, grp, PDF_NAME(V), val);
		recalculate(ctx, doc);
	}
}

int pdf_has_unsaved_changes(fz_context *ctx, pdf_document *doc)
{
	return doc->dirty;
}

int pdf_pass_event(fz_context *ctx, pdf_document *doc, pdf_page *page, pdf_ui_event *ui_event)
{
	pdf_annot *a;
	pdf_annot *annot = NULL;
	pdf_hotspot *hp = &doc->hotspot;
	fz_point *pt = &(ui_event->event.pointer.pt);
	int changed = 0;
	fz_rect bbox;

	if (page == NULL)
		return 0;

	for (a = page->annots; a; a = a->next)
	{
		bbox = pdf_bound_annot(ctx, a);
		if (pt->x >= bbox.x0 && pt->x <= bbox.x1)
			if (pt->y >= bbox.y0 && pt->y <= bbox.y1)
				annot = a;
	}

	/* Skip hidden annotations and read-only widgets. */
	if (annot)
	{
		int ff = pdf_dict_get_int(ctx, annot->obj, PDF_NAME(Ff));
		int f = pdf_dict_get_int(ctx, annot->obj, PDF_NAME(F));
		if (f & (PDF_ANNOT_IS_HIDDEN|PDF_ANNOT_IS_NO_VIEW) || ff & PDF_FIELD_IS_READ_ONLY)
			annot = NULL;
	}

	/* Skip Link annotations. */
	if (annot)
	{
		if (pdf_name_eq(ctx, pdf_dict_get(ctx, annot->obj, PDF_NAME(Subtype)), PDF_NAME(Link)))
			annot = NULL;
	}

	switch (ui_event->etype)
	{
	case PDF_EVENT_TYPE_POINTER:
		{
			switch (ui_event->event.pointer.ptype)
			{
			case PDF_POINTER_DOWN:
				if (doc->focus_obj)
				{
					/* Execute the blur action */
					execute_additional_action(ctx, doc, doc->focus_obj, "AA/Bl");
					doc->focus = NULL;
					pdf_drop_obj(ctx, doc->focus_obj);
					doc->focus_obj = NULL;
				}

				if (annot)
				{
					doc->focus = annot;
					doc->focus_obj = pdf_keep_obj(ctx, annot->obj);

					hp->num = pdf_to_num(ctx, annot->obj);
					hp->state = HOTSPOT_POINTER_DOWN;
					changed = 1;
					/* Execute the down and focus actions */
					execute_additional_action(ctx, doc, annot->obj, "AA/Fo");
					execute_additional_action(ctx, doc, annot->obj, "AA/D");
				}
				break;

			case PDF_POINTER_UP:
				if (hp->state != 0)
					changed = 1;

				hp->num = 0;
				hp->state = 0;

				if (annot)
				{
					switch (pdf_widget_type(ctx, (pdf_widget*)annot))
					{
					case PDF_WIDGET_TYPE_RADIOBUTTON:
					case PDF_WIDGET_TYPE_CHECKBOX:
						/* FIXME: treating radio buttons like check boxes, for now */
						toggle_check_box(ctx, doc, annot->obj);
						changed = 1;
						break;
					}

					/* Execute the up action */
					execute_additional_action(ctx, doc, annot->obj, "AA/U");
					/* Execute the main action chain */
					execute_action_chain(ctx, doc, annot->obj);
				}
				break;
			}
		}
		break;
	}

	return changed;
}

int
pdf_update_page(fz_context *ctx, pdf_page *page)
{
	pdf_annot *annot;
	int changed = 0;
	for (annot = page->annots; annot; annot = annot->next)
	{
		if (pdf_update_annot(ctx, annot))
			changed = 1;
	}
	return changed;
}

pdf_widget *pdf_focused_widget(fz_context *ctx, pdf_document *doc)
{
	return (pdf_widget *)doc->focus;
}

pdf_widget *pdf_first_widget(fz_context *ctx, pdf_document *doc, pdf_page *page)
{
	pdf_annot *annot = page->annots;

	while (annot && pdf_annot_type(ctx, annot) != PDF_ANNOT_WIDGET)
		annot = annot->next;

	return (pdf_widget *)annot;
}

pdf_widget *pdf_next_widget(fz_context *ctx, pdf_widget *previous)
{
	pdf_annot *annot = (pdf_annot *)previous;

	if (annot)
		annot = annot->next;

	while (annot && pdf_annot_type(ctx, annot) != PDF_ANNOT_WIDGET)
		annot = annot->next;

	return (pdf_widget *)annot;
}

pdf_widget *pdf_create_widget(fz_context *ctx, pdf_document *doc, pdf_page *page, int type, char *fieldname)
{
	pdf_obj *form = NULL;
	int old_sigflags = pdf_to_int(ctx, pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/AcroForm/SigFlags"));
	pdf_annot *annot = pdf_create_annot(ctx, page, PDF_ANNOT_WIDGET);

	fz_try(ctx)
	{
		pdf_set_field_type(ctx, doc, annot->obj, type);
		pdf_dict_put_text_string(ctx, annot->obj, PDF_NAME(T), fieldname);

		if (type == PDF_WIDGET_TYPE_SIGNATURE)
		{
			int sigflags = (old_sigflags | (SigFlag_SignaturesExist|SigFlag_AppendOnly));
			pdf_dict_putl_drop(ctx, pdf_trailer(ctx, doc), pdf_new_int(ctx, sigflags), PDF_NAME(Root), PDF_NAME(AcroForm), PDF_NAME(SigFlags), NULL);
		}

		/*
		pdf_create_annot will have linked the new widget into the page's
		annot array. We also need it linked into the document's form
		*/
		form = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/AcroForm/Fields");
		if (!form)
		{
			form = pdf_new_array(ctx, doc, 1);
			pdf_dict_putl_drop(ctx, pdf_trailer(ctx, doc), form, PDF_NAME(Root), PDF_NAME(AcroForm), PDF_NAME(Fields), NULL);
		}

		pdf_array_push(ctx, form, annot->obj); /* Cleanup relies on this statement being last */
	}
	fz_catch(ctx)
	{
		pdf_delete_annot(ctx, page, annot);

		/* An empty Fields array may have been created, but that is harmless */

		if (type == PDF_WIDGET_TYPE_SIGNATURE)
			pdf_dict_putl_drop(ctx, pdf_trailer(ctx, doc), pdf_new_int(ctx, old_sigflags), PDF_NAME(Root), PDF_NAME(AcroForm), PDF_NAME(SigFlags), NULL);

		fz_rethrow(ctx);
	}

	return (pdf_widget *)annot;
}

int pdf_widget_type(fz_context *ctx, pdf_widget *widget)
{
	pdf_annot *annot = (pdf_annot *)widget;
	if (pdf_annot_type(ctx, annot) == PDF_ANNOT_WIDGET)
		return pdf_field_type(ctx, pdf_get_bound_document(ctx, annot->obj), annot->obj);
	return PDF_WIDGET_TYPE_NOT_WIDGET;
}

static int set_text_field_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *text)
{
	pdf_obj *v = pdf_dict_getp(ctx, field, "AA/V");

	if (v && doc->js)
	{
		pdf_js_event e;
		e.target = field;
		e.value = fz_strdup(ctx, text);
		pdf_js_setup_event(doc->js, &e);
		pdf_execute_action(ctx, doc, field, v);
		if (!pdf_js_get_event(doc->js)->rc)
			return 0;
		text = pdf_js_get_event(doc->js)->value;
	}

	if (pdf_field_dirties_document(ctx, doc, field))
		doc->dirty = 1;
	update_field_value(ctx, doc, field, text);

	return 1;
}

static void update_checkbox_selector(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *val)
{
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME(Kids));

	if (kids)
	{
		int i, n = pdf_array_len(ctx, kids);

		for (i = 0; i < n; i++)
			update_checkbox_selector(ctx, doc, pdf_array_get(ctx, kids, i), val);
	}
	else
	{
		pdf_obj *n = pdf_dict_getp(ctx, field, "AP/N");
		pdf_obj *oval;

		if (pdf_dict_gets(ctx, n, val))
			oval = pdf_new_name(ctx, val);
		else
			oval = PDF_NAME(Off);
		pdf_dict_put_drop(ctx, field, PDF_NAME(AS), oval);
	}
}

static int set_checkbox_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *val)
{
	update_checkbox_selector(ctx, doc, field, val);
	update_field_value(ctx, doc, field, val);
	return 1;
}

int pdf_field_set_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *text)
{
	int res = 0;

	switch (pdf_field_type(ctx, doc, field))
	{
	case PDF_WIDGET_TYPE_TEXT:
		res = set_text_field_value(ctx, doc, field, text);
		break;

	case PDF_WIDGET_TYPE_CHECKBOX:
	case PDF_WIDGET_TYPE_RADIOBUTTON:
		res = set_checkbox_value(ctx, doc, field, text);
		break;

	default:
		/* text updater will do in most cases */
		update_field_value(ctx, doc, field, text);
		res = 1;
		break;
	}

	recalculate(ctx, doc);

	return res;
}

char *pdf_field_border_style(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	const char *bs = pdf_to_name(ctx, pdf_dict_getl(ctx, field, PDF_NAME(BS), PDF_NAME(S), NULL));
	switch (*bs)
	{
	case 'S': return "Solid";
	case 'D': return "Dashed";
	case 'B': return "Beveled";
	case 'I': return "Inset";
	case 'U': return "Underline";
	}
	return "Solid";
}

void pdf_field_set_border_style(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *text)
{
	pdf_obj *val;

	if (!strcmp(text, "Solid"))
		val = PDF_NAME(S);
	else if (!strcmp(text, "Dashed"))
		val = PDF_NAME(D);
	else if (!strcmp(text, "Beveled"))
		val = PDF_NAME(B);
	else if (!strcmp(text, "Inset"))
		val = PDF_NAME(I);
	else if (!strcmp(text, "Underline"))
		val = PDF_NAME(U);
	else
		return;

	pdf_dict_putl_drop(ctx, field, val, PDF_NAME(BS), PDF_NAME(S), NULL);
	pdf_field_mark_dirty(ctx, doc, field);
}

void pdf_field_set_button_caption(fz_context *ctx, pdf_document *doc, pdf_obj *field, const char *text)
{
	if (pdf_field_type(ctx, doc, field) == PDF_WIDGET_TYPE_PUSHBUTTON)
	{
		pdf_obj *val = pdf_new_text_string(ctx, text);
		pdf_dict_putl_drop(ctx, field, val, PDF_NAME(MK), PDF_NAME(CA), NULL);
		pdf_field_mark_dirty(ctx, doc, field);
	}
}

int pdf_field_display(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	pdf_obj *kids;
	int f, res = Display_Visible;

	/* Base response on first of children. Not ideal,
	 * but not clear how to handle children with
	 * differing values */
	while ((kids = pdf_dict_get(ctx, field, PDF_NAME(Kids))) != NULL)
		field = pdf_array_get(ctx, kids, 0);

	f = pdf_dict_get_int(ctx, field, PDF_NAME(F));

	if (f & PDF_ANNOT_IS_HIDDEN)
	{
		res = Display_Hidden;
	}
	else if (f & PDF_ANNOT_IS_PRINT)
	{
		if (f & PDF_ANNOT_IS_NO_VIEW)
			res = Display_NoView;
	}
	else
	{
		if (f & PDF_ANNOT_IS_NO_VIEW)
			res = Display_Hidden;
		else
			res = Display_NoPrint;
	}

	return res;
}

/*
 * get the field name in a char buffer that has spare room to
 * add more characters at the end.
 */
static char *get_field_name(fz_context *ctx, pdf_document *doc, pdf_obj *field, int spare)
{
	char *res = NULL;
	pdf_obj *parent = pdf_dict_get(ctx, field, PDF_NAME(Parent));
	const char *lname = pdf_dict_get_text_string(ctx, field, PDF_NAME(T));
	int llen = (int)strlen(lname);

	/*
	 * If we found a name at this point in the field hierarchy
	 * then we'll need extra space for it and a dot
	 */
	if (llen)
		spare += llen+1;

	if (parent)
	{
		res = get_field_name(ctx, doc, parent, spare);
	}
	else
	{
		res = fz_malloc(ctx, spare+1);
		res[0] = 0;
	}

	if (llen)
	{
		if (res[0])
			strcat(res, ".");

		strcat(res, lname);
	}

	return res;
}

char *pdf_field_name(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	return get_field_name(ctx, doc, field, 0);
}

const char *pdf_field_label(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	pdf_obj *label = pdf_dict_get_inheritable(ctx, field, PDF_NAME(TU));
	if (!label)
		label = pdf_dict_get_inheritable(ctx, field, PDF_NAME(T));
	if (label)
		return pdf_to_text_string(ctx, label);
	return "Text Field";
}

void pdf_field_set_display(fz_context *ctx, pdf_document *doc, pdf_obj *field, int d)
{
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME(Kids));

	if (!kids)
	{
		int mask = (PDF_ANNOT_IS_HIDDEN|PDF_ANNOT_IS_PRINT|PDF_ANNOT_IS_NO_VIEW);
		int f = pdf_dict_get_int(ctx, field, PDF_NAME(F)) & ~mask;
		pdf_obj *fo;

		switch (d)
		{
		case Display_Visible:
			f |= PDF_ANNOT_IS_PRINT;
			break;
		case Display_Hidden:
			f |= PDF_ANNOT_IS_HIDDEN;
			break;
		case Display_NoView:
			f |= (PDF_ANNOT_IS_PRINT|PDF_ANNOT_IS_NO_VIEW);
			break;
		case Display_NoPrint:
			break;
		}

		fo = pdf_new_int(ctx, f);
		pdf_dict_put_drop(ctx, field, PDF_NAME(F), fo);
	}
	else
	{
		int i, n = pdf_array_len(ctx, kids);

		for (i = 0; i < n; i++)
			pdf_field_set_display(ctx, doc, pdf_array_get(ctx, kids, i), d);
	}
}

void pdf_field_set_fill_color(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_obj *col)
{
	/* col == NULL mean transparent, but we can simply pass it on as with
	 * non-NULL values because pdf_dict_putp interprets a NULL value as
	 * delete */
	pdf_dict_putl(ctx, field, col, PDF_NAME(MK), PDF_NAME(BG), NULL);
	pdf_field_mark_dirty(ctx, doc, field);
}

void pdf_field_set_text_color(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_obj *col)
{
	char buf[100];
	const char *font;
	float size, color[3], black;
	const char *da = pdf_to_str_buf(ctx, pdf_dict_get_inheritable(ctx, field, PDF_NAME(DA)));

	pdf_parse_default_appearance(ctx, da, &font, &size, color);

	switch (pdf_array_len(ctx, col))
	{
	default:
		color[0] = color[1] = color[2] = 0;
		break;
	case 1:
		color[0] = color[1] = color[2] = pdf_array_get_real(ctx, col, 0);
		break;
	case 3:
		color[0] = pdf_array_get_real(ctx, col, 0);
		color[1] = pdf_array_get_real(ctx, col, 1);
		color[2] = pdf_array_get_real(ctx, col, 2);
		break;
	case 4:
		black = pdf_array_get_real(ctx, col, 3);
		color[0] = 1 - fz_min(1, pdf_array_get_real(ctx, col, 0) + black);
		color[1] = 1 - fz_min(1, pdf_array_get_real(ctx, col, 1) + black);
		color[2] = 1 - fz_min(1, pdf_array_get_real(ctx, col, 2) + black);
		break;
	}

	pdf_print_default_appearance(ctx, buf, sizeof buf, font, size, color);
	pdf_dict_put_string(ctx, field, PDF_NAME(DA), buf, strlen(buf));
	pdf_field_mark_dirty(ctx, doc, field);
}

fz_rect pdf_bound_widget(fz_context *ctx, pdf_widget *widget)
{
	return pdf_bound_annot(ctx, (pdf_annot*)widget);
}

char *pdf_text_widget_text(fz_context *ctx, pdf_document *doc, pdf_widget *tw)
{
	pdf_annot *annot = (pdf_annot *)tw;
	char *text = NULL;

	fz_var(text);
	fz_try(ctx)
	{
		text = pdf_field_value(ctx, doc, annot->obj);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "failed allocation in fz_text_widget_text");
	}

	return text;
}

int pdf_text_widget_max_len(fz_context *ctx, pdf_document *doc, pdf_widget *tw)
{
	pdf_annot *annot = (pdf_annot *)tw;

	return pdf_to_int(ctx, pdf_dict_get_inheritable(ctx, annot->obj, PDF_NAME(MaxLen)));
}

int pdf_text_widget_content_type(fz_context *ctx, pdf_document *doc, pdf_widget *tw)
{
	pdf_annot *annot = (pdf_annot *)tw;
	int type = PDF_WIDGET_CONTENT_UNRESTRAINED;
	pdf_obj *js = pdf_dict_getl(ctx, annot->obj, PDF_NAME(AA), PDF_NAME(F), PDF_NAME(JS), NULL);
	if (js)
	{
		char *code = pdf_load_stream_or_string_as_utf8(ctx, js);
		if (strstr(code, "AFNumber_Format"))
			type = PDF_WIDGET_CONTENT_NUMBER;
		else if (strstr(code, "AFSpecial_Format"))
			type = PDF_WIDGET_CONTENT_SPECIAL;
		else if (strstr(code, "AFDate_FormatEx"))
			type = PDF_WIDGET_CONTENT_DATE;
		else if (strstr(code, "AFTime_FormatEx"))
			type = PDF_WIDGET_CONTENT_TIME;
		fz_free(ctx, code);
	}

	return type;
}

static int run_keystroke(fz_context *ctx, pdf_document *doc, pdf_obj *field, char **text)
{
	pdf_obj *k = pdf_dict_getl(ctx, field, PDF_NAME(AA), PDF_NAME(K), NULL);

	/* Return 1 on empty string */
	if (*text[0] == 0)
		return 1;

	if (k && doc->js)
	{
		pdf_js_event e;

		e.target = field;
		e.value = *text;
		pdf_js_setup_event(doc->js, &e);
		pdf_execute_action(ctx, doc, field, k);

		if (!pdf_js_get_event(doc->js)->rc)
			return 0;

		*text = pdf_js_get_event(doc->js)->value;
	}

	return 1;
}

int pdf_text_widget_set_text(fz_context *ctx, pdf_document *doc, pdf_widget *tw, char *text)
{
	pdf_annot *annot = (pdf_annot *)tw;
	int accepted = 0;

	fz_try(ctx)
	{
		accepted = run_keystroke(ctx, doc, annot->obj, &text);
		if (accepted)
			accepted = pdf_field_set_value(ctx, doc, annot->obj, text);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "fz_text_widget_set_text failed");
	}

	return accepted;
}

/* Get either the listed value or the export value. */
int pdf_choice_widget_options(fz_context *ctx, pdf_document *doc, pdf_widget *tw, int exportval, const char *opts[])
{
	pdf_annot *annot = (pdf_annot *)tw;
	pdf_obj *optarr;
	int i, n, m;

	if (!annot)
		return 0;

	optarr = pdf_dict_get(ctx, annot->obj, PDF_NAME(Opt));
	n = pdf_array_len(ctx, optarr);

	if (opts)
	{
		for (i = 0; i < n; i++)
		{
			m = pdf_array_len(ctx, pdf_array_get(ctx, optarr, i));
			/* If it is a two element array, the second item is the one that we want if we want the listing value. */
			if (m == 2)
				if (exportval)
					opts[i] = pdf_array_get_text_string(ctx, pdf_array_get(ctx, optarr, i), 0);
				else
					opts[i] = pdf_array_get_text_string(ctx, pdf_array_get(ctx, optarr, i), 1);
			else
				opts[i] = pdf_array_get_text_string(ctx, optarr, i);
		}
	}
	return n;
}

int pdf_choice_widget_is_multiselect(fz_context *ctx, pdf_document *doc, pdf_widget *tw)
{
	pdf_annot *annot = (pdf_annot *)tw;

	if (!annot) return 0;

	switch (pdf_field_type(ctx, doc, annot->obj))
	{
	case PDF_WIDGET_TYPE_LISTBOX:
	case PDF_WIDGET_TYPE_COMBOBOX:
		return (pdf_get_field_flags(ctx, doc, annot->obj) & PDF_CH_FIELD_IS_MULTI_SELECT) != 0;
	default:
		return 0;
	}
}

int pdf_choice_widget_value(fz_context *ctx, pdf_document *doc, pdf_widget *tw, const char *opts[])
{
	pdf_annot *annot = (pdf_annot *)tw;
	pdf_obj *optarr;
	int i, n;

	if (!annot)
		return 0;

	optarr = pdf_dict_get(ctx, annot->obj, PDF_NAME(V));

	if (pdf_is_string(ctx, optarr))
	{
		if (opts)
			opts[0] = pdf_to_text_string(ctx, optarr);
		return 1;
	}
	else
	{
		n = pdf_array_len(ctx, optarr);
		if (opts)
		{
			for (i = 0; i < n; i++)
			{
				pdf_obj *elem = pdf_array_get(ctx, optarr, i);
				if (pdf_is_array(ctx, elem))
					elem = pdf_array_get(ctx, elem, 1);
				opts[i] = pdf_to_text_string(ctx, elem);
			}
		}
		return n;
	}
}

void pdf_choice_widget_set_value(fz_context *ctx, pdf_document *doc, pdf_widget *tw, int n, const char *opts[])
{
	pdf_annot *annot = (pdf_annot *)tw;
	pdf_obj *optarr = NULL, *opt;
	int i;

	if (!annot)
		return;

	fz_var(optarr);
	fz_try(ctx)
	{
		if (n != 1)
		{
			optarr = pdf_new_array(ctx, doc, n);

			for (i = 0; i < n; i++)
			{
				opt = pdf_new_text_string(ctx, opts[i]);
				pdf_array_push_drop(ctx, optarr, opt);
			}

			pdf_dict_put_drop(ctx, annot->obj, PDF_NAME(V), optarr);
		}
		else
		{
			opt = pdf_new_text_string(ctx, opts[0]);
			pdf_dict_put_drop(ctx, annot->obj, PDF_NAME(V), opt);
		}

		/* FIXME: when n > 1, we should be regenerating the indexes */
		pdf_dict_del(ctx, annot->obj, PDF_NAME(I));

		pdf_field_mark_dirty(ctx, doc, annot->obj);
		if (pdf_field_dirties_document(ctx, doc, annot->obj))
			doc->dirty = 1;
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, optarr);
		fz_rethrow(ctx);
	}
}

int pdf_signature_widget_byte_range(fz_context *ctx, pdf_document *doc, pdf_widget *widget, fz_range *byte_range)
{
	pdf_annot *annot = (pdf_annot *)widget;
	pdf_obj *br = pdf_dict_getl(ctx, annot->obj, PDF_NAME(V), PDF_NAME(ByteRange), NULL);
	int i, n = pdf_array_len(ctx, br)/2;

	if (byte_range)
	{
		for (i = 0; i < n; i++)
		{
			byte_range[i].offset = pdf_array_get_int(ctx, br, 2*i);
			byte_range[i].length = pdf_array_get_int(ctx, br, 2*i+1);
		}
	}

	return n;
}

fz_stream *pdf_signature_widget_hash_bytes(fz_context *ctx, pdf_document *doc, pdf_widget *widget)
{
	fz_range *byte_range = NULL;
	int byte_range_len;
	fz_stream *bytes = NULL;

	fz_var(byte_range);
	fz_try(ctx)
	{
		byte_range_len = pdf_signature_widget_byte_range(ctx, doc, widget, NULL);
		if (byte_range_len)
		{
			byte_range = fz_calloc(ctx, byte_range_len, sizeof(*byte_range));
			pdf_signature_widget_byte_range(ctx, doc, widget, byte_range);
		}

		bytes = fz_open_range_filter(ctx, doc->file, byte_range, byte_range_len);
	}
	fz_always(ctx)
	{
		fz_free(ctx, byte_range);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return bytes;
}

int pdf_signature_widget_contents(fz_context *ctx, pdf_document *doc, pdf_widget *widget, char **contents)
{
	pdf_annot *annot = (pdf_annot *)widget;
	pdf_obj *c = pdf_dict_getl(ctx, annot->obj, PDF_NAME(V), PDF_NAME(Contents), NULL);
	if (contents)
		*contents = pdf_to_str_buf(ctx, c);
	return pdf_to_str_len(ctx, c);
}

void pdf_signature_set_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_pkcs7_signer *signer)
{
	pdf_obj *v = NULL;
	pdf_obj *indv;
	int vnum;
	pdf_obj *byte_range;
	pdf_obj *contents;
	int max_digest_size;
	char *buf = NULL;

	vnum = pdf_create_object(ctx, doc);
	indv = pdf_new_indirect(ctx, doc, vnum, 0);
	pdf_dict_put_drop(ctx, field, PDF_NAME(V), indv);

	max_digest_size = signer->max_digest_size(signer);

	fz_var(v);
	fz_var(buf);
	fz_try(ctx)
	{
		v = pdf_new_dict(ctx, doc, 4);
		pdf_update_object(ctx, doc, vnum, v);

		buf = fz_calloc(ctx, max_digest_size, 1);

		byte_range = pdf_new_array(ctx, doc, 4);
		pdf_dict_put_drop(ctx, v, PDF_NAME(ByteRange), byte_range);

		contents = pdf_new_string(ctx, buf, max_digest_size);
		pdf_dict_put_drop(ctx, v, PDF_NAME(Contents), contents);

		pdf_dict_put(ctx, v, PDF_NAME(Filter), PDF_NAME(Adobe_PPKLite));
		pdf_dict_put(ctx, v, PDF_NAME(SubFilter), PDF_NAME(adbe_pkcs7_detached));

		/* Record details within the document structure so that contents
		* and byte_range can be updated with their correct values at
		* saving time */
		pdf_xref_store_unsaved_signature(ctx, doc, field, signer);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, v);
		fz_free(ctx, buf);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}
