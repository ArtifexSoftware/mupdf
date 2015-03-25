#include "mupdf/pdf.h"

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
	if (ff & Ff_NoExport) return 0;
	if (ff & Ff_ReadOnly) return 0;
	return 1;
}

/* Find the point in a field hierarchy where all descendents
 * share the same name */
static pdf_obj *find_head_of_field_group(fz_context *ctx, pdf_obj *obj)
{
	if (obj == NULL || pdf_dict_get(ctx, obj, PDF_NAME_T))
		return obj;
	else
		return find_head_of_field_group(ctx, pdf_dict_get(ctx, obj, PDF_NAME_Parent));
}

static void pdf_field_mark_dirty(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME_Kids);
	if (kids)
	{
		int i, n = pdf_array_len(ctx, kids);

		for (i = 0; i < n; i++)
			pdf_field_mark_dirty(ctx, doc, pdf_array_get(ctx, kids, i));
	}
	else
	{
		pdf_dirty_obj(ctx, field);
	}
}

static void update_field_value(fz_context *ctx, pdf_document *doc, pdf_obj *obj, char *text)
{
	pdf_obj *sobj = NULL;
	pdf_obj *grp;

	if (!text)
		text = "";

	/* All fields of the same name should be updated, so
	 * set the value at the head of the group */
	grp = find_head_of_field_group(ctx, obj);
	if (grp)
		obj = grp;

	fz_var(sobj);
	fz_try(ctx)
	{
		sobj = pdf_new_string(ctx, doc, text, strlen(text));
		pdf_dict_put(ctx, obj, PDF_NAME_V, sobj);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, sobj);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	pdf_field_mark_dirty(ctx, doc, obj);
}

static pdf_obj *find_field(fz_context *ctx, pdf_obj *dict, char *name, int len)
{
	pdf_obj *field;

	int i, n = pdf_array_len(ctx, dict);

	for (i = 0; i < n; i++)
	{
		char *part;

		field = pdf_array_get(ctx, dict, i);
		part = pdf_to_str_buf(ctx, pdf_dict_get(ctx, field, PDF_NAME_T));
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
		len = dot ? dot - namep : strlen(namep);
		dict = find_field(ctx, form, namep, len);
		if (dot)
			form = pdf_dict_get(ctx, dict, PDF_NAME_Kids);
	}

	return dict;
}

static void reset_field(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	/* Set V to DV whereever DV is present, and delete V where DV is not.
	 * FIXME: we assume for now that V has not been set unequal
	 * to DV higher in the hierarchy than "field".
	 *
	 * At the bottom of the hierarchy we may find widget annotations
	 * that aren't also fields, but DV and V will not be present in their
	 * dictionaries, and attempts to remove V will be harmless. */
	pdf_obj *dv = pdf_dict_get(ctx, field, PDF_NAME_DV);
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME_Kids);

	if (dv)
		pdf_dict_put(ctx, field, PDF_NAME_V, dv);
	else
		pdf_dict_del(ctx, field, PDF_NAME_V);

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
				pdf_obj *leafv = pdf_get_inheritable(ctx, doc, field, PDF_NAME_V);

				if (leafv)
					pdf_keep_obj(ctx, leafv);
				else
					leafv = PDF_NAME_Off;

				fz_try(ctx)
				{
					pdf_dict_put(ctx, field, PDF_NAME_AS, leafv);
				}
				fz_always(ctx)
				{
					pdf_drop_obj(ctx, leafv);
				}
				fz_catch(ctx)
				{
					fz_rethrow(ctx);
				}
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
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME_Kids);

	reset_field(ctx, doc, field);

	if (kids)
	{
		int i, n = pdf_array_len(ctx, kids);

		for (i = 0; i < n; i++)
			pdf_field_reset(ctx, doc, pdf_array_get(ctx, kids, i));
	}
}

static void add_field_hierarchy_to_array(fz_context *ctx, pdf_obj *array, pdf_obj *field)
{
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME_Kids);
	pdf_obj *exclude = pdf_dict_get(ctx, field, PDF_NAME_Exclude);

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
	pdf_obj *form = pdf_dict_getl(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root, PDF_NAME_AcroForm, PDF_NAME_Fields, NULL);
	int i, n;
	pdf_obj *result = pdf_new_array(ctx, doc, 0);
	pdf_obj *nil = NULL;

	fz_var(nil);
	fz_try(ctx)
	{
		/* The 'fields' array not being present signals that all fields
		* should be acted upon, so handle it using the exclude case - excluding none */
		if (exclude || !fields)
		{
			/* mark the fields we don't want to act upon */
			nil = pdf_new_null(ctx, doc);

			n = pdf_array_len(ctx, fields);

			for (i = 0; i < n; i++)
			{
				pdf_obj *field = pdf_array_get(ctx, fields, i);

				if (pdf_is_string(ctx, field))
					field = pdf_lookup_field(ctx, form, pdf_to_str_buf(ctx, field));

				if (field)
					pdf_dict_put(ctx, field, PDF_NAME_Exclude, nil);
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
					pdf_dict_del(ctx, field, PDF_NAME_Exclude);
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
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, nil);
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
			reset_field(ctx, doc, pdf_array_get(ctx, sfields, i));
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

static void execute_action(fz_context *ctx, pdf_document *doc, pdf_obj *obj, pdf_obj *a)
{
	if (a)
	{
		pdf_obj *type = pdf_dict_get(ctx, a, PDF_NAME_S);

		if (pdf_name_eq(ctx, type, PDF_NAME_JavaScript))
		{
			pdf_obj *js = pdf_dict_get(ctx, a, PDF_NAME_JS);
			if (js)
			{
				char *code = pdf_to_utf8(ctx, doc, js);
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
		else if (pdf_name_eq(ctx, type, PDF_NAME_ResetForm))
		{
			reset_form(ctx, doc, pdf_dict_get(ctx, a, PDF_NAME_Fields), pdf_to_int(ctx, pdf_dict_get(ctx, a, PDF_NAME_Flags)) & 1);
		}
		else if (pdf_name_eq(ctx, type, PDF_NAME_Named))
		{
			pdf_obj *name = pdf_dict_get(ctx, a, PDF_NAME_N);

			if (pdf_name_eq(ctx, name, PDF_NAME_Print))
				pdf_event_issue_print(ctx, doc);
		}
	}
}

static void execute_action_chain(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	pdf_obj *a = pdf_dict_get(ctx, obj, PDF_NAME_A);
	pdf_js_event e;

	e.target = obj;
	e.value = "";
	pdf_js_setup_event(doc->js, &e);

	while (a)
	{
		execute_action(ctx, doc, obj, a);
		a = pdf_dict_get(ctx, a, PDF_NAME_Next);
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
		execute_action(ctx, doc, obj, a);
	}
}

static void check_off(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	pdf_dict_put(ctx, obj, PDF_NAME_AS, PDF_NAME_Off);
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
		val = PDF_NAME_Off;

	pdf_dict_put(ctx, chk, PDF_NAME_AS, val);
}

/* Set the values of all fields in a group defined by a node
 * in the hierarchy */
static void set_check_grp(fz_context *ctx, pdf_document *doc, pdf_obj *grp, pdf_obj *val)
{
	pdf_obj *kids = pdf_dict_get(ctx, grp, PDF_NAME_Kids);

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
	if (doc->recalculating)
		return;

	doc->recalculating = 1;
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
					execute_action(ctx, doc, field, calc);
					/* A calculate action, updates event.value. We need
					* to place the value in the field */
					update_field_value(ctx, doc, field, pdf_js_get_event(doc->js)->value);
				}
			}
		}
	}
	fz_always(ctx)
	{
		doc->recalculating = 0;
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void toggle_check_box(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	pdf_obj *as = pdf_dict_get(ctx, obj, PDF_NAME_AS);
	int ff = pdf_get_field_flags(ctx, doc, obj);
	int radio = ((ff & (Ff_Pushbutton|Ff_Radio)) == Ff_Radio);
	char *val = NULL;
	pdf_obj *grp = radio ? pdf_dict_get(ctx, obj, PDF_NAME_Parent) : find_head_of_field_group(ctx, obj);

	if (!grp)
		grp = obj;

	if (as && !pdf_name_eq(ctx, as, PDF_NAME_Off))
	{
		/* "as" neither missing nor set to Off. Set it to Off, unless
		 * this is a non-toggle-off radio button. */
		if ((ff & (Ff_Pushbutton|Ff_NoToggleToOff|Ff_Radio)) != (Ff_NoToggleToOff|Ff_Radio))
		{
			check_off(ctx, doc, obj);
			val = "Off";
		}
	}
	else
	{
		pdf_obj *n, *key = NULL;
		int len, i;

		n = pdf_dict_getp(ctx, obj, "AP/N");

		/* Look for a key that isn't "Off" */
		len = pdf_dict_len(ctx, n);
		for (i = 0; i < len; i++)
		{
			key = pdf_dict_get_key(ctx, n, i);
			if (pdf_is_name(ctx, key) && !pdf_name_eq(ctx, key, PDF_NAME_Off))
				break;
		}

		/* If we found no alternative value to Off then we have no value to use */
		if (!key)
			return;

		if (radio)
		{
			/* For radio buttons, first turn off all buttons in the group and
			 * then set the one that was clicked */
			pdf_obj *kids = pdf_dict_get(ctx, grp, PDF_NAME_Kids);

			len = pdf_array_len(ctx, kids);
			for (i = 0; i < len; i++)
				check_off(ctx, doc, pdf_array_get(ctx, kids, i));

			pdf_dict_put(ctx, obj, PDF_NAME_AS, key);
		}
		else
		{
			/* For check boxes, we have located the node of the field hierarchy
			 * below which all fields share a name with the clicked one. Set
			 * all to the same value. This may cause the group to act like
			 * radio buttons, if each have distinct "On" values */
			if (grp)
				set_check_grp(ctx, doc, grp, key);
			else
				set_check(ctx, doc, obj, key);
		}
	}

	if (val && grp)
	{
		pdf_obj *v = NULL;

		fz_var(v);
		fz_try(ctx)
		{
			v = pdf_new_string(ctx, doc, val, strlen(val));
			pdf_dict_put(ctx, grp, PDF_NAME_V, v);
		}
		fz_always(ctx)
		{
			pdf_drop_obj(ctx, v);
		}
		fz_catch(ctx)
		{
			fz_rethrow(ctx);
		}

		recalculate(ctx, doc);
	}
}

int pdf_has_unsaved_changes(fz_context *ctx, pdf_document *doc)
{
	return doc->dirty;
}

int pdf_pass_event(fz_context *ctx, pdf_document *doc, pdf_page *page, pdf_ui_event *ui_event)
{
	pdf_annot *annot;
	pdf_hotspot *hp = &doc->hotspot;
	fz_point *pt = &(ui_event->event.pointer.pt);
	int changed = 0;

	if (page == NULL)
		return 0;

	for (annot = page->annots; annot; annot = annot->next)
	{
		if (pt->x >= annot->pagerect.x0 && pt->x <= annot->pagerect.x1)
			if (pt->y >= annot->pagerect.y0 && pt->y <= annot->pagerect.y1)
				break;
	}

	if (annot)
	{
		int f = pdf_to_int(ctx, pdf_dict_get(ctx, annot->obj, PDF_NAME_F));

		if (f & (F_Hidden|F_NoView))
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
					hp->gen = pdf_to_gen(ctx, annot->obj);
					hp->state = HOTSPOT_POINTER_DOWN;
					changed = 1;
					/* Exectute the down and focus actions */
					execute_additional_action(ctx, doc, annot->obj, "AA/Fo");
					execute_additional_action(ctx, doc, annot->obj, "AA/D");
				}
				break;

			case PDF_POINTER_UP:
				if (hp->state != 0)
					changed = 1;

				hp->num = 0;
				hp->gen = 0;
				hp->state = 0;

				if (annot)
				{
					switch (annot->widget_type)
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

void pdf_update_page(fz_context *ctx, pdf_document *doc, pdf_page *page)
{
	pdf_annot *annot;

	/* Reset changed_annots to empty */
	page->changed_annots = NULL;

	/*
		Free all annots in tmp_annots, since these were
		referenced only from changed_annots.
	*/
	if (page->tmp_annots)
	{
		pdf_drop_annot(ctx, page->tmp_annots);
		page->tmp_annots = NULL;
	}

	/* Add all changed annots to the list */
	for (annot = page->annots; annot; annot = annot->next)
	{
		pdf_xobject *ap = pdf_keep_xobject(ctx, annot->ap);
		int ap_iteration = annot->ap_iteration;

		fz_try(ctx)
		{
			pdf_update_annot(ctx, doc, annot);

			if ((ap != annot->ap || ap_iteration != annot->ap_iteration))
			{
				annot->next_changed = page->changed_annots;
				page->changed_annots = annot;
			}
		}
		fz_always(ctx)
		{
			pdf_drop_xobject(ctx, ap);
		}
		fz_catch(ctx)
		{
			fz_rethrow(ctx);
		}
	}

	/*
		Add all deleted annots to the list, since these also
		warrant a screen update
	*/
	for (annot = page->deleted_annots; annot; annot = annot->next)
	{
		annot->next_changed = page->changed_annots;
		page->changed_annots = annot;
	}

	/*
		Move deleted_annots to tmp_annots to keep them separate
		from any future deleted ones. They cannot yet be freed
		since they are linked into changed_annots
	*/
	page->tmp_annots = page->deleted_annots;
	page->deleted_annots = NULL;
}

pdf_annot *pdf_poll_changed_annot(fz_context *ctx, pdf_document *idoc, pdf_page *page)
{
	pdf_annot *annot = page->changed_annots;

	if (annot)
		page->changed_annots = annot->next_changed;

	return annot;
}

pdf_widget *pdf_focused_widget(fz_context *ctx, pdf_document *doc)
{
	return (pdf_widget *)doc->focus;
}

pdf_widget *pdf_first_widget(fz_context *ctx, pdf_document *doc, pdf_page *page)
{
	pdf_annot *annot = page->annots;

	while (annot && annot->widget_type == PDF_WIDGET_TYPE_NOT_WIDGET)
		annot = annot->next;

	return (pdf_widget *)annot;
}

pdf_widget *pdf_next_widget(fz_context *ctx, pdf_widget *previous)
{
	pdf_annot *annot = (pdf_annot *)previous;

	if (annot)
		annot = annot->next;

	while (annot && annot->widget_type == PDF_WIDGET_TYPE_NOT_WIDGET)
		annot = annot->next;

	return (pdf_widget *)annot;
}

pdf_widget *pdf_create_widget(fz_context *ctx, pdf_document *doc, pdf_page *page, int type, char *fieldname)
{
	pdf_obj *form = NULL;
	int old_sigflags = pdf_to_int(ctx, pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/AcroForm/SigFlags"));
	pdf_annot *annot = pdf_create_annot(ctx, doc, page, FZ_ANNOT_WIDGET);

	fz_try(ctx)
	{
		pdf_set_field_type(ctx, doc, annot->obj, type);
		pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_T, pdf_new_string(ctx, doc, fieldname, strlen(fieldname)));
		annot->widget_type = type;

		if (type == PDF_WIDGET_TYPE_SIGNATURE)
		{
			int sigflags = (old_sigflags | (SigFlag_SignaturesExist|SigFlag_AppendOnly));
			pdf_dict_putl_drop(ctx, pdf_trailer(ctx, doc), pdf_new_int(ctx, doc, sigflags), PDF_NAME_Root, PDF_NAME_AcroForm, PDF_NAME_SigFlags, NULL);
		}

		/*
		pdf_create_annot will have linked the new widget into the page's
		annot array. We also need it linked into the document's form
		*/
		form = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/AcroForm/Fields");
		if (!form)
		{
			form = pdf_new_array(ctx, doc, 1);
			pdf_dict_putl_drop(ctx, pdf_trailer(ctx, doc), form, PDF_NAME_Root, PDF_NAME_AcroForm, PDF_NAME_Fields, NULL);
		}

		pdf_array_push(ctx, form, annot->obj); /* Cleanup relies on this statement being last */
	}
	fz_catch(ctx)
	{
		pdf_delete_annot(ctx, doc, page, annot);

		/* An empty Fields array may have been created, but that is harmless */

		if (type == PDF_WIDGET_TYPE_SIGNATURE)
			pdf_dict_putl_drop(ctx, pdf_trailer(ctx, doc), pdf_new_int(ctx, doc, old_sigflags), PDF_NAME_Root, PDF_NAME_AcroForm, PDF_NAME_SigFlags, NULL);

		fz_rethrow(ctx);
	}

	return (pdf_widget *)annot;
}

int pdf_widget_get_type(fz_context *ctx, pdf_widget *widget)
{
	pdf_annot *annot = (pdf_annot *)widget;
	return annot->widget_type;
}

static int set_text_field_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, char *text)
{
	pdf_obj *v = pdf_dict_getp(ctx, field, "AA/V");

	if (v && doc->js)
	{
		pdf_js_event e;

		e.target = field;
		e.value = text;
		pdf_js_setup_event(doc->js, &e);
		execute_action(ctx, doc, field, v);

		if (!pdf_js_get_event(doc->js)->rc)
			return 0;

		text = pdf_js_get_event(doc->js)->value;
	}

	if (pdf_field_dirties_document(ctx, doc, field))
		doc->dirty = 1;
	update_field_value(ctx, doc, field, text);

	return 1;
}

static void update_checkbox_selector(fz_context *ctx, pdf_document *doc, pdf_obj *field, char *val)
{
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME_Kids);

	if (kids)
	{
		int i, n = pdf_array_len(ctx, kids);

		for (i = 0; i < n; i++)
			update_checkbox_selector(ctx, doc, pdf_array_get(ctx, kids, i), val);
	}
	else
	{
		pdf_obj *n = pdf_dict_getp(ctx, field, "AP/N");
		pdf_obj *oval = NULL;

		fz_var(oval);
		fz_try(ctx)
		{
			if (pdf_dict_gets(ctx, n, val))
				oval = pdf_new_name(ctx, doc, val);
			else
				oval = PDF_NAME_Off;

			pdf_dict_put(ctx, field, PDF_NAME_AS, oval);
		}
		fz_always(ctx)
		{
			pdf_drop_obj(ctx, oval);
		}
		fz_catch(ctx)
		{
			fz_rethrow(ctx);
		}
	}
}

static int set_checkbox_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, char *val)
{
	update_checkbox_selector(ctx, doc, field, val);
	update_field_value(ctx, doc, field, val);
	return 1;
}

int pdf_field_set_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, char *text)
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
	char *bs = pdf_to_name(ctx, pdf_dict_getl(ctx, field, PDF_NAME_BS, PDF_NAME_S, NULL));

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

void pdf_field_set_border_style(fz_context *ctx, pdf_document *doc, pdf_obj *field, char *text)
{
	pdf_obj *val = NULL;

	if (!strcmp(text, "Solid"))
		val = PDF_NAME_S;
	else if (!strcmp(text, "Dashed"))
		val = PDF_NAME_D;
	else if (!strcmp(text, "Beveled"))
		val = PDF_NAME_B;
	else if (!strcmp(text, "Inset"))
		val = PDF_NAME_I;
	else if (!strcmp(text, "Underline"))
		val = PDF_NAME_U;
	else
		return;

	fz_try(ctx);
	{
		pdf_dict_putl(ctx, field, val, PDF_NAME_BS, PDF_NAME_S, NULL);
		pdf_field_mark_dirty(ctx, doc, field);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, val);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

void pdf_field_set_button_caption(fz_context *ctx, pdf_document *doc, pdf_obj *field, char *text)
{
	pdf_obj *val = pdf_new_string(ctx, doc, text, strlen(text));

	fz_try(ctx);
	{
		if (pdf_field_type(ctx, doc, field) == PDF_WIDGET_TYPE_PUSHBUTTON)
		{
			pdf_dict_putl(ctx, field, val, PDF_NAME_MK, PDF_NAME_CA, NULL);
			pdf_field_mark_dirty(ctx, doc, field);
		}
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, val);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

int pdf_field_display(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	pdf_obj *kids;
	int f, res = Display_Visible;

	/* Base response on first of children. Not ideal,
	 * but not clear how to handle children with
	 * differing values */
	while ((kids = pdf_dict_get(ctx, field, PDF_NAME_Kids)) != NULL)
		field = pdf_array_get(ctx, kids, 0);

	f = pdf_to_int(ctx, pdf_dict_get(ctx, field, PDF_NAME_F));

	if (f & F_Hidden)
	{
		res = Display_Hidden;
	}
	else if (f & F_Print)
	{
		if (f & F_NoView)
			res = Display_NoView;
	}
	else
	{
		if (f & F_NoView)
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
	pdf_obj *parent = pdf_dict_get(ctx, field, PDF_NAME_Parent);
	char *lname = pdf_to_str_buf(ctx, pdf_dict_get(ctx, field, PDF_NAME_T));
	int llen = strlen(lname);

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

void pdf_field_set_display(fz_context *ctx, pdf_document *doc, pdf_obj *field, int d)
{
	pdf_obj *kids = pdf_dict_get(ctx, field, PDF_NAME_Kids);

	if (!kids)
	{
		int mask = (F_Hidden|F_Print|F_NoView);
		int f = pdf_to_int(ctx, pdf_dict_get(ctx, field, PDF_NAME_F)) & ~mask;
		pdf_obj *fo = NULL;

		switch (d)
		{
		case Display_Visible:
			f |= F_Print;
			break;
		case Display_Hidden:
			f |= F_Hidden;
			break;
		case Display_NoView:
			f |= (F_Print|F_NoView);
			break;
		case Display_NoPrint:
			break;
		}

		fz_var(fo);
		fz_try(ctx)
		{
			fo = pdf_new_int(ctx, doc, f);
			pdf_dict_put(ctx, field, PDF_NAME_F, fo);
		}
		fz_always(ctx)
		{
			pdf_drop_obj(ctx, fo);
		}
		fz_catch(ctx)
		{
			fz_rethrow(ctx);
		}
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
	pdf_dict_putl(ctx, field, col, PDF_NAME_MK, PDF_NAME_BG, NULL);
	pdf_field_mark_dirty(ctx, doc, field);
}

void pdf_field_set_text_color(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_obj *col)
{
	pdf_da_info di;
	fz_buffer *fzbuf = NULL;
	char *da = pdf_to_str_buf(ctx, pdf_get_inheritable(ctx, doc, field, PDF_NAME_DA));
	unsigned char *buf;
	int len;
	pdf_obj *daobj = NULL;

	memset(&di, 0, sizeof(di));

	fz_var(fzbuf);
	fz_var(di);
	fz_var(daobj);
	fz_try(ctx)
	{
		int i;

		pdf_parse_da(ctx, da, &di);
		di.col_size = pdf_array_len(ctx, col);

		len = fz_mini(di.col_size, nelem(di.col));
		for (i = 0; i < len; i++)
			di.col[i] = pdf_to_real(ctx, pdf_array_get(ctx, col, i));

		fzbuf = fz_new_buffer(ctx, 0);
		pdf_fzbuf_print_da(ctx, fzbuf, &di);
		len = fz_buffer_storage(ctx, fzbuf, &buf);
		daobj = pdf_new_string(ctx, doc, (char *)buf, len);
		pdf_dict_put(ctx, field, PDF_NAME_DA, daobj);
		pdf_field_mark_dirty(ctx, doc, field);
	}
	fz_always(ctx)
	{
		pdf_da_info_fin(ctx, &di);
		fz_drop_buffer(ctx, fzbuf);
		pdf_drop_obj(ctx, daobj);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "%s", fz_caught_message(ctx));
	}
}

fz_rect *pdf_bound_widget(fz_context *ctx, pdf_widget *widget, fz_rect *rect)
{
	pdf_annot *annot = (pdf_annot *)widget;

	if (rect == NULL)
		return NULL;
	*rect = annot->pagerect;

	return rect;
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

	return pdf_to_int(ctx, pdf_get_inheritable(ctx, doc, annot->obj, PDF_NAME_MaxLen));
}

int pdf_text_widget_content_type(fz_context *ctx, pdf_document *doc, pdf_widget *tw)
{
	pdf_annot *annot = (pdf_annot *)tw;
	char *code = NULL;
	int type = PDF_WIDGET_CONTENT_UNRESTRAINED;

	fz_var(code);
	fz_try(ctx)
	{
		code = pdf_get_string_or_stream(ctx, doc, pdf_dict_getl(ctx, annot->obj, PDF_NAME_AA, PDF_NAME_F, PDF_NAME_JS, NULL));
		if (code)
		{
			if (strstr(code, "AFNumber_Format"))
				type = PDF_WIDGET_CONTENT_NUMBER;
			else if (strstr(code, "AFSpecial_Format"))
				type = PDF_WIDGET_CONTENT_SPECIAL;
			else if (strstr(code, "AFDate_FormatEx"))
				type = PDF_WIDGET_CONTENT_DATE;
			else if (strstr(code, "AFTime_FormatEx"))
				type = PDF_WIDGET_CONTENT_TIME;
		}
	}
	fz_always(ctx)
	{
		fz_free(ctx, code);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "failure in fz_text_widget_content_type");
	}

	return type;
}

static int run_keystroke(fz_context *ctx, pdf_document *doc, pdf_obj *field, char **text)
{
	pdf_obj *k = pdf_dict_getl(ctx, field, PDF_NAME_AA, PDF_NAME_K, NULL);

	if (k && doc->js)
	{
		pdf_js_event e;

		e.target = field;
		e.value = *text;
		pdf_js_setup_event(doc->js, &e);
		execute_action(ctx, doc, field, k);

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

int pdf_choice_widget_options(fz_context *ctx, pdf_document *doc, pdf_widget *tw, char *opts[])
{
	pdf_annot *annot = (pdf_annot *)tw;
	pdf_obj *optarr;
	int i, n;

	if (!annot)
		return 0;

	optarr = pdf_dict_get(ctx, annot->obj, PDF_NAME_Opt);
	n = pdf_array_len(ctx, optarr);

	if (opts)
	{
		for (i = 0; i < n; i++)
		{
			opts[i] = pdf_to_str_buf(ctx, pdf_array_get(ctx, optarr, i));
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
		return (pdf_get_field_flags(ctx, doc, annot->obj) & Ff_MultiSelect) != 0;
	default:
		return 0;
	}
}

int pdf_choice_widget_value(fz_context *ctx, pdf_document *doc, pdf_widget *tw, char *opts[])
{
	pdf_annot *annot = (pdf_annot *)tw;
	pdf_obj *optarr;
	int i, n;

	if (!annot)
		return 0;

	optarr = pdf_dict_get(ctx, annot->obj, PDF_NAME_V);

	if (pdf_is_string(ctx, optarr))
	{
		if (opts)
			opts[0] = pdf_to_str_buf(ctx, optarr);

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

				opts[i] = pdf_to_str_buf(ctx, elem);
			}
		}

		return n;
	}
}

void pdf_choice_widget_set_value(fz_context *ctx, pdf_document *doc, pdf_widget *tw, int n, char *opts[])
{
	pdf_annot *annot = (pdf_annot *)tw;
	pdf_obj *optarr = NULL, *opt = NULL;
	int i;

	if (!annot)
		return;

	fz_var(optarr);
	fz_var(opt);
	fz_try(ctx)
	{
		if (n != 1)
		{
			optarr = pdf_new_array(ctx, doc, n);

			for (i = 0; i < n; i++)
			{
				opt = pdf_new_string(ctx, doc, opts[i], strlen(opts[i]));
				pdf_array_push(ctx, optarr, opt);
				pdf_drop_obj(ctx, opt);
				opt = NULL;
			}

			pdf_dict_put(ctx, annot->obj, PDF_NAME_V, optarr);
			pdf_drop_obj(ctx, optarr);
		}
		else
		{
			opt = pdf_new_string(ctx, doc, opts[0], strlen(opts[0]));
			pdf_dict_put(ctx, annot->obj, PDF_NAME_V, opt);
			pdf_drop_obj(ctx, opt);
		}

		/* FIXME: when n > 1, we should be regenerating the indexes */
		pdf_dict_del(ctx, annot->obj, PDF_NAME_I);

		pdf_field_mark_dirty(ctx, doc, annot->obj);
		if (pdf_field_dirties_document(ctx, doc, annot->obj))
			doc->dirty = 1;
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, optarr);
		pdf_drop_obj(ctx, opt);
		fz_rethrow(ctx);
	}
}

int pdf_signature_widget_byte_range(fz_context *ctx, pdf_document *doc, pdf_widget *widget, int (*byte_range)[2])
{
	pdf_annot *annot = (pdf_annot *)widget;
	pdf_obj *br = pdf_dict_getl(ctx, annot->obj, PDF_NAME_V, PDF_NAME_ByteRange, NULL);
	int i, n = pdf_array_len(ctx, br)/2;

	if (byte_range)
	{
		for (i = 0; i < n; i++)
		{
			byte_range[i][0] = pdf_to_int(ctx, pdf_array_get(ctx, br, 2*i));
			byte_range[i][1] = pdf_to_int(ctx, pdf_array_get(ctx, br, 2*i+1));
		}
	}

	return n;
}

int pdf_signature_widget_contents(fz_context *ctx, pdf_document *doc, pdf_widget *widget, char **contents)
{
	pdf_annot *annot = (pdf_annot *)widget;
	pdf_obj *c = pdf_dict_getl(ctx, annot->obj, PDF_NAME_V, PDF_NAME_Contents, NULL);
	if (contents)
		*contents = pdf_to_str_buf(ctx, c);
	return pdf_to_str_len(ctx, c);
}

void pdf_signature_set_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_signer *signer)
{
	pdf_obj *v;
	pdf_obj *indv;
	int vnum;
	pdf_obj *byte_range;
	pdf_obj *contents;
	char buf[2048];
	pdf_unsaved_sig *unsaved_sig;

	memset(buf, 0, sizeof(buf));

	vnum = pdf_create_object(ctx, doc);
	indv = pdf_new_indirect(ctx, doc, vnum, 0);
	pdf_dict_put_drop(ctx, field, PDF_NAME_V, indv);

	fz_var(v);
	fz_try(ctx)
	{
		v = pdf_new_dict(ctx, doc, 4);
		pdf_update_object(ctx, doc, vnum, v);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, v);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	byte_range = pdf_new_array(ctx, doc, 4);
	pdf_dict_put_drop(ctx, v, PDF_NAME_ByteRange, byte_range);

	contents = pdf_new_string(ctx, doc, buf, sizeof(buf));
	pdf_dict_put_drop(ctx, v, PDF_NAME_Contents, contents);

	pdf_dict_put_drop(ctx, v, PDF_NAME_Filter, PDF_NAME_Adobe_PPKLite);
	pdf_dict_put_drop(ctx, v, PDF_NAME_SubFilter, PDF_NAME_adbe_pkcs7_detached);

	/* Record details within the document structure so that contents
	 * and byte_range can be updated with their correct values at
	 * saving time */
	unsaved_sig = fz_malloc_struct(ctx, pdf_unsaved_sig);
	unsaved_sig->field = pdf_keep_obj(ctx, field);
	unsaved_sig->signer = pdf_keep_signer(ctx, signer);
	unsaved_sig->next = doc->unsaved_sigs;
	doc->unsaved_sigs = unsaved_sig;
}
