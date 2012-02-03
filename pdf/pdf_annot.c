#include "fitz.h"
#include "mupdf.h"

static fz_obj *
resolve_dest_rec(pdf_document *xref, fz_obj *dest, int depth)
{
	if (depth > 10) /* Arbitrary to avoid infinite recursion */
		return NULL;

	if (fz_is_name(dest) || fz_is_string(dest))
	{
		dest = pdf_lookup_dest(xref, dest);
		return resolve_dest_rec(xref, dest, depth+1);
	}

	else if (fz_is_array(dest))
	{
		return dest;
	}

	else if (fz_is_dict(dest))
	{
		dest = fz_dict_gets(dest, "D");
		return resolve_dest_rec(xref, dest, depth+1);
	}

	else if (fz_is_indirect(dest))
		return dest;

	return NULL;
}

static fz_obj *
resolve_dest(pdf_document *xref, fz_obj *dest)
{
	return resolve_dest_rec(xref, dest, 0);
}

fz_link_dest
pdf_parse_link_dest(pdf_document *xref, fz_obj *dest)
{
	fz_link_dest ld;
	fz_obj *obj;

	int l_from_2 = 0;
	int b_from_3 = 0;
	int r_from_4 = 0;
	int t_from_5 = 0;
	int t_from_3 = 0;
	int t_from_2 = 0;
	int z_from_4 = 0;

	dest = resolve_dest(xref, dest);
	if (dest == NULL || !fz_is_array(dest))
	{
		ld.kind = FZ_LINK_NONE;
		return ld;
	}
	obj = fz_array_get(dest, 0);
	if (fz_is_int(obj))
		ld.ld.gotor.page = fz_to_int(obj);
	else
		ld.ld.gotor.page = pdf_find_page_number(xref, obj);

	ld.kind = FZ_LINK_GOTO;
	ld.ld.gotor.flags = 0;
	ld.ld.gotor.lt.x = 0;
	ld.ld.gotor.lt.y = 0;
	ld.ld.gotor.rb.x = 0;
	ld.ld.gotor.rb.y = 0;
	ld.ld.gotor.file_spec = NULL;
	ld.ld.gotor.new_window = 0;

	obj = fz_array_get(dest, 1);
	if (!fz_is_name(obj))
		return ld;

	if (!strcmp("XYZ", fz_to_name(obj)))
	{
		l_from_2 = t_from_3 = z_from_4 = 1;
		ld.ld.gotor.flags |= fz_link_flag_r_is_zoom;
	}
	else if ((!strcmp("Fit", fz_to_name(obj))) || (!strcmp("FitB", fz_to_name(obj))))
	{
		ld.ld.gotor.flags |= fz_link_flag_fit_h;
		ld.ld.gotor.flags |= fz_link_flag_fit_v;
	}
	else if ((!strcmp("FitH", fz_to_name(obj))) || (!strcmp("FitBH", fz_to_name(obj))))
	{
		t_from_2 = 1;
		ld.ld.gotor.flags |= fz_link_flag_fit_h;
	}
	else if ((!strcmp("FitV", fz_to_name(obj))) || (!strcmp("FitBV", fz_to_name(obj))))
	{
		l_from_2 = 1;
		ld.ld.gotor.flags |= fz_link_flag_fit_v;
	}
	else if (!strcmp("FitR", fz_to_name(obj)))
	{
		l_from_2 = b_from_3 = r_from_4 = t_from_5 = 1;
		ld.ld.gotor.flags |= fz_link_flag_fit_h;
		ld.ld.gotor.flags |= fz_link_flag_fit_v;
	}

	if (l_from_2)
	{
		obj = fz_array_get(dest, 2);
		if (fz_is_int(obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_l_valid;
			ld.ld.gotor.lt.x = fz_to_int(obj);
		}
		else if (fz_is_real(obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_l_valid;
			ld.ld.gotor.lt.x = fz_to_real(obj);
		}
	}
	if (b_from_3)
	{
		obj = fz_array_get(dest, 3);
		if (fz_is_int(obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_b_valid;
			ld.ld.gotor.rb.y = fz_to_int(obj);
		}
		else if (fz_is_real(obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_b_valid;
			ld.ld.gotor.rb.y = fz_to_real(obj);
		}
	}
	if (r_from_4)
	{
		obj = fz_array_get(dest, 4);
		if (fz_is_int(obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_r_valid;
			ld.ld.gotor.rb.x = fz_to_int(obj);
		}
		else if (fz_is_real(obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_r_valid;
			ld.ld.gotor.rb.x = fz_to_real(obj);
		}
	}
	if (t_from_5 || t_from_3 || t_from_2)
	{
		if (t_from_5)
			obj = fz_array_get(dest, 5);
		else if (t_from_3)
			obj = fz_array_get(dest, 3);
		else
			obj = fz_array_get(dest, 2);
		if (fz_is_int(obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_t_valid;
			ld.ld.gotor.lt.y = fz_to_int(obj);
		}
		else if (fz_is_real(obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_t_valid;
			ld.ld.gotor.lt.y = fz_to_real(obj);
		}
	}
	if (z_from_4)
	{
		obj = fz_array_get(dest, 4);
		if (fz_is_int(obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_r_valid;
			ld.ld.gotor.rb.x = fz_to_int(obj);
		}
		else if (fz_is_real(obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_r_valid;
			ld.ld.gotor.rb.x = fz_to_real(obj);
		}
	}

	/* Duplicate the values out for the sake of stupid clients */
	if ((ld.ld.gotor.flags & (fz_link_flag_l_valid | fz_link_flag_r_valid)) == fz_link_flag_l_valid)
		ld.ld.gotor.rb.x = ld.ld.gotor.lt.x;
	if ((ld.ld.gotor.flags & (fz_link_flag_l_valid | fz_link_flag_r_valid | fz_link_flag_r_is_zoom)) == fz_link_flag_r_valid)
		ld.ld.gotor.lt.x = ld.ld.gotor.rb.x;
	if ((ld.ld.gotor.flags & (fz_link_flag_t_valid | fz_link_flag_b_valid)) == fz_link_flag_t_valid)
		ld.ld.gotor.rb.y = ld.ld.gotor.lt.y;
	if ((ld.ld.gotor.flags & (fz_link_flag_t_valid | fz_link_flag_b_valid)) == fz_link_flag_b_valid)
		ld.ld.gotor.lt.y = ld.ld.gotor.rb.y;

	return ld;
}

fz_link_dest
pdf_parse_action(pdf_document *xref, fz_obj *action)
{
	fz_link_dest ld;
	fz_obj *obj, *dest;
	fz_context *ctx = xref->ctx;

	ld.kind = FZ_LINK_NONE;

	if (!action)
		return ld;

	obj = fz_dict_gets(action, "S");
	if (!strcmp(fz_to_name(obj), "GoTo"))
	{
		dest = fz_dict_gets(action, "D");
		ld = pdf_parse_link_dest(xref, dest);
	}
	else if (!strcmp(fz_to_name(obj), "URI"))
	{
		ld.kind = FZ_LINK_URI;
		ld.ld.uri.is_map = fz_to_bool(fz_dict_gets(action, "IsMap"));
		ld.ld.uri.uri = pdf_to_utf8(ctx, fz_dict_gets(action, "URI"));
	}
	else if (!strcmp(fz_to_name(obj), "Launch"))
	{
		ld.kind = FZ_LINK_LAUNCH;
		ld.ld.launch.file_spec = pdf_to_utf8(ctx, fz_dict_gets(action, "F"));
		ld.ld.launch.new_window = fz_to_int(fz_dict_gets(action, "NewWindow"));
	}
	else if (!strcmp(fz_to_name(obj), "Named"))
	{
		ld.kind = FZ_LINK_NAMED;
		ld.ld.named.named = pdf_to_utf8(ctx, fz_dict_gets(action, "N"));
	}
	else if (!strcmp(fz_to_name(obj), "GoToR"))
	{
		dest = fz_dict_gets(action, "D");
		ld = pdf_parse_link_dest(xref, dest);
		ld.kind = FZ_LINK_GOTOR;
		ld.ld.gotor.file_spec = pdf_to_utf8(ctx, fz_dict_gets(action, "F"));
		ld.ld.gotor.new_window = fz_to_int(fz_dict_gets(action, "NewWindow"));
	}
	return ld;
}

static fz_link *
pdf_load_link(pdf_document *xref, fz_obj *dict, fz_matrix page_ctm)
{
	fz_obj *dest = NULL;
	fz_obj *action;
	fz_obj *obj;
	fz_rect bbox;
	fz_context *ctx = xref->ctx;
	fz_link_dest ld;

	dest = NULL;

	obj = fz_dict_gets(dict, "Rect");
	if (obj)
		bbox = pdf_to_rect(ctx, obj);
	else
		bbox = fz_empty_rect;

	bbox = fz_transform_rect(page_ctm, bbox);

	obj = fz_dict_gets(dict, "Dest");
	if (obj)
	{
		dest = resolve_dest(xref, obj);
		ld = pdf_parse_link_dest(xref, dest);
	}
	else
	{
		action = fz_dict_gets(dict, "A");
		/* fall back to additional action button's down/up action */
		if (!action)
			action = fz_dict_getsa(fz_dict_gets(dict, "AA"), "U", "D");

		ld = pdf_parse_action(xref, action);
	}
	if (ld.kind == FZ_LINK_NONE)
		return NULL;
	return fz_new_link(ctx, bbox, ld);
}

fz_link *
pdf_load_link_annots(pdf_document *xref, fz_obj *annots, fz_matrix page_ctm)
{
	fz_link *link, *head, *tail;
	fz_obj *obj;
	int i, n;

	head = tail = NULL;
	link = NULL;

	n = fz_array_len(annots);
	for (i = 0; i < n; i++)
	{
		obj = fz_array_get(annots, i);
		link = pdf_load_link(xref, obj, page_ctm);
		if (link)
		{
			if (!head)
				head = tail = link;
			else
			{
				tail->next = link;
				tail = link;
			}
		}
	}

	return head;
}

void
pdf_free_annot(fz_context *ctx, pdf_annot *annot)
{
	pdf_annot *next;

	do
	{
		next = annot->next;
		if (annot->ap)
			pdf_drop_xobject(ctx, annot->ap);
		if (annot->obj)
			fz_drop_obj(annot->obj);
		fz_free(ctx, annot);
		annot = next;
	}
	while (annot);
}

static void
pdf_transform_annot(pdf_annot *annot)
{
	fz_matrix matrix = annot->ap->matrix;
	fz_rect bbox = annot->ap->bbox;
	fz_rect rect = annot->rect;
	float w, h, x, y;

	bbox = fz_transform_rect(matrix, bbox);
	if (bbox.x1 == bbox.x0)
		w = 0;
	else
		w = (rect.x1 - rect.x0) / (bbox.x1 - bbox.x0);
	if (bbox.y1 == bbox.y0)
		h = 0;
	else
		h = (rect.y1 - rect.y0) / (bbox.y1 - bbox.y0);
	x = rect.x0 - bbox.x0;
	y = rect.y0 - bbox.y0;

	annot->matrix = fz_concat(fz_scale(w, h), fz_translate(x, y));
}

pdf_annot *
pdf_load_annots(pdf_document *xref, fz_obj *annots)
{
	pdf_annot *annot, *head, *tail;
	fz_obj *obj, *ap, *as, *n, *rect;
	pdf_xobject *form;
	int i, len;
	fz_context *ctx = xref->ctx;

	head = tail = NULL;
	annot = NULL;

	len = fz_array_len(annots);
	for (i = 0; i < len; i++)
	{
		obj = fz_array_get(annots, i);

		rect = fz_dict_gets(obj, "Rect");
		ap = fz_dict_gets(obj, "AP");
		as = fz_dict_gets(obj, "AS");
		if (fz_is_dict(ap))
		{
			n = fz_dict_gets(ap, "N"); /* normal state */

			/* lookup current state in sub-dictionary */
			if (!pdf_is_stream(xref, fz_to_num(n), fz_to_gen(n)))
				n = fz_dict_get(n, as);

			if (pdf_is_stream(xref, fz_to_num(n), fz_to_gen(n)))
			{
				fz_try(ctx)
				{
					form = pdf_load_xobject(xref, n);
				}
				fz_catch(ctx)
				{
					fz_warn(ctx, "ignoring broken annotation");
					continue;
				}

				annot = fz_malloc_struct(ctx, pdf_annot);
				annot->obj = fz_keep_obj(obj);
				annot->rect = pdf_to_rect(ctx, rect);
				annot->ap = form;
				annot->next = NULL;

				pdf_transform_annot(annot);

				if (annot)
				{
					if (!head)
						head = tail = annot;
					else
					{
						tail->next = annot;
						tail = annot;
					}
				}
			}
		}
	}

	return head;
}
