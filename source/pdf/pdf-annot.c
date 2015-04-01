#include "mupdf/pdf.h"

static pdf_obj *
resolve_dest_rec(fz_context *ctx, pdf_document *doc, pdf_obj *dest, fz_link_kind kind, int depth)
{
	if (depth > 10) /* Arbitrary to avoid infinite recursion */
		return NULL;

	if (pdf_is_name(ctx, dest) || pdf_is_string(ctx, dest))
	{
		if (kind == FZ_LINK_GOTO)
		{
			dest = pdf_lookup_dest(ctx, doc, dest);
			dest = resolve_dest_rec(ctx, doc, dest, kind, depth+1);
		}

		return dest;
	}

	else if (pdf_is_array(ctx, dest))
	{
		return dest;
	}

	else if (pdf_is_dict(ctx, dest))
	{
		dest = pdf_dict_get(ctx, dest, PDF_NAME_D);
		return resolve_dest_rec(ctx, doc, dest, kind, depth+1);
	}

	else if (pdf_is_indirect(ctx, dest))
		return dest;

	return NULL;
}

static pdf_obj *
resolve_dest(fz_context *ctx, pdf_document *doc, pdf_obj *dest, fz_link_kind kind)
{
	return resolve_dest_rec(ctx, doc, dest, kind, 0);
}

fz_link_dest
pdf_parse_link_dest(fz_context *ctx, pdf_document *doc, fz_link_kind kind, pdf_obj *dest)
{
	fz_link_dest ld;
	pdf_obj *obj;

	int l_from_2 = 0;
	int b_from_3 = 0;
	int r_from_4 = 0;
	int t_from_5 = 0;
	int t_from_3 = 0;
	int t_from_2 = 0;
	int z_from_4 = 0;

	ld.kind = kind;
	ld.ld.gotor.flags = 0;
	ld.ld.gotor.lt.x = 0;
	ld.ld.gotor.lt.y = 0;
	ld.ld.gotor.rb.x = 0;
	ld.ld.gotor.rb.y = 0;
	ld.ld.gotor.page = -1;
	ld.ld.gotor.dest = NULL;

	dest = resolve_dest(ctx, doc, dest, kind);
	if (dest == NULL)
	{
		fz_warn(ctx, "undefined link destination");
		return ld;
	}

	if (pdf_is_name(ctx, dest))
	{
		ld.ld.gotor.dest = pdf_to_name(ctx, dest);
		return ld;
	}
	else if (pdf_is_string(ctx, dest))
	{
		ld.ld.gotor.dest = pdf_to_str_buf(ctx, dest);
		return ld;
	}

	obj = pdf_array_get(ctx, dest, 0);
	if (pdf_is_int(ctx, obj))
		ld.ld.gotor.page = pdf_to_int(ctx, obj);
	else
	{
		fz_try(ctx)
		{
			ld.ld.gotor.page = pdf_lookup_page_number(ctx, doc, obj);
		}
		fz_catch(ctx)
		{
			ld.kind = FZ_LINK_NONE;
			return ld;
		}
	}

	obj = pdf_array_get(ctx, dest, 1);
	if (!pdf_is_name(ctx, obj))
		return ld;

	if (pdf_name_eq(ctx, PDF_NAME_XYZ, obj))
	{
		l_from_2 = t_from_3 = z_from_4 = 1;
		ld.ld.gotor.flags |= fz_link_flag_r_is_zoom;
	}
	else if ((pdf_name_eq(ctx, PDF_NAME_Fit, obj)) || (pdf_name_eq(ctx, PDF_NAME_FitB, obj)))
	{
		ld.ld.gotor.flags |= fz_link_flag_fit_h;
		ld.ld.gotor.flags |= fz_link_flag_fit_v;
	}
	else if ((pdf_name_eq(ctx, PDF_NAME_FitH, obj)) || (pdf_name_eq(ctx, PDF_NAME_FitBH, obj)))
	{
		t_from_2 = 1;
		ld.ld.gotor.flags |= fz_link_flag_fit_h;
	}
	else if ((pdf_name_eq(ctx, PDF_NAME_FitV, obj)) || (pdf_name_eq(ctx, PDF_NAME_FitBV, obj)))
	{
		l_from_2 = 1;
		ld.ld.gotor.flags |= fz_link_flag_fit_v;
	}
	else if (pdf_name_eq(ctx, PDF_NAME_FitR, obj))
	{
		l_from_2 = b_from_3 = r_from_4 = t_from_5 = 1;
		ld.ld.gotor.flags |= fz_link_flag_fit_h;
		ld.ld.gotor.flags |= fz_link_flag_fit_v;
	}

	if (l_from_2)
	{
		obj = pdf_array_get(ctx, dest, 2);
		if (pdf_is_int(ctx, obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_l_valid;
			ld.ld.gotor.lt.x = pdf_to_int(ctx, obj);
		}
		else if (pdf_is_real(ctx, obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_l_valid;
			ld.ld.gotor.lt.x = pdf_to_real(ctx, obj);
		}
	}
	if (b_from_3)
	{
		obj = pdf_array_get(ctx, dest, 3);
		if (pdf_is_int(ctx, obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_b_valid;
			ld.ld.gotor.rb.y = pdf_to_int(ctx, obj);
		}
		else if (pdf_is_real(ctx, obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_b_valid;
			ld.ld.gotor.rb.y = pdf_to_real(ctx, obj);
		}
	}
	if (r_from_4)
	{
		obj = pdf_array_get(ctx, dest, 4);
		if (pdf_is_int(ctx, obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_r_valid;
			ld.ld.gotor.rb.x = pdf_to_int(ctx, obj);
		}
		else if (pdf_is_real(ctx, obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_r_valid;
			ld.ld.gotor.rb.x = pdf_to_real(ctx, obj);
		}
	}
	if (t_from_5 || t_from_3 || t_from_2)
	{
		if (t_from_5)
			obj = pdf_array_get(ctx, dest, 5);
		else if (t_from_3)
			obj = pdf_array_get(ctx, dest, 3);
		else
			obj = pdf_array_get(ctx, dest, 2);
		if (pdf_is_int(ctx, obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_t_valid;
			ld.ld.gotor.lt.y = pdf_to_int(ctx, obj);
		}
		else if (pdf_is_real(ctx, obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_t_valid;
			ld.ld.gotor.lt.y = pdf_to_real(ctx, obj);
		}
	}
	if (z_from_4)
	{
		obj = pdf_array_get(ctx, dest, 4);
		if (pdf_is_int(ctx, obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_r_valid;
			ld.ld.gotor.rb.x = pdf_to_int(ctx, obj);
		}
		else if (pdf_is_real(ctx, obj))
		{
			ld.ld.gotor.flags |= fz_link_flag_r_valid;
			ld.ld.gotor.rb.x = pdf_to_real(ctx, obj);
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

char *
pdf_parse_file_spec(fz_context *ctx, pdf_document *doc, pdf_obj *file_spec)
{
	pdf_obj *filename=NULL;
	char *path = NULL;

	if (pdf_is_string(ctx, file_spec))
		filename = file_spec;

	if (pdf_is_dict(ctx, file_spec)) {
#if defined(_WIN32) || defined(_WIN64)
		filename = pdf_dict_get(ctx, file_spec, PDF_NAME_DOS);
#else
		filename = pdf_dict_get(ctx, file_spec, PDF_NAME_Unix);
#endif
		if (!filename)
			filename = pdf_dict_geta(ctx, file_spec, PDF_NAME_UF, PDF_NAME_F);
	}

	if (!pdf_is_string(ctx, filename))
	{
		fz_warn(ctx, "cannot parse file specification");
		return NULL;
	}

	path = pdf_to_utf8(ctx, doc, filename);
#if defined(_WIN32) || defined(_WIN64)
	if (strcmp(pdf_to_name(ctx, pdf_dict_gets(ctx, file_spec, "FS")), "URL") != 0)
	{
		/* move the file name into the expected place and use the expected path separator */
		char *c;
		if (path[0] == '/' && (('A' <= path[1] && path[1] <= 'Z') || ('a' <= path[1] && path[1] <= 'z')) && path[2] == '/')
		{
			path[0] = path[1];
			path[1] = ':';
		}
		for (c = path; *c; c++)
		{
			if (*c == '/')
				*c = '\\';
		}
	}
#endif
	return path;
}

fz_link_dest
pdf_parse_action(fz_context *ctx, pdf_document *doc, pdf_obj *action)
{
	fz_link_dest ld;
	pdf_obj *obj, *dest, *file_spec;

	ld.kind = FZ_LINK_NONE;

	if (!action)
		return ld;

	obj = pdf_dict_get(ctx, action, PDF_NAME_S);
	if (pdf_name_eq(ctx, PDF_NAME_GoTo, obj))
	{
		dest = pdf_dict_get(ctx, action, PDF_NAME_D);
		ld = pdf_parse_link_dest(ctx, doc, FZ_LINK_GOTO, dest);
	}
	else if (pdf_name_eq(ctx, PDF_NAME_URI, obj))
	{
		ld.kind = FZ_LINK_URI;
		ld.ld.uri.is_map = pdf_to_bool(ctx, pdf_dict_get(ctx, action, PDF_NAME_IsMap));
		ld.ld.uri.uri = pdf_to_utf8(ctx, doc, pdf_dict_get(ctx, action, PDF_NAME_URI));
	}
	else if (pdf_name_eq(ctx, PDF_NAME_Launch, obj))
	{
		ld.kind = FZ_LINK_LAUNCH;
		file_spec = pdf_dict_get(ctx, action, PDF_NAME_F);
		ld.ld.launch.file_spec = pdf_parse_file_spec(ctx, doc, file_spec);
		ld.ld.launch.new_window = pdf_to_int(ctx, pdf_dict_get(ctx, action, PDF_NAME_NewWindow));
		ld.ld.launch.is_uri = pdf_name_eq(ctx, PDF_NAME_URL, pdf_dict_get(ctx, file_spec, PDF_NAME_FS));
	}
	else if (pdf_name_eq(ctx, PDF_NAME_Named, obj))
	{
		ld.kind = FZ_LINK_NAMED;
		ld.ld.named.named = fz_strdup(ctx, pdf_to_name(ctx, pdf_dict_get(ctx, action, PDF_NAME_N)));
	}
	else if (pdf_name_eq(ctx, PDF_NAME_GoToR, obj))
	{
		dest = pdf_dict_get(ctx, action, PDF_NAME_D);
		file_spec = pdf_dict_get(ctx, action, PDF_NAME_F);
		ld = pdf_parse_link_dest(ctx, doc, FZ_LINK_GOTOR, dest);
		ld.ld.gotor.file_spec = pdf_parse_file_spec(ctx, doc, file_spec);
		ld.ld.gotor.new_window = pdf_to_int(ctx, pdf_dict_get(ctx, action, PDF_NAME_NewWindow));
	}
	return ld;
}

static fz_link *
pdf_load_link(fz_context *ctx, pdf_document *doc, pdf_obj *dict, const fz_matrix *page_ctm)
{
	pdf_obj *action;
	pdf_obj *obj;
	fz_rect bbox;
	fz_link_dest ld;

	obj = pdf_dict_get(ctx, dict, PDF_NAME_Rect);
	if (obj)
		pdf_to_rect(ctx, obj, &bbox);
	else
		bbox = fz_empty_rect;

	fz_transform_rect(&bbox, page_ctm);

	obj = pdf_dict_get(ctx, dict, PDF_NAME_Dest);
	if (obj)
		ld = pdf_parse_link_dest(ctx, doc, FZ_LINK_GOTO, obj);
	else
	{
		action = pdf_dict_get(ctx, dict, PDF_NAME_A);
		/* fall back to additional action button's down/up action */
		if (!action)
			action = pdf_dict_geta(ctx, pdf_dict_get(ctx, dict, PDF_NAME_AA), PDF_NAME_U, PDF_NAME_D);

		ld = pdf_parse_action(ctx, doc, action);
	}
	if (ld.kind == FZ_LINK_NONE)
		return NULL;
	return fz_new_link(ctx, &bbox, ld);
}

fz_link *
pdf_load_link_annots(fz_context *ctx, pdf_document *doc, pdf_obj *annots, const fz_matrix *page_ctm)
{
	fz_link *link, *head, *tail;
	pdf_obj *obj;
	int i, n;

	head = tail = NULL;
	link = NULL;

	n = pdf_array_len(ctx, annots);
	for (i = 0; i < n; i++)
	{
		/* FIXME: Move the try/catch out of the loop for performance? */
		fz_try(ctx)
		{
			obj = pdf_array_get(ctx, annots, i);
			link = pdf_load_link(ctx, doc, obj, page_ctm);
		}
		fz_catch(ctx)
		{
			fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
			link = NULL;
		}

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
pdf_drop_annot(fz_context *ctx, pdf_annot *annot)
{
	pdf_annot *next;

	while (annot)
	{
		next = annot->next;
		if (annot->ap)
			pdf_drop_xobject(ctx, annot->ap);
		pdf_drop_obj(ctx, annot->obj);
		fz_free(ctx, annot);
		annot = next;
	}
}

void
pdf_transform_annot(fz_context *ctx, pdf_annot *annot)
{
	fz_rect bbox = annot->ap->bbox;
	fz_rect rect = annot->rect;
	float w, h, x, y;

	fz_transform_rect(&bbox, &annot->ap->matrix);
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

	fz_pre_scale(fz_translate(&annot->matrix, x, y), w, h);
}

fz_annot_type pdf_annot_obj_type(fz_context *ctx, pdf_obj *obj)
{
	pdf_obj *subtype = pdf_dict_get(ctx, obj, PDF_NAME_Subtype);
	if (pdf_name_eq(ctx, PDF_NAME_Text, subtype))
		return FZ_ANNOT_TEXT;
	else if (pdf_name_eq(ctx, PDF_NAME_Link, subtype))
		return FZ_ANNOT_LINK;
	else if (pdf_name_eq(ctx, PDF_NAME_FreeText, subtype))
		return FZ_ANNOT_FREETEXT;
	else if (pdf_name_eq(ctx, PDF_NAME_Line, subtype))
		return FZ_ANNOT_LINE;
	else if (pdf_name_eq(ctx, PDF_NAME_Square, subtype))
		return FZ_ANNOT_SQUARE;
	else if (pdf_name_eq(ctx, PDF_NAME_Circle, subtype))
		return FZ_ANNOT_CIRCLE;
	else if (pdf_name_eq(ctx, PDF_NAME_Polygon, subtype))
		return FZ_ANNOT_POLYGON;
	else if (pdf_name_eq(ctx, PDF_NAME_PolyLine, subtype))
		return FZ_ANNOT_POLYLINE;
	else if (pdf_name_eq(ctx, PDF_NAME_Highlight, subtype))
		return FZ_ANNOT_HIGHLIGHT;
	else if (pdf_name_eq(ctx, PDF_NAME_Underline, subtype))
		return FZ_ANNOT_UNDERLINE;
	else if (pdf_name_eq(ctx, PDF_NAME_Squiggly, subtype))
		return FZ_ANNOT_SQUIGGLY;
	else if (pdf_name_eq(ctx, PDF_NAME_StrikeOut, subtype))
		return FZ_ANNOT_STRIKEOUT;
	else if (pdf_name_eq(ctx, PDF_NAME_Stamp, subtype))
		return FZ_ANNOT_STAMP;
	else if (pdf_name_eq(ctx, PDF_NAME_Caret, subtype))
		return FZ_ANNOT_CARET;
	else if (pdf_name_eq(ctx, PDF_NAME_Ink, subtype))
		return FZ_ANNOT_INK;
	else if (pdf_name_eq(ctx, PDF_NAME_Popup, subtype))
		return FZ_ANNOT_POPUP;
	else if (pdf_name_eq(ctx, PDF_NAME_FileAttachment, subtype))
		return FZ_ANNOT_FILEATTACHMENT;
	else if (pdf_name_eq(ctx, PDF_NAME_Sound, subtype))
		return FZ_ANNOT_SOUND;
	else if (pdf_name_eq(ctx, PDF_NAME_Movie, subtype))
		return FZ_ANNOT_MOVIE;
	else if (pdf_name_eq(ctx, PDF_NAME_Widget, subtype))
		return FZ_ANNOT_WIDGET;
	else if (pdf_name_eq(ctx, PDF_NAME_Screen, subtype))
		return FZ_ANNOT_SCREEN;
	else if (pdf_name_eq(ctx, PDF_NAME_PrinterMark, subtype))
		return FZ_ANNOT_PRINTERMARK;
	else if (pdf_name_eq(ctx, PDF_NAME_TrapNet, subtype))
		return FZ_ANNOT_TRAPNET;
	else if (pdf_name_eq(ctx, PDF_NAME_Watermark, subtype))
		return FZ_ANNOT_WATERMARK;
	else if (pdf_name_eq(ctx, PDF_NAME_3D, subtype))
		return FZ_ANNOT_3D;
	else
		return -1;
}

void
pdf_load_annots(fz_context *ctx, pdf_document *doc, pdf_page *page, pdf_obj *annots)
{
	pdf_annot *annot, **itr;
	pdf_obj *obj, *ap, *as, *n, *rect;
	int i, len, keep_annot;

	fz_var(annot);
	fz_var(itr);
	fz_var(keep_annot);

	itr = &page->annots;

	len = pdf_array_len(ctx, annots);
	/*
	Create an initial linked list of pdf_annot structures with only the obj field
	filled in. We do this because update_appearance has the potential to change
	the annot array, so we don't want to be iterating through the array while
	that happens.
	*/
	fz_try(ctx)
	{
		for (i = 0; i < len; i++)
		{
			obj = pdf_array_get(ctx, annots, i);
			annot = fz_malloc_struct(ctx, pdf_annot);
			annot->obj = pdf_keep_obj(ctx, obj);
			annot->page = page;
			annot->next = NULL;

			*itr = annot;
			itr = &annot->next;
		}
	}
	fz_catch(ctx)
	{
		pdf_drop_annot(ctx, page->annots);
		page->annots = NULL;
		fz_rethrow(ctx);
	}

	/*
	Iterate through the newly created annot linked list, using a double pointer to
	facilitate deleting broken annotations.
	*/
	itr = &page->annots;
	while (*itr)
	{
		annot = *itr;

		fz_try(ctx)
		{
			pdf_hotspot *hp = &doc->hotspot;

			n = NULL;

			if (doc->update_appearance)
				doc->update_appearance(ctx, doc, annot);

			obj = annot->obj;
			rect = pdf_dict_get(ctx, obj, PDF_NAME_Rect);
			ap = pdf_dict_get(ctx, obj, PDF_NAME_AP);
			as = pdf_dict_get(ctx, obj, PDF_NAME_AS);

			/* We only collect annotations with an appearance
			 * stream into this list, so remove any that don't
			 * (such as links) and continue. */
			keep_annot = pdf_is_dict(ctx, ap);
			if (!keep_annot)
				break;

			if (hp->num == pdf_to_num(ctx, obj)
				&& hp->gen == pdf_to_gen(ctx, obj)
				&& (hp->state & HOTSPOT_POINTER_DOWN))
			{
				n = pdf_dict_get(ctx, ap, PDF_NAME_D); /* down state */
			}

			if (n == NULL)
				n = pdf_dict_get(ctx, ap, PDF_NAME_N); /* normal state */

			/* lookup current state in sub-dictionary */
			if (!pdf_is_stream(ctx, doc, pdf_to_num(ctx, n), pdf_to_gen(ctx, n)))
				n = pdf_dict_get(ctx, n, as);

			pdf_to_rect(ctx, rect, &annot->rect);
			annot->pagerect = annot->rect;
			fz_transform_rect(&annot->pagerect, &page->ctm);
			annot->ap = NULL;
			annot->annot_type = pdf_annot_obj_type(ctx, obj);
			annot->widget_type = annot->annot_type == FZ_ANNOT_WIDGET ? pdf_field_type(ctx, doc, obj) : PDF_WIDGET_TYPE_NOT_WIDGET;

			if (pdf_is_stream(ctx, doc, pdf_to_num(ctx, n), pdf_to_gen(ctx, n)))
			{
				annot->ap = pdf_load_xobject(ctx, doc, n);
				pdf_transform_annot(ctx, annot);
				annot->ap_iteration = annot->ap->iteration;
			}

			if (obj == doc->focus_obj)
				doc->focus = annot;

			/* Move to next item in the linked list */
			itr = &annot->next;
		}
		fz_catch(ctx)
		{
			if (fz_caught(ctx) == FZ_ERROR_TRYLATER)
			{
				pdf_drop_annot(ctx, page->annots);
				page->annots = NULL;
				fz_rethrow(ctx);
			}
			keep_annot = 0;
			fz_warn(ctx, "ignoring broken annotation");
		}
		if (!keep_annot)
		{
			/* Move to next item in the linked list, dropping this one */
			*itr = annot->next;
			annot->next = NULL; /* Required because pdf_drop_annot follows the "next" chain */
			pdf_drop_annot(ctx, annot);
		}
	}

	page->annot_tailp = itr;
}

pdf_annot *
pdf_first_annot(fz_context *ctx, pdf_page *page)
{
	return page ? page->annots : NULL;
}

pdf_annot *
pdf_next_annot(fz_context *ctx, pdf_page *page, pdf_annot *annot)
{
	return annot ? annot->next : NULL;
}

fz_rect *
pdf_bound_annot(fz_context *ctx, pdf_page *page, pdf_annot *annot, fz_rect *rect)
{
	if (rect == NULL)
		return NULL;

	if (annot)
		*rect = annot->pagerect;
	else
		*rect = fz_empty_rect;
	return rect;
}

fz_annot_type
pdf_annot_type(fz_context *ctx, pdf_annot *annot)
{
	return annot->annot_type;
}
