#include "mupdf/pdf.h"

#define TEXT_ANNOT_SIZE (25.0)

static const char *annot_type_str(fz_annot_type type)
{
	switch (type)
	{
	case FZ_ANNOT_TEXT: return "Text";
	case FZ_ANNOT_LINK: return "Link";
	case FZ_ANNOT_FREETEXT: return "FreeText";
	case FZ_ANNOT_LINE: return "Line";
	case FZ_ANNOT_SQUARE: return "Square";
	case FZ_ANNOT_CIRCLE: return "Circle";
	case FZ_ANNOT_POLYGON: return "Polygon";
	case FZ_ANNOT_POLYLINE: return "PolyLine";
	case FZ_ANNOT_HIGHLIGHT: return "Highlight";
	case FZ_ANNOT_UNDERLINE: return "Underline";
	case FZ_ANNOT_SQUIGGLY: return "Squiggly";
	case FZ_ANNOT_STRIKEOUT: return "StrikeOut";
	case FZ_ANNOT_STAMP: return "Stamp";
	case FZ_ANNOT_CARET: return "Caret";
	case FZ_ANNOT_INK: return "Ink";
	case FZ_ANNOT_POPUP: return "Popup";
	case FZ_ANNOT_FILEATTACHMENT: return "FileAttachment";
	case FZ_ANNOT_SOUND: return "Sound";
	case FZ_ANNOT_MOVIE: return "Movie";
	case FZ_ANNOT_WIDGET: return "Widget";
	case FZ_ANNOT_SCREEN: return "Screen";
	case FZ_ANNOT_PRINTERMARK: return "PrinterMark";
	case FZ_ANNOT_TRAPNET: return "TrapNet";
	case FZ_ANNOT_WATERMARK: return "Watermark";
	case FZ_ANNOT_3D: return "3D";
	default: return "";
	}
}

void
pdf_update_annot(fz_context *ctx, pdf_document *doc, pdf_annot *annot)
{
	pdf_obj *obj, *ap, *as, *n;

	if (doc->update_appearance)
		doc->update_appearance(ctx, doc, annot);

	obj = annot->obj;

	ap = pdf_dict_get(ctx, obj, PDF_NAME_AP);
	as = pdf_dict_get(ctx, obj, PDF_NAME_AS);

	if (pdf_is_dict(ctx, ap))
	{
		pdf_hotspot *hp = &doc->hotspot;

		n = NULL;

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

		pdf_drop_xobject(ctx, annot->ap);
		annot->ap = NULL;

		if (pdf_is_stream(ctx, doc, pdf_to_num(ctx, n), pdf_to_gen(ctx, n)))
		{
			fz_try(ctx)
			{
				annot->ap = pdf_load_xobject(ctx, doc, n);
				pdf_transform_annot(ctx, annot);
				annot->ap_iteration = annot->ap->iteration;
			}
			fz_catch(ctx)
			{
				fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
				fz_warn(ctx, "ignoring broken annotation");
			}
		}
	}
}

pdf_annot *
pdf_create_annot(fz_context *ctx, pdf_document *doc, pdf_page *page, fz_annot_type type)
{
	pdf_annot *annot = NULL;
	pdf_obj *annot_obj = pdf_new_dict(ctx, doc, 0);
	pdf_obj *ind_obj = NULL;

	fz_var(annot);
	fz_var(ind_obj);
	fz_try(ctx)
	{
		int ind_obj_num;
		fz_rect rect = {0.0, 0.0, 0.0, 0.0};
		const char *type_str = annot_type_str(type);
		pdf_obj *annot_arr = pdf_dict_get(ctx, page->me, PDF_NAME_Annots);
		if (annot_arr == NULL)
		{
			annot_arr = pdf_new_array(ctx, doc, 0);
			pdf_dict_put_drop(ctx, page->me, PDF_NAME_Annots, annot_arr);
		}

		pdf_dict_put_drop(ctx, annot_obj, PDF_NAME_Type, PDF_NAME_Annot);

		pdf_dict_put_drop(ctx, annot_obj, PDF_NAME_Subtype, pdf_new_name(ctx, doc, type_str));
		pdf_dict_put_drop(ctx, annot_obj, PDF_NAME_Rect, pdf_new_rect(ctx, doc, &rect));

		/* Make printable as default */
		pdf_dict_put_drop(ctx, annot_obj, PDF_NAME_F, pdf_new_int(ctx, doc, F_Print));

		annot = fz_malloc_struct(ctx, pdf_annot);
		annot->page = page;
		annot->rect = rect;
		annot->pagerect = rect;
		annot->ap = NULL;
		annot->widget_type = PDF_WIDGET_TYPE_NOT_WIDGET;
		annot->annot_type = type;

		/*
			Both annotation object and annotation structure are now created.
			Insert the object in the hierarchy and the structure in the
			page's array.
		*/
		ind_obj_num = pdf_create_object(ctx, doc);
		pdf_update_object(ctx, doc, ind_obj_num, annot_obj);
		ind_obj = pdf_new_indirect(ctx, doc, ind_obj_num, 0);
		pdf_array_push(ctx, annot_arr, ind_obj);
		annot->obj = pdf_keep_obj(ctx, ind_obj);

		/*
			Linking must be done after any call that might throw because
			pdf_drop_annot below actually frees a list. Put the new annot
			at the end of the list, so that it will be drawn last.
		*/
		*page->annot_tailp = annot;
		page->annot_tailp = &annot->next;

		doc->dirty = 1;
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, annot_obj);
		pdf_drop_obj(ctx, ind_obj);
	}
	fz_catch(ctx)
	{
		pdf_drop_annot(ctx, annot);
		fz_rethrow(ctx);
	}

	return annot;
}

void
pdf_delete_annot(fz_context *ctx, pdf_document *doc, pdf_page *page, pdf_annot *annot)
{
	pdf_annot **annotptr;
	pdf_obj *old_annot_arr;
	pdf_obj *annot_arr;

	if (annot == NULL)
		return;

	/* Remove annot from page's list */
	for (annotptr = &page->annots; *annotptr; annotptr = &(*annotptr)->next)
	{
		if (*annotptr == annot)
			break;
	}

	/* Check the passed annotation was of this page */
	if (*annotptr == NULL)
		return;

	*annotptr = annot->next;
	/* If the removed annotation was the last in the list adjust the end pointer */
	if (*annotptr == NULL)
		page->annot_tailp = annotptr;

	/* Stick it in the deleted list */
	annot->next = page->deleted_annots;
	page->deleted_annots = annot;

	pdf_drop_xobject(ctx, annot->ap);
	annot->ap = NULL;

	/* Recreate the "Annots" array with this annot removed */
	old_annot_arr = pdf_dict_get(ctx, page->me, PDF_NAME_Annots);

	if (old_annot_arr)
	{
		int i, n = pdf_array_len(ctx, old_annot_arr);
		annot_arr = pdf_new_array(ctx, doc, n?(n-1):0);

		fz_try(ctx)
		{
			for (i = 0; i < n; i++)
			{
				pdf_obj *obj = pdf_array_get(ctx, old_annot_arr, i);

				if (obj != annot->obj)
					pdf_array_push(ctx, annot_arr, obj);
			}

			if (pdf_is_indirect(ctx, old_annot_arr))
				pdf_update_object(ctx, doc, pdf_to_num(ctx, old_annot_arr), annot_arr);
			else
				pdf_dict_put(ctx, page->me, PDF_NAME_Annots, annot_arr);

			if (pdf_is_indirect(ctx, annot->obj))
				pdf_delete_object(ctx, doc, pdf_to_num(ctx, annot->obj));
		}
		fz_always(ctx)
		{
			pdf_drop_obj(ctx, annot_arr);
		}
		fz_catch(ctx)
		{
			fz_rethrow(ctx);
		}
	}

	pdf_drop_obj(ctx, annot->obj);
	annot->obj = NULL;
	doc->dirty = 1;
}

void
pdf_set_markup_annot_quadpoints(fz_context *ctx, pdf_document *doc, pdf_annot *annot, fz_point *qp, int n)
{
	fz_matrix ctm;
	pdf_obj *arr = pdf_new_array(ctx, doc, n*2);
	int i;

	fz_invert_matrix(&ctm, &annot->page->ctm);

	pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_QuadPoints, arr);

	for (i = 0; i < n; i++)
	{
		fz_point pt = qp[i];
		pdf_obj *r;

		fz_transform_point(&pt, &ctm);
		r = pdf_new_real(ctx, doc, pt.x);
		pdf_array_push_drop(ctx, arr, r);
		r = pdf_new_real(ctx, doc, pt.y);
		pdf_array_push_drop(ctx, arr, r);
	}
}

static void update_rect(fz_context *ctx, pdf_annot *annot)
{
	pdf_to_rect(ctx, pdf_dict_get(ctx, annot->obj, PDF_NAME_Rect), &annot->rect);
	annot->pagerect = annot->rect;
	fz_transform_rect(&annot->pagerect, &annot->page->ctm);
}

void
pdf_set_ink_annot_list(fz_context *ctx, pdf_document *doc, pdf_annot *annot, fz_point *pts, int *counts, int ncount, float color[3], float thickness)
{
	fz_matrix ctm;
	pdf_obj *list = pdf_new_array(ctx, doc, ncount);
	pdf_obj *bs, *col;
	fz_rect rect;
	int i, k = 0;

	fz_invert_matrix(&ctm, &annot->page->ctm);

	pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_InkList, list);

	for (i = 0; i < ncount; i++)
	{
		int j;
		pdf_obj *arc = pdf_new_array(ctx, doc, counts[i]);

		pdf_array_push_drop(ctx, list, arc);

		for (j = 0; j < counts[i]; j++)
		{
			fz_point pt = pts[k];

			fz_transform_point(&pt, &ctm);

			if (i == 0 && j == 0)
			{
				rect.x0 = rect.x1 = pt.x;
				rect.y0 = rect.y1 = pt.y;
			}
			else
			{
				fz_include_point_in_rect(&rect, &pt);
			}

			pdf_array_push_drop(ctx, arc, pdf_new_real(ctx, doc, pt.x));
			pdf_array_push_drop(ctx, arc, pdf_new_real(ctx, doc, pt.y));
			k++;
		}
	}

	/*
		Expand the rectangle by thickness all around. We cannot use
		fz_expand_rect because the rectangle might be empty in the
		single point case
	*/
	if (k > 0)
	{
		rect.x0 -= thickness;
		rect.y0 -= thickness;
		rect.x1 += thickness;
		rect.y1 += thickness;
	}

	pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_Rect, pdf_new_rect(ctx, doc, &rect));
	update_rect(ctx, annot);

	bs = pdf_new_dict(ctx, doc, 1);
	pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_BS, bs);
	pdf_dict_put_drop(ctx, bs, PDF_NAME_W, pdf_new_real(ctx, doc, thickness));

	col = pdf_new_array(ctx, doc, 3);
	pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_C, col);
	for (i = 0; i < 3; i++)
		pdf_array_push_drop(ctx, col, pdf_new_real(ctx, doc, color[i]));
}

static void find_free_font_name(fz_context *ctx, pdf_obj *fdict, char *buf, int buf_size)
{
	int i;

	/* Find a number X such that /FX doesn't occur as a key in fdict */
	for (i = 0; 1; i++)
	{
		snprintf(buf, buf_size, "F%d", i);

		if (!pdf_dict_gets(ctx, fdict, buf))
			break;
	}
}

void pdf_set_text_annot_position(fz_context *ctx, pdf_document *doc, pdf_annot *annot, fz_point pt)
{
	fz_matrix ctm;
	fz_rect rect;
	int flags;

	fz_invert_matrix(&ctm, &annot->page->ctm);
	rect.x0 = pt.x;
	rect.x1 = pt.x + TEXT_ANNOT_SIZE;
	rect.y0 = pt.y;
	rect.y1 = pt.y + TEXT_ANNOT_SIZE;
	fz_transform_rect(&rect, &ctm);

	pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_Rect, pdf_new_rect(ctx, doc, &rect));

	flags = pdf_to_int(ctx, pdf_dict_get(ctx, annot->obj, PDF_NAME_F));
	flags |= (F_NoZoom|F_NoRotate);
	pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_F, pdf_new_int(ctx, doc, flags));

	update_rect(ctx, annot);
}

void pdf_set_annot_contents(fz_context *ctx, pdf_document *doc, pdf_annot *annot, char *text)
{
	pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_Contents, pdf_new_string(ctx, doc, text, strlen(text)));
}

char *pdf_annot_contents(fz_context *ctx, pdf_document *doc, pdf_annot *annot)
{
	return pdf_to_str_buf(ctx, pdf_dict_get(ctx, annot->obj, PDF_NAME_Contents));
}

void pdf_set_free_text_details(fz_context *ctx, pdf_document *doc, pdf_annot *annot, fz_point *pos, char *text, char *font_name, float font_size, float color[3])
{
	char nbuf[32];
	pdf_obj *dr;
	pdf_obj *form_fonts;
	pdf_obj *font = NULL;
	pdf_obj *ref;
	pdf_font_desc *font_desc = NULL;
	pdf_da_info da_info;
	fz_buffer *fzbuf = NULL;
	fz_matrix ctm;
	fz_point page_pos;

	fz_invert_matrix(&ctm, &annot->page->ctm);

	dr = pdf_dict_get(ctx, annot->page->me, PDF_NAME_Resources);
	if (!dr)
	{
		dr = pdf_new_dict(ctx, doc, 1);
		pdf_dict_put_drop(ctx, annot->page->me, PDF_NAME_Resources, dr);
	}

	/* Ensure the resource dictionary includes a font dict */
	form_fonts = pdf_dict_get(ctx, dr, PDF_NAME_Font);
	if (!form_fonts)
	{
		form_fonts = pdf_new_dict(ctx, doc, 1);
		pdf_dict_put_drop(ctx, dr, PDF_NAME_Font, form_fonts);
		/* form_fonts is still valid if execution continues past the above call */
	}

	fz_var(fzbuf);
	fz_var(font);
	fz_try(ctx)
	{
		unsigned char *da_str;
		int da_len;
		fz_rect bounds;

		find_free_font_name(ctx, form_fonts, nbuf, sizeof(nbuf));

		font = pdf_new_dict(ctx, doc, 5);
		ref = pdf_new_ref(ctx, doc, font);
		pdf_dict_puts_drop(ctx, form_fonts, nbuf, ref);

		pdf_dict_put_drop(ctx, font, PDF_NAME_Type, PDF_NAME_Font);
		pdf_dict_put_drop(ctx, font, PDF_NAME_Subtype, PDF_NAME_Type1);
		pdf_dict_put_drop(ctx, font, PDF_NAME_BaseFont, pdf_new_name(ctx, doc, font_name));
		pdf_dict_put_drop(ctx, font, PDF_NAME_Encoding, PDF_NAME_WinAnsiEncoding);

		memcpy(da_info.col, color, sizeof(float)*3);
		da_info.col_size = 3;
		da_info.font_name = nbuf;
		da_info.font_size = font_size;

		fzbuf = fz_new_buffer(ctx, 0);
		pdf_fzbuf_print_da(ctx, fzbuf, &da_info);

		da_len = fz_buffer_storage(ctx, fzbuf, &da_str);
		pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_DA, pdf_new_string(ctx, doc, (char *)da_str, da_len));

		/* FIXME: should convert to WinAnsiEncoding */
		pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_Contents, pdf_new_string(ctx, doc, text, strlen(text)));

		font_desc = pdf_load_font(ctx, doc, NULL, font, 0);
		pdf_measure_text(ctx, font_desc, (unsigned char *)text, strlen(text), &bounds);

		page_pos = *pos;
		fz_transform_point(&page_pos, &ctm);

		bounds.x0 *= font_size;
		bounds.x1 *= font_size;
		bounds.y0 *= font_size;
		bounds.y1 *= font_size;

		bounds.x0 += page_pos.x;
		bounds.x1 += page_pos.x;
		bounds.y0 += page_pos.y;
		bounds.y1 += page_pos.y;

		pdf_dict_put_drop(ctx, annot->obj, PDF_NAME_Rect, pdf_new_rect(ctx, doc, &bounds));
		update_rect(ctx, annot);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, font);
		fz_drop_buffer(ctx, fzbuf);
		pdf_drop_font(ctx, font_desc);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}
