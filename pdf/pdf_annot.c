#include "fitz.h"
#include "mupdf.h"

void
pdf_free_link(fz_context *ctx, pdf_link *link)
{
	pdf_link *next;

	do
	{
		next = link->next;
		if (link->dest)
			fz_drop_obj(ctx, link->dest);
		fz_free(ctx, link);
		link = next;
	}
	while(link != NULL);
}

static fz_obj *
resolve_dest(pdf_xref *xref, fz_obj *dest)
{
	if (fz_is_name(xref->ctx, dest) || fz_is_string(xref->ctx, dest))
	{
		dest = pdf_lookup_dest(xref, dest);
		return resolve_dest(xref, dest);
	}

	else if (fz_is_array(xref->ctx, dest))
	{
		return dest;
	}

	else if (fz_is_dict(xref->ctx, dest))
	{
		dest = fz_dict_gets(xref->ctx, dest, "D");
		return resolve_dest(xref, dest);
	}

	else if (fz_is_indirect(dest))
		return dest;

	return NULL;
}

pdf_link *
pdf_load_link(pdf_xref *xref, fz_obj *dict)
{
	fz_obj *dest;
	fz_obj *action;
	fz_obj *obj;
	fz_rect bbox;
	pdf_link_kind kind;
	fz_context *ctx = xref->ctx;

	dest = NULL;

	obj = fz_dict_gets(ctx, dict, "Rect");
	if (obj)
		bbox = pdf_to_rect(ctx, obj);
	else
		bbox = fz_empty_rect;

	obj = fz_dict_gets(ctx, dict, "Dest");
	if (obj)
	{
		kind = PDF_LINK_GOTO;
		dest = resolve_dest(xref, obj);
	}

	action = fz_dict_gets(ctx, dict, "A");

	/* fall back to additional action button's down/up action */
	if (!action)
		action = fz_dict_getsa(ctx, fz_dict_gets(ctx, dict, "AA"), "U", "D");

	if (action)
	{
		obj = fz_dict_gets(ctx, action, "S");
		if (fz_is_name(ctx, obj) && !strcmp(fz_to_name(ctx, obj), "GoTo"))
		{
			kind = PDF_LINK_GOTO;
			dest = resolve_dest(xref, fz_dict_gets(ctx, action, "D"));
		}
		else if (fz_is_name(ctx, obj) && !strcmp(fz_to_name(ctx, obj), "URI"))
		{
			kind = PDF_LINK_URI;
			dest = fz_dict_gets(ctx, action, "URI");
		}
		else if (fz_is_name(ctx, obj) && !strcmp(fz_to_name(ctx, obj), "Launch"))
		{
			kind = PDF_LINK_LAUNCH;
			dest = fz_dict_gets(ctx, action, "F");
		}
		else if (fz_is_name(ctx, obj) && !strcmp(fz_to_name(ctx, obj), "Named"))
		{
			kind = PDF_LINK_NAMED;
			dest = fz_dict_gets(ctx, action, "N");
		}
		else if (fz_is_name(ctx, obj) && (!strcmp(fz_to_name(ctx, obj), "GoToR")))
		{
			kind = PDF_LINK_ACTION;
			dest = action;
		}
		else
		{
			dest = NULL;
		}
	}

	if (dest)
	{
		pdf_link *link = fz_malloc(ctx, sizeof(pdf_link));
		link->kind = kind;
		link->rect = bbox;
		link->dest = fz_keep_obj(dest);
		link->next = NULL;
		return link;
	}

	return NULL;
}

void
pdf_load_links(pdf_link **linkp, pdf_xref *xref, fz_obj *annots)
{
	pdf_link *link, *head, *tail;
	fz_obj *obj;
	int i, n;
	fz_context *ctx = xref->ctx;

	head = tail = NULL;
	link = NULL;

	n = fz_array_len(ctx, annots);
	for (i = 0; i < n; i++)
	{
		obj = fz_array_get(ctx, annots, i);
		link = pdf_load_link(xref, obj);
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

	*linkp = head;
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
			fz_drop_obj(ctx, annot->obj);
		fz_free(ctx, annot);
		annot = next;
	}
	while (annot != NULL);
}

static void
pdf_transform_annot(pdf_annot *annot)
{
	fz_matrix matrix = annot->ap->matrix;
	fz_rect bbox = annot->ap->bbox;
	fz_rect rect = annot->rect;
	float w, h, x, y;

	bbox = fz_transform_rect(matrix, bbox);
	w = (rect.x1 - rect.x0) / (bbox.x1 - bbox.x0);
	h = (rect.y1 - rect.y0) / (bbox.y1 - bbox.y0);
	x = rect.x0 - bbox.x0;
	y = rect.y0 - bbox.y0;

	annot->matrix = fz_concat(fz_scale(w, h), fz_translate(x, y));
}

void
pdf_load_annots(pdf_annot **annotp, pdf_xref *xref, fz_obj *annots)
{
	pdf_annot *annot, *head, *tail;
	fz_obj *obj, *ap, *as, *n, *rect;
	pdf_xobject *form;
	fz_error error;
	int i, len;
	fz_context *ctx = xref->ctx;

	head = tail = NULL;
	annot = NULL;

	len = fz_array_len(ctx, annots);
	for (i = 0; i < len; i++)
	{
		obj = fz_array_get(ctx, annots, i);

		rect = fz_dict_gets(ctx, obj, "Rect");
		ap = fz_dict_gets(ctx, obj, "AP");
		as = fz_dict_gets(ctx, obj, "AS");
		if (fz_is_dict(ctx, ap))
		{
			n = fz_dict_gets(ctx, ap, "N"); /* normal state */

			/* lookup current state in sub-dictionary */
			if (!pdf_is_stream(xref, fz_to_num(n), fz_to_gen(n)))
				n = fz_dict_get(ctx, n, as);

			if (pdf_is_stream(xref, fz_to_num(n), fz_to_gen(n)))
			{
				error = pdf_load_xobject(&form, xref, n);
				if (error)
				{
					fz_error_handle(error, "ignoring broken annotation");
					continue;
				}

				annot = fz_malloc(ctx, sizeof(pdf_annot));
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

	*annotp = head;
}
