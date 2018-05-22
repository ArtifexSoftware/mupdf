#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>

#ifdef _WIN32
#define timegm _mkgmtime
#endif


static void
pdf_drop_annot_imp(fz_context *ctx, pdf_annot *annot)
{
	pdf_drop_obj(ctx, annot->ap);
	pdf_drop_obj(ctx, annot->obj);
}

void
pdf_drop_annots(fz_context *ctx, pdf_annot *annot)
{
	while (annot)
	{
		pdf_annot *next = annot->next;
		fz_drop_annot(ctx, &annot->super);
		annot = next;
	}
}

/* Create transform to fit appearance stream to annotation Rect */
void
pdf_annot_transform(fz_context *ctx, pdf_annot *annot, fz_matrix *annot_ctm)
{
	fz_rect bbox, rect;
	fz_matrix matrix;
	float w, h, x, y;

	pdf_to_rect(ctx, pdf_dict_get(ctx, annot->obj, PDF_NAME(Rect)), &rect);
	pdf_xobject_bbox(ctx, annot->ap, &bbox);
	pdf_xobject_matrix(ctx, annot->ap, &matrix);

	fz_transform_rect(&bbox, &matrix);
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

	fz_pre_scale(fz_translate(annot_ctm, x, y), w, h);
}

pdf_annot *pdf_new_annot(fz_context *ctx, pdf_page *page, pdf_obj *obj)
{
	pdf_annot *annot;

	annot = fz_new_derived_annot(ctx, pdf_annot);

	annot->super.drop_annot = (fz_annot_drop_fn*)pdf_drop_annot_imp;
	annot->super.bound_annot = (fz_annot_bound_fn*)pdf_bound_annot;
	annot->super.run_annot = (fz_annot_run_fn*)pdf_run_annot;
	annot->super.next_annot = (fz_annot_next_fn*)pdf_next_annot;

	annot->page = page; /* only borrowed, as the page owns the annot */
	annot->obj = pdf_keep_obj(ctx, obj);

	return annot;
}

void
pdf_load_annots(fz_context *ctx, pdf_page *page, pdf_obj *annots)
{
	pdf_document *doc = page->doc;
	pdf_annot *annot;
	pdf_obj *subtype;
	int i, n;

	n = pdf_array_len(ctx, annots);
	for (i = 0; i < n; ++i)
	{
		pdf_obj *obj = pdf_array_get(ctx, annots, i);
		if (obj)
		{
			subtype = pdf_dict_get(ctx, obj, PDF_NAME(Subtype));
			if (pdf_name_eq(ctx, subtype, PDF_NAME(Link)))
				continue;
			if (pdf_name_eq(ctx, subtype, PDF_NAME(Popup)))
				continue;

			annot = pdf_new_annot(ctx, page, obj);
			fz_try(ctx)
			{
				pdf_update_annot(ctx, annot);
				annot->has_new_ap = 0;
			}
			fz_catch(ctx)
				fz_warn(ctx, "could not update appearance for annotation");

			if (doc->focus_obj == obj)
				doc->focus = annot;

			*page->annot_tailp = annot;
			page->annot_tailp = &annot->next;
		}
	}
}

pdf_annot *
pdf_first_annot(fz_context *ctx, pdf_page *page)
{
	return page ? page->annots : NULL;
}

pdf_annot *
pdf_next_annot(fz_context *ctx, pdf_annot *annot)
{
	return annot ? annot->next : NULL;
}

fz_rect *
pdf_bound_annot(fz_context *ctx, pdf_annot *annot, fz_rect *rect)
{
	pdf_obj *obj = pdf_dict_get(ctx, annot->obj, PDF_NAME(Rect));
	fz_rect mediabox;
	fz_matrix page_ctm;
	pdf_to_rect(ctx, obj, rect);
	pdf_page_transform(ctx, annot->page, &mediabox, &page_ctm);
	fz_transform_rect(rect, &page_ctm);
	return rect;
}

void
pdf_dirty_annot(fz_context *ctx, pdf_annot *annot)
{
	annot->needs_new_ap = 1;
	if (annot->page && annot->page->doc)
		annot->page->doc->dirty = 1;
}
