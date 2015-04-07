#include "mupdf/pdf.h"

static void
pdf_run_annot_with_usage(fz_context *ctx, pdf_document *doc, pdf_page *page, pdf_annot *annot, fz_device *dev, const fz_matrix *ctm, char *event, fz_cookie *cookie)
{
	fz_matrix local_ctm;
	pdf_processor *proc;

	fz_concat(&local_ctm, &page->ctm, ctm);

	proc = pdf_new_run_processor(ctx, dev, &local_ctm, event, NULL, 0);
	fz_try(ctx)
		pdf_process_annot(ctx, proc, doc, page, annot, cookie);
	fz_always(ctx)
		pdf_drop_processor(ctx, proc);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void pdf_run_page_contents_with_usage(fz_context *ctx, pdf_document *doc, pdf_page *page, fz_device *dev, const fz_matrix *ctm, char *event, fz_cookie *cookie)
{
	fz_matrix local_ctm;
	pdf_processor *proc;

	fz_concat(&local_ctm, &page->ctm, ctm);

	if (page->transparency)
	{
		fz_rect mediabox = page->mediabox;
		fz_begin_group(ctx, dev, fz_transform_rect(&mediabox, &local_ctm), 1, 0, 0, 1);
	}

	proc = pdf_new_run_processor(ctx, dev, &local_ctm, event, NULL, 0);

	fz_try(ctx)
		pdf_process_contents(ctx, proc, doc, page->resources, page->contents, cookie);
	fz_always(ctx)
		pdf_drop_processor(ctx, proc);
	fz_catch(ctx)
		fz_rethrow(ctx);

	if (page->transparency)
		fz_end_group(ctx, dev);
}

void pdf_run_page_contents(fz_context *ctx, pdf_page *page, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	pdf_document *doc = page->doc;
	int nocache;

	nocache = !!(dev->hints & FZ_NO_CACHE);
	if (nocache)
		pdf_mark_xref(ctx, doc);

	fz_try(ctx)
	{
		pdf_run_page_contents_with_usage(ctx, doc, page, dev, ctm, "View", cookie);
	}
	fz_always(ctx)
	{
		if (nocache)
			pdf_clear_xref_to_mark(ctx, doc);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
	if (page->incomplete & PDF_PAGE_INCOMPLETE_CONTENTS)
		fz_throw(ctx, FZ_ERROR_TRYLATER, "incomplete rendering");
}

void pdf_run_annot(fz_context *ctx, pdf_page *page, pdf_annot *annot, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	pdf_document *doc = page->doc;
	int nocache;

	nocache = !!(dev->hints & FZ_NO_CACHE);
	if (nocache)
		pdf_mark_xref(ctx, doc);
	fz_try(ctx)
	{
		pdf_run_annot_with_usage(ctx, doc, page, annot, dev, ctm, "View", cookie);
	}
	fz_always(ctx)
	{
		if (nocache)
			pdf_clear_xref_to_mark(ctx, doc);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
	if (page->incomplete & PDF_PAGE_INCOMPLETE_ANNOTS)
		fz_throw(ctx, FZ_ERROR_TRYLATER, "incomplete rendering");
}

static void pdf_run_page_annots_with_usage(fz_context *ctx, pdf_document *doc, pdf_page *page, fz_device *dev, const fz_matrix *ctm, char *event, fz_cookie *cookie)
{
	pdf_annot *annot;

	if (cookie && cookie->progress_max != -1)
	{
		int count = 1;
		for (annot = page->annots; annot; annot = annot->next)
			count++;
		cookie->progress_max += count;
	}

	for (annot = page->annots; annot; annot = annot->next)
	{
		/* Check the cookie for aborting */
		if (cookie)
		{
			if (cookie->abort)
				break;
			cookie->progress++;
		}

		pdf_run_annot_with_usage(ctx, doc, page, annot, dev, ctm, event, cookie);
	}
}

void
pdf_run_page_with_usage(fz_context *ctx, pdf_document *doc, pdf_page *page, fz_device *dev, const fz_matrix *ctm, char *event, fz_cookie *cookie)
{
	int nocache = !!(dev->hints & FZ_NO_CACHE);

	if (nocache)
		pdf_mark_xref(ctx, doc);
	fz_try(ctx)
	{
		pdf_run_page_contents_with_usage(ctx, doc, page, dev, ctm, event, cookie);
		pdf_run_page_annots_with_usage(ctx, doc, page, dev, ctm, event, cookie);
	}
	fz_always(ctx)
	{
		if (nocache)
			pdf_clear_xref_to_mark(ctx, doc);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
	if (page->incomplete)
		fz_throw(ctx, FZ_ERROR_TRYLATER, "incomplete rendering");
}

void
pdf_run_page(fz_context *ctx, pdf_page *page, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	pdf_document *doc = page->doc;
	pdf_run_page_with_usage(ctx, doc, page, dev, ctm, "View", cookie);
}

void
pdf_run_glyph(fz_context *ctx, pdf_document *doc, pdf_obj *resources, fz_buffer *contents, fz_device *dev, const fz_matrix *ctm, void *gstate, int nested_depth)
{
	pdf_processor *proc;

	if (nested_depth > 10)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Too many nestings of Type3 glyphs");

	proc = pdf_new_run_processor(ctx, dev, ctm, "View", gstate, nested_depth+1);
	fz_try(ctx)
		pdf_process_glyph(ctx, proc, doc, resources, contents);
	fz_always(ctx)
		pdf_drop_processor(ctx, proc);
	fz_catch(ctx)
		fz_rethrow(ctx);
}
