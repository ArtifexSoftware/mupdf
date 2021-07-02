#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

fz_display_list *
pdf_new_display_list_from_annot(fz_context *ctx, pdf_annot *annot)
{
	fz_display_list *list;
	fz_device *dev = NULL;

	fz_var(dev);

	list = fz_new_display_list(ctx, pdf_bound_annot(ctx, annot));

	fz_try(ctx)
	{
		dev = fz_new_list_device(ctx, list);
		pdf_run_annot(ctx, annot, dev, fz_identity, NULL);
		fz_close_device(ctx, dev);
	}
	fz_always(ctx)
	{
		fz_drop_device(ctx, dev);
	}
	fz_catch(ctx)
	{
		fz_drop_display_list(ctx, list);
		fz_rethrow(ctx);
	}

	return list;
}

fz_pixmap *
pdf_new_pixmap_from_annot(fz_context *ctx, pdf_annot *annot, fz_matrix ctm, fz_colorspace *cs, fz_separations *seps, int alpha)
{
	fz_rect rect;
	fz_irect bbox;
	fz_pixmap *pix;
	fz_device *dev = NULL;

	fz_var(dev);

	rect = pdf_bound_annot(ctx, annot);
	rect = fz_transform_rect(rect, ctm);
	bbox = fz_round_rect(rect);

	pix = fz_new_pixmap_with_bbox(ctx, cs, bbox, seps, alpha);
	if (alpha)
		fz_clear_pixmap(ctx, pix);
	else
		fz_clear_pixmap_with_value(ctx, pix, 0xFF);

	fz_try(ctx)
	{
		dev = fz_new_draw_device(ctx, ctm, pix);
		pdf_run_annot(ctx, annot, dev, fz_identity, NULL);
		fz_close_device(ctx, dev);
	}
	fz_always(ctx)
	{
		fz_drop_device(ctx, dev);
	}
	fz_catch(ctx)
	{
		fz_drop_pixmap(ctx, pix);
		fz_rethrow(ctx);
	}

	return pix;
}

fz_stext_page *
pdf_new_stext_page_from_annot(fz_context *ctx, pdf_annot *annot, const fz_stext_options *options)
{
	fz_stext_page *text;
	fz_device *dev = NULL;

	fz_var(dev);

	if (annot == NULL)
		return NULL;

	text = fz_new_stext_page(ctx, pdf_bound_annot(ctx, annot));
	fz_try(ctx)
	{
		dev = fz_new_stext_device(ctx, text, options);
		pdf_run_annot(ctx, annot, dev, fz_identity, NULL);
		fz_close_device(ctx, dev);
	}
	fz_always(ctx)
	{
		fz_drop_device(ctx, dev);
	}
	fz_catch(ctx)
	{
		fz_drop_stext_page(ctx, text);
		fz_rethrow(ctx);
	}

	return text;
}

fz_pixmap *
pdf_new_pixmap_from_page_contents_with_separations_and_usage(fz_context *ctx, pdf_page *page, fz_matrix ctm, fz_colorspace *cs, fz_separations *seps, int alpha, const char *usage)
{
	fz_rect rect;
	fz_irect bbox;
	fz_pixmap *pix;
	fz_device *dev = NULL;

	fz_var(dev);

	rect = pdf_bound_page(ctx, page);
	rect = fz_transform_rect(rect, ctm);
	bbox = fz_round_rect(rect);

	pix = fz_new_pixmap_with_bbox(ctx, cs, bbox, seps, alpha);
	if (alpha)
		fz_clear_pixmap(ctx, pix);
	else
		fz_clear_pixmap_with_value(ctx, pix, 0xFF);

	fz_try(ctx)
	{
		dev = fz_new_draw_device(ctx, ctm, pix);
		fz_try(ctx)
		{
			pdf_run_page_contents_with_usage(ctx, page, dev, fz_identity, usage, NULL);
		}
		fz_catch(ctx)
		{
			dev->close_device = NULL; /* aborted run, don't warn about unclosed device */
			if (fz_caught(ctx) != FZ_ERROR_ABORT)
				fz_rethrow(ctx);
		}
		fz_close_device(ctx, dev);
	}
	fz_always(ctx)
	{
		fz_drop_device(ctx, dev);
	}
	fz_catch(ctx)
	{
		fz_drop_pixmap(ctx, pix);
		fz_rethrow(ctx);
	}

	return pix;
}

fz_pixmap *
pdf_new_pixmap_from_page_contents_with_usage(fz_context *ctx, pdf_page *page, fz_matrix ctm, fz_colorspace *cs, int alpha, const char *usage)
{
	return pdf_new_pixmap_from_page_contents_with_separations_and_usage(ctx, page, ctm, cs, NULL, alpha, usage);
}

fz_pixmap *
pdf_new_pixmap_from_page_with_separations_and_usage(fz_context *ctx, pdf_page *page, fz_matrix ctm, fz_colorspace *cs, fz_separations *seps, int alpha, const char *usage)
{
	fz_rect rect;
	fz_irect bbox;
	fz_pixmap *pix;
	fz_device *dev = NULL;

	fz_var(dev);

	rect = pdf_bound_page(ctx, page);
	rect = fz_transform_rect(rect, ctm);
	bbox = fz_round_rect(rect);

	pix = fz_new_pixmap_with_bbox(ctx, cs, bbox, seps, alpha);

	fz_try(ctx)
	{
		if (alpha)
			fz_clear_pixmap(ctx, pix);
		else
			fz_clear_pixmap_with_value(ctx, pix, 0xFF);

		dev = fz_new_draw_device(ctx, ctm, pix);
		fz_try(ctx)
		{
			pdf_run_page_with_usage(ctx, page, dev, fz_identity, usage, NULL);
		}
		fz_catch(ctx)
		{
			dev->close_device = NULL; /* aborted run, don't warn about unclosed device */
			if (fz_caught(ctx) != FZ_ERROR_ABORT)
				fz_rethrow(ctx);
		}
		fz_close_device(ctx, dev);
	}
	fz_always(ctx)
	{
		fz_drop_device(ctx, dev);
	}
	fz_catch(ctx)
	{
		fz_drop_pixmap(ctx, pix);
		fz_rethrow(ctx);
	}

	return pix;
}

fz_pixmap *
pdf_new_pixmap_from_page_with_usage(fz_context *ctx, pdf_page *page, fz_matrix ctm, fz_colorspace *cs, int alpha, const char *usage)
{
	return pdf_new_pixmap_from_page_with_separations_and_usage(ctx, page, ctm, cs, NULL, alpha, usage);
}
