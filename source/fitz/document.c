#include "mupdf/fitz.h"

enum
{
	FZ_DOCUMENT_HANDLER_MAX = 10
};

#define DEFW (450)
#define DEFH (600)
#define DEFEM (12)

struct fz_document_handler_context_s
{
	int refs;
	int count;
	const fz_document_handler *handler[FZ_DOCUMENT_HANDLER_MAX];
};

void fz_new_document_handler_context(fz_context *ctx)
{
	ctx->handler = fz_malloc_struct(ctx, fz_document_handler_context);
	ctx->handler->refs = 1;
}

fz_document_handler_context *fz_keep_document_handler_context(fz_context *ctx)
{
	if (!ctx || !ctx->handler)
		return NULL;
	return fz_keep_imp(ctx, ctx->handler, &ctx->handler->refs);
}

void fz_drop_document_handler_context(fz_context *ctx)
{
	if (!ctx || !ctx->handler)
		return;

	if (fz_drop_imp(ctx, ctx->handler, &ctx->handler->refs))
	{
		fz_free(ctx, ctx->handler);
		ctx->handler = NULL;
	}
}

void fz_register_document_handler(fz_context *ctx, const fz_document_handler *handler)
{
	fz_document_handler_context *dc;
	int i;

	if (!ctx || !handler)
		return;

	dc = ctx->handler;
	if (dc == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Document handler list not found");

	for (i = 0; i < dc->count; i++)
		if (dc->handler[i] == handler)
			return;

	if (dc->count >= FZ_DOCUMENT_HANDLER_MAX)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Too many document handlers");

	dc->handler[dc->count++] = handler;
}

fz_document *
fz_open_document_with_stream(fz_context *ctx, const char *magic, fz_stream *stream)
{
	int i, score;
	int best_i, best_score;
	fz_document_handler_context *dc;

	if (ctx == NULL)
		return NULL;
	if (magic == NULL || stream == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no document to open");

	dc = ctx->handler;
	if (dc->count == 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "No document handlers registered");

	best_i = -1;
	best_score = 0;
	for (i = 0; i < dc->count; i++)
	{
		score = dc->handler[i]->recognize(ctx, magic);
		if (best_score < score)
		{
			best_score = score;
			best_i = i;
		}
	}

	if (best_i >= 0)
		return dc->handler[best_i]->open_with_stream(ctx, stream);

	fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find document handler for file type: %s", magic);
}

fz_document *
fz_open_document(fz_context *ctx, const char *filename)
{
	int i, score;
	int best_i, best_score;
	fz_document_handler_context *dc;

	if (ctx == NULL)
		return NULL;
	if (filename == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no document to open");

	dc = ctx->handler;
	if (dc->count == 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "No document handlers registered");

	best_i = -1;
	best_score = 0;
	for (i = 0; i < dc->count; i++)
	{
		score = dc->handler[i]->recognize(ctx, filename);
		if (best_score < score)
		{
			best_score = score;
			best_i = i;
		}
	}

	if (best_i >= 0)
		return dc->handler[best_i]->open(ctx, filename);

	fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find document handler for file: '%s'", filename);
}

void *
fz_new_document_of_size(fz_context *ctx, int size)
{
	fz_document *doc = fz_calloc(ctx, 1, size);
	doc->refs = 1;
	return doc;
}

fz_document *
fz_keep_document(fz_context *ctx, fz_document *doc)
{
	return fz_keep_imp(ctx, doc, &doc->refs);
}

void
fz_drop_document(fz_context *ctx, fz_document *doc)
{
	if (fz_drop_imp(ctx, doc, &doc->refs))
		if (doc->drop_document)
			doc->drop_document(ctx, doc);
}

static void
fz_ensure_layout(fz_context *ctx, fz_document *doc)
{
	if (doc && doc->layout && !doc->did_layout)
	{
		doc->layout(ctx, doc, DEFW, DEFH, DEFEM);
		doc->did_layout = 1;
	}
}

int
fz_needs_password(fz_context *ctx, fz_document *doc)
{
	if (doc && doc->needs_password)
		return doc->needs_password(ctx, doc);
	return 0;
}

int
fz_authenticate_password(fz_context *ctx, fz_document *doc, const char *password)
{
	if (doc && doc->authenticate_password)
		return doc->authenticate_password(ctx, doc, password);
	return 1;
}

int
fz_has_permission(fz_context *ctx, fz_document *doc, fz_permission p)
{
	if (doc && doc->has_permission)
		return doc->has_permission(ctx, doc, p);
	return 1;
}

fz_outline *
fz_load_outline(fz_context *ctx, fz_document *doc)
{
	if (doc && doc->load_outline)
		return doc->load_outline(ctx, doc);
	return NULL;
}

void
fz_layout_document(fz_context *ctx, fz_document *doc, float w, float h, float em)
{
	if (doc && doc->layout)
	{
		doc->layout(ctx, doc, w, h, em);
		doc->did_layout = 1;
	}
}

int
fz_count_pages(fz_context *ctx, fz_document *doc)
{
	fz_ensure_layout(ctx, doc);
	if (doc && doc->count_pages)
		return doc->count_pages(ctx, doc);
	return 0;
}

int
fz_lookup_metadata(fz_context *ctx, fz_document *doc, const char *key, char *buf, int size)
{
	if (buf && size > 0)
		buf[0] = 0;
	if (doc && doc->lookup_metadata)
		return doc->lookup_metadata(ctx, doc, key, buf, size);
	return -1;
}

fz_page *
fz_load_page(fz_context *ctx, fz_document *doc, int number)
{
	fz_ensure_layout(ctx, doc);
	if (doc && doc->load_page)
		return doc->load_page(ctx, doc, number);
	return NULL;
}

fz_link *
fz_load_links(fz_context *ctx, fz_page *page)
{
	if (page && page->load_links && page)
		return page->load_links(ctx, page);
	return NULL;
}

fz_rect *
fz_bound_page(fz_context *ctx, fz_page *page, fz_rect *r)
{
	if (page && page->bound_page && page && r)
		return page->bound_page(ctx, page, r);
	if (r)
		*r = fz_empty_rect;
	return r;
}

fz_annot *
fz_first_annot(fz_context *ctx, fz_page *page)
{
	if (page && page->first_annot && page)
		return page->first_annot(ctx, page);
	return NULL;
}

fz_annot *
fz_next_annot(fz_context *ctx, fz_annot *annot)
{
	if (annot && annot->next_annot)
		return annot->next_annot(ctx, annot);
	return NULL;
}

fz_rect *
fz_bound_annot(fz_context *ctx, fz_annot *annot, fz_rect *rect)
{
	if (annot && annot->bound_annot && rect)
		return annot->bound_annot(ctx, annot, rect);
	if (rect)
		*rect = fz_empty_rect;
	return rect;
}

void
fz_run_page_contents(fz_context *ctx, fz_page *page, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie)
{
	if (page && page->run_page_contents && page)
	{
		fz_try(ctx)
		{
			page->run_page_contents(ctx, page, dev, transform, cookie);
		}
		fz_catch(ctx)
		{
			if (fz_caught(ctx) != FZ_ERROR_ABORT)
				fz_rethrow(ctx);
		}
	}
}

void
fz_run_annot(fz_context *ctx, fz_annot *annot, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie)
{
	if (annot && annot->run_annot)
	{
		fz_try(ctx)
		{
			annot->run_annot(ctx, annot, dev, transform, cookie);
		}
		fz_catch(ctx)
		{
			if (fz_caught(ctx) != FZ_ERROR_ABORT)
				fz_rethrow(ctx);
		}
	}
}

void
fz_run_page(fz_context *ctx, fz_page *page, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie)
{
	fz_annot *annot;

	fz_run_page_contents(ctx, page, dev, transform, cookie);

	if (cookie && cookie->progress_max != -1)
	{
		int count = 1;
		for (annot = fz_first_annot(ctx, page); annot; annot = fz_next_annot(ctx, annot))
			count++;
		cookie->progress_max += count;
	}

	for (annot = fz_first_annot(ctx, page); annot; annot = fz_next_annot(ctx, annot))
	{
		/* Check the cookie for aborting */
		if (cookie)
		{
			if (cookie->abort)
				break;
			cookie->progress++;
		}

		fz_run_annot(ctx, annot, dev, transform, cookie);
	}
}

void *
fz_new_annot(fz_context *ctx, int size)
{
	fz_annot *annot = Memento_label(fz_calloc(ctx, 1, size), "fz_annot");
	annot->refs = 1;
	return annot;
}

fz_annot *
fz_keep_annot(fz_context *ctx, fz_annot *annot)
{
	return fz_keep_imp(ctx, annot, &annot->refs);
}

void
fz_drop_annot(fz_context *ctx, fz_annot *annot)
{
	if (fz_drop_imp(ctx, annot, &annot->refs))
	{
		if (annot->drop_annot)
			annot->drop_annot(ctx, annot);
		fz_free(ctx, annot);
	}
}

void *
fz_new_page(fz_context *ctx, int size)
{
	fz_page *page = Memento_label(fz_calloc(ctx, 1, size), "fz_page");
	page->refs = 1;
	return page;
}

fz_page *
fz_keep_page(fz_context *ctx, fz_page *page)
{
	return fz_keep_imp(ctx, page, &page->refs);
}

void
fz_drop_page(fz_context *ctx, fz_page *page)
{
	if (fz_drop_imp(ctx, page, &page->refs))
	{
		if (page->drop_page)
			page->drop_page(ctx, page);
		fz_free(ctx, page);
	}
}

fz_transition *
fz_page_presentation(fz_context *ctx, fz_page *page, fz_transition *transition, float *duration)
{
	float dummy;
	if (duration)
		*duration = 0;
	else
		duration = &dummy;
	if (page && page->page_presentation && page)
		return page->page_presentation(ctx, page, transition, duration);
	return NULL;
}

int fz_count_separations_on_page(fz_context *ctx, fz_page *page)
{
	if (ctx == NULL || page == NULL || page->count_separations == NULL)
		return 0;

	return page->count_separations(ctx, page);
}

void fz_control_separation_on_page(fz_context *ctx, fz_page *page, int sep, int disable)
{
	if (ctx == NULL || page == NULL || page->control_separation == NULL)
		return;

	page->control_separation(ctx, page, sep, disable);
}

int fz_separation_disabled_on_page (fz_context *ctx, fz_page *page, int sep)
{
	if (ctx == NULL || page == NULL || page->separation_disabled == NULL)
		return 0;
	return page->separation_disabled(ctx, page, sep);
}

const char *fz_get_separation_on_page(fz_context *ctx, fz_page *page, int sep, uint32_t *rgba, uint32_t *cmyk)
{
	if (ctx == NULL || page == NULL || page->get_separation == NULL)
	{
		*rgba = 0;
		*cmyk = 0;
		return NULL;
	}
	return page->get_separation(ctx, page, sep, rgba, cmyk);
}
