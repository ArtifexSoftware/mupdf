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
	ctx->handler->refs++;
	return ctx->handler;
}

void fz_drop_document_handler_context(fz_context *ctx)
{
	if (!ctx || !ctx->handler)
		return;

	if (--ctx->handler->refs != 0)
		return;

	fz_free(ctx, ctx->handler);
	ctx->handler = NULL;
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

static inline int fz_tolower(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c + 32;
	return c;
}

int fz_strcasecmp(const char *a, const char *b)
{
	while (fz_tolower(*a) == fz_tolower(*b))
	{
		if (*a++ == 0)
			return 0;
		b++;
	}
	return fz_tolower(*a) - fz_tolower(*b);
}

fz_document *
fz_open_document_with_stream(fz_context *ctx, const char *magic, fz_stream *stream)
{
	int i, score;
	int best_i, best_score;
	fz_document_handler_context *dc;

	if (ctx == NULL || magic == NULL || stream == NULL)
		return NULL;

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

	return NULL;
}

fz_document *
fz_open_document(fz_context *ctx, const char *filename)
{
	int i, score;
	int best_i, best_score;
	fz_document_handler_context *dc;

	if (ctx == NULL || filename == NULL)
		return NULL;

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

	return NULL;
}

void *
fz_new_document(fz_context *ctx, int size)
{
	fz_document *doc = fz_calloc(ctx, 1, size);
	doc->refs = 1;
	return doc;
}

fz_document *
fz_keep_document(fz_context *ctx, fz_document *doc)
{
	++doc->refs;
	return doc;
}

void
fz_drop_document(fz_context *ctx, fz_document *doc)
{
	if (doc && --doc->refs == 0 && doc->close)
		doc->close(ctx, doc);
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

void
fz_write_document(fz_context *ctx, fz_document *doc, char *filename, fz_write_options *opts)
{
	if (doc && doc->write)
		doc->write(ctx, doc, filename, opts);
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
fz_next_annot(fz_context *ctx, fz_page *page, fz_annot *annot)
{
	if (page && page->next_annot && annot)
		return page->next_annot(ctx, page, annot);
	return NULL;
}

fz_rect *
fz_bound_annot(fz_context *ctx, fz_page *page, fz_annot *annot, fz_rect *rect)
{
	if (page && page->bound_annot && annot && rect)
		return page->bound_annot(ctx, page, annot, rect);
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
fz_run_annot(fz_context *ctx, fz_page *page, fz_annot *annot, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie)
{
	if (page && page->run_annot && page && annot)
	{
		fz_try(ctx)
		{
			page->run_annot(ctx, page, annot, dev, transform, cookie);
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
	fz_rect mediabox;

	fz_bound_page(ctx, page, &mediabox);
	fz_begin_page(ctx, dev, &mediabox, transform);

	fz_run_page_contents(ctx, page, dev, transform, cookie);

	if (cookie && cookie->progress_max != -1)
	{
		int count = 1;
		for (annot = fz_first_annot(ctx, page); annot; annot = fz_next_annot(ctx, page, annot))
			count++;
		cookie->progress_max += count;
	}

	for (annot = fz_first_annot(ctx, page); annot; annot = fz_next_annot(ctx, page, annot))
	{
		/* Check the cookie for aborting */
		if (cookie)
		{
			if (cookie->abort)
				break;
			cookie->progress++;
		}

		fz_run_annot(ctx, page, annot, dev, transform, cookie);
	}

	fz_end_page(ctx, dev);
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
	if (page)
		++page->refs;
	return page;
}

void
fz_drop_page(fz_context *ctx, fz_page *page)
{
	if (page) {
		if (--page->refs == 0 && page->drop_page_imp)
		{
			page->drop_page_imp(ctx, page);
			fz_free(ctx, page);
		}
	}
}

fz_transition *
fz_page_presentation(fz_context *ctx, fz_page *page, float *duration)
{
	float dummy;
	if (duration)
		*duration = 0;
	else
		duration = &dummy;
	if (page && page->page_presentation && page)
		return page->page_presentation(ctx, page, duration);
	return NULL;
}
