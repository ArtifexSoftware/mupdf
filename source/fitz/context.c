#include "fitz-imp.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

struct fz_id_context_s
{
	int refs;
	int id;
};

static void
fz_drop_id_context(fz_context *ctx)
{
	if (!ctx)
		return;
	if (fz_drop_imp(ctx, ctx->id, &ctx->id->refs))
		fz_free(ctx, ctx->id);
}

static void
fz_new_id_context(fz_context *ctx)
{
	ctx->id = fz_malloc_struct(ctx, fz_id_context);
	ctx->id->refs = 1;
	ctx->id->id = 0;
}

static fz_id_context *
fz_keep_id_context(fz_context *ctx)
{
	if (!ctx)
		return NULL;
	return fz_keep_imp(ctx, ctx->id, &ctx->id->refs);
}

struct fz_style_context_s
{
	int refs;
	char *user_css;
	int use_document_css;
};

static void fz_new_style_context(fz_context *ctx)
{
	if (ctx)
	{
		ctx->style = fz_malloc_struct(ctx, fz_style_context);
		ctx->style->refs = 1;
		ctx->style->user_css = NULL;
		ctx->style->use_document_css = 1;
	}
}

static fz_style_context *fz_keep_style_context(fz_context *ctx)
{
	if (!ctx)
		return NULL;
	return fz_keep_imp(ctx, ctx->style, &ctx->style->refs);
}

static void fz_drop_style_context(fz_context *ctx)
{
	if (!ctx)
		return;
	if (fz_drop_imp(ctx, ctx->style, &ctx->style->refs))
	{
		fz_free(ctx, ctx->style->user_css);
		fz_free(ctx, ctx->style);
	}
}

void fz_set_use_document_css(fz_context *ctx, int use)
{
	ctx->style->use_document_css = use;
}

int fz_use_document_css(fz_context *ctx)
{
	return ctx->style->use_document_css;
}

void fz_set_user_css(fz_context *ctx, const char *user_css)
{
	fz_free(ctx, ctx->style->user_css);
	ctx->style->user_css = fz_strdup(ctx, user_css);
}

const char *fz_user_css(fz_context *ctx)
{
	return ctx->style->user_css;
}

static void fz_new_tuning_context(fz_context *ctx)
{
	if (ctx)
	{
		ctx->tuning = fz_malloc_struct(ctx, fz_tuning_context);
		ctx->tuning->refs = 1;
		ctx->tuning->image_decode = fz_default_image_decode;
		ctx->tuning->image_scale = fz_default_image_scale;
	}
}

static fz_tuning_context *fz_keep_tuning_context(fz_context *ctx)
{
	if (!ctx)
		return NULL;
	return fz_keep_imp(ctx, ctx->tuning, &ctx->tuning->refs);
}

static void fz_drop_tuning_context(fz_context *ctx)
{
	if (!ctx)
		return;
	if (fz_drop_imp(ctx, ctx->tuning, &ctx->tuning->refs))
	{
		fz_free(ctx, ctx->tuning);
	}
}

void fz_tune_image_decode(fz_context *ctx, fz_tune_image_decode_fn *image_decode, void *arg)
{
	ctx->tuning->image_decode = image_decode ? image_decode : fz_default_image_decode;
	ctx->tuning->image_decode_arg = arg;
}

void fz_tune_image_scale(fz_context *ctx, fz_tune_image_scale_fn *image_scale, void *arg)
{
	ctx->tuning->image_scale = image_scale ? image_scale : fz_default_image_scale;
	ctx->tuning->image_scale_arg = arg;
}

void
fz_drop_context(fz_context *ctx)
{
	if (!ctx)
		return;

	/* Other finalisation calls go here (in reverse order) */
	fz_drop_document_handler_context(ctx);
	fz_drop_glyph_cache_context(ctx);
	fz_drop_store_context(ctx);
	fz_drop_aa_context(ctx);
	fz_drop_style_context(ctx);
	fz_drop_tuning_context(ctx);
	fz_drop_colorspace_context(ctx);
	fz_drop_font_context(ctx);
	fz_drop_id_context(ctx);
	fz_drop_output_context(ctx);

	if (ctx->warn)
	{
		fz_flush_warnings(ctx);
		fz_free(ctx, ctx->warn);
	}

	if (ctx->error)
	{
		assert(ctx->error->top == ctx->error->stack - 1);
		fz_free(ctx, ctx->error);
	}

	/* Free the context itself */
	ctx->alloc->free(ctx->alloc->user, ctx);
}

/* Allocate new context structure, and initialise allocator, and sections
 * that aren't shared between contexts.
 */
static fz_context *
new_context_phase1(const fz_alloc_context *alloc, const fz_locks_context *locks)
{
	fz_context *ctx;

	ctx = alloc->malloc(alloc->user, sizeof(fz_context));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof *ctx);
	ctx->user = NULL;
	ctx->alloc = alloc;
	ctx->locks = locks;

	ctx->glyph_cache = NULL;

	ctx->error = Memento_label(fz_malloc_no_throw(ctx, sizeof(fz_error_context)), "fz_error_context");
	if (!ctx->error)
		goto cleanup;
	ctx->error->top = ctx->error->stack - 1;
	ctx->error->errcode = FZ_ERROR_NONE;
	ctx->error->message[0] = 0;

	ctx->warn = Memento_label(fz_malloc_no_throw(ctx, sizeof(fz_warn_context)), "fz_warn_context");
	if (!ctx->warn)
		goto cleanup;
	ctx->warn->message[0] = 0;
	ctx->warn->count = 0;

	/* New initialisation calls for context entries go here */
	fz_try(ctx)
	{
		fz_new_aa_context(ctx);
	}
	fz_catch(ctx)
	{
		goto cleanup;
	}

	return ctx;

cleanup:
	fprintf(stderr, "cannot create context (phase 1)\n");
	fz_drop_context(ctx);
	return NULL;
}

fz_context *
fz_new_context_imp(const fz_alloc_context *alloc, const fz_locks_context *locks, size_t max_store, const char *version)
{
	fz_context *ctx;

	if (strcmp(version, FZ_VERSION))
	{
		fprintf(stderr, "cannot create context: incompatible header (%s) and library (%s) versions\n", version, FZ_VERSION);
		return NULL;
	}

	if (!alloc)
		alloc = &fz_alloc_default;

	if (!locks)
		locks = &fz_locks_default;

	ctx = new_context_phase1(alloc, locks);
	if (!ctx)
		return NULL;

	/* Now initialise sections that are shared */
	fz_try(ctx)
	{
		fz_new_output_context(ctx);
		fz_new_store_context(ctx, max_store);
		fz_new_glyph_cache_context(ctx);
		fz_new_colorspace_context(ctx);
		fz_new_font_context(ctx);
		fz_new_id_context(ctx);
		fz_new_document_handler_context(ctx);
		fz_new_style_context(ctx);
		fz_new_tuning_context(ctx);
	}
	fz_catch(ctx)
	{
		fprintf(stderr, "cannot create context (phase 2)\n");
		fz_drop_context(ctx);
		return NULL;
	}
	return ctx;
}

fz_context *
fz_clone_context(fz_context *ctx)
{
	/* We cannot safely clone the context without having locking/
	 * unlocking functions. */
	if (ctx == NULL || ctx->locks == &fz_locks_default)
		return NULL;
	return fz_clone_context_internal(ctx);
}

fz_context *
fz_clone_context_internal(fz_context *ctx)
{
	fz_context *new_ctx;

	if (ctx == NULL || ctx->alloc == NULL)
		return NULL;

	new_ctx = new_context_phase1(ctx->alloc, ctx->locks);
	if (!new_ctx)
		return NULL;

	/* Inherit AA defaults from old context. */
	fz_copy_aa_context(new_ctx, ctx);

	/* Keep thread lock checking happy by copying pointers first and locking under new context */
	new_ctx->output = ctx->output;
	new_ctx->output = fz_keep_output_context(new_ctx);
	new_ctx->user = ctx->user;
	new_ctx->store = ctx->store;
	new_ctx->store = fz_keep_store_context(new_ctx);
	new_ctx->glyph_cache = ctx->glyph_cache;
	new_ctx->glyph_cache = fz_keep_glyph_cache(new_ctx);
	new_ctx->colorspace = ctx->colorspace;
	new_ctx->colorspace = fz_keep_colorspace_context(new_ctx);
	new_ctx->font = ctx->font;
	new_ctx->font = fz_keep_font_context(new_ctx);
	new_ctx->style = ctx->style;
	new_ctx->style = fz_keep_style_context(new_ctx);
	new_ctx->id = ctx->id;
	new_ctx->id = fz_keep_id_context(new_ctx);
	new_ctx->tuning = ctx->tuning;
	new_ctx->tuning = fz_keep_tuning_context(new_ctx);
	new_ctx->handler = ctx->handler;
	new_ctx->handler = fz_keep_document_handler_context(new_ctx);

	return new_ctx;
}

int
fz_gen_id(fz_context *ctx)
{
	int id;
	fz_lock(ctx, FZ_LOCK_ALLOC);
	/* We'll never wrap around in normal use, but if we do, then avoid 0. */
	do
		id = ++ctx->id->id;
	while (id == 0);
	fz_unlock(ctx, FZ_LOCK_ALLOC);
	return id;
}

void fz_set_user_context(fz_context *ctx, void *user)
{
	if (ctx != NULL)
		ctx->user = user;
}

void *fz_user_context(fz_context *ctx)
{
	if (ctx == NULL)
		return NULL;

	return ctx->user;
}
