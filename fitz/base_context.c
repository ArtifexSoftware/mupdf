#include "fitz.h"

static fz_obj *
fz_resolve_indirect_null(fz_obj *ref)
{
	return ref;
}

fz_obj *(*fz_resolve_indirect)(fz_obj*) = fz_resolve_indirect_null;

void
fz_free_context(fz_context *ctx)
{
	assert(ctx != NULL);

	/* Other finalisation calls go here (in reverse order) */

	if (ctx->error)
	{
		assert(ctx->error->top == -1);
		free(ctx->error);
	}

	/* Free the context itself */
	free(ctx);
}

fz_context *
fz_new_context(void)
{
	fz_context *ctx;

	ctx = malloc(sizeof(fz_context));
	if (!ctx)
		return NULL;

	ctx->error = malloc(sizeof(fz_error_context));
	if (!ctx->error)
		goto cleanup;
	ctx->error->top = -1;
	ctx->error->message[0] = 0;

	/* New initialisation calls for context entries go here */

	return ctx;

cleanup:
	fprintf(stderr, "cannot create context\n");
	fz_free_context(ctx);
	return NULL;
}

fz_context *
fz_clone_context(fz_context *ctx)
{
	return fz_new_context();
}
