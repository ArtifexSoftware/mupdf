#include "mupdf/pdf.h"

static int
pdf_make_hash_key(fz_context *ctx, fz_store_hash *hash, void *key_)
{
	pdf_obj *key = (pdf_obj *)key_;

	if (!pdf_is_indirect(ctx, key))
		return 0;
	hash->u.i.i0 = pdf_to_num(ctx, key);
	hash->u.i.i1 = pdf_to_gen(ctx, key);
	hash->u.i.ptr = pdf_get_indirect_document(ctx, key);
	return 1;
}

static void *
pdf_keep_key(fz_context *ctx, void *key)
{
	return (void *)pdf_keep_obj(ctx, (pdf_obj *)key);
}

static void
pdf_drop_key(fz_context *ctx, void *key)
{
	pdf_drop_obj(ctx, (pdf_obj *)key);
}

static int
pdf_cmp_key(fz_context *ctx, void *k0, void *k1)
{
	return pdf_objcmp(ctx, (pdf_obj *)k0, (pdf_obj *)k1);
}

#ifndef NDEBUG
static void
pdf_debug_key(fz_context *ctx, FILE *out, void *key_)
{
	pdf_obj *key = (pdf_obj *)key_;

	if (pdf_is_indirect(ctx, key))
	{
		fprintf(out, "(%d %d R) ", pdf_to_num(ctx, key), pdf_to_gen(ctx, key));
	}
	else
		pdf_fprint_obj(ctx, out, key, 0);
}
#endif

static fz_store_type pdf_obj_store_type =
{
	pdf_make_hash_key,
	pdf_keep_key,
	pdf_drop_key,
	pdf_cmp_key,
#ifndef NDEBUG
	pdf_debug_key
#endif
};

void
pdf_store_item(fz_context *ctx, pdf_obj *key, void *val, unsigned int itemsize)
{
	void *existing;
	existing = fz_store_item(ctx, key, val, itemsize, &pdf_obj_store_type);
	assert(existing == NULL);
}

void *
pdf_find_item(fz_context *ctx, fz_store_drop_fn *drop, pdf_obj *key)
{
	return fz_find_item(ctx, drop, key, &pdf_obj_store_type);
}

void
pdf_remove_item(fz_context *ctx, fz_store_drop_fn *drop, pdf_obj *key)
{
	fz_remove_item(ctx, drop, key, &pdf_obj_store_type);
}
