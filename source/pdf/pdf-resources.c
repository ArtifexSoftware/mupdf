#include "mupdf/pdf.h"

static void
res_table_free(fz_context *ctx, pdf_res_table *table)
{
	int i, n;
	pdf_obj *res;

	if (table == NULL)
		return;
	if (table->hash != NULL)
	{
		n = fz_hash_len(ctx, table->hash);
		for (i = 0; i < n; i++)
		{
			res = fz_hash_get_val(ctx, table->hash, i);
			if (res)
				pdf_drop_obj(ctx, res);
		}
		fz_drop_hash(ctx, table->hash);
	}
	fz_free(ctx, table);
}

static void
res_image_get_md5(fz_context *ctx, fz_image *image, unsigned char *digest)
{
	fz_pixmap *pixmap;
	fz_md5 state;
	int h;
	unsigned char *d;

	pixmap = fz_get_pixmap_from_image(ctx, image, NULL, NULL, 0, 0);
	fz_md5_init(&state);
	d = pixmap->samples;
	h = pixmap->h;
	while (h--)
	{
		fz_md5_update(&state, d, pixmap->w * pixmap->n);
		d += pixmap->stride;
	}
	fz_md5_final(&state, digest);
	fz_drop_pixmap(ctx, pixmap);
}

/* Image specific methods */
static void
res_image_init(fz_context *ctx, pdf_document *doc, pdf_res_table *table)
{
	int len, k;
	pdf_obj *obj;
	pdf_obj *type;
	pdf_obj *res = NULL;
	fz_image *image = NULL;
	unsigned char digest[16];

	fz_var(obj);
	fz_var(image);
	fz_var(res);

	fz_try(ctx)
	{
		table->hash = fz_new_hash_table(ctx, 4096, 16, -1);
		len = pdf_count_objects(ctx, doc);
		for (k = 1; k < len; k++)
		{
			obj = pdf_load_object(ctx, doc, k);
			type = pdf_dict_get(ctx, obj, PDF_NAME_Subtype);
			if (pdf_name_eq(ctx, type, PDF_NAME_Image))
			{
				image = pdf_load_image(ctx, doc, obj);
				res_image_get_md5(ctx, image, digest);
				fz_drop_image(ctx, image);
				image = NULL;

				/* Don't allow overwrites. */
				if (fz_hash_find(ctx, table->hash, digest) == NULL)
					fz_hash_insert(ctx, table->hash, digest, obj);
			}
			else
			{
				pdf_drop_obj(ctx, obj);
			}
			obj = NULL;
		}
	}
	fz_always(ctx)
	{
		fz_drop_image(ctx, image);
		pdf_drop_obj(ctx, obj);
	}
	fz_catch(ctx)
	{
		res_table_free(ctx, table);
		fz_rethrow(ctx);
	}
}

static pdf_obj *
res_image_search(fz_context *ctx, pdf_document *doc, pdf_res_table *table, void *item, unsigned char *digest)
{
	fz_image *image = item;
	fz_hash_table *hash = table->hash;
	pdf_obj *res;

	if (hash == NULL)
		res_image_init(ctx, doc, doc->resources->image);
	hash = doc->resources->image->hash;

	/* Create md5 and see if we have the item in our table */
	res_image_get_md5(ctx, image, digest);
	res = fz_hash_find(ctx, hash, digest);
	if (res)
		pdf_keep_obj(ctx, res);
	return res;
}

/* Font specific methods */

/* We do need to come up with an effective way to see what is already in the
 * file to avoid adding to what is already there. This is avoided for pdfwrite
 * as we check as we add each font.  For adding text to an existing file though
 * it may be more problematic */
static void
res_font_init(fz_context *ctx, pdf_document *doc, pdf_res_table *table)
{
	table->hash = fz_new_hash_table(ctx, 4096, 16, -1);
}

static void
res_font_get_md5(fz_context *ctx, fz_buffer *buffer, unsigned char *digest)
{
	fz_md5 state;

	fz_md5_init(&state);
	fz_md5_update(&state, buffer->data, buffer->len);
	fz_md5_final(&state, digest);
}

static pdf_obj *
res_font_search(fz_context *ctx, pdf_document *doc, pdf_res_table *table, void *item, unsigned char digest[16])
{
	fz_buffer *buffer = item;
	fz_hash_table *hash = table->hash;
	pdf_obj *res;

	if (hash == NULL)
		res_font_init(ctx, doc, doc->resources->font);
	hash = doc->resources->font->hash;

	/* Create md5 and see if we have the item in our table */
	res_font_get_md5(ctx, buffer, digest);
	res = fz_hash_find(ctx, hash, digest);
	if (res)
		pdf_keep_obj(ctx, res);
	return res;
}

/* Accessible methods */
pdf_obj *
pdf_find_resource(fz_context *ctx, pdf_document *doc, pdf_res_table *table, void *item, unsigned char md5[16])
{
	return table->search(ctx, doc, table, item, md5);
}

pdf_obj *
pdf_insert_resource(fz_context *ctx, pdf_res_table *table, void *key, pdf_obj *obj)
{
	pdf_obj *res;

	fz_try(ctx)
	{
		res = fz_hash_insert(ctx, table->hash, key, obj);
		if (res != NULL)
			fz_warn(ctx, "warning: resource already present");
		else
			res = pdf_keep_obj(ctx, obj);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
	return res;
}

void
pdf_drop_resource_tables(fz_context *ctx, pdf_document *doc)
{
	if (doc->resources == NULL)
		return;
	res_table_free(ctx, doc->resources->color);
	res_table_free(ctx, doc->resources->font);
	res_table_free(ctx, doc->resources->image);
	res_table_free(ctx, doc->resources->pattern);
	res_table_free(ctx, doc->resources->shading);
	fz_free(ctx, doc->resources);
	doc->resources = NULL;
}

void
pdf_init_resource_tables(fz_context *ctx, pdf_document *doc)
{
	fz_try(ctx)
	{
		doc->resources = fz_calloc(ctx, 1, sizeof(pdf_resource_tables));
		doc->resources->image = fz_calloc(ctx, 1, sizeof(pdf_res_table));
		doc->resources->image->search = res_image_search;
		doc->resources->font = fz_calloc(ctx, 1, sizeof(pdf_res_table));
		doc->resources->font->search = res_font_search;
	}
	fz_catch(ctx)
	{
		pdf_drop_resource_tables(ctx, doc);
		fz_rethrow(ctx);
	}
}
