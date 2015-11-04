#include "mupdf/pdf.h"

static void
res_table_free(fz_context *ctx, pdf_res_table *table)
{
	int i, n;
	pdf_res *res;

	if (table == NULL)
		return;
	if (table->hash != NULL)
	{
		n = fz_hash_len(ctx, table->hash);
		for (i = 0; i < n; i++)
		{
			void *v = fz_hash_get_val(ctx, table->hash, i);
			if (v)
			{
				res = (pdf_res*)v;
				pdf_drop_obj(ctx, res->obj);
				fz_free(ctx, res);
			}
		}
		fz_drop_hash(ctx, table->hash);
	}
	fz_free(ctx, table);
}

static void
res_image_get_md5(fz_context *ctx, fz_image *image, unsigned char *digest)
{
	fz_pixmap *pixmap = NULL;
	int n, size;
	fz_buffer *buffer = NULL;
	fz_md5 state;

	fz_var(pixmap);
	fz_var(buffer);

	fz_try(ctx)
	{
		pixmap = fz_get_pixmap_from_image(ctx, image, 0, 0);
		n = (pixmap->n == 1 ? 1 : pixmap->n - 1);
		size = image->w * image->h * n;
		buffer = fz_new_buffer(ctx, size);
		buffer->len = size;
		if (pixmap->n == 1)
		{
			memcpy(buffer->data, pixmap->samples, size);
		}
		else
		{
			/* Need to remove the alpha plane */
			unsigned char *d = buffer->data;
			unsigned char *s = pixmap->samples;
			int mod = n;
			while (size--)
			{
				*d++ = *s++;
				mod--;
				if (mod == 0)
					s++, mod = n;
			}
		}
		fz_md5_init(&state);
		fz_md5_update(&state, buffer->data, buffer->len);
		fz_md5_final(&state, digest);
	}
	fz_always(ctx)
	{
		fz_drop_pixmap(ctx, pixmap);
		fz_drop_buffer(ctx, buffer);
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "image md5 calculation failed");
	}
}

/* Image specific methods */
static void
res_image_init(fz_context *ctx, pdf_document *doc, pdf_res_table *table)
{
	int len, k;
	pdf_obj *obj;
	pdf_obj *type;
	pdf_res *res = NULL;
	fz_image *image = NULL;
	unsigned char digest[16];
	int num = 0;

	fz_var(obj);
	fz_var(image);
	fz_var(res);

	fz_try(ctx)
	{
		table->hash = fz_new_hash_table(ctx, 4096, 16, -1);
		len = pdf_count_objects(ctx, doc);
		for (k = 1; k < len; k++)
		{
			obj = pdf_load_object(ctx, doc, k, 0);
			type = pdf_dict_get(ctx, obj, PDF_NAME_Subtype);
			if (pdf_name_eq(ctx, type, PDF_NAME_Image))
			{
				image = pdf_load_image(ctx, doc, obj);
				res_image_get_md5(ctx, image, digest);
				fz_drop_image(ctx, image);
				image = NULL;

				/* Don't allow overwrites. Number the resources for pdfwrite */
				if (fz_hash_find(ctx, table->hash, (void *)digest) == NULL)
				{
					res = fz_malloc(ctx, sizeof(pdf_res));
					res->num = num;
					res->obj = obj;
					num = num + 1;
					fz_hash_insert(ctx, table->hash, (void *)digest, obj);
				}
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
		table->count = num;
		fz_drop_image(ctx, image);
		pdf_drop_obj(ctx, obj);
	}
	fz_catch(ctx)
	{
		res_table_free(ctx, table);
		fz_rethrow_message(ctx, "image resources table failed to initialize");
	}
}

static void*
res_image_search(fz_context *ctx, pdf_document *doc, pdf_res_table *table, void *item,
	void *md5)
{
	unsigned char digest[16];

	fz_image *image = (fz_image*)item;
	fz_hash_table *hash = table->hash;
	pdf_res *res;

	if (hash == NULL)
		res_image_init(ctx, doc, doc->resources->image);
	hash = doc->resources->image->hash;

	/* Create md5 and see if we have the item in our table */
	res_image_get_md5(ctx, image, digest);
	res = fz_hash_find(ctx, hash, (void*)digest);

	/* Return the digest value so that we can avoid having to recompute it when
	 * we come back to add the new resource reference */
	if (res == NULL)
		memcpy(md5, digest, 16);
	else
		pdf_keep_obj(ctx, res->obj);
	return (void*) res;
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

static void*
res_font_search(fz_context *ctx, pdf_document *doc, pdf_res_table *table, void *item,
	void *md5)
{
	unsigned char digest[16];
	fz_buffer *buffer = (fz_buffer*)item;
	fz_hash_table *hash = table->hash;
	pdf_res *res;

	if (hash == NULL)
		res_font_init(ctx, doc, doc->resources->font);
	hash = doc->resources->font->hash;

	/* Create md5 and see if we have the item in our table */
	res_font_get_md5(ctx, buffer, digest);
	res = fz_hash_find(ctx, hash, (void*)digest);

	/* Return the digest value so that we can avoid having to recompute it when
	 * we come back to add the new resource reference */
	if (res == NULL)
		memcpy(md5, digest, 16);
	else
		pdf_keep_obj(ctx, res->obj);
	return (void*)res;
}

/* Accessible methods */
void*
pdf_resource_table_search(fz_context *ctx, pdf_document *doc, pdf_res_table *table,
	void *item, void *md5)
{
	return table->search(ctx, doc, table, item, md5);
}

void*
pdf_resource_table_put(fz_context *ctx, pdf_res_table *table, void *key, pdf_obj *obj)
{
	void *result;
	pdf_res *res = NULL;

	fz_var(res);

	fz_try(ctx)
	{
		res = fz_malloc(ctx, sizeof(pdf_res));
		res->num = table->count + 1;
		res->obj = obj;
		result = fz_hash_insert(ctx, table->hash, key, (void*)res);
		if (result != NULL)
		{
			fz_free(ctx, res);
			fz_warn(ctx, "warning: hash already present");
		}
		else
		{
			table->count = table->count + 1;
			pdf_keep_obj(ctx, obj);
			result = res;
		}
	}
	fz_catch(ctx)
	{
		fz_free(ctx, res);
		fz_rethrow(ctx);
	}
	return result;
}

void
pdf_resource_table_free(fz_context *ctx, pdf_document *doc)
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
pdf_resource_table_init(fz_context *ctx, pdf_document *doc)
{
	fz_var(doc);
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
		if (doc->resources != NULL)
		{
			fz_free(ctx, doc->resources->color);
			fz_free(ctx, doc->resources->font);
			fz_free(ctx, doc->resources);
			doc->resources = NULL;
		}
		fz_rethrow_message(ctx, "resources failed to allocate");
	}
}
