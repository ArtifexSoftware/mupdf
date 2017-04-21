#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

struct pdf_graft_map_s
{
	int refs;
	int len;
	pdf_document *src;
	int *dst_from_src;
};

pdf_graft_map *
pdf_new_graft_map(fz_context *ctx, pdf_document *src)
{
	pdf_graft_map *map = NULL;

	map = fz_malloc_struct(ctx, pdf_graft_map);

	fz_try(ctx)
	{
		map->src = (pdf_document*) fz_keep_document(ctx, (fz_document*)src);
		map->len = pdf_xref_len(ctx, src);
		map->dst_from_src = fz_calloc(ctx, map->len, sizeof(int));
	}
	fz_catch(ctx)
	{
		fz_free(ctx, map);
		fz_rethrow(ctx);
	}
	map->refs = 1;
	return map;
}

pdf_graft_map *
fz_keep_graft_map(fz_context *ctx, pdf_graft_map *map)
{
	return fz_keep_imp(ctx, map, &map->refs);
}

void
pdf_drop_graft_map(fz_context *ctx, pdf_graft_map *map)
{
	if (fz_drop_imp(ctx, map, &map->refs))
	{
		fz_drop_document(ctx, &map->src->super);
		fz_free(ctx, map->dst_from_src);
		fz_free(ctx, map);
	}
}

/* Graft object from dst to source */
pdf_obj *
pdf_graft_object(fz_context *ctx, pdf_document *dst, pdf_document *src, pdf_obj *obj_ref, pdf_graft_map *map)
{
	pdf_obj *val, *key;
	pdf_obj *new_obj = NULL;
	pdf_obj *new_dict = NULL;
	pdf_obj *new_array = NULL;
	pdf_obj *ref = NULL;
	fz_buffer *buffer = NULL;
	pdf_graft_map *drop_map = NULL;
	pdf_document *bound;
	int new_num, src_num, len, i;

	/* Primitive objects are not bound to a document, so can be re-used as is. */
	if (!pdf_is_indirect(ctx, obj_ref) && !pdf_is_dict(ctx, obj_ref) && !pdf_is_array(ctx, obj_ref))
		return pdf_keep_obj(ctx, obj_ref);

	if (map == NULL)
		drop_map = map = pdf_new_graft_map(ctx, src);
	else if (src != map->src)
		fz_throw(ctx, FZ_ERROR_GENERIC, "graft map does not belong to the source document");

	bound = pdf_get_bound_document(ctx, obj_ref);
	if (bound && bound != src)
		fz_throw(ctx, FZ_ERROR_GENERIC, "grafted object does not belong to the source document");

	if (pdf_is_indirect(ctx, obj_ref))
	{
		src_num = pdf_to_num(ctx, obj_ref);

		if (src_num < 1 || src_num >= map->len)
		{
			pdf_drop_graft_map(ctx, drop_map);
			fz_throw(ctx, FZ_ERROR_GENERIC, "source object number out of range");
		}

		/* Check if we have done this one.  If yes, then drop map (if allocated)
		 * and return our indirect ref */
		if (map->dst_from_src[src_num] != 0)
		{
			int dest_num = map->dst_from_src[src_num];
			pdf_drop_graft_map(ctx, drop_map);
			return pdf_new_indirect(ctx, dst, dest_num, 0);
		}

		fz_var(buffer);
		fz_var(ref);

		fz_try(ctx)
		{
			/* Create new slot for our src object, set the mapping and call again
			 * using the resolved indirect reference */
			new_num = pdf_create_object(ctx, dst);
			map->dst_from_src[src_num] = new_num;
			new_obj = pdf_graft_object(ctx, dst, src, pdf_resolve_indirect(ctx, obj_ref), map);

			/* Return a ref to the new_obj making sure to attach any stream */
			pdf_update_object(ctx, dst, new_num, new_obj);
			pdf_drop_obj(ctx, new_obj);
			ref = pdf_new_indirect(ctx, dst, new_num, 0);
			if (pdf_is_stream(ctx, obj_ref))
			{
				buffer = pdf_load_raw_stream_number(ctx, src, src_num);
				pdf_update_stream(ctx, dst, ref, buffer, 1);
			}
		}
		fz_always(ctx)
		{
			fz_drop_buffer(ctx, buffer);
			pdf_drop_graft_map(ctx, drop_map);
		}
		fz_catch(ctx)
		{
			pdf_drop_obj(ctx, ref);
			fz_rethrow(ctx);
		}
		return ref;
	}
	else if (pdf_is_dict(ctx, obj_ref))
	{
		fz_var(new_dict);

		fz_try(ctx)
		{
			len = pdf_dict_len(ctx, obj_ref);
			new_dict = pdf_new_dict(ctx, dst, len);

			for (i = 0; i < len; i++)
			{
				key = pdf_dict_get_key(ctx, obj_ref, i);
				val = pdf_dict_get_val(ctx, obj_ref, i);
				pdf_dict_put_drop(ctx, new_dict, key, pdf_graft_object(ctx, dst, src, val, map));
			}
		}
		fz_always(ctx)
		{
			pdf_drop_graft_map(ctx, drop_map);
		}
		fz_catch(ctx)
		{
			pdf_drop_obj(ctx, new_dict);
			fz_rethrow(ctx);
		}
		return new_dict;
	}
	else if (pdf_is_array(ctx, obj_ref))
	{
		fz_var(new_array);

		fz_try(ctx)
		{
			/* Step through the array items handling indirect refs */
			len = pdf_array_len(ctx, obj_ref);
			new_array = pdf_new_array(ctx, dst, len);

			for (i = 0; i < len; i++)
			{
				val = pdf_array_get(ctx, obj_ref, i);
				pdf_array_push_drop(ctx, new_array, pdf_graft_object(ctx, dst, src, val, map));
			}
		}
		fz_always(ctx)
		{
			pdf_drop_graft_map(ctx, drop_map);
		}
		fz_catch(ctx)
		{
			pdf_drop_obj(ctx, new_array);
			fz_rethrow(ctx);
		}
		return new_array;
	}
	else
	{
		pdf_drop_graft_map(ctx, drop_map);
		return pdf_keep_obj(ctx, obj_ref);;
	}
}
