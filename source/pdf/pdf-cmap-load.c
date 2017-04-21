#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

size_t
pdf_cmap_size(fz_context *ctx, pdf_cmap *cmap)
{
	if (cmap == NULL)
		return 0;
	if (cmap->storable.refs < 0)
		return 0;

	return pdf_cmap_size(ctx, cmap->usecmap) +
		cmap->rcap * sizeof *cmap->ranges +
		cmap->xcap * sizeof *cmap->xranges +
		cmap->mcap * sizeof *cmap->mranges;
}

/*
 * Load CMap stream in PDF file
 */
pdf_cmap *
pdf_load_embedded_cmap(fz_context *ctx, pdf_document *doc, pdf_obj *stmobj)
{
	fz_stream *file = NULL;
	pdf_cmap *cmap = NULL;
	pdf_cmap *usecmap = NULL;
	pdf_obj *obj;

	fz_var(file);
	fz_var(cmap);
	fz_var(usecmap);

	if (pdf_obj_marked(ctx, stmobj))
		fz_throw(ctx, FZ_ERROR_GENERIC, "Recursion in embedded cmap");

	if ((cmap = pdf_find_item(ctx, pdf_drop_cmap_imp, stmobj)) != NULL)
		return cmap;

	fz_try(ctx)
	{
		file = pdf_open_stream(ctx, stmobj);
		cmap = pdf_load_cmap(ctx, file);

		obj = pdf_dict_get(ctx, stmobj, PDF_NAME_WMode);
		if (pdf_is_int(ctx, obj))
			pdf_set_cmap_wmode(ctx, cmap, pdf_to_int(ctx, obj));

		obj = pdf_dict_get(ctx, stmobj, PDF_NAME_UseCMap);
		if (pdf_is_name(ctx, obj))
		{
			usecmap = pdf_load_system_cmap(ctx, pdf_to_name(ctx, obj));
			pdf_set_usecmap(ctx, cmap, usecmap);
		}
		else if (pdf_is_indirect(ctx, obj))
		{
			if (pdf_mark_obj(ctx, obj))
				fz_throw(ctx, FZ_ERROR_GENERIC, "recursive CMap");
			fz_try(ctx)
				usecmap = pdf_load_embedded_cmap(ctx, doc, obj);
			fz_always(ctx)
				pdf_unmark_obj(ctx, obj);
			fz_catch(ctx)
				fz_rethrow(ctx);
			pdf_set_usecmap(ctx, cmap, usecmap);
		}

		pdf_store_item(ctx, stmobj, cmap, pdf_cmap_size(ctx, cmap));
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, file);
		pdf_drop_cmap(ctx, usecmap);
	}
	fz_catch(ctx)
	{
		pdf_drop_cmap(ctx, cmap);
		fz_rethrow(ctx);
	}

	return cmap;
}

/*
 * Create an Identity-* CMap (for both 1 and 2-byte encodings)
 */
pdf_cmap *
pdf_new_identity_cmap(fz_context *ctx, int wmode, int bytes)
{
	pdf_cmap *cmap = pdf_new_cmap(ctx);
	fz_try(ctx)
	{
		unsigned int high = (1 << (bytes * 8)) - 1;
		if (wmode)
			fz_strlcpy(cmap->cmap_name, "Identity-V", sizeof cmap->cmap_name);
		else
			fz_strlcpy(cmap->cmap_name, "Identity-H", sizeof cmap->cmap_name);
		pdf_add_codespace(ctx, cmap, 0, high, bytes);
		pdf_map_range_to_range(ctx, cmap, 0, high, 0);
		pdf_sort_cmap(ctx, cmap);
		pdf_set_cmap_wmode(ctx, cmap, wmode);
	}
	fz_catch(ctx)
	{
		pdf_drop_cmap(ctx, cmap);
		fz_rethrow(ctx);
	}
	return cmap;
}

/*
 * Load predefined CMap from system.
 */
pdf_cmap *
pdf_load_system_cmap(fz_context *ctx, const char *cmap_name)
{
	pdf_cmap *usecmap;
	pdf_cmap *cmap;

	cmap = pdf_load_builtin_cmap(ctx, cmap_name);
	if (!cmap)
		fz_throw(ctx, FZ_ERROR_GENERIC, "no builtin cmap file: %s", cmap_name);

	if (cmap->usecmap_name[0] && !cmap->usecmap)
	{
		usecmap = pdf_load_system_cmap(ctx, cmap->usecmap_name);
		if (!usecmap)
			fz_throw(ctx, FZ_ERROR_GENERIC, "no builtin cmap file: %s", cmap->usecmap_name);
		pdf_set_usecmap(ctx, cmap, usecmap);
	}

	return cmap;
}
