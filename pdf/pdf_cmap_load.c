#include "fitz.h"
#include "mupdf.h"

/*
 * Load CMap stream in PDF file
 */
fz_error
pdf_load_embedded_cmap(pdf_cmap **cmapp, pdf_xref *xref, fz_obj *stmobj)
{
	fz_error error = fz_okay;
	fz_stream *file = NULL;
	pdf_cmap *cmap = NULL;
	pdf_cmap *usecmap;
	fz_obj *wmode;
	fz_obj *obj;
	fz_context *ctx = xref->ctx;

	if ((*cmapp = pdf_find_item(ctx, xref->store, (pdf_store_drop_fn *)pdf_drop_cmap, stmobj)))
	{
		pdf_keep_cmap(*cmapp);
		return fz_okay;
	}

	error = pdf_open_stream(&file, xref, fz_to_num(stmobj), fz_to_gen(stmobj));
	if (error)
	{
		error = fz_error_note(error, "cannot open cmap stream (%d %d R)", fz_to_num(stmobj), fz_to_gen(stmobj));
		goto cleanup;
	}

	error = pdf_parse_cmap(&cmap, file);
	if (error)
	{
		error = fz_error_note(error, "cannot parse cmap stream (%d %d R)", fz_to_num(stmobj), fz_to_gen(stmobj));
		goto cleanup;
	}

	fz_close(file);

	wmode = fz_dict_gets(stmobj, "WMode");
	if (fz_is_int(wmode))
		pdf_set_wmode(cmap, fz_to_int(wmode));

	obj = fz_dict_gets(stmobj, "UseCMap");
	if (fz_is_name(obj))
	{
		error = pdf_load_system_cmap(ctx, &usecmap, fz_to_name(obj));
		if (error)
		{
			error = fz_error_note(error, "cannot load system usecmap '%s'", fz_to_name(obj));
			goto cleanup;
		}
		pdf_set_usecmap(ctx, cmap, usecmap);
		pdf_drop_cmap(ctx, usecmap);
	}
	else if (fz_is_indirect(obj))
	{
		error = pdf_load_embedded_cmap(&usecmap, xref, obj);
		if (error)
		{
			error = fz_error_note(error, "cannot load embedded usecmap (%d %d R)", fz_to_num(obj), fz_to_gen(obj));
			goto cleanup;
		}
		pdf_set_usecmap(ctx, cmap, usecmap);
		pdf_drop_cmap(ctx, usecmap);
	}

	pdf_store_item(ctx, xref->store, (pdf_store_keep_fn *)pdf_keep_cmap, (pdf_store_drop_fn *)pdf_drop_cmap, stmobj, cmap);

	*cmapp = cmap;
	return fz_okay;

cleanup:
	if (file)
		fz_close(file);
	if (cmap)
		pdf_drop_cmap(ctx, cmap);
	return error; /* already rethrown */
}

/*
 * Create an Identity-* CMap (for both 1 and 2-byte encodings)
 */
pdf_cmap *
pdf_new_identity_cmap(fz_context *ctx, int wmode, int bytes)
{
	pdf_cmap *cmap = pdf_new_cmap(ctx);
	sprintf(cmap->cmap_name, "Identity-%c", wmode ? 'V' : 'H');
	pdf_add_codespace(ctx, cmap, 0x0000, 0xffff, bytes);
	pdf_map_range_to_range(ctx, cmap, 0x0000, 0xffff, 0);
	pdf_sort_cmap(ctx, cmap);
	pdf_set_wmode(cmap, wmode);
	return cmap;
}

/*
 * Load predefined CMap from system.
 */
fz_error
pdf_load_system_cmap(fz_context *ctx, pdf_cmap **cmapp, char *cmap_name)
{
	pdf_cmap *usecmap;
	pdf_cmap *cmap;

	cmap = pdf_find_builtin_cmap(cmap_name);
	if (!cmap)
		return fz_error_make("no builtin cmap file: %s", cmap_name);

	if (cmap->usecmap_name[0] && !cmap->usecmap)
	{
		usecmap = pdf_find_builtin_cmap(cmap->usecmap_name);
		if (!usecmap)
			return fz_error_make("nu builtin cmap file: %s", cmap->usecmap_name);
		pdf_set_usecmap(ctx, cmap, usecmap);
	}

	*cmapp = cmap;
	return fz_okay;
}
