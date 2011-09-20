#include "fitz.h"
#include "mupdf.h"

fz_error
pdf_load_pattern(pdf_pattern **patp, pdf_xref *xref, fz_obj *dict)
{
	fz_error error;
	pdf_pattern *pat;
	fz_obj *obj;
	fz_context *ctx = xref->ctx;

	if ((*patp = pdf_find_item(ctx, xref->store, (pdf_store_drop_fn *)pdf_drop_pattern, dict)))
	{
		pdf_keep_pattern(*patp);
		return fz_okay;
	}

	pat = fz_malloc(ctx, sizeof(pdf_pattern));
	pat->refs = 1;
	pat->resources = NULL;
	pat->contents = NULL;

	/* Store pattern now, to avoid possible recursion if objects refer back to this one */
	pdf_store_item(ctx, xref->store, (pdf_store_keep_fn *)pdf_keep_pattern, (pdf_store_drop_fn *)pdf_drop_pattern, dict, pat);

	pat->ismask = fz_to_int(fz_dict_gets(dict, "PaintType")) == 2;
	pat->xstep = fz_to_real(fz_dict_gets(dict, "XStep"));
	pat->ystep = fz_to_real(fz_dict_gets(dict, "YStep"));

	obj = fz_dict_gets(dict, "BBox");
	pat->bbox = pdf_to_rect(ctx, obj);

	obj = fz_dict_gets(dict, "Matrix");
	if (obj)
		pat->matrix = pdf_to_matrix(ctx, obj);
	else
		pat->matrix = fz_identity;

	pat->resources = fz_dict_gets(dict, "Resources");
	if (pat->resources)
		fz_keep_obj(pat->resources);

	error = pdf_load_stream(&pat->contents, xref, fz_to_num(dict), fz_to_gen(dict));
	if (error)
	{
		pdf_remove_item(ctx, xref->store, (pdf_store_drop_fn *)pdf_drop_pattern, dict);
		pdf_drop_pattern(ctx, pat);
		return fz_error_note(error, "cannot load pattern stream (%d %d R)", fz_to_num(dict), fz_to_gen(dict));
	}

	*patp = pat;
	return fz_okay;
}

pdf_pattern *
pdf_keep_pattern(pdf_pattern *pat)
{
	pat->refs ++;
	return pat;
}

void
pdf_drop_pattern(fz_context *ctx, pdf_pattern *pat)
{
	if (pat && --pat->refs == 0)
	{
		if (pat->resources)
			fz_drop_obj(pat->resources);
		if (pat->contents)
			fz_drop_buffer(ctx, pat->contents);
		fz_free(ctx, pat);
	}
}
