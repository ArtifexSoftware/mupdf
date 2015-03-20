#include "mupdf/pdf.h"

pdf_pattern *
pdf_keep_pattern(fz_context *ctx, pdf_pattern *pat)
{
	return (pdf_pattern *)fz_keep_storable(ctx, &pat->storable);
}

void
pdf_drop_pattern(fz_context *ctx, pdf_pattern *pat)
{
	fz_drop_storable(ctx, &pat->storable);
}

static void
pdf_drop_pattern_imp(fz_context *ctx, fz_storable *pat_)
{
	pdf_pattern *pat = (pdf_pattern *)pat_;
	if (pat->resources)
		pdf_drop_obj(ctx, pat->resources);
	if (pat->contents)
		pdf_drop_obj(ctx, pat->contents);
	fz_free(ctx, pat);
}

static unsigned int
pdf_pattern_size(pdf_pattern *pat)
{
	if (pat == NULL)
		return 0;
	return sizeof(*pat);
}

pdf_pattern *
pdf_load_pattern(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	pdf_pattern *pat;
	pdf_obj *obj;

	if ((pat = pdf_find_item(ctx, pdf_drop_pattern_imp, dict)) != NULL)
	{
		return pat;
	}

	pat = fz_malloc_struct(ctx, pdf_pattern);
	FZ_INIT_STORABLE(pat, 1, pdf_drop_pattern_imp);
	pat->document = doc;
	pat->resources = NULL;
	pat->contents = NULL;

	fz_try(ctx)
	{
		/* Store pattern now, to avoid possible recursion if objects refer back to this one */
		pdf_store_item(ctx, dict, pat, pdf_pattern_size(pat));

		pat->ismask = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_PaintType)) == 2;
		pat->xstep = pdf_to_real(ctx, pdf_dict_get(ctx, dict, PDF_NAME_XStep));
		pat->ystep = pdf_to_real(ctx, pdf_dict_get(ctx, dict, PDF_NAME_YStep));

		obj = pdf_dict_gets(ctx, dict, "BBox");
		pdf_to_rect(ctx, obj, &pat->bbox);

		obj = pdf_dict_gets(ctx, dict, "Matrix");
		if (obj)
			pdf_to_matrix(ctx, obj, &pat->matrix);
		else
			pat->matrix = fz_identity;

		pat->resources = pdf_dict_get(ctx, dict, PDF_NAME_Resources);
		if (pat->resources)
			pdf_keep_obj(ctx, pat->resources);

		pat->contents = pdf_keep_obj(ctx, dict);
	}
	fz_catch(ctx)
	{
		pdf_remove_item(ctx, pdf_drop_pattern_imp, dict);
		pdf_drop_pattern(ctx, pat);
		fz_rethrow_message(ctx, "cannot load pattern (%d %d R)", pdf_to_num(ctx, dict), pdf_to_gen(ctx, dict));
	}
	return pat;
}
