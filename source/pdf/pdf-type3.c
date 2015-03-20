#include "mupdf/pdf.h"

static void
pdf_run_glyph_func(fz_context *ctx, void *doc, void *rdb, fz_buffer *contents, fz_device *dev, const fz_matrix *ctm, void *gstate, int nested_depth)
{
	pdf_run_glyph(ctx, doc, (pdf_obj *)rdb, contents, dev, ctm, gstate, nested_depth);
}

static void
pdf_t3_free_resources(fz_context *ctx, void *doc, void *rdb_)
{
	pdf_obj *rdb = (pdf_obj *)rdb_;
	pdf_drop_obj(ctx, rdb);
}

pdf_font_desc *
pdf_load_type3_font(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, pdf_obj *dict)
{
	char buf[256];
	char *estrings[256];
	pdf_font_desc *fontdesc = NULL;
	pdf_obj *encoding;
	pdf_obj *widths;
	pdf_obj *charprocs;
	pdf_obj *obj;
	int first, last;
	int i, k, n;
	fz_rect bbox;
	fz_matrix matrix;

	fz_var(fontdesc);

	/* Make a new type3 font entry in the document */
	if (doc->num_type3_fonts == doc->max_type3_fonts)
	{
		int new_max = doc->max_type3_fonts * 2;

		if (new_max == 0)
			new_max = 4;
		doc->type3_fonts = fz_resize_array(ctx, doc->type3_fonts, new_max, sizeof(*doc->type3_fonts));
		doc->max_type3_fonts = new_max;
	}

	fz_try(ctx)
	{
		obj = pdf_dict_get(ctx, dict, PDF_NAME_Name);
		if (pdf_is_name(ctx, obj))
			fz_strlcpy(buf, pdf_to_name(ctx, obj), sizeof buf);
		else
			fz_strlcpy(buf, "Unnamed-T3", sizeof buf);

		fontdesc = pdf_new_font_desc(ctx);

		obj = pdf_dict_get(ctx, dict, PDF_NAME_FontMatrix);
		pdf_to_matrix(ctx, obj, &matrix);

		obj = pdf_dict_get(ctx, dict, PDF_NAME_FontBBox);
		fz_transform_rect(pdf_to_rect(ctx, obj, &bbox), &matrix);

		fontdesc->font = fz_new_type3_font(ctx, buf, &matrix);
		fontdesc->size += sizeof(fz_font) + 256 * (sizeof(fz_buffer*) + sizeof(float));

		fz_set_font_bbox(ctx, fontdesc->font, bbox.x0, bbox.y0, bbox.x1, bbox.y1);

		/* Encoding */

		for (i = 0; i < 256; i++)
			estrings[i] = NULL;

		encoding = pdf_dict_get(ctx, dict, PDF_NAME_Encoding);
		if (!encoding)
		{
			fz_throw(ctx, FZ_ERROR_GENERIC, "syntaxerror: Type3 font missing Encoding");
		}

		if (pdf_is_name(ctx, encoding))
			pdf_load_encoding(estrings, pdf_to_name(ctx, encoding));

		if (pdf_is_dict(ctx, encoding))
		{
			pdf_obj *base, *diff, *item;

			base = pdf_dict_get(ctx, encoding, PDF_NAME_BaseEncoding);
			if (pdf_is_name(ctx, base))
				pdf_load_encoding(estrings, pdf_to_name(ctx, base));

			diff = pdf_dict_get(ctx, encoding, PDF_NAME_Differences);
			if (pdf_is_array(ctx, diff))
			{
				n = pdf_array_len(ctx, diff);
				k = 0;
				for (i = 0; i < n; i++)
				{
					item = pdf_array_get(ctx, diff, i);
					if (pdf_is_int(ctx, item))
						k = pdf_to_int(ctx, item);
					if (pdf_is_name(ctx, item) && k >= 0 && k < nelem(estrings))
						estrings[k++] = pdf_to_name(ctx, item);
				}
			}
		}

		fontdesc->encoding = pdf_new_identity_cmap(ctx, 0, 1);
		fontdesc->size += pdf_cmap_size(ctx, fontdesc->encoding);

		pdf_load_to_unicode(ctx, doc, fontdesc, estrings, NULL, pdf_dict_get(ctx, dict, PDF_NAME_ToUnicode));

		/* Widths */

		pdf_set_default_hmtx(ctx, fontdesc, 0);

		first = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_FirstChar));
		last = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_LastChar));

		if (first < 0 || last > 255 || first > last)
			first = last = 0;

		widths = pdf_dict_get(ctx, dict, PDF_NAME_Widths);
		if (!widths)
		{
			fz_throw(ctx, FZ_ERROR_GENERIC, "syntaxerror: Type3 font missing Widths");
		}

		for (i = first; i <= last; i++)
		{
			float w = pdf_to_real(ctx, pdf_array_get(ctx, widths, i - first));
			w = fontdesc->font->t3matrix.a * w * 1000;
			fontdesc->font->t3widths[i] = w * 0.001f;
			pdf_add_hmtx(ctx, fontdesc, i, i, w);
		}

		pdf_end_hmtx(ctx, fontdesc);

		/* Resources -- inherit page resources if the font doesn't have its own */

		fontdesc->font->t3freeres = pdf_t3_free_resources;
		fontdesc->font->t3resources = pdf_dict_get(ctx, dict, PDF_NAME_Resources);
		if (!fontdesc->font->t3resources)
			fontdesc->font->t3resources = rdb;
		if (fontdesc->font->t3resources)
			pdf_keep_obj(ctx, fontdesc->font->t3resources);
		if (!fontdesc->font->t3resources)
			fz_warn(ctx, "no resource dictionary for type 3 font!");

		fontdesc->font->t3doc = doc;
		fontdesc->font->t3run = pdf_run_glyph_func;

		/* CharProcs */

		charprocs = pdf_dict_get(ctx, dict, PDF_NAME_CharProcs);
		if (!charprocs)
		{
			fz_throw(ctx, FZ_ERROR_GENERIC, "syntaxerror: Type3 font missing CharProcs");
		}

		for (i = 0; i < 256; i++)
		{
			if (estrings[i])
			{
				obj = pdf_dict_gets(ctx, charprocs, estrings[i]);
				if (pdf_is_stream(ctx, doc, pdf_to_num(ctx, obj), pdf_to_gen(ctx, obj)))
				{
					fontdesc->font->t3procs[i] = pdf_load_stream(ctx, doc, pdf_to_num(ctx, obj), pdf_to_gen(ctx, obj));
					fontdesc->size += fontdesc->font->t3procs[i]->cap;
					fontdesc->size += 0; // TODO: display list size calculation
				}
			}
		}
	}
	fz_catch(ctx)
	{
		if (fontdesc)
			pdf_drop_font(ctx, fontdesc);
		fz_rethrow_message(ctx, "cannot load type3 font (%d %d R)", pdf_to_num(ctx, dict), pdf_to_gen(ctx, dict));
	}

	doc->type3_fonts[doc->num_type3_fonts++] = fz_keep_font(ctx, fontdesc->font);

	return fontdesc;
}

void pdf_load_type3_glyphs(fz_context *ctx, pdf_document *doc, pdf_font_desc *fontdesc, int nested_depth)
{
	int i;

	fz_try(ctx)
	{
		for (i = 0; i < 256; i++)
		{
			if (fontdesc->font->t3procs[i])
			{
				fz_prepare_t3_glyph(ctx, fontdesc->font, i, nested_depth);
				fontdesc->size += 0; // TODO: display list size calculation
			}
		}
	}
	fz_catch(ctx)
	{
		fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
		fz_warn(ctx, "Type3 glyph load failed: %s", fz_caught_message(ctx));
	}
}
