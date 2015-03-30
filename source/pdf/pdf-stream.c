#include "mupdf/pdf.h"

/*
 * Check if an object is a stream or not.
 */
int
pdf_is_stream(fz_context *ctx, pdf_document *doc, int num, int gen)
{
	pdf_xref_entry *entry;

	if (num <= 0 || num >= pdf_xref_len(ctx, doc))
		return 0;

	entry = pdf_cache_object(ctx, doc, num, gen);

	return entry->stm_ofs != 0 || entry->stm_buf;
}

/*
 * Scan stream dictionary for an explicit /Crypt filter
 */
static int
pdf_stream_has_crypt(fz_context *ctx, pdf_obj *stm)
{
	pdf_obj *filters;
	pdf_obj *obj;
	int i;

	filters = pdf_dict_geta(ctx, stm, PDF_NAME_Filter, PDF_NAME_F);
	if (filters)
	{
		if (pdf_name_eq(ctx, filters, PDF_NAME_Crypt))
			return 1;
		if (pdf_is_array(ctx, filters))
		{
			int n = pdf_array_len(ctx, filters);
			for (i = 0; i < n; i++)
			{
				obj = pdf_array_get(ctx, filters, i);
				if (pdf_name_eq(ctx, obj, PDF_NAME_Crypt))
					return 1;
			}
		}
	}
	return 0;
}

static fz_jbig2_globals *
pdf_load_jbig2_globals(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	fz_jbig2_globals *globals;
	fz_buffer *buf = NULL;

	fz_var(buf);

	if ((globals = pdf_find_item(ctx, fz_drop_jbig2_globals_imp, dict)) != NULL)
	{
		return globals;
	}

	fz_try(ctx)
	{
		buf = pdf_load_stream(ctx, doc, pdf_to_num(ctx, dict), pdf_to_gen(ctx, dict));
		globals = fz_load_jbig2_globals(ctx, buf->data, buf->len);
		pdf_store_item(ctx, dict, globals, buf->len);
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return globals;
}

static void
build_compression_params(fz_context *ctx, pdf_obj *f, pdf_obj *p, fz_compression_params *params)
{
	int predictor = pdf_to_int(ctx, pdf_dict_get(ctx, p, PDF_NAME_Predictor));
	pdf_obj *columns_obj = pdf_dict_get(ctx, p, PDF_NAME_Columns);
	int columns = pdf_to_int(ctx, columns_obj);
	int colors = pdf_to_int(ctx, pdf_dict_get(ctx, p, PDF_NAME_Colors));
	int bpc = pdf_to_int(ctx, pdf_dict_get(ctx, p, PDF_NAME_BitsPerComponent));

	params->type = FZ_IMAGE_RAW;

	if (pdf_name_eq(ctx, f, PDF_NAME_CCITTFaxDecode) || pdf_name_eq(ctx, f, PDF_NAME_CCF))
	{
		pdf_obj *k = pdf_dict_get(ctx, p, PDF_NAME_K);
		pdf_obj *eol = pdf_dict_get(ctx, p, PDF_NAME_EndOfLine);
		pdf_obj *eba = pdf_dict_get(ctx, p, PDF_NAME_EncodedByteAlign);
		pdf_obj *rows = pdf_dict_get(ctx, p, PDF_NAME_Rows);
		pdf_obj *eob = pdf_dict_get(ctx, p, PDF_NAME_EndOfBlock);
		pdf_obj *bi1 = pdf_dict_get(ctx, p, PDF_NAME_BlackIs1);

		params->type = FZ_IMAGE_FAX;
		params->u.fax.k = (k ? pdf_to_int(ctx, k) : 0);
		params->u.fax.end_of_line = (eol ? pdf_to_bool(ctx, eol) : 0);
		params->u.fax.encoded_byte_align = (eba ? pdf_to_bool(ctx, eba) : 0);
		params->u.fax.columns = (columns_obj ? columns : 1728);
		params->u.fax.rows = (rows ? pdf_to_int(ctx, rows) : 0);
		params->u.fax.end_of_block = (eob ? pdf_to_bool(ctx, eob) : 1);
		params->u.fax.black_is_1 = (bi1 ? pdf_to_bool(ctx, bi1) : 0);
	}
	else if (pdf_name_eq(ctx, f, PDF_NAME_DCTDecode) || pdf_name_eq(ctx, f, PDF_NAME_DCT))
	{
		pdf_obj *ct = pdf_dict_get(ctx, p, PDF_NAME_ColorTransform);

		params->type = FZ_IMAGE_JPEG;
		params->u.jpeg.color_transform = (ct ? pdf_to_int(ctx, ct) : -1);
	}
	else if (pdf_name_eq(ctx, f, PDF_NAME_RunLengthDecode) || pdf_name_eq(ctx, f, PDF_NAME_RL))
	{
		params->type = FZ_IMAGE_RLD;
	}
	else if (pdf_name_eq(ctx, f, PDF_NAME_FlateDecode) || pdf_name_eq(ctx, f, PDF_NAME_Fl))
	{
		params->type = FZ_IMAGE_FLATE;
		params->u.flate.predictor = predictor;
		params->u.flate.columns = columns;
		params->u.flate.colors = colors;
		params->u.flate.bpc = bpc;
	}
	else if (pdf_name_eq(ctx, f, PDF_NAME_LZWDecode) || pdf_name_eq(ctx, f, PDF_NAME_LZW))
	{
		pdf_obj *ec = pdf_dict_get(ctx, p, PDF_NAME_EarlyChange);

		params->type = FZ_IMAGE_LZW;
		params->u.lzw.predictor = predictor;
		params->u.lzw.columns = columns;
		params->u.lzw.colors = colors;
		params->u.lzw.bpc = bpc;
		params->u.lzw.early_change = (ec ? pdf_to_int(ctx, ec) : 1);
	}
}

/*
 * Create a filter given a name and param dictionary.
 */
static fz_stream *
build_filter(fz_context *ctx, fz_stream *chain, pdf_document *doc, pdf_obj *f, pdf_obj *p, int num, int gen, fz_compression_params *params)
{
	fz_compression_params local_params;

	if (params == NULL)
		params = &local_params;

	build_compression_params(ctx, f, p, params);

	/* If we were using params we were passed in, and we successfully
	 * recognised the image type, we can use the existing filter and
	 * shortstop here. */
	if (params != &local_params && params->type != FZ_IMAGE_RAW)
		return chain;

	if (params->type != FZ_IMAGE_RAW)
		return fz_open_image_decomp_stream(ctx, chain, params, NULL);

	if (pdf_name_eq(ctx, f, PDF_NAME_ASCIIHexDecode) || pdf_name_eq(ctx, f, PDF_NAME_AHx))
		return fz_open_ahxd(ctx, chain);

	else if (pdf_name_eq(ctx, f, PDF_NAME_ASCII85Decode) || pdf_name_eq(ctx, f, PDF_NAME_A85))
		return fz_open_a85d(ctx, chain);

	else if (pdf_name_eq(ctx, f, PDF_NAME_JBIG2Decode))
	{
		fz_jbig2_globals *globals = NULL;
		pdf_obj *obj = pdf_dict_get(ctx, p, PDF_NAME_JBIG2Globals);
		if (pdf_is_indirect(ctx, obj))
			globals = pdf_load_jbig2_globals(ctx, doc, obj);
		/* fz_open_jbig2d takes possession of globals */
		return fz_open_jbig2d(ctx, chain, globals);
	}

	else if (pdf_name_eq(ctx, f, PDF_NAME_JPXDecode))
		return chain; /* JPX decoding is special cased in the image loading code */

	else if (pdf_name_eq(ctx, f, PDF_NAME_Crypt))
	{
		pdf_obj *name;

		if (!doc->crypt)
		{
			fz_warn(ctx, "crypt filter in unencrypted document");
			return chain;
		}

		name = pdf_dict_get(ctx, p, PDF_NAME_Name);
		if (pdf_is_name(ctx, name))
			return pdf_open_crypt_with_filter(ctx, chain, doc->crypt, name, num, gen);

		return chain;
	}

	fz_warn(ctx, "unknown filter name (%s)", pdf_to_name(ctx, f));
	return chain;
}

/*
 * Build a chain of filters given filter names and param dicts.
 * If head is given, start filter chain with it.
 * Assume ownership of head.
 */
static fz_stream *
build_filter_chain(fz_context *ctx, fz_stream *chain, pdf_document *doc, pdf_obj *fs, pdf_obj *ps, int num, int gen, fz_compression_params *params)
{
	pdf_obj *f;
	pdf_obj *p;
	int i, n;

	fz_try(ctx)
	{
		n = pdf_array_len(ctx, fs);
		for (i = 0; i < n; i++)
		{
			fz_stream *chain2;

			f = pdf_array_get(ctx, fs, i);
			p = pdf_array_get(ctx, ps, i);
			chain2 = chain;
			chain = NULL;
			chain = build_filter(ctx, chain2, doc, f, p, num, gen, (i == n-1 ? params : NULL));
		}
	}
	fz_catch(ctx)
	{
		fz_drop_stream(ctx, chain);
		fz_rethrow(ctx);
	}

	return chain;
}

/*
 * Build a filter for reading raw stream data.
 * This is a null filter to constrain reading to the stream length (and to
 * allow for other people accessing the file), followed by a decryption
 * filter.
 *
 * orig_num and orig_gen are used purely to seed the encryption.
 */
static fz_stream *
pdf_open_raw_filter(fz_context *ctx, fz_stream *chain, pdf_document *doc, pdf_obj *stmobj, int num, int orig_num, int orig_gen, int offset)
{
	int hascrypt;
	int len;

	if (num > 0 && num < pdf_xref_len(ctx, doc))
	{
		pdf_xref_entry *entry = pdf_get_xref_entry(ctx, doc, num);
		if (entry->stm_buf)
			return fz_open_buffer(ctx, entry->stm_buf);
	}

	/* don't close chain when we close this filter */
	fz_keep_stream(ctx, chain);

	len = pdf_to_int(ctx, pdf_dict_get(ctx, stmobj, PDF_NAME_Length));
	chain = fz_open_null(ctx, chain, len, offset);

	hascrypt = pdf_stream_has_crypt(ctx, stmobj);
	if (doc->crypt && !hascrypt)
		chain = pdf_open_crypt(ctx, chain, doc->crypt, orig_num, orig_gen);

	return chain;
}

/*
 * Construct a filter to decode a stream, constraining
 * to stream length and decrypting.
 */
static fz_stream *
pdf_open_filter(fz_context *ctx, pdf_document *doc, fz_stream *chain, pdf_obj *stmobj, int num, int gen, int offset, fz_compression_params *imparams)
{
	pdf_obj *filters;
	pdf_obj *params;

	filters = pdf_dict_geta(ctx, stmobj, PDF_NAME_Filter, PDF_NAME_F);
	params = pdf_dict_geta(ctx, stmobj, PDF_NAME_DecodeParms, PDF_NAME_DP);

	chain = pdf_open_raw_filter(ctx, chain, doc, stmobj, num, num, gen, offset);

	fz_var(chain);

	fz_try(ctx)
	{
		if (pdf_is_name(ctx, filters))
		{
			fz_stream *chain2 = chain;
			chain = NULL;
			chain = build_filter(ctx, chain2, doc, filters, params, num, gen, imparams);
		}
		else if (pdf_array_len(ctx, filters) > 0)
		{
			fz_stream *chain2 = chain;
			chain = NULL;
			chain = build_filter_chain(ctx, chain2, doc, filters, params, num, gen, imparams);
		}
	}
	fz_catch(ctx)
	{
		fz_drop_stream(ctx, chain);
		fz_rethrow(ctx);
	}

	return chain;
}

/*
 * Construct a filter to decode a stream, without
 * constraining to stream length, and without decryption.
 */
fz_stream *
pdf_open_inline_stream(fz_context *ctx, pdf_document *doc, pdf_obj *stmobj, int length, fz_stream *chain, fz_compression_params *imparams)
{
	pdf_obj *filters;
	pdf_obj *params;

	filters = pdf_dict_geta(ctx, stmobj, PDF_NAME_Filter, PDF_NAME_F);
	params = pdf_dict_geta(ctx, stmobj, PDF_NAME_DecodeParms, PDF_NAME_DP);

	/* don't close chain when we close this filter */
	fz_keep_stream(ctx, chain);

	if (pdf_is_name(ctx, filters))
		return build_filter(ctx, chain, doc, filters, params, 0, 0, imparams);
	if (pdf_array_len(ctx, filters) > 0)
		return build_filter_chain(ctx, chain, doc, filters, params, 0, 0, imparams);

	if (imparams)
		imparams->type = FZ_IMAGE_RAW;
	return fz_open_null(ctx, chain, length, fz_tell(ctx, chain));
}

void
pdf_load_compressed_inline_image(fz_context *ctx, pdf_document *doc, pdf_obj *dict, int length, fz_stream *stm, int indexed, fz_image *image)
{
	fz_compressed_buffer *bc = fz_malloc_struct(ctx, fz_compressed_buffer);

	fz_try(ctx)
	{
		int dummy_l2factor = 0;
		bc->buffer = fz_new_buffer(ctx, 1024);

		stm = pdf_open_inline_stream(ctx, doc, dict, length, stm, &bc->params);
		stm = fz_open_leecher(ctx, stm, bc->buffer);
		stm = fz_open_image_decomp_stream(ctx, stm, &bc->params, &dummy_l2factor);

		image->tile = fz_decomp_image_from_stream(ctx, stm, image, indexed, 0, 0);
	}
	fz_catch(ctx)
	{
		fz_drop_compressed_buffer(ctx, bc);
		fz_rethrow(ctx);
	}
	image->buffer = bc;
}

/*
 * Open a stream for reading the raw (compressed but decrypted) data.
 */
fz_stream *
pdf_open_raw_stream(fz_context *ctx, pdf_document *doc, int num, int gen)
{
	return pdf_open_raw_renumbered_stream(ctx, doc, num, gen, num, gen);
}

fz_stream *
pdf_open_raw_renumbered_stream(fz_context *ctx, pdf_document *doc, int num, int gen, int orig_num, int orig_gen)
{
	pdf_xref_entry *x;

	if (num <= 0 || num >= pdf_xref_len(ctx, doc))
		fz_throw(ctx, FZ_ERROR_GENERIC, "object id out of range (%d %d R)", num, gen);

	x = pdf_cache_object(ctx, doc, num, gen);
	if (x->stm_ofs == 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "object is not a stream");

	return pdf_open_raw_filter(ctx, doc->file, doc, x->obj, num, orig_num, orig_gen, x->stm_ofs);
}

static fz_stream *
pdf_open_image_stream(fz_context *ctx, pdf_document *doc, int num, int gen, int orig_num, int orig_gen, fz_compression_params *params)
{
	pdf_xref_entry *x;

	if (num <= 0 || num >= pdf_xref_len(ctx, doc))
		fz_throw(ctx, FZ_ERROR_GENERIC, "object id out of range (%d %d R)", num, gen);

	x = pdf_cache_object(ctx, doc, num, gen);
	if (x->stm_ofs == 0 && x->stm_buf == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "object is not a stream");

	return pdf_open_filter(ctx, doc, doc->file, x->obj, orig_num, orig_gen, x->stm_ofs, params);
}

/*
 * Open a stream for reading uncompressed data.
 * Put the opened file in doc->stream.
 * Using doc->file while a stream is open is a Bad idea.
 */
fz_stream *
pdf_open_stream(fz_context *ctx, pdf_document *doc, int num, int gen)
{
	return pdf_open_image_stream(ctx, doc, num, gen, num, gen, NULL);
}

fz_stream *
pdf_open_stream_with_offset(fz_context *ctx, pdf_document *doc, int num, int gen, pdf_obj *dict, int stm_ofs)
{
	if (stm_ofs == 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "object is not a stream");

	return pdf_open_filter(ctx, doc, doc->file, dict, num, gen, stm_ofs, NULL);
}

/*
 * Load raw (compressed but decrypted) contents of a stream into buf.
 */
fz_buffer *
pdf_load_raw_stream(fz_context *ctx, pdf_document *doc, int num, int gen)
{
	return pdf_load_raw_renumbered_stream(ctx, doc, num, gen, num, gen);
}

fz_buffer *
pdf_load_raw_renumbered_stream(fz_context *ctx, pdf_document *doc, int num, int gen, int orig_num, int orig_gen)
{
	fz_stream *stm;
	pdf_obj *dict;
	int len;
	fz_buffer *buf;

	if (num > 0 && num < pdf_xref_len(ctx, doc))
	{
		pdf_xref_entry *entry = pdf_get_xref_entry(ctx, doc, num);
		if (entry->stm_buf)
			return fz_keep_buffer(ctx, entry->stm_buf);
	}

	dict = pdf_load_object(ctx, doc, num, gen);

	len = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_Length));

	pdf_drop_obj(ctx, dict);

	stm = pdf_open_raw_renumbered_stream(ctx, doc, num, gen, orig_num, orig_gen);

	buf = fz_read_all(ctx, stm, len);

	fz_drop_stream(ctx, stm);
	return buf;
}

static int
pdf_guess_filter_length(int len, char *filter)
{
	if (!strcmp(filter, "ASCIIHexDecode"))
		return len / 2;
	if (!strcmp(filter, "ASCII85Decode"))
		return len * 4 / 5;
	if (!strcmp(filter, "FlateDecode"))
		return len * 3;
	if (!strcmp(filter, "RunLengthDecode"))
		return len * 3;
	if (!strcmp(filter, "LZWDecode"))
		return len * 2;
	return len;
}

/* Check if an entry has a cached stream and return whether it is directly
 * reusable. A buffer is directly reusable only if the stream is
 * uncompressed, or if it is compressed purely a compression method we can
 * return details of in fz_compression_params.
 *
 * If the stream is reusable return 1, and set params as required, otherwise
 * return 0. */
static int
can_reuse_buffer(fz_context *ctx, pdf_xref_entry *entry, fz_compression_params *params)
{
	pdf_obj *f;
	pdf_obj *p;

	if (!entry || !entry->obj || !entry->stm_buf)
		return 0;

	if (params)
		params->type = FZ_IMAGE_RAW;

	f = pdf_dict_geta(ctx, entry->obj, PDF_NAME_Filter, PDF_NAME_F);
	/* If there are no filters, it's uncompressed, and we can use it */
	if (!f)
		return 1;

	p = pdf_dict_geta(ctx, entry->obj, PDF_NAME_DecodeParms, PDF_NAME_DP);
	if (pdf_is_array(ctx, f))
	{
		int len = pdf_array_len(ctx, f);

		/* Empty array of filters. It's uncompressed. We can cope. */
		if (len == 0)
			return 1;
		/* 1 filter is the most we can hope to cope with - if more,*/
		if (len != 1)
			return 0;
		p = pdf_array_get(ctx, p, 0);
	}
	if (pdf_is_null(ctx, f))
		return 1; /* Null filter is uncompressed */
	if (!pdf_is_name(ctx, f))
		return 0;

	/* There are filters, so unless we have the option of shortstopping,
	 * we can't use the existing buffer. */
	if (!params)
		return 0;

	build_compression_params(ctx, f, p, params);

	return (params->type == FZ_IMAGE_RAW) ? 0 : 1;

}

static fz_buffer *
pdf_load_image_stream(fz_context *ctx, pdf_document *doc, int num, int gen, int orig_num, int orig_gen, fz_compression_params *params, int *truncated)
{
	fz_stream *stm = NULL;
	pdf_obj *dict, *obj;
	int i, len, n;
	fz_buffer *buf;

	fz_var(buf);

	if (num > 0 && num < pdf_xref_len(ctx, doc))
	{
		pdf_xref_entry *entry = pdf_get_xref_entry(ctx, doc, num);
		/* Return ref to existing buffer, but only if uncompressed,
		 * or shortstoppable */
		if (can_reuse_buffer(ctx, entry, params))
			return fz_keep_buffer(ctx, entry->stm_buf);
	}

	dict = pdf_load_object(ctx, doc, num, gen);

	len = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_Length));
	obj = pdf_dict_get(ctx, dict, PDF_NAME_Filter);
	len = pdf_guess_filter_length(len, pdf_to_name(ctx, obj));
	n = pdf_array_len(ctx, obj);
	for (i = 0; i < n; i++)
		len = pdf_guess_filter_length(len, pdf_to_name(ctx, pdf_array_get(ctx, obj, i)));

	pdf_drop_obj(ctx, dict);

	stm = pdf_open_image_stream(ctx, doc, num, gen, orig_num, orig_gen, params);

	fz_try(ctx)
	{
		if (truncated)
			buf = fz_read_best(ctx, stm, len, truncated);
		else
			buf = fz_read_all(ctx, stm, len);
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, stm);
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "cannot read raw stream (%d %d R)", num, gen);
	}

	return buf;
}

/*
 * Load uncompressed contents of a stream into buf.
 */
fz_buffer *
pdf_load_stream(fz_context *ctx, pdf_document *doc, int num, int gen)
{
	return pdf_load_image_stream(ctx, doc, num, gen, num, gen, NULL, NULL);
}

fz_buffer *
pdf_load_renumbered_stream(fz_context *ctx, pdf_document *doc, int num, int gen, int orig_num, int orig_gen, int *truncated)
{
	return pdf_load_image_stream(ctx, doc, num, gen, orig_num, orig_gen, NULL, truncated);
}

fz_compressed_buffer *
pdf_load_compressed_stream(fz_context *ctx, pdf_document *doc, int num, int gen)
{
	fz_compressed_buffer *bc = fz_malloc_struct(ctx, fz_compressed_buffer);

	fz_try(ctx)
	{
		bc->buffer = pdf_load_image_stream(ctx, doc, num, gen, num, gen, &bc->params, NULL);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, bc);
		fz_rethrow(ctx);
	}
	return bc;
}

static fz_stream *
pdf_open_object_array(fz_context *ctx, pdf_document *doc, pdf_obj *list)
{
	fz_stream *stm;
	int i, n;

	n = pdf_array_len(ctx, list);
	stm = fz_open_concat(ctx, n, 1);

	fz_var(i); /* Workaround Mac compiler bug */
	for (i = 0; i < n; i++)
	{
		pdf_obj *obj = pdf_array_get(ctx, list, i);
		fz_try(ctx)
		{
			fz_concat_push(ctx, stm, pdf_open_stream(ctx, doc, pdf_to_num(ctx, obj), pdf_to_gen(ctx, obj)));
		}
		fz_catch(ctx)
		{
			fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
			fz_warn(ctx, "cannot load content stream part %d/%d", i + 1, n);
			continue;
		}
	}

	return stm;
}

fz_stream *
pdf_open_contents_stream(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	int num, gen;

	if (pdf_is_array(ctx, obj))
		return pdf_open_object_array(ctx, doc, obj);

	num = pdf_to_num(ctx, obj);
	gen = pdf_to_gen(ctx, obj);
	if (pdf_is_stream(ctx, doc, num, gen))
		return pdf_open_image_stream(ctx, doc, num, gen, num, gen, NULL);

	fz_throw(ctx, FZ_ERROR_GENERIC, "pdf object stream missing (%d %d R)", num, gen);
}
