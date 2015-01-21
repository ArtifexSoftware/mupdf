#include "mupdf/pdf.h"

fz_rect *
pdf_to_rect(fz_context *ctx, pdf_obj *array, fz_rect *r)
{
	float a = pdf_to_real(ctx, pdf_array_get(ctx, array, 0));
	float b = pdf_to_real(ctx, pdf_array_get(ctx, array, 1));
	float c = pdf_to_real(ctx, pdf_array_get(ctx, array, 2));
	float d = pdf_to_real(ctx, pdf_array_get(ctx, array, 3));
	r->x0 = fz_min(a, c);
	r->y0 = fz_min(b, d);
	r->x1 = fz_max(a, c);
	r->y1 = fz_max(b, d);
	return r;
}

fz_matrix *
pdf_to_matrix(fz_context *ctx, pdf_obj *array, fz_matrix *m)
{
	m->a = pdf_to_real(ctx, pdf_array_get(ctx, array, 0));
	m->b = pdf_to_real(ctx, pdf_array_get(ctx, array, 1));
	m->c = pdf_to_real(ctx, pdf_array_get(ctx, array, 2));
	m->d = pdf_to_real(ctx, pdf_array_get(ctx, array, 3));
	m->e = pdf_to_real(ctx, pdf_array_get(ctx, array, 4));
	m->f = pdf_to_real(ctx, pdf_array_get(ctx, array, 5));
	return m;
}

/* Convert Unicode/PdfDocEncoding string into utf-8 */
char *
pdf_to_utf8(fz_context *ctx, pdf_document *doc, pdf_obj *src)
{
	fz_buffer *strmbuf = NULL;
	unsigned char *srcptr;
	char *dstptr, *dst;
	int srclen;
	int dstlen = 0;
	int ucs;
	int i;

	fz_var(strmbuf);
	fz_try(ctx)
	{
		if (pdf_is_string(ctx, src))
		{
			srcptr = (unsigned char *) pdf_to_str_buf(ctx, src);
			srclen = pdf_to_str_len(ctx, src);
		}
		else if (pdf_is_stream(ctx, doc, pdf_to_num(ctx, src), pdf_to_gen(ctx, src)))
		{
			strmbuf = pdf_load_stream(ctx, doc, pdf_to_num(ctx, src), pdf_to_gen(ctx, src));
			srclen = fz_buffer_storage(ctx, strmbuf, (unsigned char **)&srcptr);
		}
		else
		{
			srclen = 0;
		}

		if (srclen >= 2 && srcptr[0] == 254 && srcptr[1] == 255)
		{
			for (i = 2; i + 1 < srclen; i += 2)
			{
				ucs = srcptr[i] << 8 | srcptr[i+1];
				dstlen += fz_runelen(ucs);
			}

			dstptr = dst = fz_malloc(ctx, dstlen + 1);

			for (i = 2; i + 1 < srclen; i += 2)
			{
				ucs = srcptr[i] << 8 | srcptr[i+1];
				dstptr += fz_runetochar(dstptr, ucs);
			}
		}
		else if (srclen >= 2 && srcptr[0] == 255 && srcptr[1] == 254)
		{
			for (i = 2; i + 1 < srclen; i += 2)
			{
				ucs = srcptr[i] | srcptr[i+1] << 8;
				dstlen += fz_runelen(ucs);
			}

			dstptr = dst = fz_malloc(ctx, dstlen + 1);

			for (i = 2; i + 1 < srclen; i += 2)
			{
				ucs = srcptr[i] | srcptr[i+1] << 8;
				dstptr += fz_runetochar(dstptr, ucs);
			}
		}
		else
		{
			for (i = 0; i < srclen; i++)
				dstlen += fz_runelen(pdf_doc_encoding[srcptr[i]]);

			dstptr = dst = fz_malloc(ctx, dstlen + 1);

			for (i = 0; i < srclen; i++)
			{
				ucs = pdf_doc_encoding[srcptr[i]];
				dstptr += fz_runetochar(dstptr, ucs);
			}
		}
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, strmbuf);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	*dstptr = '\0';
	return dst;
}

/* Convert Unicode/PdfDocEncoding string into ucs-2 */
unsigned short *
pdf_to_ucs2(fz_context *ctx, pdf_document *doc, pdf_obj *src)
{
	unsigned char *srcptr = (unsigned char *) pdf_to_str_buf(ctx, src);
	unsigned short *dstptr, *dst;
	int srclen = pdf_to_str_len(ctx, src);
	int i;

	if (srclen >= 2 && srcptr[0] == 254 && srcptr[1] == 255)
	{
		dstptr = dst = fz_malloc_array(ctx, (srclen - 2) / 2 + 1, sizeof(short));
		for (i = 2; i + 1 < srclen; i += 2)
			*dstptr++ = srcptr[i] << 8 | srcptr[i+1];
	}
	else if (srclen >= 2 && srcptr[0] == 255 && srcptr[1] == 254)
	{
		dstptr = dst = fz_malloc_array(ctx, (srclen - 2) / 2 + 1, sizeof(short));
		for (i = 2; i + 1 < srclen; i += 2)
			*dstptr++ = srcptr[i] | srcptr[i+1] << 8;
	}
	else
	{
		dstptr = dst = fz_malloc_array(ctx, srclen + 1, sizeof(short));
		for (i = 0; i < srclen; i++)
			*dstptr++ = pdf_doc_encoding[srcptr[i]];
	}

	*dstptr = '\0';
	return dst;
}

/* allow to convert to UCS-2 without the need for an fz_context */
/* (buffer must be at least (fz_to_str_len(src) + 1) * 2 bytes in size) */
void
pdf_to_ucs2_buf(fz_context *ctx, unsigned short *buffer, pdf_obj *src)
{
	unsigned char *srcptr = (unsigned char *) pdf_to_str_buf(ctx, src);
	unsigned short *dstptr = buffer;
	int srclen = pdf_to_str_len(ctx, src);
	int i;

	if (srclen >= 2 && srcptr[0] == 254 && srcptr[1] == 255)
	{
		for (i = 2; i + 1 < srclen; i += 2)
			*dstptr++ = srcptr[i] << 8 | srcptr[i+1];
	}
	else if (srclen >= 2 && srcptr[0] == 255 && srcptr[1] == 254)
	{
		for (i = 2; i + 1 < srclen; i += 2)
			*dstptr++ = srcptr[i] | srcptr[i+1] << 8;
	}
	else
	{
		for (i = 0; i < srclen; i++)
			*dstptr++ = pdf_doc_encoding[srcptr[i]];
	}

	*dstptr = '\0';
}

/* Convert UCS-2 string into PdfDocEncoding for authentication */
char *
pdf_from_ucs2(fz_context *ctx, pdf_document *doc, unsigned short *src)
{
	int i, j, len;
	char *docstr;

	len = 0;
	while (src[len])
		len++;

	docstr = fz_malloc(ctx, len + 1);

	for (i = 0; i < len; i++)
	{
		/* shortcut: check if the character has the same code point in both encodings */
		if (0 < src[i] && src[i] < 256 && pdf_doc_encoding[src[i]] == src[i]) {
			docstr[i] = src[i];
			continue;
		}

		/* search through pdf_docencoding for the character's code point */
		for (j = 0; j < 256; j++)
			if (pdf_doc_encoding[j] == src[i])
				break;
		docstr[i] = j;

		/* fail, if a character can't be encoded */
		if (!docstr[i])
		{
			fz_free(ctx, docstr);
			return NULL;
		}
	}
	docstr[len] = '\0';

	return docstr;
}

pdf_obj *
pdf_to_utf8_name(fz_context *ctx, pdf_document *doc, pdf_obj *src)
{
	char *buf = pdf_to_utf8(ctx, doc, src);
	pdf_obj *dst = pdf_new_name(ctx, doc, buf);
	fz_free(ctx, buf);
	return dst;
}

pdf_obj *
pdf_parse_array(fz_context *ctx, pdf_document *doc, fz_stream *file, pdf_lexbuf *buf)
{
	pdf_obj *ary = NULL;
	pdf_obj *obj = NULL;
	int a = 0, b = 0, n = 0;
	pdf_token tok;
	pdf_obj *op = NULL;

	fz_var(obj);

	ary = pdf_new_array(ctx, doc, 4);

	fz_try(ctx)
	{
		while (1)
		{
			tok = pdf_lex(ctx, file, buf);

			if (tok != PDF_TOK_INT && tok != PDF_TOK_R)
			{
				if (n > 0)
				{
					obj = pdf_new_int(ctx, doc, a);
					pdf_array_push(ctx, ary, obj);
					pdf_drop_obj(ctx, obj);
					obj = NULL;
				}
				if (n > 1)
				{
					obj = pdf_new_int(ctx, doc, b);
					pdf_array_push(ctx, ary, obj);
					pdf_drop_obj(ctx, obj);
					obj = NULL;
				}
				n = 0;
			}

			if (tok == PDF_TOK_INT && n == 2)
			{
				obj = pdf_new_int(ctx, doc, a);
				pdf_array_push(ctx, ary, obj);
				pdf_drop_obj(ctx, obj);
				obj = NULL;
				a = b;
				n --;
			}

			switch (tok)
			{
			case PDF_TOK_CLOSE_ARRAY:
				op = ary;
				goto end;

			case PDF_TOK_INT:
				if (n == 0)
					a = buf->i;
				if (n == 1)
					b = buf->i;
				n ++;
				break;

			case PDF_TOK_R:
				if (n != 2)
					fz_throw(ctx, FZ_ERROR_GENERIC, "cannot parse indirect reference in array");
				obj = pdf_new_indirect(ctx, doc, a, b);
				pdf_array_push(ctx, ary, obj);
				pdf_drop_obj(ctx, obj);
				obj = NULL;
				n = 0;
				break;

			case PDF_TOK_OPEN_ARRAY:
				obj = pdf_parse_array(ctx, doc, file, buf);
				pdf_array_push(ctx, ary, obj);
				pdf_drop_obj(ctx, obj);
				obj = NULL;
				break;

			case PDF_TOK_OPEN_DICT:
				obj = pdf_parse_dict(ctx, doc, file, buf);
				pdf_array_push(ctx, ary, obj);
				pdf_drop_obj(ctx, obj);
				obj = NULL;
				break;

			case PDF_TOK_NAME:
				obj = pdf_new_name(ctx, doc, buf->scratch);
				pdf_array_push(ctx, ary, obj);
				pdf_drop_obj(ctx, obj);
				obj = NULL;
				break;
			case PDF_TOK_REAL:
				obj = pdf_new_real(ctx, doc, buf->f);
				pdf_array_push(ctx, ary, obj);
				pdf_drop_obj(ctx, obj);
				obj = NULL;
				break;
			case PDF_TOK_STRING:
				obj = pdf_new_string(ctx, doc, buf->scratch, buf->len);
				pdf_array_push(ctx, ary, obj);
				pdf_drop_obj(ctx, obj);
				obj = NULL;
				break;
			case PDF_TOK_TRUE:
				obj = pdf_new_bool(ctx, doc, 1);
				pdf_array_push(ctx, ary, obj);
				pdf_drop_obj(ctx, obj);
				obj = NULL;
				break;
			case PDF_TOK_FALSE:
				obj = pdf_new_bool(ctx, doc, 0);
				pdf_array_push(ctx, ary, obj);
				pdf_drop_obj(ctx, obj);
				obj = NULL;
				break;
			case PDF_TOK_NULL:
				obj = pdf_new_null(ctx, doc);
				pdf_array_push(ctx, ary, obj);
				pdf_drop_obj(ctx, obj);
				obj = NULL;
				break;

			default:
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot parse token in array");
			}
		}
end:
		{}
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, obj);
		pdf_drop_obj(ctx, ary);
		fz_rethrow_message(ctx, "cannot parse array");
	}
	return op;
}

pdf_obj *
pdf_parse_dict(fz_context *ctx, pdf_document *doc, fz_stream *file, pdf_lexbuf *buf)
{
	pdf_obj *dict;
	pdf_obj *key = NULL;
	pdf_obj *val = NULL;
	pdf_token tok;
	int a, b;

	dict = pdf_new_dict(ctx, doc, 8);

	fz_var(key);
	fz_var(val);

	fz_try(ctx)
	{
		while (1)
		{
			tok = pdf_lex(ctx, file, buf);
	skip:
			if (tok == PDF_TOK_CLOSE_DICT)
				break;

			/* for BI .. ID .. EI in content streams */
			if (tok == PDF_TOK_KEYWORD && !strcmp(buf->scratch, "ID"))
				break;

			if (tok != PDF_TOK_NAME)
				fz_throw(ctx, FZ_ERROR_GENERIC, "invalid key in dict");

			key = pdf_new_name(ctx, doc, buf->scratch);

			tok = pdf_lex(ctx, file, buf);

			switch (tok)
			{
			case PDF_TOK_OPEN_ARRAY:
				val = pdf_parse_array(ctx, doc, file, buf);
				break;

			case PDF_TOK_OPEN_DICT:
				val = pdf_parse_dict(ctx, doc, file, buf);
				break;

			case PDF_TOK_NAME: val = pdf_new_name(ctx, doc, buf->scratch); break;
			case PDF_TOK_REAL: val = pdf_new_real(ctx, doc, buf->f); break;
			case PDF_TOK_STRING: val = pdf_new_string(ctx, doc, buf->scratch, buf->len); break;
			case PDF_TOK_TRUE: val = pdf_new_bool(ctx, doc, 1); break;
			case PDF_TOK_FALSE: val = pdf_new_bool(ctx, doc, 0); break;
			case PDF_TOK_NULL: val = pdf_new_null(ctx, doc); break;

			case PDF_TOK_INT:
				/* 64-bit to allow for numbers > INT_MAX and overflow */
				a = buf->i;
				tok = pdf_lex(ctx, file, buf);
				if (tok == PDF_TOK_CLOSE_DICT || tok == PDF_TOK_NAME ||
					(tok == PDF_TOK_KEYWORD && !strcmp(buf->scratch, "ID")))
				{
					val = pdf_new_int(ctx, doc, a);
					pdf_dict_put(ctx, dict, key, val);
					pdf_drop_obj(ctx, val);
					val = NULL;
					pdf_drop_obj(ctx, key);
					key = NULL;
					goto skip;
				}
				if (tok == PDF_TOK_INT)
				{
					b = buf->i;
					tok = pdf_lex(ctx, file, buf);
					if (tok == PDF_TOK_R)
					{
						val = pdf_new_indirect(ctx, doc, a, b);
						break;
					}
				}
				fz_throw(ctx, FZ_ERROR_GENERIC, "invalid indirect reference in dict");

			default:
				fz_throw(ctx, FZ_ERROR_GENERIC, "unknown token in dict");
			}

			pdf_dict_put(ctx, dict, key, val);
			pdf_drop_obj(ctx, val);
			val = NULL;
			pdf_drop_obj(ctx, key);
			key = NULL;
		}
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, dict);
		pdf_drop_obj(ctx, key);
		pdf_drop_obj(ctx, val);
		fz_rethrow_message(ctx, "cannot parse dict");
	}
	return dict;
}

pdf_obj *
pdf_parse_stm_obj(fz_context *ctx, pdf_document *doc, fz_stream *file, pdf_lexbuf *buf)
{
	pdf_token tok;

	tok = pdf_lex(ctx, file, buf);

	switch (tok)
	{
	case PDF_TOK_OPEN_ARRAY:
		return pdf_parse_array(ctx, doc, file, buf);
	case PDF_TOK_OPEN_DICT:
		return pdf_parse_dict(ctx, doc, file, buf);
	case PDF_TOK_NAME: return pdf_new_name(ctx, doc, buf->scratch); break;
	case PDF_TOK_REAL: return pdf_new_real(ctx, doc, buf->f); break;
	case PDF_TOK_STRING: return pdf_new_string(ctx, doc, buf->scratch, buf->len); break;
	case PDF_TOK_TRUE: return pdf_new_bool(ctx, doc, 1); break;
	case PDF_TOK_FALSE: return pdf_new_bool(ctx, doc, 0); break;
	case PDF_TOK_NULL: return pdf_new_null(ctx, doc); break;
	case PDF_TOK_INT: return pdf_new_int(ctx, doc, buf->i); break;
	default: fz_throw(ctx, FZ_ERROR_GENERIC, "unknown token in object stream");
	}
}

pdf_obj *
pdf_parse_ind_obj(fz_context *ctx, pdf_document *doc,
	fz_stream *file, pdf_lexbuf *buf,
	int *onum, int *ogen, int *ostmofs, int *try_repair)
{
	pdf_obj *obj = NULL;
	int num = 0, gen = 0, stm_ofs;
	pdf_token tok;
	int a, b;

	fz_var(obj);

	tok = pdf_lex(ctx, file, buf);
	if (tok != PDF_TOK_INT)
	{
		if (try_repair)
			*try_repair = 1;
		fz_throw(ctx, FZ_ERROR_GENERIC, "expected object number");
	}
	num = buf->i;

	tok = pdf_lex(ctx, file, buf);
	if (tok != PDF_TOK_INT)
	{
		if (try_repair)
			*try_repair = 1;
		fz_throw(ctx, FZ_ERROR_GENERIC, "expected generation number (%d ? obj)", num);
	}
	gen = buf->i;

	tok = pdf_lex(ctx, file, buf);
	if (tok != PDF_TOK_OBJ)
	{
		if (try_repair)
			*try_repair = 1;
		fz_throw(ctx, FZ_ERROR_GENERIC, "expected 'obj' keyword (%d %d ?)", num, gen);
	}

	tok = pdf_lex(ctx, file, buf);

	switch (tok)
	{
	case PDF_TOK_OPEN_ARRAY:
		obj = pdf_parse_array(ctx, doc, file, buf);
		break;

	case PDF_TOK_OPEN_DICT:
		obj = pdf_parse_dict(ctx, doc, file, buf);
		break;

	case PDF_TOK_NAME: obj = pdf_new_name(ctx, doc, buf->scratch); break;
	case PDF_TOK_REAL: obj = pdf_new_real(ctx, doc, buf->f); break;
	case PDF_TOK_STRING: obj = pdf_new_string(ctx, doc, buf->scratch, buf->len); break;
	case PDF_TOK_TRUE: obj = pdf_new_bool(ctx, doc, 1); break;
	case PDF_TOK_FALSE: obj = pdf_new_bool(ctx, doc, 0); break;
	case PDF_TOK_NULL: obj = pdf_new_null(ctx, doc); break;

	case PDF_TOK_INT:
		a = buf->i;
		tok = pdf_lex(ctx, file, buf);

		if (tok == PDF_TOK_STREAM || tok == PDF_TOK_ENDOBJ)
		{
			obj = pdf_new_int(ctx, doc, a);
			goto skip;
		}
		if (tok == PDF_TOK_INT)
		{
			b = buf->i;
			tok = pdf_lex(ctx, file, buf);
			if (tok == PDF_TOK_R)
			{
				obj = pdf_new_indirect(ctx, doc, a, b);
				break;
			}
		}
		fz_throw(ctx, FZ_ERROR_GENERIC, "expected 'R' keyword (%d %d R)", num, gen);

	case PDF_TOK_ENDOBJ:
		obj = pdf_new_null(ctx, doc);
		goto skip;

	default:
		fz_throw(ctx, FZ_ERROR_GENERIC, "syntax error in object (%d %d R)", num, gen);
	}

	fz_try(ctx)
	{
		tok = pdf_lex(ctx, file, buf);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, obj);
		fz_rethrow_message(ctx, "cannot parse indirect object (%d %d R)", num, gen);
	}

skip:
	if (tok == PDF_TOK_STREAM)
	{
		int c = fz_read_byte(ctx, file);
		while (c == ' ')
			c = fz_read_byte(ctx, file);
		if (c == '\r')
		{
			c = fz_peek_byte(ctx, file);
			if (c != '\n')
				fz_warn(ctx, "line feed missing after stream begin marker (%d %d R)", num, gen);
			else
				fz_read_byte(ctx, file);
		}
		stm_ofs = fz_tell(ctx, file);
	}
	else if (tok == PDF_TOK_ENDOBJ)
	{
		stm_ofs = 0;
	}
	else
	{
		fz_warn(ctx, "expected 'endobj' or 'stream' keyword (%d %d R)", num, gen);
		stm_ofs = 0;
	}

	if (onum) *onum = num;
	if (ogen) *ogen = gen;
	if (ostmofs) *ostmofs = stm_ofs;
	return obj;
}
