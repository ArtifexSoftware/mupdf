#include "fitz-internal.h"
#include "mupdf-internal.h"

#define MATRIX_COEFS (6)

enum
{
	Ff_NoToggleToOff = 1 << (15-1),
	Ff_Radio         = 1 << (16-1),
	Ff_Pushbutton    = 1 << (17-1),
	Ff_RadioInUnison = 1 << (26-1),
	Ff_Combo         = 1 << (18-1)
};

enum
{
	BS_Solid,
	BS_Dashed,
	BS_Beveled,
	BS_Inset,
	BS_Underline
};

enum
{
	Q_Left  = 0,
	Q_Cent  = 1,
	Q_Right = 2
};

struct fz_widget_s
{
	pdf_document *doc;
	int           type;
	pdf_obj      *obj;
};

struct fz_widget_text_s
{
	fz_widget super;
	char     *text;
};

typedef struct da_info_s
{
	char *font_name;
	int font_size;
	float col[4];
	int col_size;
} da_info;

typedef struct font_info_s
{
	da_info da_rec;
	pdf_font_desc *font;
} font_info;

typedef struct text_widget_info_s
{
	pdf_obj *dr;
	font_info font_rec;
	int q;
	int multiline;
} text_widget_info;

static const char *fmt_re = "%f %f %f %f re\n";
static const char *fmt_f = "f\n";
static const char *fmt_s = "s\n";
static const char *fmt_g = "%f g\n";
static const char *fmt_m = "%f %f m\n";
static const char *fmt_l = "%f %f l\n";
static const char *fmt_w = "%f w\n";
static const char *fmt_Tx_BMC = "/Tx BMC\n";
static const char *fmt_q = "q\n";
static const char *fmt_W = "W\n";
static const char *fmt_n = "n\n";
static const char *fmt_BT = "BT\n";
static const char *fmt_Tm = "%1.2f %1.2f %1.2f %1.2f %1.2f %1.2f Tm\n";
static const char *fmt_Tj = "(%s) Tj\n";
static const char *fmt_ET = "ET\n";
static const char *fmt_Q = "Q\n";
static const char *fmt_EMC = "EMC\n";

static fz_buffer *form_contents(pdf_document *doc, pdf_xobject *form)
{
	return pdf_get_stream(doc, pdf_to_num(form->contents));
}

static void account_for_rot(fz_rect *rect, fz_matrix *mat, int rot)
{
	float width = rect->x1;
	float height = rect->y1;

	switch (rot)
	{
	default:
		*mat = fz_identity;
		break;
	case 90:
		*mat = fz_concat(fz_rotate(rot), fz_translate(width, 0));
		rect->x1 = height;
		rect->y1 = width;
		break;
	case 180:
		*mat = fz_concat(fz_rotate(rot), fz_translate(width, height));
		break;
	case 270:
		*mat = fz_concat(fz_rotate(rot), fz_translate(0, height));
		rect->x1 = height;
		rect->y1 = width;
		break;
	}
}

static pdf_obj *get_inheritable(pdf_document *doc, pdf_obj *obj, char *key)
{
	pdf_obj *fobj = NULL;

	while (!fobj && obj)
	{
		fobj = pdf_dict_gets(obj, key);

		if (!fobj)
			obj = pdf_dict_gets(obj, "Parent");
	}

	return fobj ? fobj
				: pdf_dict_gets(pdf_dict_gets(pdf_dict_gets(doc->trailer, "Root"), "AcroForm"), key);
}

static char *get_string_or_stream(pdf_document *doc, pdf_obj *obj)
{
	fz_context *ctx = doc->ctx;
	int len = 0;
	char *buf = NULL;
	fz_buffer *strmbuf = NULL;
	char *text = NULL;

	fz_var(strmbuf);
	fz_var(text);
	fz_try(ctx)
	{
		if (pdf_is_string(obj))
		{
			len = pdf_to_str_len(obj);
			buf = pdf_to_str_buf(obj);
		}
		else if (pdf_is_stream(doc, pdf_to_num(obj), pdf_to_gen(obj)))
		{
			strmbuf = pdf_load_stream(doc, pdf_to_num(obj), pdf_to_gen(obj));
			len = fz_buffer_storage(ctx, strmbuf, &buf);
		}

		if (buf)
		{
			text = fz_malloc(ctx, len+1);
			memcpy(text, buf, len);
			text[len] = 0;
		}
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, strmbuf);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, text);
		fz_rethrow(ctx);
	}

	return text;
}

static char *get_field_type_name(pdf_document *doc, pdf_obj *obj)
{
	pdf_obj *type = get_inheritable(doc, obj, "FT");

	return type ? pdf_to_name(type)
				: NULL;
}

static int get_field_flags(pdf_document *doc, pdf_obj *obj)
{
	pdf_obj *flags = get_inheritable(doc, obj, "Ff");

	return flags ? pdf_to_int(flags)
				 : 0;
}

static int get_field_type(pdf_document *doc, pdf_obj *obj)
{
	char *type = get_field_type_name(doc, obj);
	int   flags = get_field_flags(doc, obj);

	if (!strcmp(type, "Btn"))
	{
		if (flags & Ff_Pushbutton)
			return FZ_WIDGET_TYPE_PUSHBUTTON;
		else if (flags & Ff_Radio)
			return FZ_WIDGET_TYPE_RADIOBUTTON;
		else
			return FZ_WIDGET_TYPE_CHECKBOX;
	}
	else if (!strcmp(type, "Tx"))
		return FZ_WIDGET_TYPE_TEXT;
	else if (!strcmp(type, "Ch"))
	{
		if (flags & Ff_Combo)
			return FZ_WIDGET_TYPE_COMBOBOX;
		else
			return FZ_WIDGET_TYPE_LISTBOX;
	}
	else
		return -1;
}

static void pdf_field_mark_dirty(fz_context *ctx, pdf_obj *field)
{
	if (!pdf_dict_gets(field, "Dirty"))
	{
		pdf_obj *nullobj = pdf_new_null(ctx);
		fz_try(ctx)
		{
			pdf_dict_puts(field, "Dirty", nullobj);
		}
		fz_always(ctx)
		{
			pdf_drop_obj(nullobj);
		}
		fz_catch(ctx)
		{
			fz_rethrow(ctx);
		}
	}
}

static void copy_resources(pdf_obj *dst, pdf_obj *src)
{
	int i, len;

	len = pdf_dict_len(src);
	for (i = 0; i < len; i++)
	{
		pdf_obj *key = pdf_dict_get_key(src, i);

		if (!pdf_dict_get(dst, key))
			fz_dict_put(dst, key, pdf_dict_get_val(src, i));
	}
}

static fz_widget *new_widget(pdf_document *doc, pdf_obj *obj)
{
	fz_widget *widget = NULL;

	fz_try(doc->ctx)
	{
		int type = get_field_type(doc, obj);

		switch(type)
		{
		case FZ_WIDGET_TYPE_TEXT:
			widget = &(fz_malloc_struct(doc->ctx, fz_widget_text)->super);
			break;
		default:
			widget = fz_malloc_struct(doc->ctx, fz_widget);
			break;
		}

		widget->doc  = doc;
		widget->type = type;
		widget->obj  = pdf_keep_obj(obj);
	}
	fz_catch(doc->ctx)
	{
		fz_warn(doc->ctx, "failed to load foccussed widget");
	}

	return widget;
}

static void da_info_fin(fz_context *ctx, da_info *di)
{
	fz_free(ctx, di->font_name);
	di->font_name = NULL;
}

static void da_check_stack(int *stack, int *top)
{
	if (*top == 32)
	{
		memmove(stack, stack + 1, 31 * sizeof(stack[0]));
		*top = 31;
	}
}

static void parse_da(fz_context *ctx, char *da, da_info *di)
{
	float stack[32];
	int top = 0;
	int tok;
	char *name = NULL;
	pdf_lexbuf lbuf;
	fz_stream *str = fz_open_memory(ctx, da, strlen(da));

	memset(lbuf.scratch, 0, sizeof(lbuf.scratch));
	lbuf.size = sizeof(lbuf.scratch);

	fz_var(str);
	fz_var(name);
	fz_try(ctx)
	{
		for (tok = pdf_lex(str, &lbuf); tok != PDF_TOK_EOF; tok = pdf_lex(str, &lbuf))
		{
			switch (tok)
			{
			case PDF_TOK_NAME:
				fz_free(ctx, name);
				name = fz_strdup(ctx, lbuf.scratch);
				break;

			case PDF_TOK_INT:
				da_check_stack(stack, &top);
				stack[top] = lbuf.i;
				top ++;
				break;

			case PDF_TOK_REAL:
				da_check_stack(stack, &top);
				stack[top] = lbuf.f;
				top ++;
				break;

			case PDF_TOK_KEYWORD:
				if (!strcmp(lbuf.scratch, "Tf"))
				{
					di->font_size = stack[0];
					di->font_name = name;
					name = NULL;
				}
				else if (!strcmp(lbuf.scratch, "rg"))
				{
					di->col[0] = stack[0];
					di->col[1] = stack[1];
					di->col[2] = stack[2];
					di->col_size = 3;
				}

				fz_free(ctx, name);
				name = NULL;
				top = 0;
				break;
			}
		}
	}
	fz_always(ctx)
	{
		fz_free(ctx, name);
		fz_close(str);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void get_font_info(pdf_document *doc, pdf_obj *dr, char *da, font_info *font_rec)
{
	fz_context *ctx = doc->ctx;

	parse_da(ctx, da, &font_rec->da_rec);
	if (font_rec->da_rec.font_name == NULL)
		fz_throw(ctx, "No font name in default appearance");
	font_rec->font = pdf_load_font(doc, dr, pdf_dict_gets(pdf_dict_gets(dr, "Font"), font_rec->da_rec.font_name));
}

static void font_info_fin(fz_context *ctx, font_info *font_rec)
{
	pdf_drop_font(ctx, font_rec->font);
	font_rec->font = NULL;
	da_info_fin(ctx, &font_rec->da_rec);
}

static void get_text_widget_info(pdf_document *doc, pdf_obj *widget, text_widget_info *info)
{
	fz_context *ctx = doc->ctx;
	char *da = pdf_to_str_buf(get_inheritable(doc, widget, "DA"));

	info->dr = get_inheritable(doc, widget, "DR");
	info->q = pdf_to_int(get_inheritable(doc, widget, "Q"));
	info->multiline = 0;
	get_font_info(doc, info->dr, da, &info->font_rec);
}

static void fzbuf_print_da(fz_context *ctx, fz_buffer *fzbuf, da_info *di)
{
	if (di->font_name != NULL && di->font_size != 0)
		fz_buffer_printf(ctx, fzbuf, "/%s %d Tf", di->font_name, di->font_size);

	if (di->col_size != 0)
		fz_buffer_printf(ctx, fzbuf, " %f %f %f rg", di->col[0], di->col[1], di->col[2]);
}

static fz_rect measure_text(pdf_document *doc, font_info *font_rec, fz_matrix *tm, char *text)
{
	fz_rect bbox = pdf_measure_text(doc->ctx, font_rec->font, text, strlen(text), NULL);

	bbox.x0 *= font_rec->da_rec.font_size * tm->a;
	bbox.y0 *= font_rec->da_rec.font_size * tm->d;
	bbox.x1 *= font_rec->da_rec.font_size * tm->a;
	bbox.y1 *= font_rec->da_rec.font_size * tm->d;

	return bbox;
}

static void fzbuf_print_text(fz_context *ctx, fz_buffer *fzbuf, fz_rect *clip, font_info *font_rec, fz_matrix *tm, char *text)
{
	fz_buffer_printf(ctx, fzbuf, fmt_q);
	if (clip)
	{
		fz_buffer_printf(ctx, fzbuf, fmt_re, clip->x0, clip->y0, clip->x1 - clip->x0, clip->y1 - clip->y0);
		fz_buffer_printf(ctx, fzbuf, fmt_W);
		fz_buffer_printf(ctx, fzbuf, fmt_n);
	}

	fz_buffer_printf(ctx, fzbuf, fmt_BT);

	fzbuf_print_da(ctx, fzbuf, &font_rec->da_rec);

	fz_buffer_printf(ctx, fzbuf, "\n");
	if (tm)
		fz_buffer_printf(ctx, fzbuf, fmt_Tm, tm->a, tm->b, tm->c, tm->d, tm->e, tm->f);

	fz_buffer_printf(ctx, fzbuf, fmt_Tj, text);
	fz_buffer_printf(ctx, fzbuf, fmt_ET);
	fz_buffer_printf(ctx, fzbuf, fmt_Q);
}

static fz_buffer *create_text_buffer(fz_context *ctx, fz_rect *clip, font_info *font_rec, fz_matrix *tm, char *text)
{
	fz_buffer *fzbuf = fz_new_buffer(ctx, 0);

	fz_try(ctx)
	{
		fz_buffer_printf(ctx, fzbuf, fmt_Tx_BMC);
		fzbuf_print_text(ctx, fzbuf, clip, font_rec, tm, text);
		fz_buffer_printf(ctx, fzbuf, fmt_EMC);
	}
	fz_catch(ctx)
	{
		fz_drop_buffer(ctx, fzbuf);
		fz_rethrow(ctx);
	}

	return fzbuf;
}

static fz_buffer *create_aligned_text_buffer(pdf_document *doc, fz_rect *clip, text_widget_info *info, fz_matrix *tm, char *text)
{
	fz_context *ctx = doc->ctx;
	fz_matrix atm = *tm;

	if (info->q != Q_Left)
	{
		fz_rect rect = measure_text(doc, &info->font_rec, tm, text);

		atm.e -= info->q == Q_Right ? rect.x1
							  : (rect.x1 - rect.x0) / 2;
	}

	return create_text_buffer(ctx, clip, &info->font_rec, &atm, text);
}

static void measure_ascent_descent(pdf_document *doc, font_info *finf, char *text, float *ascent, float *descent)
{
	fz_context *ctx = doc->ctx;
	char *testtext = NULL;
	fz_rect bbox;
	font_info tinf = *finf;

	fz_var(testtext);
	fz_try(ctx)
	{
		/* Heuristic: adding "My" to text will in most cases
		 * produce a measurement that will encompass all chars */
		testtext = fz_malloc(ctx, strlen(text) + 3);
		strcpy(testtext, "My");
		strcat(testtext, text);
		tinf.da_rec.font_size = 1;
		bbox = measure_text(doc, &tinf, &fz_identity, testtext);
		*descent = -bbox.y0;
		*ascent = bbox.y1;
	}
	fz_always(ctx)
	{
		fz_free(ctx, testtext);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

fz_buffer *create_text_appearance(pdf_document *doc, fz_rect *bbox, fz_matrix *oldtm, text_widget_info *info, char *text)
{
	fz_context *ctx = doc->ctx;
	int fontsize, da_fontsize;
	float height, width;
	fz_buffer *fzbuf = NULL;
	fz_rect rect;
	fz_rect tbox;
	rect = *bbox;

	if (rect.x1 - rect.x0 >= 2.0 && rect.y1 - rect.y0 >= 2.0)
	{
		rect.x0 += 1.0;
		rect.x1 -= 1.0;
		rect.y0 += 1.0;
		rect.y1 -= 1.0;
	}

	height = MAX(bbox->y1 - bbox->y0 - 4.0, 1);
	width = MAX(bbox->x1 - bbox->x0 - 4.0, 1);

	fz_var(fzbuf);
	fz_try(ctx)
	{
	    float ascent, descent;
		fz_matrix tm;

		da_fontsize = info->font_rec.da_rec.font_size;
		fontsize = da_fontsize ? da_fontsize : floor(height);

		if (oldtm)
		{
			tm = *oldtm;
		}
		else
		{
			measure_ascent_descent(doc, &info->font_rec, text, &ascent, &descent);
			tm = fz_identity;
			tm.e = 2.0;
			tm.f = 2.0 + fontsize * descent;

			switch(info->q)
			{
			case Q_Right: tm.e += width; break;
			case Q_Cent: tm.e += width/2; break;
			}
		}

		if (!da_fontsize)
		{
			info->font_rec.da_rec.font_size = fontsize;
			tbox = measure_text(doc, &info->font_rec, &tm, text);

			if (tbox.x1 - tbox.x0 > width)
			{
				/* Scale the text to fit but use the same offset
				 * to keep the baseline constant */
				tm.a *= width / (tbox.x1 - tbox.x0);
				tm.d *= width / (tbox.x1 - tbox.x0);
			}
		}

		fzbuf = create_aligned_text_buffer(doc, &rect, info, &tm, text);
	}
	fz_catch(ctx)
	{
		fz_drop_buffer(ctx, fzbuf);
		fz_rethrow(ctx);
	}

	return fzbuf;
}

static void update_marked_content(pdf_document *doc, pdf_xobject *form, fz_buffer *fzbuf)
{
	fz_context *ctx = doc->ctx;
	int tok;
	pdf_lexbuf lbuf;
	fz_stream *str_outer = NULL;
	fz_stream *str_inner = NULL;
	unsigned char *buf;
	int            len;
	fz_buffer *newbuf = NULL;

	memset(lbuf.scratch, 0, sizeof(lbuf.scratch));
	lbuf.size = sizeof(lbuf.scratch);

	fz_var(str_outer);
	fz_var(str_inner);
	fz_var(newbuf);
	fz_try(ctx)
	{
		int bmc_found;
		int first = 1;

		newbuf = fz_new_buffer(ctx, 0);
		len = fz_buffer_storage(ctx, form_contents(doc, form), &buf);
		str_outer = fz_open_memory(ctx, buf, len);
		len = fz_buffer_storage(ctx, fzbuf, &buf);
		str_inner = fz_open_memory(ctx, buf, len);

		/* Copy the existing appearance stream to newbuf while looking for BMC */
		for (tok = pdf_lex(str_outer, &lbuf); tok != PDF_TOK_EOF; tok = pdf_lex(str_outer, &lbuf))
		{
			if (first)
				first = 0;
			else
				fz_buffer_printf(ctx, newbuf, " ");

			pdf_print_token(ctx, newbuf, tok, &lbuf);
			if (tok == PDF_TOK_KEYWORD && !strcmp(lbuf.scratch, "BMC"))
				break;
		}

		bmc_found = (tok != PDF_TOK_EOF);

		if (bmc_found)
		{
			/* Drop Tx BMC from the replacement appearance stream */
			(void)pdf_lex(str_inner, &lbuf);
			(void)pdf_lex(str_inner, &lbuf);
		}

		/* Copy the replacement appearance stream to newbuf */
		for (tok = pdf_lex(str_inner, &lbuf); tok != PDF_TOK_EOF; tok = pdf_lex(str_inner, &lbuf))
		{
			fz_buffer_printf(ctx, newbuf, " ");
			pdf_print_token(ctx, newbuf, tok, &lbuf);
		}

		if (bmc_found)
		{
			/* Drop the rest of the existing appearance stream until EMC found */
			for (tok = pdf_lex(str_outer, &lbuf); tok != PDF_TOK_EOF; tok = pdf_lex(str_outer, &lbuf))
			{
				if (tok == PDF_TOK_KEYWORD && !strcmp(lbuf.scratch, "EMC"))
					break;
			}

			/* Copy the rest of the existing appearance stream to newbuf */
			for (tok = pdf_lex(str_outer, &lbuf); tok != PDF_TOK_EOF; tok = pdf_lex(str_outer, &lbuf))
			{
				fz_buffer_printf(ctx, newbuf, " ");
				pdf_print_token(ctx, newbuf, tok, &lbuf);
			}
		}

		/* Use newbuf in place of the existing appearance stream */
		pdf_xobject_set_contents(doc, form, newbuf);
	}
	fz_always(ctx)
	{
		fz_close(str_outer);
		fz_close(str_inner);
		fz_drop_buffer(ctx, newbuf);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static int get_matrix(pdf_document *doc, pdf_xobject *form, int q, fz_matrix *mt)
{
	fz_context *ctx = doc->ctx;
	int found = 0;
	unsigned char *buf;
	int bufsize;
	pdf_lexbuf lbuf;
	fz_stream *str;

	bufsize = fz_buffer_storage(ctx, form_contents(doc, form), &buf);
	str = fz_open_memory(ctx, buf, bufsize);

	memset(lbuf.scratch, 0, sizeof(lbuf.scratch));
	lbuf.size = sizeof(lbuf.scratch);

	fz_try(ctx)
	{
		int tok;
		float coefs[MATRIX_COEFS];
		int coef_i = 0;

		/* Look for the text matrix Tm in the stream */
		for (tok = pdf_lex(str, &lbuf); tok != PDF_TOK_EOF; tok = pdf_lex(str, &lbuf))
		{
			if (tok == PDF_TOK_INT || tok == PDF_TOK_REAL)
			{
				if (coef_i >= MATRIX_COEFS)
				{
					int i;
					for (i = 0; i < MATRIX_COEFS-1; i++)
						coefs[i] = coefs[i+1];

					coef_i = MATRIX_COEFS-1;
				}

				coefs[coef_i++] = tok == PDF_TOK_INT ? lbuf.i
													 : lbuf.f;
			}
			else
			{
				if (tok == PDF_TOK_KEYWORD && !strcmp(lbuf.scratch, "Tm") && coef_i == MATRIX_COEFS)
				{
					found = 1;
					mt->a = coefs[0];
					mt->b = coefs[1];
					mt->c = coefs[2];
					mt->d = coefs[3];
					mt->e = coefs[4];
					mt->f = coefs[5];
				}

				coef_i = 0;
			}
		}

		if (found)
		{
			fz_rect bbox = pdf_to_rect(ctx, pdf_dict_gets(form->contents, "BBox"));

			switch (q)
			{
			case Q_Left:
				mt->e = bbox.x0 + 1;
				break;

			case Q_Cent:
				mt->e = (bbox.x1 - bbox.x0) / 2;
				break;

			case Q_Right:
				mt->e = bbox.x1 - 1;
				break;
			}
		}
	}
	fz_always(ctx)
	{
		fz_close(str);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return found;
}

static void update_text_appearance(pdf_document *doc, pdf_obj *obj, char *text)
{
	fz_context *ctx = doc->ctx;
	text_widget_info info;
	pdf_obj *ap, *n;
	pdf_xobject *form = NULL;
	fz_buffer *fzbuf = NULL;
	fz_matrix tm;
	int has_tm;

	memset(&info, 0, sizeof(info));

	fz_var(info);
	fz_var(form);
	fz_var(fzbuf);
	fz_try(ctx)
	{
		get_text_widget_info(doc, obj, &info);
		ap = pdf_dict_gets(obj, "AP");
		if (pdf_is_dict(ap))
		{
			n = pdf_dict_gets(ap, "N");

			if (pdf_is_stream(doc, pdf_to_num(n), pdf_to_gen(n)))
			{
				form = pdf_load_xobject(doc, n);

				/* copy the default resources to the xobject */
				copy_resources(form->resources, info.dr);

				has_tm = get_matrix(doc, form, info.q, &tm);
				fzbuf = create_text_appearance(doc, &form->bbox, has_tm ? &tm : NULL, &info, text);
				update_marked_content(doc, form, fzbuf);
			}
		}
	}
	fz_always(ctx)
	{
		pdf_drop_xobject(ctx, form);
		fz_drop_buffer(ctx, fzbuf);
		font_info_fin(ctx, &info.font_rec);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "update_text_appearance failed");
	}
}

static void update_text_field_value(fz_context *ctx, pdf_obj *obj, char *text)
{
	pdf_obj *parent = pdf_dict_gets(obj, "Parent");
	pdf_obj *sobj = NULL;

	if (parent)
		obj = parent;

	fz_var(sobj);
	fz_try(ctx)
	{
		sobj = pdf_new_string(ctx, text, strlen(text));
		pdf_dict_puts(obj, "V", sobj);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(sobj);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void synthesize_text_widget(pdf_document *doc, pdf_obj *obj)
{
	fz_context *ctx = doc->ctx;
	pdf_obj *ap = NULL;
	fz_rect rect;
	pdf_obj *formobj = NULL;
	pdf_xobject *form = NULL;
	fz_buffer *fzbuf = NULL;

	fz_var(formobj);
	fz_var(ap);
	fz_var(form);
	fz_var(fzbuf);
	fz_try(ctx)
	{
		rect = pdf_to_rect(ctx, pdf_dict_gets(obj, "Rect"));
		rect.x1 -= rect.x0;
		rect.y1 -= rect.y0;
		rect.x0 = rect.y0 = 0;
		formobj = pdf_new_xobject(doc, &rect, &fz_identity);
		form = pdf_load_xobject(doc, formobj);
		fzbuf = fz_new_buffer(ctx, 0);
		fz_buffer_printf(ctx, fzbuf, "/Tx BMC EMC");
		pdf_xobject_set_contents(doc, form, fzbuf);

		ap = pdf_new_dict(ctx, 1);
		pdf_dict_puts(ap, "N", formobj);
		pdf_dict_puts(obj, "AP", ap);
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, fzbuf);
		pdf_drop_xobject(ctx, form);
		pdf_drop_obj(formobj);
		pdf_drop_obj(ap);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static pdf_xobject *load_or_create_form(pdf_document *doc, pdf_obj *obj, fz_rect *rect)
{
	fz_context *ctx = doc->ctx;
	pdf_obj *ap = NULL;
	pdf_obj *tobj = NULL;
	fz_matrix mat;
	int rot;
	pdf_obj *formobj = NULL;
	pdf_xobject *form = NULL;
	const char *dn;

	fz_var(formobj);
	fz_var(tobj);
	fz_var(form);
	fz_try(ctx)
	{
		pdf_hotspot *hp = &doc->hotspot;
		if (hp->num == pdf_to_num(obj)
			&& hp->gen == pdf_to_gen(obj)
			&& (hp->state & HOTSPOT_POINTER_DOWN))
		{
			dn = "D";
		}
		else
		{
			dn = "N";
		}

		rot = pdf_to_int(pdf_dict_getp(obj, "MK/R"));
		*rect = pdf_to_rect(ctx, pdf_dict_gets(obj, "Rect"));
		rect->x1 -= rect->x0;
		rect->y1 -= rect->y0;
		rect->x0 = rect->y0 = 0;
		account_for_rot(rect, &mat, rot);

		ap = pdf_dict_gets(obj, "AP");
		if (ap == NULL)
		{
			tobj = pdf_new_dict(ctx, 1);
			pdf_dict_puts(obj, "AP", tobj);
			ap = tobj;
			tobj = NULL;
		}

		formobj = pdf_dict_gets(ap, dn);
		if (formobj == NULL)
		{
			tobj = pdf_new_xobject(doc, rect, &mat);
			pdf_dict_puts(ap, dn, tobj);
			formobj = tobj;
			tobj = NULL;
		}

		form = pdf_load_xobject(doc, formobj);

		copy_resources(form->resources, get_inheritable(doc, obj, "DR"));
	}
	fz_always(ctx)
	{
		pdf_drop_obj(tobj);
	}
	fz_catch(ctx)
	{
		pdf_drop_xobject(ctx, form);
		fz_rethrow(ctx);
	}

	return form;
}

static fzbuf_print_color(fz_context *ctx, fz_buffer *fzbuf, pdf_obj *arr, int stroke, float adj)
{
	switch(pdf_array_len(arr))
	{
	case 1:
		fz_buffer_printf(ctx, fzbuf, stroke?"%f G\n":"%f g\n",
			pdf_to_real(pdf_array_get(arr, 0)) + adj);
		break;
	case 3:
		fz_buffer_printf(ctx, fzbuf, stroke?"%f %f %f rg\n":"%f %f %f rg\n",
			pdf_to_real(pdf_array_get(arr, 0)) + adj,
			pdf_to_real(pdf_array_get(arr, 1)) + adj,
			pdf_to_real(pdf_array_get(arr, 2)) + adj);
		break;
	case 4:
		fz_buffer_printf(ctx, fzbuf, stroke?"%f %f %f %f k\n":"%f %f %f %f k\n",
			pdf_to_real(pdf_array_get(arr, 0)),
			pdf_to_real(pdf_array_get(arr, 1)),
			pdf_to_real(pdf_array_get(arr, 2)),
			pdf_to_real(pdf_array_get(arr, 3)));
		break;
	}
}

static int get_border_style(pdf_obj *obj)
{
	char *sname = pdf_to_name(pdf_dict_getp(obj, "BS/S"));

	if (!strcmp(sname, "D"))
		return BS_Dashed;
	else if (!strcmp(sname, "B"))
		return BS_Beveled;
	else if (!strcmp(sname, "I"))
		return BS_Inset;
	else if (!strcmp(sname, "U"))
		return BS_Underline;
	else
		return BS_Solid;
}

static float get_border_width(pdf_obj *obj)
{
	float w = pdf_to_real(pdf_dict_getp(obj, "BS/W"));
	return w == 0.0 ? 1.0 : w;
}

static void update_pushbutton_widget(pdf_document *doc, pdf_obj *obj)
{
	fz_context *ctx = doc->ctx;
	fz_rect rect;
	pdf_xobject *form = NULL;
	fz_buffer *fzbuf = NULL;
	pdf_obj *tobj = NULL;
	font_info font_rec;
	int bstyle;
	float bwidth;
	float btotal;

	memset(&font_rec, 0, sizeof(font_rec));

	fz_var(font_rec);
	fz_var(form);
	fz_var(fzbuf);
	fz_try(ctx)
	{
		form = load_or_create_form(doc, obj, &rect);
		fzbuf = fz_new_buffer(ctx, 0);
		tobj = pdf_dict_getp(obj, "MK/BG");
		if (pdf_is_array(tobj))
		{
			fzbuf_print_color(ctx, fzbuf, tobj, 0, 0.0);
			fz_buffer_printf(ctx, fzbuf, fmt_re,
				rect.x0, rect.y0, rect.x1, rect.y1);
			fz_buffer_printf(ctx, fzbuf, fmt_f);
		}
		bstyle = get_border_style(obj);
		bwidth = get_border_width(obj);
		btotal = bwidth;
		if (bstyle == BS_Beveled || bstyle == BS_Inset)
		{
			btotal += bwidth;

			if (bstyle == BS_Beveled)
				fz_buffer_printf(ctx, fzbuf, fmt_g, 1.0);
			else
				fz_buffer_printf(ctx, fzbuf, fmt_g, 0.33);
			fz_buffer_printf(ctx, fzbuf, fmt_m, bwidth, bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_l, bwidth, rect.y1 - bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_l, rect.x1 - bwidth, rect.y1 - bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_l, rect.x1 - 2 * bwidth, rect.y1 - 2 * bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_l, 2 * bwidth, rect.y1 - 2 * bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_l, 2 * bwidth, 2 * bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_f);
			if (bstyle == BS_Beveled)
				fzbuf_print_color(ctx, fzbuf, tobj, 0, -0.25);
			else
				fz_buffer_printf(ctx, fzbuf, fmt_g, 0.66);
			fz_buffer_printf(ctx, fzbuf, fmt_m, rect.x1 - bwidth, rect.y1 - bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_l, rect.x1 - bwidth, bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_l, bwidth, bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_l, 2 * bwidth, 2 * bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_l, rect.x1 - 2 * bwidth, 2 * bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_l, rect.x1 - 2 * bwidth, rect.y1 - 2 * bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_f);
		}

		tobj = pdf_dict_getp(obj, "MK/BC");
		if (tobj)
		{
			fzbuf_print_color(ctx, fzbuf, tobj, 1, 0.0);
			fz_buffer_printf(ctx, fzbuf, fmt_w, bwidth);
			fz_buffer_printf(ctx, fzbuf, fmt_re,
				bwidth/2, bwidth/2,
				rect.x1 -bwidth/2, rect.y1 - bwidth/2);
			fz_buffer_printf(ctx, fzbuf, fmt_s);
		}

		tobj = pdf_dict_getp(obj, "MK/CA");
		if (tobj)
		{
			fz_rect clip = rect;
			fz_rect bounds;
			fz_matrix mat;
			char *da = pdf_to_str_buf(pdf_dict_gets(obj, "DA"));
			char *text = pdf_to_str_buf(tobj);

			clip.x0 += btotal;
			clip.y0 += btotal;
			clip.x1 -= btotal;
			clip.y1 -= btotal;

			get_font_info(doc, form->resources, da, &font_rec);
			bounds = measure_text(doc, &font_rec, &fz_identity, text);
			mat = fz_translate((rect.x1 - bounds.x1)/2, (rect.y1 - bounds.y1)/2);
			fzbuf_print_text(ctx, fzbuf, &clip, &font_rec, &mat, text);
		}

		pdf_xobject_set_contents(doc, form, fzbuf);
	}
	fz_always(ctx)
	{
		font_info_fin(ctx, &font_rec);
		fz_drop_buffer(ctx, fzbuf);
		pdf_drop_xobject(ctx, form);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

void pdf_update_appearance(pdf_document *doc, pdf_obj *obj)
{
	if (!pdf_dict_gets(obj, "AP") || pdf_dict_gets(obj, "Dirty"))
	{
		if (!strcmp(pdf_to_name(pdf_dict_gets(obj, "Subtype")), "Widget"))
		{
			switch(get_field_type(doc, obj))
			{
			case FZ_WIDGET_TYPE_TEXT:
				synthesize_text_widget(doc, obj);
				break;
			case FZ_WIDGET_TYPE_PUSHBUTTON:
				update_pushbutton_widget(doc, obj);
				break;
			}
		}

		pdf_dict_dels(obj, "Dirty");
	}
}

static void execute_action(pdf_document *doc, pdf_obj *obj)
{
	fz_context *ctx = doc->ctx;
	pdf_obj *a;

	a = pdf_dict_gets(obj, "A");
	while (a)
	{
		char *type = pdf_to_name(pdf_dict_gets(a, "S"));

		if (!strcmp(type, "JavaScript"))
		{
			pdf_obj *js = pdf_dict_gets(a, "JS");
			if (js)
			{
				char *code = get_string_or_stream(doc, js);
				fz_try(ctx)
				{
					pdf_js_setup_event(doc->js, obj);
					pdf_js_execute(doc->js, code);
				}
				fz_always(ctx)
				{
					fz_free(ctx, code);
				}
				fz_catch(ctx)
				{
					fz_rethrow(ctx);
				}
			}
		}

		a = pdf_dict_gets(a, "Next");
	}
}

static void toggle_check_box(pdf_document *doc, pdf_obj *obj)
{
	pdf_obj *as;

	as = pdf_dict_gets(obj, "AS");

	if (strcmp(pdf_to_name(as), "Off"))
	{
		/* "as" neither missing nor set to Off. Set it to Off. */
		pdf_obj *off = fz_new_name(doc->ctx, "Off");
		pdf_dict_puts(obj, "AS", off);
		pdf_drop_obj(off);
	}
	else
	{
	    pdf_obj *ap, *n, *key;
		int len, i;

		ap = pdf_dict_gets(obj, "AP");
		n = pdf_dict_gets(ap, "N");

		/* Look for a key that isn't "Off" */
		len = pdf_dict_len(n);
		for (i = 0; i < len; i++)
		{
			key = pdf_dict_get_key(n, i);
			if (pdf_is_name(key) && strcmp(pdf_to_name(key), "Off"))
			{
				pdf_dict_puts(obj, "AS", key);
				break;
			}
		}
	}

	/* FIXME: should probably update the V entry in the field dictionary too */
}

int pdf_pass_event(pdf_document *doc, pdf_page *page, fz_ui_event *ui_event)
{
	pdf_annot *annot;
	pdf_hotspot *hp = &doc->hotspot;
	fz_point  *pt = &(ui_event->event.pointer.pt);
	int changed = 0;

	for (annot = page->annots; annot; annot = annot->next)
	{
		if (pt->x >= annot->pagerect.x0 && pt->x <= annot->pagerect.x1)
			if (pt->y >= annot->pagerect.y0 && pt->y <= annot->pagerect.y1)
				break;
	}

	switch (ui_event->etype)
	{
	case FZ_EVENT_TYPE_POINTER:
		{
			switch (ui_event->event.pointer.ptype)
			{
			case FZ_POINTER_DOWN:
				if (doc->focus)
				{
					fz_free_widget(doc->ctx, doc->focus);
					doc->focus = NULL;
				}

				if (annot)
				{
					doc->focus = new_widget(doc, annot->obj);
					hp->num = pdf_to_num(annot->obj);
					hp->gen = pdf_to_gen(annot->obj);
					hp->state = HOTSPOT_POINTER_DOWN;
					changed = 1;
				}
				break;

			case FZ_POINTER_UP:
				if (hp->state != 0)
					changed = 1;

				hp->num = 0;
				hp->gen = 0;
				hp->state = 0;

				if (annot)
				{
					switch(get_field_type(doc, annot->obj))
					{
					case FZ_WIDGET_TYPE_RADIOBUTTON:
					case FZ_WIDGET_TYPE_CHECKBOX:
						/* FIXME: treating radio buttons like check boxes, for now */
						toggle_check_box(doc, annot->obj);
						changed = 1;
						break;
					}

					execute_action(doc, annot->obj);
				}
				break;
			}
		}
		break;
	}

	return changed;
}

fz_rect *pdf_get_screen_update(pdf_document *doc)
{
	return NULL;
}

fz_widget *pdf_get_focussed_widget(pdf_document *doc)
{
	return doc->focus;
}

void fz_free_widget(fz_context *ctx, fz_widget *widget)
{
	if (widget)
	{
		switch(widget->type)
		{
		case FZ_WIDGET_TYPE_TEXT:
			fz_free(ctx, ((fz_widget_text *)widget)->text);
			break;
		}

		pdf_drop_obj(widget->obj);
		fz_free(ctx, widget);
	}
}

int fz_widget_get_type(fz_widget *widget)
{
	return widget->type;
}

char *pdf_field_getValue(pdf_document *doc, pdf_obj *field)
{
	return get_string_or_stream(doc, get_inheritable(doc, field, "V"));
}

void pdf_field_setValue(pdf_document *doc, pdf_obj *field, char *text)
{
	update_text_appearance(doc, field, text);
	update_text_field_value(doc->ctx, field, text);
}

char *pdf_field_getBorderStyle(pdf_document *doc, pdf_obj *field)
{
	char *bs = pdf_to_name(pdf_dict_getp(field, "BS/S"));

	switch (*bs)
	{
	case 'S': return "Solid";
	case 'D': return "Dashed";
	case 'B': return "Beveled";
	case 'I': return "Inset";
	case 'U': return "Underline";
	}

	return "Solid";
}

void pdf_field_setBorderStyle(pdf_document *doc, pdf_obj *field, char *text)
{
	fz_context *ctx = doc->ctx;
	pdf_obj *val = NULL;

	if (!strcmp(text, "Solid"))
		val = fz_new_name(ctx, "S");
	else if (!strcmp(text, "Dashed"))
		val = fz_new_name(ctx, "D");
	else if (!strcmp(text, "Beveled"))
		val = fz_new_name(ctx, "B");
	else if (!strcmp(text, "Inset"))
		val = fz_new_name(ctx, "I");
	else if (!strcmp(text, "Underline"))
		val = fz_new_name(ctx, "U");
	else
		return;

	fz_try(ctx);
	{
		pdf_dict_putp(field, "BS/S", val);
		pdf_field_mark_dirty(ctx, field);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(val);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

void pdf_field_buttonSetCaption(pdf_document *doc, pdf_obj *field, char *text)
{
	fz_context *ctx = doc->ctx;
	pdf_obj *val = pdf_new_string(ctx, text, strlen(text));

	fz_try(ctx);
	{
		if (get_field_type(doc, field) == FZ_WIDGET_TYPE_PUSHBUTTON)
		{
			pdf_dict_putp(field, "MK/CA", val);
			pdf_field_mark_dirty(ctx, field);
		}
	}
	fz_always(ctx)
	{
		pdf_drop_obj(val);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

void pdf_field_setFillColor(pdf_document *doc, pdf_obj *field, pdf_obj *col)
{
	pdf_dict_putp(field, "MK/BG", col);
	pdf_field_mark_dirty(doc->ctx, field);
}

void pdf_field_setTextColor(pdf_document *doc, pdf_obj *field, pdf_obj *col)
{
	fz_context *ctx = doc->ctx;
	da_info di;
	fz_buffer *fzbuf = NULL;
	char *da = pdf_to_str_buf(pdf_dict_gets(field, "DA"));
	unsigned char *buf;
	int len;
	pdf_obj *daobj = NULL;

	memset(&di, 0, sizeof(di));

	fz_var(fzbuf);
	fz_var(di);
	fz_var(daobj);
	fz_try(ctx)
	{
		parse_da(ctx, da, &di);
		di.col_size = 3;
		di.col[0] = pdf_to_real(pdf_array_get(col, 0));
		di.col[1] = pdf_to_real(pdf_array_get(col, 1));
		di.col[2] = pdf_to_real(pdf_array_get(col, 2));
		fzbuf = fz_new_buffer(ctx, 0);
		fzbuf_print_da(ctx, fzbuf, &di);
		len = fz_buffer_storage(ctx, fzbuf, &buf);
		daobj = pdf_new_string(ctx, buf, len);
		pdf_dict_puts(field, "DA", daobj);
		pdf_field_mark_dirty(ctx, field);
	}
	fz_always(ctx)
	{
		da_info_fin(ctx, &di);
		fz_drop_buffer(ctx, fzbuf);
		pdf_drop_obj(daobj);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "%s", ctx->error->message);
	}
}

char *fz_widget_text_get_text(fz_widget_text *tw)
{
	pdf_document *doc = tw->super.doc;
	fz_context *ctx = doc->ctx;

	fz_free(ctx, tw->text);
	tw->text = NULL;

	fz_try(ctx)
	{
		tw->text = pdf_field_getValue(doc, tw->super.obj);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "failed allocation in fz_widget_text_get_text");
	}

	return tw->text;
}

void fz_widget_text_set_text(fz_widget_text *tw, char *text)
{
	fz_context *ctx = tw->super.doc->ctx;

	fz_try(ctx)
	{
		pdf_field_setValue(tw->super.doc, tw->super.obj, text);
		fz_free(ctx, tw->text);
		tw->text = fz_strdup(ctx, text);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "fz_widget_text_set_text failed");
	}
}
