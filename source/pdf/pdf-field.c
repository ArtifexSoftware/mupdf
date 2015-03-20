#include "mupdf/pdf.h"

pdf_obj *pdf_get_inheritable(fz_context *ctx, pdf_document *doc, pdf_obj *obj, pdf_obj *key)
{
	pdf_obj *fobj = NULL;

	while (!fobj && obj)
	{
		fobj = pdf_dict_get(ctx, obj, key);

		if (!fobj)
			obj = pdf_dict_get(ctx, obj, PDF_NAME_Parent);
	}

	return fobj ? fobj : pdf_dict_get(ctx, pdf_dict_get(ctx, pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root), PDF_NAME_AcroForm), key);
}

char *pdf_get_string_or_stream(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	int len = 0;
	char *buf = NULL;
	fz_buffer *strmbuf = NULL;
	char *text = NULL;

	fz_var(strmbuf);
	fz_var(text);
	fz_try(ctx)
	{
		if (pdf_is_string(ctx, obj))
		{
			len = pdf_to_str_len(ctx, obj);
			buf = pdf_to_str_buf(ctx, obj);
		}
		else if (pdf_is_stream(ctx, doc, pdf_to_num(ctx, obj), pdf_to_gen(ctx, obj)))
		{
			strmbuf = pdf_load_stream(ctx, doc, pdf_to_num(ctx, obj), pdf_to_gen(ctx, obj));
			len = fz_buffer_storage(ctx, strmbuf, (unsigned char **)&buf);
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

char *pdf_field_value(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	return pdf_get_string_or_stream(ctx, doc, pdf_get_inheritable(ctx, doc, field, PDF_NAME_V));
}

int pdf_get_field_flags(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	return pdf_to_int(ctx, pdf_get_inheritable(ctx, doc, obj, PDF_NAME_Ff));
}

static pdf_obj *get_field_type_name(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	return pdf_get_inheritable(ctx, doc, obj, PDF_NAME_FT);
}

int pdf_field_type(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	pdf_obj *type = get_field_type_name(ctx, doc, obj);
	int flags = pdf_get_field_flags(ctx, doc, obj);

	if (pdf_name_eq(ctx, type, PDF_NAME_Btn))
	{
		if (flags & Ff_Pushbutton)
			return PDF_WIDGET_TYPE_PUSHBUTTON;
		else if (flags & Ff_Radio)
			return PDF_WIDGET_TYPE_RADIOBUTTON;
		else
			return PDF_WIDGET_TYPE_CHECKBOX;
	}
	else if (pdf_name_eq(ctx, type, PDF_NAME_Tx))
		return PDF_WIDGET_TYPE_TEXT;
	else if (pdf_name_eq(ctx, type, PDF_NAME_Ch))
	{
		if (flags & Ff_Combo)
			return PDF_WIDGET_TYPE_COMBOBOX;
		else
			return PDF_WIDGET_TYPE_LISTBOX;
	}
	else if (pdf_name_eq(ctx, type, PDF_NAME_Sig))
		return PDF_WIDGET_TYPE_SIGNATURE;
	else
		return PDF_WIDGET_TYPE_NOT_WIDGET;
}

void pdf_set_field_type(fz_context *ctx, pdf_document *doc, pdf_obj *obj, int type)
{
	int setbits = 0;
	int clearbits = 0;
	pdf_obj *typename = NULL;

	switch(type)
	{
	case PDF_WIDGET_TYPE_PUSHBUTTON:
		typename = PDF_NAME_Btn;
		setbits = Ff_Pushbutton;
		break;
	case PDF_WIDGET_TYPE_CHECKBOX:
		typename = PDF_NAME_Btn;
		clearbits = Ff_Pushbutton;
		setbits = Ff_Radio;
		break;
	case PDF_WIDGET_TYPE_RADIOBUTTON:
		typename = PDF_NAME_Btn;
		clearbits = (Ff_Pushbutton|Ff_Radio);
		break;
	case PDF_WIDGET_TYPE_TEXT:
		typename = PDF_NAME_Tx;
		break;
	case PDF_WIDGET_TYPE_LISTBOX:
		typename = PDF_NAME_Ch;
		clearbits = Ff_Combo;
		break;
	case PDF_WIDGET_TYPE_COMBOBOX:
		typename = PDF_NAME_Ch;
		setbits = Ff_Combo;
		break;
	case PDF_WIDGET_TYPE_SIGNATURE:
		typename = PDF_NAME_Sig;
		break;
	}

	if (typename)
		pdf_dict_put_drop(ctx, obj, PDF_NAME_FT, typename);

	if (setbits != 0 || clearbits != 0)
	{
		int bits = pdf_to_int(ctx, pdf_dict_get(ctx, obj, PDF_NAME_Ff));
		bits &= ~clearbits;
		bits |= setbits;
		pdf_dict_put_drop(ctx, obj, PDF_NAME_Ff, pdf_new_int(ctx, doc, bits));
	}
}
