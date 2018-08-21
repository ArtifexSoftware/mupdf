#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>

char *pdf_field_value(fz_context *ctx, pdf_document *doc, pdf_obj *field)
{
	pdf_obj *v = pdf_dict_get_inheritable(ctx, field, PDF_NAME(V));
	if (pdf_is_name(ctx, v))
		return fz_strdup(ctx, pdf_to_name(ctx, v));
	return pdf_load_stream_or_string_as_utf8(ctx, v);
}

int pdf_get_field_flags(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	return pdf_to_int(ctx, pdf_dict_get_inheritable(ctx, obj, PDF_NAME(Ff)));
}

static pdf_obj *get_field_type_name(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	return pdf_dict_get_inheritable(ctx, obj, PDF_NAME(FT));
}

int pdf_field_type(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	pdf_obj *type = get_field_type_name(ctx, doc, obj);
	int flags = pdf_get_field_flags(ctx, doc, obj);

	if (pdf_name_eq(ctx, type, PDF_NAME(Btn)))
	{
		if (flags & PDF_BTN_FIELD_IS_PUSHBUTTON)
			return PDF_WIDGET_TYPE_PUSHBUTTON;
		else if (flags & PDF_BTN_FIELD_IS_RADIO)
			return PDF_WIDGET_TYPE_RADIOBUTTON;
		else
			return PDF_WIDGET_TYPE_CHECKBOX;
	}
	else if (pdf_name_eq(ctx, type, PDF_NAME(Tx)))
		return PDF_WIDGET_TYPE_TEXT;
	else if (pdf_name_eq(ctx, type, PDF_NAME(Ch)))
	{
		if (flags & PDF_CH_FIELD_IS_COMBO)
			return PDF_WIDGET_TYPE_COMBOBOX;
		else
			return PDF_WIDGET_TYPE_LISTBOX;
	}
	else if (pdf_name_eq(ctx, type, PDF_NAME(Sig)))
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
		typename = PDF_NAME(Btn);
		setbits = PDF_BTN_FIELD_IS_PUSHBUTTON;
		break;
	case PDF_WIDGET_TYPE_CHECKBOX:
		typename = PDF_NAME(Btn);
		clearbits = PDF_BTN_FIELD_IS_PUSHBUTTON;
		setbits = PDF_BTN_FIELD_IS_RADIO;
		break;
	case PDF_WIDGET_TYPE_RADIOBUTTON:
		typename = PDF_NAME(Btn);
		clearbits = (PDF_BTN_FIELD_IS_PUSHBUTTON|PDF_BTN_FIELD_IS_RADIO);
		break;
	case PDF_WIDGET_TYPE_TEXT:
		typename = PDF_NAME(Tx);
		break;
	case PDF_WIDGET_TYPE_LISTBOX:
		typename = PDF_NAME(Ch);
		clearbits = PDF_CH_FIELD_IS_COMBO;
		break;
	case PDF_WIDGET_TYPE_COMBOBOX:
		typename = PDF_NAME(Ch);
		setbits = PDF_CH_FIELD_IS_COMBO;
		break;
	case PDF_WIDGET_TYPE_SIGNATURE:
		typename = PDF_NAME(Sig);
		break;
	}

	if (typename)
		pdf_dict_put_drop(ctx, obj, PDF_NAME(FT), typename);

	if (setbits != 0 || clearbits != 0)
	{
		int bits = pdf_dict_get_int(ctx, obj, PDF_NAME(Ff));
		bits &= ~clearbits;
		bits |= setbits;
		pdf_dict_put_int(ctx, obj, PDF_NAME(Ff), bits);
	}
}
