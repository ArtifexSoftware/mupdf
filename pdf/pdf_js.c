#include "fitz-internal.h"
#include "mupdf-internal.h"

struct pdf_js_s
{
	pdf_document   *doc;
	pdf_obj        *form;
	pdf_jsimp      *imp;
	pdf_jsimp_type *doctype;
	pdf_jsimp_type *fieldtype;
};

static pdf_jsimp_obj *field_getValue(void *jsctx, void *obj)
{
	pdf_js  *js    = (pdf_js *)jsctx;
	pdf_obj *field = (pdf_obj *)obj;

	return pdf_jsimp_fromString(js->imp, pdf_field_getValue(js->doc, field));
}

static void field_setValue(void *jsctx, void *obj, pdf_jsimp_obj *val)
{
	pdf_js  *js    = (pdf_js *)jsctx;
	pdf_obj *field = (pdf_obj *)obj;

	pdf_field_setValue(js->doc, field, pdf_jsimp_toString(js->imp, val));
}

static pdf_jsimp_obj *doc_getField(void *jsctx, void *obj, int argc, pdf_jsimp_obj *args[])
{
	pdf_js  *js = (pdf_js *)jsctx;
	pdf_obj *field;
	int      n, i;
	char    *name;

	if (argc != 1)
		return NULL;

	name = pdf_jsimp_toString(js->imp, args[0]);

	n = pdf_array_len(js->form);

	for (i = 0; i < n; i++)
	{
		pdf_obj *t;
		field = pdf_array_get(js->form, i);
		t = pdf_dict_gets(field, "T");
		if (!strcmp(name, pdf_to_str_buf(t)))
			break;
	}

	return (i < n) ? pdf_jsimp_new_obj(js->imp, js->fieldtype, field)
				   : NULL;
}

static void declare_dom(pdf_js *js)
{
	pdf_jsimp      *imp       = js->imp;

	/* Create the document type */
	js->doctype = pdf_jsimp_new_type(imp, NULL);
	pdf_jsimp_addmethod(imp, js->doctype, "getField", doc_getField);

	/* Create the field type */
	js->fieldtype = pdf_jsimp_new_type(imp, NULL);
	pdf_jsimp_addproperty(imp, js->fieldtype, "value", field_getValue, field_setValue);

	/* Create the document object and tell the engine to use */
	pdf_jsimp_set_global_type(js->imp, js->doctype);
}

pdf_js *pdf_new_js(pdf_document *doc)
{
	fz_context *ctx = doc->ctx;
	pdf_js     *js = NULL;
	pdf_obj    *javascript = NULL;
	fz_buffer  *fzbuf = NULL;

	fz_var(js);
	fz_var(javascript);
	fz_var(fzbuf);
	fz_try(ctx)
	{
		int len, i;
		pdf_obj *root, *acroform;
		js = fz_malloc_struct(ctx, pdf_js);
		js->doc = doc;

		/* Find the form array */
		root = pdf_dict_gets(doc->trailer, "Root");
		acroform = pdf_dict_gets(root, "AcroForm");
		js->form = pdf_dict_gets(acroform, "Fields");

		/* Initialise the javascript engine, passing the main context
		 * for use in memory allocation and exception handling. Also
		 * pass our js context, for it to pass back to us. */
		js->imp = pdf_new_jsimp(ctx, js);
		declare_dom(js);

		javascript = pdf_load_name_tree(doc, "JavaScript");
		len = pdf_dict_len(javascript);

		for (i = 0; i < len; i++)
		{
			pdf_obj *fragment = pdf_dict_get_val(javascript, i);
			pdf_obj *code = pdf_dict_gets(fragment, "JS");

			if (pdf_is_stream(doc, pdf_to_num(code), pdf_to_gen(code)))
			{
				unsigned char *buf;
				int len;

				fzbuf = pdf_load_stream(doc, pdf_to_num(code), pdf_to_gen(code));
				len = fz_buffer_storage(ctx, fzbuf, &buf);
				pdf_jsimp_execute_count(js->imp, buf, len);
				fz_drop_buffer(ctx, fzbuf);
				fzbuf = NULL;
			}
		}
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, fzbuf);
		pdf_drop_obj(javascript);
	}
	fz_catch(ctx)
	{
		pdf_drop_js(js);
		js = NULL;
	}

	return js;
}

void pdf_drop_js(pdf_js *js)
{
	if (js)
	{
		fz_context *ctx = js->doc->ctx;
		pdf_jsimp_drop_type(js->imp, js->fieldtype);
		pdf_jsimp_drop_type(js->imp, js->doctype);
		pdf_drop_jsimp(js->imp);
		fz_free(ctx, js);
	}
}

void pdf_js_execute(pdf_js *js, char *code)
{
	if (js)
	{
		fz_context *ctx = js->doc->ctx;
		fz_try(ctx)
		{
			pdf_jsimp_execute(js->imp, code);
		}
		fz_catch(ctx)
		{
		}
	}
}

void pdf_js_execute_count(pdf_js *js, char *code, int count)
{
	if (js)
	{
		fz_context *ctx = js->doc->ctx;
		fz_try(ctx)
		{
			pdf_jsimp_execute_count(js->imp, code, count);
		}
		fz_catch(ctx)
		{
		}
	}
}