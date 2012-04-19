#include "fitz-internal.h"
#include "mupdf-internal.h"

struct pdf_js_s
{
	pdf_document   *doc;
	pdf_obj        *form;
	pdf_jsimp      *imp;
	pdf_jsimp_type *doctype;
	pdf_jsimp_type *fieldtype;
	pdf_jsimp_obj  *jsdoc;
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

	/* Create the document object and tell the engine to use
	 * it as "this" */
	js->jsdoc = pdf_jsimp_new_obj(imp, js->doctype, NULL);
	pdf_jsimp_set_this(js->imp, js->jsdoc);
}

pdf_js *pdf_new_js(pdf_document *doc)
{
	fz_context *ctx = doc->ctx;
	pdf_js     *js = NULL;

	fz_var(js);
	fz_try(ctx)
	{
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
	}
	fz_catch(ctx)
	{
		pdf_drop_js(js);
	}

	return js;
}

void pdf_drop_js(pdf_js *js)
{
	if (js)
	{
		fz_context *ctx = js->doc->ctx;
		pdf_drop_jsimp(js->imp);
		fz_free(ctx, js);
	}
}

void pdf_js_execute(pdf_js *js, char *code)
{
	pdf_jsimp_execute(js->imp, code);
}