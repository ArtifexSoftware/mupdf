#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#if FZ_ENABLE_JS

#include "mujs.h"

#include <stdarg.h>
#include <string.h>

struct pdf_js_s
{
	fz_context *ctx;
	pdf_document *doc;
	pdf_obj *form;
	pdf_js_event event;
	js_State *imp;
};

FZ_NORETURN static void rethrow(pdf_js *js)
{
	js_newerror(js->imp, fz_caught_message(js->ctx));
	js_throw(js->imp);
}

/* Unpack argument object with named arguments into actual parameters. */
static pdf_js *unpack_arguments(js_State *J, ...)
{
	if (js_isobject(J, 1))
	{
		int i = 1;
		va_list args;

		js_copy(J, 1);

		va_start(args, J);
		for (;;)
		{
			const char *s = va_arg(args, const char *);
			if (!s)
				break;
			js_getproperty(J, -1, s);
			js_replace(J, i++);
		}
		va_end(args);

		js_pop(J, 1);
	}
	return js_getcontext(J);
}

static char *pdf_from_utf8(fz_context *ctx, const char *utf8)
{
	char *pdf = fz_malloc(ctx, strlen(utf8)+1);
	int i = 0;
	unsigned char c;

	while ((c = *utf8) != 0)
	{
		if ((c & 0x80) == 0 && pdf_doc_encoding[c] == c)
		{
			pdf[i++] = c;
			utf8++ ;
		}
		else
		{
			int rune;
			int j;

			utf8 += fz_chartorune(&rune, utf8);

			for (j = 0; j < sizeof(pdf_doc_encoding) && pdf_doc_encoding[j] != rune; j++)
				;

			if (j < sizeof(pdf_doc_encoding))
				pdf[i++] = j;
		}
	}

	pdf[i] = 0;

	return pdf;
}

static void app_alert(js_State *J)
{
	pdf_js *js = unpack_arguments(J, "cMsg", "nIcon", "nType", "cTitle", 0);
	pdf_alert_event event;

	event.message = js_tostring(J, 1);
	event.icon_type = js_tointeger(J, 2);
	event.button_group_type = js_tointeger(J, 3);
	event.title = js_tostring(J, 4);

	fz_try(js->ctx)
		pdf_event_issue_alert(js->ctx, js->doc, &event);
	fz_catch(js->ctx)
		rethrow(js);

	js_pushnumber(J, event.button_pressed);
}

static void app_execDialog(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	// monitor
	// inheritDialog
	// parentDoc

	fz_try(js->ctx)
		pdf_event_issue_exec_dialog(js->ctx, js->doc);
	fz_catch(js->ctx)
		rethrow(js);

	// return "ok" or "cancel"
	js_pushstring(J, "cancel");
}

static void app_execMenuItem(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	const char *cMenuItem = js_tostring(J, 1);
	fz_try(js->ctx)
		pdf_event_issue_exec_menu_item(js->ctx, js->doc, cMenuItem);
	fz_catch(js->ctx)
		rethrow(js);
}

static void app_launchURL(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	const char *cUrl = js_tostring(J, 1);
	int bNewFrame = js_toboolean(J, 1);
	fz_try(js->ctx)
		pdf_event_issue_launch_url(js->ctx, js->doc, cUrl, bNewFrame);
	fz_catch(js->ctx)
		rethrow(js);
}

static void field_finalize(js_State *J, void *p)
{
	pdf_js *js = js_getcontext(J);
	pdf_drop_obj(js->ctx, p);
}

static void field_buttonSetCaption(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	pdf_obj *field = js_touserdata(J, 0, "Field");
	const char *cCaption = js_tostring(J, 1);
	char *caption = pdf_from_utf8(js->ctx, cCaption);
	fz_try(js->ctx)
		pdf_field_set_button_caption(js->ctx, js->doc, field, caption);
	fz_always(js->ctx)
		fz_free(js->ctx, caption);
	fz_catch(js->ctx)
		rethrow(js);
}

static void field_getName(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	pdf_obj *field = js_touserdata(J, 0, "Field");
	char *name;
	fz_try(js->ctx)
		name = pdf_field_name(js->ctx, js->doc, field);
	fz_catch(js->ctx)
		rethrow(js);
	js_pushstring(J, name); /* to utf8? */
}

static void field_setName(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	fz_warn(js->ctx, "Unexpected call to field_setName");
}

static void field_getDisplay(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	pdf_obj *field = js_touserdata(J, 0, "Field");
	int display;
	fz_try(js->ctx)
		display = pdf_field_display(js->ctx, js->doc, field);
	fz_catch(js->ctx)
		rethrow(js);
	js_pushnumber(J, display);
}

static void field_setDisplay(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	pdf_obj *field = js_touserdata(J, 0, "Field");
	int display = js_tonumber(J, 1);
	fz_try(js->ctx)
		pdf_field_set_display(js->ctx, js->doc, field, display);
	fz_catch(js->ctx)
		rethrow(js);
}

static pdf_obj *load_color(pdf_js *js, int idx)
{
	fz_context *ctx = js->ctx;
	pdf_document *doc = js->doc;
	js_State *J = js->imp;

	pdf_obj *color = NULL;
	int i, n;
	float c;

	n = js_getlength(J, idx);

	/* The only legitimate color expressed as an array of length 1
	 * is [T], meaning transparent. Return a NULL object to represent
	 * transparent */
	if (n <= 1)
		return NULL;

	fz_var(color);

	fz_try(ctx)
	{
		color = pdf_new_array(ctx, doc, n-1);
		for (i = 0; i < n-1; i++)
		{
			js_getindex(J, idx, i+1);
			c = js_tonumber(J, -1);
			js_pop(J, 1);

			pdf_array_push_drop(ctx, color, pdf_new_real(ctx, doc, c));
		}
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, color);
		rethrow(js);
	}

	return color;
}

static void field_getFillColor(js_State *J)
{
	js_pushundefined(J);
}

static void field_setFillColor(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	pdf_obj *field = js_touserdata(J, 0, "Field");
	pdf_obj *color = load_color(js, 1);
	fz_try(js->ctx)
		pdf_field_set_fill_color(js->ctx, js->doc, field, color);
	fz_always(js->ctx)
		pdf_drop_obj(js->ctx, color);
	fz_catch(js->ctx)
		rethrow(js);
}

static void field_getTextColor(js_State *J)
{
	js_pushundefined(J);
}

static void field_setTextColor(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	pdf_obj *field = js_touserdata(J, 0, "Field");
	pdf_obj *color = load_color(js, 1);
	fz_try(js->ctx)
		pdf_field_set_text_color(js->ctx, js->doc, field, color);
	fz_always(js->ctx)
		pdf_drop_obj(js->ctx, color);
	fz_catch(js->ctx)
		rethrow(js);
}

static void field_getBorderStyle(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	pdf_obj *field = js_touserdata(J, 0, "Field");
	const char *border_style;
	fz_try(js->ctx)
		border_style = pdf_field_border_style(js->ctx, js->doc, field);
	fz_catch(js->ctx)
		rethrow(js);
	js_pushstring(J, border_style);
}

static void field_setBorderStyle(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	pdf_obj *field = js_touserdata(J, 0, "Field");
	const char *border_style = js_tostring(J, 1);
	fz_try(js->ctx)
		pdf_field_set_border_style(js->ctx, js->doc, field, border_style);
	fz_catch(js->ctx)
		rethrow(js);
}

static void field_getValue(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	pdf_obj *field = js_touserdata(J, 0, "Field");
	char *val;

	fz_try(js->ctx)
		val = pdf_field_value(js->ctx, js->doc, field);
	fz_catch(js->ctx)
		rethrow(js);

	js_pushstring(J, val ? val : "");

	fz_free(js->ctx, val);
}

static void field_setValue(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	pdf_obj *field = js_touserdata(J, 0, "Field");
	const char *value = js_tostring(J, 1);

	fz_try(js->ctx)
		(void)pdf_field_set_value(js->ctx, js->doc, field, value);
	fz_catch(js->ctx)
		rethrow(js);
}

static void event_getTarget(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	js_getregistry(J, "Field");
	js_newuserdata(J, "Field", pdf_keep_obj(js->ctx, js->event.target), field_finalize);
}

static void event_setTarget(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	fz_warn(js->ctx, "Unexpected call to event_setTarget");
}

static void event_getValue(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	const char *v = js->event.value;
	js_pushstring(J, v ? v : "");
}

static void event_setValue(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	const char *value = js_tostring(J, 1);
	fz_free(js->ctx, js->event.value);
	js->event.value = fz_strdup(js->ctx, value);
}

static void event_getWillCommit(js_State *J)
{
	js_pushnumber(J, 1);
}

static void event_setWillCommit(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	fz_warn(js->ctx, "Unexpected call to event_setWillCommit");
}

static void event_getRC(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	js_pushnumber(J, js->event.rc);
}

static void event_setRC(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	js->event.rc = js_tointeger(js->imp, 1);
}

static void doc_getField(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	fz_context *ctx = js->ctx;
	const char *cName = js_tostring(J, 1);
	char *name = pdf_from_utf8(ctx, cName);
	pdf_obj *dict;

	fz_try(ctx)
		dict = pdf_lookup_field(ctx, js->form, name);
	fz_always(ctx)
		fz_free(ctx, name);
	fz_catch(ctx)
		rethrow(js);

	if (dict)
	{
		js_getregistry(J, "Field");
		js_newuserdata(J, "Field", pdf_keep_obj(js->ctx, dict), field_finalize);
	}
	else
	{
		js_pushnull(J);
	}
}

static void reset_field(pdf_js *js, const char *cName)
{
	fz_context *ctx = js->ctx;
	if (cName)
	{
		char *name = pdf_from_utf8(ctx, cName);
		fz_try(ctx)
		{
			pdf_obj *field = js_touserdata(js->imp, 0, "Field");
			if (field)
				pdf_field_reset(ctx, js->doc, field);
		}
		fz_always(ctx)
			fz_free(ctx, name);
		fz_catch(ctx)
			rethrow(js);
	}
}

static void doc_resetForm(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	fz_context *ctx = js->ctx;
	int i, n;

	/* An array of fields has been passed in. Call pdf_reset_field on each item. */
	if (js_isarray(J, 1))
	{
		n = js_getlength(J, 1);
		for (i = 0; i < n; ++i)
		{
			js_getindex(J, 1, i);
			reset_field(js, js_tostring(J, -1));
			js_pop(J, 1);
		}
	}

	/* No argument or null passed in means reset all. */
	else
	{
		n = pdf_array_len(ctx, js->form);
		for (i = 0; i < n; i++)
		{
			fz_try(ctx)
				pdf_field_reset(ctx, js->doc, pdf_array_get(ctx, js->form, i));
			fz_catch(ctx)
				rethrow(js);
		}
	}
}

static void doc_print(js_State *J)
{
	pdf_js *js = js_getcontext(J);
	fz_try(js->ctx)
		pdf_event_issue_print(js->ctx, js->doc);
	fz_catch(js->ctx)
		rethrow(js);
}

static void doc_mailDoc(js_State *J)
{
	pdf_js *js = unpack_arguments(J, "bUI", "cTo", "cCc", "cBcc", "cSubject", "cMessage", 0);
	pdf_mail_doc_event event;

	event.ask_user = js_isdefined(J, 1) ? js_toboolean(J, 1) : 1;
	event.to = js_tostring(J, 2);
	event.cc = js_tostring(J, 3);
	event.bcc = js_tostring(J, 4);
	event.subject = js_tostring(J, 5);
	event.message = js_tostring(J, 6);

	fz_try(js->ctx)
		pdf_event_issue_mail_doc(js->ctx, js->doc, &event);
	fz_catch(js->ctx)
		rethrow(js);
}

static void addmethod(js_State *J, const char *name, js_CFunction fun, int n)
{
	const char *realname = strchr(name, '.');
	realname = realname ? realname + 1 : name;
	js_newcfunction(J, fun, name, n);
	js_defproperty(J, -2, realname, JS_READONLY | JS_DONTENUM | JS_DONTCONF);
}

static void addproperty(js_State *J, const char *name, js_CFunction getfun, js_CFunction setfun)
{
	const char *realname = strchr(name, '.');
	realname = realname ? realname + 1 : name;
	js_newcfunction(J, getfun, name, 0);
	js_newcfunction(J, setfun, name, 1);
	js_defaccessor(J, -3, realname, JS_READONLY | JS_DONTENUM | JS_DONTCONF);
}

static void declare_dom(pdf_js *js)
{
	js_State *J = js->imp;

	/* Allow access to the global environment via the 'global' name */
	js_pushglobal(J);
	js_defglobal(J, "global", JS_READONLY | JS_DONTCONF | JS_DONTENUM);

	/* Create the 'app' object */
	js_newobject(J);
	{
#if defined(_WIN32) || defined(_WIN64)
		js_pushstring(J, "WIN");
#elif defined(__APPLE__)
		js_pushstring(J, "MAC");
#else
		js_pushstring(J, "UNIX");
#endif
		js_defproperty(J, -2, "app.platform", JS_READONLY | JS_DONTENUM | JS_DONTCONF);

		addmethod(J, "app.alert", app_alert, 4);
		addmethod(J, "app.execDialog", app_execDialog, 0);
		addmethod(J, "app.execMenuItem", app_execMenuItem, 1);
		addmethod(J, "app.launchURL", app_launchURL, 2);
	}
	js_defglobal(J, "app", JS_READONLY | JS_DONTCONF | JS_DONTENUM);

	/* Create the 'event' object */
	js_newobject(J);
	{
		addproperty(J, "event.target", event_getTarget, event_setTarget);
		addproperty(J, "event.value", event_getValue, event_setValue);
		addproperty(J, "event.willCommit", event_getWillCommit, event_setWillCommit);
		addproperty(J, "event.rc", event_getRC, event_setRC);
	}
	js_defglobal(J, "event", JS_READONLY | JS_DONTCONF | JS_DONTENUM);

	/* Create the Field prototype object */
	js_newobject(J);
	{
		addproperty(J, "Field.value", field_getValue, field_setValue);
		addproperty(J, "Field.borderStyle", field_getBorderStyle, field_setBorderStyle);
		addproperty(J, "Field.textColor", field_getTextColor, field_setTextColor);
		addproperty(J, "Field.fillColor", field_getFillColor, field_setFillColor);
		addproperty(J, "Field.display", field_getDisplay, field_setDisplay);
		addproperty(J, "Field.name", field_getName, field_setName);
		addmethod(J, "Field.buttonSetCaption", field_buttonSetCaption, 1);
	}
	js_setregistry(J, "Field");

	/* Create the Doc prototype object */
	js_newobject(J);
	{
		addmethod(J, "Doc.getField", doc_getField, 1);
		addmethod(J, "Doc.resetForm", doc_resetForm, 0);
		addmethod(J, "Doc.print", doc_print, 0);
		addmethod(J, "Doc.mailDoc", doc_mailDoc, 6);
	}
	js_setregistry(J, "Doc");

	js_getregistry(J, "Doc");
	js_setglobal(J, "MuPDF_Doc"); /* for pdf-util.js use */
}

extern const char fz_source_pdf_pdf_js_util_js[];

static void preload_helpers(pdf_js *js)
{
	/* When testing on the cluster:
	 * Use a fixed date for "new Date" and Date.now().
	 * Sadly, this breaks uses of the Date function without the new keyword.
	 * Return a fixed number from Math.random().
	 */
#ifdef CLUSTER
	js_dostring(js->imp,
"var MuPDFOldDate = Date\n"
"Date = function() { return new MuPDFOldDate(298252800000); }\n"
"Date.now = function() { return 298252800000; }\n"
"Date.UTC = function() { return 298252800000; }\n"
"Date.parse = MuPDFOldDate.parse;\n"
"Math.random = function() { return 1/4; }\n"
	);
#endif

	js_dostring(js->imp, fz_source_pdf_pdf_js_util_js);
}

void pdf_drop_js(fz_context *ctx, pdf_js *js)
{
	if (js)
	{
		js_freestate(js->imp);
		fz_free(ctx, js->event.value);
		fz_free(ctx, js);
	}
}

static void *pdf_js_alloc(void *actx, void *ptr, int n)
{
	fz_context *ctx = actx;
	if (n == 0) {
		fz_free(ctx, ptr);
		return NULL;
	}
	return fz_resize_array_no_throw(ctx, ptr, n, 1);
}

static pdf_js *pdf_new_js(fz_context *ctx, pdf_document *doc)
{
	pdf_js *js = fz_malloc_struct(ctx, pdf_js);

	js->ctx = ctx;
	js->doc = doc;

	fz_try(ctx)
	{
		pdf_obj *root, *acroform;

		/* Find the form array */
		root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
		acroform = pdf_dict_get(ctx, root, PDF_NAME_AcroForm);
		js->form = pdf_dict_get(ctx, acroform, PDF_NAME_Fields);

		/* Initialise the javascript engine, passing the fz_context for use in memory allocation. */
		js->imp = js_newstate(pdf_js_alloc, ctx, 0);
		if (!js->imp)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot initialize javascript engine");

		/* Also set our pdf_js context, so we can retrieve it in callbacks. */
		js_setcontext(js->imp, js);

		declare_dom(js);
		preload_helpers(js);
	}
	fz_catch(ctx)
	{
		pdf_drop_js(ctx, js);
		js = NULL;
	}

	return js;
}

static void pdf_js_load_document_level(pdf_js *js)
{
	fz_context *ctx = js->ctx;
	pdf_document *doc = js->doc;
	pdf_obj *javascript;
	int len, i;

	javascript = pdf_load_name_tree(ctx, doc, PDF_NAME_JavaScript);
	len = pdf_dict_len(ctx, javascript);

	fz_try(ctx)
	{
		for (i = 0; i < len; i++)
		{
			pdf_obj *fragment = pdf_dict_get_val(ctx, javascript, i);
			pdf_obj *code = pdf_dict_get(ctx, fragment, PDF_NAME_JS);
			char *codebuf = pdf_load_stream_or_string_as_utf8(ctx, code);
			pdf_js_execute(js, codebuf);
			fz_free(ctx, codebuf);
		}
	}
	fz_always(ctx)
		pdf_drop_obj(ctx, javascript);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void pdf_js_setup_event(pdf_js *js, pdf_js_event *e)
{
	if (js)
	{
		fz_context *ctx = js->ctx;
		char *ev = e->value ? e->value : "";
		char *v = fz_strdup(ctx, ev);

		fz_free(ctx, js->event.value);
		js->event.value = v;

		js->event.target = e->target;
		js->event.rc = 1;
	}
}

pdf_js_event *pdf_js_get_event(pdf_js *js)
{
	return js ? &js->event : NULL;
}

void pdf_js_execute(pdf_js *js, char *source)
{
	if (js)
	{
		if (js_ploadstring(js->imp, "[pdf]", source))
		{
			fz_warn(js->ctx, "%s", js_tostring(js->imp, -1));
			js_pop(js->imp, 1);
			return;
		}
		js_getregistry(js->imp, "Doc"); /* set 'this' to the Doc object */
		if (js_pcall(js->imp, 0))
		{
			fz_warn(js->ctx, "%s", js_tostring(js->imp, -1));
			js_pop(js->imp, 1);
			return;
		}
		js_pop(js->imp, 1);
	}
}

void pdf_enable_js(fz_context *ctx, pdf_document *doc)
{
	if (!doc->js)
	{
		doc->js = pdf_new_js(ctx, doc);
		pdf_js_load_document_level(doc->js);
	}
}

void pdf_disable_js(fz_context *ctx, pdf_document *doc)
{
	pdf_drop_js(ctx, doc->js);
	doc->js = NULL;
}

int pdf_js_supported(fz_context *ctx, pdf_document *doc)
{
	return doc->js != NULL;
}

#else /* FZ_ENABLE_JS */

void pdf_drop_js(fz_context *ctx, pdf_js *js) { }
void pdf_enable_js(fz_context *ctx, pdf_document *doc) { }
void pdf_disable_js(fz_context *ctx, pdf_document *doc) { }
int pdf_js_supported(fz_context *ctx, pdf_document *doc) { return 0; }
void pdf_js_setup_event(pdf_js *js, pdf_js_event *e) { }
pdf_js_event *pdf_js_get_event(pdf_js *js) { return NULL; }
void pdf_js_execute(pdf_js *js, char *code) { }

#endif /* FZ_ENABLE_JS */
