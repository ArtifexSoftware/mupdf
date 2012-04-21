/*
 * This is a dummy JavaScript engine. It cheats by recognising the specific
 * strings in calc.pdf, and hence will work only for that file. It is for
 * testing only.
 */


#include "fitz-internal.h"
#include "mupdf-internal.h"

enum
{
	FUNC_NONE,
	FUNC_PLUS,
	FUNC_MINUS,
	FUNC_MULT,
	FUNC_DIV
};

struct pdf_jsimp_s
{
	fz_context *ctx;
	void       *jsctx;
	double accum;
	double entry;
	double multiplier;
	double divisor;
	int func;
	pdf_jsimp_obj *jsthis;
	pdf_jsimp_obj *display;
	pdf_jsimp_obj *funcfield;
};

/* We need only a couple of specific methods for calc.pdf */
struct pdf_jsimp_type_s
{
	pdf_jsimp_dtr    *dtr;
	pdf_jsimp_method *getField;
	pdf_jsimp_getter *getValue;
	pdf_jsimp_setter *setValue;
};

struct pdf_jsimp_obj_s
{
	pdf_jsimp_type *type;
	void *obj;
};


static double digit_button(pdf_jsimp *imp, int digit)
{
	imp->entry = imp->entry * imp->multiplier + digit / imp->divisor;

	if (imp->divisor >= 10)
	{
		imp->divisor = imp->divisor * 10;
	}
	else
	{
		imp->multiplier = 10;
	}

	return imp->entry;
}

static void assign_display_value(pdf_jsimp *imp, double val)
{
	fz_context *ctx = imp->ctx;
	char valstr[256];
	pdf_jsimp_obj *valobj = NULL;
	pdf_jsimp_obj *strarg = NULL;

	fz_var(valobj);
	fz_var(strarg);
	fz_try(ctx)
	{
		if (imp->display == NULL)
		{
			pdf_jsimp_obj *doc = imp->jsthis;
			strarg = pdf_jsimp_fromString(imp, "Display");
			imp->display = doc->type->getField(imp->jsctx, doc->obj, 1, &strarg);
		}

		snprintf(valstr, sizeof(valstr), "%.8f", val);
		if (imp->display && imp->display->type->setValue)
		{
			valobj = pdf_jsimp_fromString(imp, valstr);
			imp->display->type->setValue(imp->jsctx, imp->display->obj, valobj);
		}
	}
	fz_always(ctx)
	{
		pdf_jsimp_drop_obj(imp, strarg);
		pdf_jsimp_drop_obj(imp, valobj);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void assign_func_value(pdf_jsimp *imp, int val)
{
	fz_context *ctx = imp->ctx;
	pdf_jsimp_obj *valobj = NULL;
	pdf_jsimp_obj *strarg = NULL;

	fz_var(valobj);
	fz_var(strarg);
	fz_try(ctx)
	{
		if (imp->funcfield == NULL)
		{
			pdf_jsimp_obj *strarg = pdf_jsimp_fromString(imp, "Func");
			pdf_jsimp_obj *doc = imp->jsthis;
			imp->funcfield = doc->type->getField(imp->jsctx, doc->obj, 1, &strarg);
		}

		if (imp->funcfield && imp->funcfield->type->setValue)
		{
			switch(val)
			{
			case FUNC_NONE:
				valobj = pdf_jsimp_fromString(imp, "");
				break;
			case FUNC_MULT:
				valobj = pdf_jsimp_fromString(imp, "MULT");
				break;
			case FUNC_DIV:
				valobj = pdf_jsimp_fromString(imp, "DIV");
				break;
			case FUNC_PLUS:
				valobj = pdf_jsimp_fromString(imp, "PLUS");
				break;
			case FUNC_MINUS:
				valobj = pdf_jsimp_fromString(imp, "MINUS");
				break;
			}

			if (valobj)
				imp->funcfield->type->setValue(imp->jsctx, imp->funcfield->obj, valobj);
		}
	}
	fz_always(ctx)
	{
		pdf_jsimp_drop_obj(imp, strarg);
		pdf_jsimp_drop_obj(imp, valobj);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void clear_entry(pdf_jsimp *imp)
{
	imp->entry = 0;
	imp->multiplier = 1;
	imp->divisor = 1;
}

static void update_result(pdf_jsimp *imp)
{
	switch(imp->func)
	{
	case FUNC_PLUS:
		imp->accum = imp->accum + imp->entry;
		break;
	case FUNC_MINUS:
		imp->accum = imp->accum - imp->entry;
		break;
	case FUNC_MULT:
		imp->accum = imp->accum * imp->entry;
		break;
	case FUNC_DIV:
		if (imp->entry != 0)
			imp->accum = imp->accum / imp->entry;
		break;
	}

	imp->func = FUNC_NONE;
	assign_func_value(imp, FUNC_NONE);
	clear_entry(imp);
}

static void func_button(pdf_jsimp *imp, int func)
{
	if (imp->func != FUNC_NONE)
	{
		update_result(imp);
	}
	else
	{
		if (imp->entry != 0)
			imp->accum = imp->entry;

		imp->func = func;
		assign_func_value(imp, func);
		clear_entry(imp);
	}
}

static void all_cancel(pdf_jsimp *imp)
{
	clear_entry(imp);
	assign_display_value(imp, 0);
	imp->accum = 0;
	assign_func_value(imp, FUNC_NONE);
}

pdf_jsimp *pdf_new_jsimp(fz_context *ctx, void *jsctx)
{
	pdf_jsimp *imp = fz_malloc_struct(ctx, pdf_jsimp);

	imp->ctx = ctx;
	imp->jsctx = jsctx;
	imp->accum = 0;
	imp->entry = 0;
	imp->divisor = 1;
	imp->multiplier = 1;

	return imp;
}

void pdf_drop_jsimp(pdf_jsimp *imp)
{
	if (imp)
	{
		fz_free(imp->ctx, imp);
	}
}

pdf_jsimp_type *pdf_jsimp_new_type(pdf_jsimp *imp, pdf_jsimp_dtr *dtr)
{
	pdf_jsimp_type *type = fz_malloc_struct(imp->ctx, pdf_jsimp_type);
	type->dtr = dtr;

	return type;
}

void pdf_jsimp_drop_type(pdf_jsimp *imp, pdf_jsimp_type *type)
{
	fz_free(imp->ctx, type);
}

void pdf_jsimp_addmethod(pdf_jsimp *imp, pdf_jsimp_type *type, char *name, pdf_jsimp_method *meth)
{
	if (!strcmp(name, "getField"))
	{
		type->getField = meth;
	}
}

void pdf_jsimp_addproperty(pdf_jsimp *imp, pdf_jsimp_type *type, char *name, pdf_jsimp_getter *get, pdf_jsimp_setter *set)
{
	if (!strcmp(name, "value"))
	{
		type->getValue = get;
		type->setValue = set;
	}
}

pdf_jsimp_obj *pdf_jsimp_new_obj(pdf_jsimp *imp, pdf_jsimp_type *type, void *natobj)
{
	pdf_jsimp_obj *obj = fz_malloc_struct(imp->ctx, pdf_jsimp_obj);
	obj->type = type;
	obj->obj  = natobj;

	return obj;
}

void pdf_jsimp_drop_obj(pdf_jsimp *imp, pdf_jsimp_obj *obj)
{
	if (obj)
	{
		if (obj->type)
		{
			if (obj->type->dtr)
				obj->type->dtr(imp->jsctx, obj->obj);
		}
		else
		{
			/* It's a string */
			fz_free(imp->ctx, obj->obj);
		}

		fz_free(imp->ctx, obj);
	}
}

void pdf_jsimp_set_this(pdf_jsimp *imp, pdf_jsimp_obj *obj)
{
	imp->jsthis = obj;
}


pdf_jsimp_obj *pdf_jsimp_fromString(pdf_jsimp *imp, char *str)
{
	/* Represent a string object as a pdf_jsimp_obj with a NULL type */
	pdf_jsimp_obj *obj = fz_malloc_struct(imp->ctx, pdf_jsimp_obj);
	fz_try(imp->ctx)
	{
		obj->obj = fz_strdup(imp->ctx, str);
	}
	fz_catch(imp->ctx)
	{
		pdf_jsimp_drop_obj(imp, obj);
		fz_rethrow(imp->ctx);
	}

	return obj;
}

char *pdf_jsimp_toString(pdf_jsimp *imp, pdf_jsimp_obj *obj)
{
	return (char *)(obj->type ? NULL : obj->obj);
}

void pdf_jsimp_execute(pdf_jsimp *imp, char *code)
{
	if (!strcmp(code, "display.value = digit_button(0);"))
	{
		assign_display_value(imp, digit_button(imp, 0));
	}
	else if (!strcmp(code, "display.value = digit_button(1);\r"))
	{
		assign_display_value(imp, digit_button(imp, 1));
	}
	else if (!strcmp(code, "display.value = digit_button(2)"))
	{
		assign_display_value(imp, digit_button(imp, 2));
	}
	else if (!strcmp(code, "display.value = digit_button(3)"))
	{
		assign_display_value(imp, digit_button(imp, 3));
	}
	else if (!strcmp(code, "display.value = digit_button(4)"))
	{
		assign_display_value(imp, digit_button(imp, 4));
	}
	else if (!strcmp(code, "display.value = digit_button(5)"))
	{
		assign_display_value(imp, digit_button(imp, 5));
	}
	else if (!strcmp(code, "display.value = digit_button(6);"))
	{
		assign_display_value(imp, digit_button(imp, 6));
	}
	else if (!strcmp(code, "display.value = digit_button(7);"))
	{
		assign_display_value(imp, digit_button(imp, 7));
	}
	else if (!strcmp(code, "display.value = digit_button(8);"))
	{
		assign_display_value(imp, digit_button(imp, 8));
	}
	else if (!strcmp(code, "display.value = digit_button(9);"))
	{
		assign_display_value(imp, digit_button(imp, 9));
	}
	else if (!strcmp(code, "if (divisor == 1) {\r divisor = 10;\r multiplier = 1;\r }"))
	{
		if (imp->divisor == 1)
		{
			imp->divisor = 10;
			imp->multiplier = 1;
		}
	}
	else if (!strcmp(code, "all_cancel();"))
	{
		all_cancel(imp);
	}
	else if (!strcmp(code, "clear_entry();\rdisplay.value = 0;"))
	{
		clear_entry(imp);
		assign_display_value(imp, 0);
	}
	else if (!strcmp(code, "func_button(\"MULT\");"))
	{
		func_button(imp, FUNC_MULT);
	}
	else if (!strcmp(code, "func_button(\"DIV\");"))
	{
		func_button(imp, FUNC_DIV);
	}
	else if (!strcmp(code, "func_button(\"PLUS\");"))
	{
		func_button(imp, FUNC_PLUS);
	}
	else if (!strcmp(code, "func_button(\"MINUS\");"))
	{
		func_button(imp, FUNC_MINUS);
	}
	else if (!strcmp(code, "update_result();\rdisplay.value = accum;"))
	{
		update_result(imp);
		assign_display_value(imp, imp->accum);
	}
}