/*
 * This is a dummy JavaScript engine. It cheats by recognising the specific
 * strings in calc.pdf, and hence will work only for that file. It is for
 * testing only.
 */

extern "C" {
#include "fitz-internal.h"
#include "mupdf-internal.h"
}

#include <v8.h>

using namespace v8;


struct PDFJSImp
{
	fz_context			*ctx;
	void				*jsctx;
	Persistent<Context>	 context;

	PDFJSImp(fz_context *ctx, void *jsctx) : ctx(ctx), jsctx(jsctx)
	{
		HandleScope scope;
		context = Persistent<Context>::New(Context::New());
	}

	~PDFJSImp()
	{
		context.Dispose();
	}
};

/* We need only a couple of specific methods for calc.pdf */
struct PDFJSImpType
{
	PDFJSImp                  *imp;
	Persistent<ObjectTemplate> templ;
	pdf_jsimp_dtr             *dtr;

	PDFJSImpType(PDFJSImp *imp, pdf_jsimp_dtr *dtr): imp(imp), dtr(dtr)
	{
		HandleScope scope;
		templ = Persistent<ObjectTemplate>::New(ObjectTemplate::New());
		templ->SetInternalFieldCount(1);
	}

	~PDFJSImpType()
	{
		templ.Dispose();
	}
};

struct PDFJSImpMethod
{
	void             *jsctx;
	pdf_jsimp_method *meth;

	PDFJSImpMethod(void *jsctx, pdf_jsimp_method *meth) : jsctx(jsctx), meth(meth) {}
};

struct PDFJSImpProperty
{
	void             *jsctx;
	pdf_jsimp_getter *get;
	pdf_jsimp_setter *set;

	PDFJSImpProperty(void *jsctx, pdf_jsimp_getter *get, pdf_jsimp_setter *set) : jsctx(jsctx), get(get), set(set) {}
};

class PDFJSImpObject
{
	Persistent<Value>   pobj;
	String::Utf8Value  *utf8;

public:
	PDFJSImpObject(Handle<Value> obj)
	{
		pobj = Persistent<Value>::New(obj);
		utf8 = NULL;
	}

	PDFJSImpObject(const char *str)
	{
		pobj = Persistent<Value>::New(String::New(str));
		utf8 = NULL;
	}

	~PDFJSImpObject()
	{
		delete utf8;
		pobj.Dispose();
	}

	char *toString()
	{
		delete utf8;
		utf8 = new String::Utf8Value(pobj);
		return **utf8;
	}

	Handle<Value> toValue()
	{
		return pobj;
	}
};


extern "C" pdf_jsimp *pdf_new_jsimp(fz_context *ctx, void *jsctx)
{
	return reinterpret_cast<pdf_jsimp *>(new PDFJSImp(ctx, jsctx));
}

extern "C" void pdf_drop_jsimp(pdf_jsimp *imp)
{
	delete reinterpret_cast<PDFJSImp *>(imp);
}

extern "C" pdf_jsimp_type *pdf_jsimp_new_type(pdf_jsimp *imp, pdf_jsimp_dtr *dtr)
{
	return reinterpret_cast<pdf_jsimp_type *>(new PDFJSImpType((PDFJSImp *)imp, dtr));
}

extern "C" void pdf_jsimp_drop_type(pdf_jsimp *imp, pdf_jsimp_type *type)
{
	delete reinterpret_cast<PDFJSImpType *>(type);
}

static Handle<Value> callMethod(const Arguments &args)
{
	HandleScope scope;
	Local<Object> self = args.Holder();
	Local<External> owrap;
	void *nself = NULL;
	Local<External> mwrap = Local<External>::Cast(args.Data());
	PDFJSImpMethod *m = (PDFJSImpMethod *)mwrap->Value();
	int c = args.Length();
	PDFJSImpObject **native_args = new PDFJSImpObject*[c];

	if (self->InternalFieldCount() > 0)
	{
		owrap = Local<External>::Cast(self->GetInternalField(0));
		nself = owrap->Value();
	}

	for (int i = 0; i < c; i++)
		native_args[i] = new PDFJSImpObject(args[i]);

	PDFJSImpObject *obj = reinterpret_cast<PDFJSImpObject *>(m->meth(m->jsctx, nself, c, reinterpret_cast<pdf_jsimp_obj **>(native_args)));
	Handle<Value> val = obj->toValue();
	delete obj;

	for (int i = 0; i < c; i++)
		delete native_args[i];

	delete native_args;

	return scope.Close(val);
}

extern "C" void pdf_jsimp_addmethod(pdf_jsimp *imp, pdf_jsimp_type *type, char *name, pdf_jsimp_method *meth)
{
	PDFJSImpType *vType = reinterpret_cast<PDFJSImpType *>(type);
	HandleScope scope;

	vType->templ->Set(String::New(name), FunctionTemplate::New(callMethod, External::New(new PDFJSImpMethod(vType->imp->jsctx, meth))));
}

static Handle<Value> getProp(Local<String> property, const AccessorInfo &info)
{
	HandleScope scope;
	Local<Object> self = info.Holder();
	Local<External> owrap = Local<External>::Cast(self->GetInternalField(0));
	Local<External> pwrap = Local<External>::Cast(info.Data());
	PDFJSImpProperty *p = reinterpret_cast<PDFJSImpProperty *>(pwrap->Value());

	PDFJSImpObject *obj = reinterpret_cast<PDFJSImpObject *>(p->get(p->jsctx, owrap->Value()));
	Handle<Value> val = obj->toValue();
	delete obj;
	return scope.Close(val);
}

static void setProp(Local<String> property, Local<Value> value, const AccessorInfo &info)
{
	HandleScope scope;
	Local<Object> self = info.Holder();
	Local<External> owrap = Local<External>::Cast(self->GetInternalField(0));
	Local<External> wrap = Local<External>::Cast(info.Data());
	PDFJSImpProperty *p = reinterpret_cast<PDFJSImpProperty *>(wrap->Value());
	PDFJSImpObject *obj = new PDFJSImpObject(value);

	p->set(p->jsctx, owrap->Value(), reinterpret_cast<pdf_jsimp_obj *>(obj));
	delete obj;
}

extern "C" void pdf_jsimp_addproperty(pdf_jsimp *imp, pdf_jsimp_type *type, char *name, pdf_jsimp_getter *get, pdf_jsimp_setter *set)
{
	PDFJSImpType *vType = reinterpret_cast<PDFJSImpType *>(type);
	HandleScope scope;

	vType->templ->SetAccessor(String::New(name), getProp, setProp, External::New(new PDFJSImpProperty(vType->imp->jsctx, get, set)));
}

extern "C" void pdf_jsimp_set_global_type(pdf_jsimp *imp, pdf_jsimp_type *type)
{
	PDFJSImp	 *vImp  = reinterpret_cast<PDFJSImp *>(imp);
	PDFJSImpType *vType = reinterpret_cast<PDFJSImpType *>(type);
	HandleScope scope;

	vImp->context = Persistent<Context>::New(Context::New(NULL, vType->templ));
}

extern "C" pdf_jsimp_obj *pdf_jsimp_new_obj(pdf_jsimp *imp, pdf_jsimp_type *type, void *natobj)
{
	PDFJSImpType *vType = reinterpret_cast<PDFJSImpType *>(type);
	HandleScope scope;
	Local<Object> obj = vType->templ->NewInstance();
	obj->SetInternalField(0, External::New(natobj));

	return reinterpret_cast<pdf_jsimp_obj *>(new PDFJSImpObject(obj));
}

extern "C" void pdf_jsimp_drop_obj(pdf_jsimp *imp, pdf_jsimp_obj *obj)
{
	delete reinterpret_cast<PDFJSImpObject *>(obj);
}

extern "C" pdf_jsimp_obj *pdf_jsimp_fromString(pdf_jsimp *imp, char *str)
{
	return reinterpret_cast<pdf_jsimp_obj *>(new PDFJSImpObject(str));
}

extern "C" char *pdf_jsimp_toString(pdf_jsimp *imp, pdf_jsimp_obj *obj)
{
	return reinterpret_cast<PDFJSImpObject *>(obj)->toString();
}

extern "C" void pdf_jsimp_execute(pdf_jsimp *imp, char *code)
{
	PDFJSImp *vImp = reinterpret_cast<PDFJSImp *>(imp);
	HandleScope scope;
	Context::Scope context_scope(vImp->context);
	Script::Compile(String::New(code))->Run();
}

extern "C" void pdf_jsimp_execute_count(pdf_jsimp *imp, char *code, int count)
{
	PDFJSImp *vImp = reinterpret_cast<PDFJSImp *>(imp);
	HandleScope scope;
	Context::Scope context_scope(vImp->context);
	Script::Compile(String::New(code, count))->Run();
}