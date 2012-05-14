/*
 * This is a dummy JavaScript engine. It cheats by recognising the specific
 * strings in calc.pdf, and hence will work only for that file. It is for
 * testing only.
 */

extern "C" {
#include "fitz-internal.h"
#include "mupdf-internal.h"
}

#include <vector>
#include <set>
#include <v8.h>

using namespace v8;
using namespace std;

/* Object we pass to FunctionTemplate::New, which v8 passes back to us in
 * callMethod, allowing us to call our client's, passed-in method. */
struct PDFJSImpMethod
{
	void             *jsctx;
	pdf_jsimp_method *meth;

	PDFJSImpMethod(void *jsctx, pdf_jsimp_method *meth) : jsctx(jsctx), meth(meth) {}
};

/* Object we pass to ObjectTemplate::SetAccessor, which v8 passes back to us in
 * setProp and getProp, allowing us to call our client's, passed-in set/get methods. */
struct PDFJSImpProperty
{
	void             *jsctx;
	pdf_jsimp_getter *get;
	pdf_jsimp_setter *set;

	PDFJSImpProperty(void *jsctx, pdf_jsimp_getter *get, pdf_jsimp_setter *set) : jsctx(jsctx), get(get), set(set) {}
};

struct PDFJSImp;

/* Internal representation of the pdf_jsimp_type object */
struct PDFJSImpType
{
	PDFJSImp                  *imp;
	Persistent<ObjectTemplate> templ;
	pdf_jsimp_dtr             *dtr;
	vector<PDFJSImpMethod *> methods;
	vector<PDFJSImpProperty *> properties;

	PDFJSImpType(PDFJSImp *imp, pdf_jsimp_dtr *dtr): imp(imp), dtr(dtr)
	{
		HandleScope scope;
		templ = Persistent<ObjectTemplate>::New(ObjectTemplate::New());
		templ->SetInternalFieldCount(1);
	}

	~PDFJSImpType()
	{
		vector<PDFJSImpMethod *>::iterator mit;
		for (mit = methods.begin(); mit < methods.end(); mit++)
			delete *mit;

		vector<PDFJSImpProperty *>::iterator pit;
		for (pit = properties.begin(); pit < properties.end(); pit++)
			delete *pit;

		templ.Dispose();
	}
};

/* Info via which we destroy the client side part of objects that
 * v8 garbage collects */
struct PDFJSImpGCObj
{
	Persistent<Object> pobj;
	PDFJSImpType *type;

	PDFJSImpGCObj(Handle<Object> obj, PDFJSImpType *type): type(type)
	{
		pobj = Persistent<Object>::New(obj);
	}

	~PDFJSImpGCObj()
	{
		pobj.Dispose();
	}
};

/* Internal representation of the pdf_jsimp object */
struct PDFJSImp
{
	fz_context			*ctx;
	void				*jsctx;
	Persistent<Context>	 context;
	vector<PDFJSImpType *> types;
	set<PDFJSImpGCObj *> gclist;

	PDFJSImp(fz_context *ctx, void *jsctx) : ctx(ctx), jsctx(jsctx)
	{
		HandleScope scope;
		context = Persistent<Context>::New(Context::New());
	}

	~PDFJSImp()
	{
		HandleScope scope;
		/* Tell v8 our context will not be used again */
		context.Dispose();

		/* Unlink and destroy all the objects that v8 has yet to gc */
		set<PDFJSImpGCObj *>::iterator oit;
		for (oit = gclist.begin(); oit != gclist.end(); oit++)
		{
			(*oit)->pobj.ClearWeak(); /* So that gcCallback wont get called */
			PDFJSImpType *vType = (*oit)->type;
			Local<External> owrap = Local<External>::Cast((*oit)->pobj->GetInternalField(0));
			vType->dtr(vType->imp->jsctx, owrap->Value());
			delete *oit;
		}

		vector<PDFJSImpType *>::iterator it;
		for (it = types.begin(); it < types.end(); it++)
			delete *it;
	}
};

/* Internal representation of the pdf_jsimp_obj object */
class PDFJSImpObject
{
	Persistent<Value>   pobj;
	String::Utf8Value  *utf8;

public:
	PDFJSImpObject(Handle<Value> obj): utf8(NULL)
	{
		pobj = Persistent<Value>::New(obj);
	}

	PDFJSImpObject(const char *str): utf8(NULL)
	{
		pobj = Persistent<Value>::New(String::New(str));
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
	PDFJSImp *vImp = reinterpret_cast<PDFJSImp *>(imp);
	PDFJSImpType *vType = new PDFJSImpType(vImp, dtr);
	vImp->types.push_back(vType);
	return reinterpret_cast<pdf_jsimp_type *>(vType);
}

extern "C" void pdf_jsimp_drop_type(pdf_jsimp *imp, pdf_jsimp_type *type)
{
	/* Types are recorded and destroyed as part of PDFJSImp */
}

static Handle<Value> callMethod(const Arguments &args)
{
	HandleScope scope;
	Local<External> mwrap = Local<External>::Cast(args.Data());
	PDFJSImpMethod *m = (PDFJSImpMethod *)mwrap->Value();

	Local<Object> self = args.Holder();
	Local<External> owrap;
	void *nself = NULL;
	if (self->InternalFieldCount() > 0)
	{
		owrap = Local<External>::Cast(self->GetInternalField(0));
		nself = owrap->Value();
	}

	int c = args.Length();
	PDFJSImpObject **native_args = new PDFJSImpObject*[c];
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

	PDFJSImpMethod *pmeth = new PDFJSImpMethod(vType->imp->jsctx, meth);
	vType->templ->Set(String::New(name), FunctionTemplate::New(callMethod, External::New(pmeth)));
	vType->methods.push_back(pmeth);
}

static Handle<Value> getProp(Local<String> property, const AccessorInfo &info)
{
	HandleScope scope;
	Local<External> pwrap = Local<External>::Cast(info.Data());
	PDFJSImpProperty *p = reinterpret_cast<PDFJSImpProperty *>(pwrap->Value());

	Local<Object> self = info.Holder();
	Local<External> owrap;
	void *nself = NULL;
	if (self->InternalFieldCount() > 0)
	{
		owrap = Local<External>::Cast(self->GetInternalField(0));
		nself = owrap->Value();
	}

	PDFJSImpObject *obj = reinterpret_cast<PDFJSImpObject *>(p->get(p->jsctx, nself));
	Handle<Value> val = obj->toValue();
	delete obj;
	return scope.Close(val);
}

static void setProp(Local<String> property, Local<Value> value, const AccessorInfo &info)
{
	HandleScope scope;
	Local<External> wrap = Local<External>::Cast(info.Data());
	PDFJSImpProperty *p = reinterpret_cast<PDFJSImpProperty *>(wrap->Value());

	Local<Object> self = info.Holder();
	Local<External> owrap;
	void *nself = NULL;
	if (self->InternalFieldCount() > 0)
	{
		owrap = Local<External>::Cast(self->GetInternalField(0));
		nself = owrap->Value();
	}

	PDFJSImpObject *obj = new PDFJSImpObject(value);

	p->set(p->jsctx, nself, reinterpret_cast<pdf_jsimp_obj *>(obj));
	delete obj;
}

extern "C" void pdf_jsimp_addproperty(pdf_jsimp *imp, pdf_jsimp_type *type, char *name, pdf_jsimp_getter *get, pdf_jsimp_setter *set)
{
	PDFJSImpType *vType = reinterpret_cast<PDFJSImpType *>(type);
	HandleScope scope;

	PDFJSImpProperty *prop = new PDFJSImpProperty(vType->imp->jsctx, get, set);
	vType->templ->SetAccessor(String::New(name), getProp, setProp, External::New(prop));
	vType->properties.push_back(prop);
}

extern "C" void pdf_jsimp_set_global_type(pdf_jsimp *imp, pdf_jsimp_type *type)
{
	PDFJSImp	 *vImp  = reinterpret_cast<PDFJSImp *>(imp);
	PDFJSImpType *vType = reinterpret_cast<PDFJSImpType *>(type);
	HandleScope scope;

	vImp->context = Persistent<Context>::New(Context::New(NULL, vType->templ));
}

static void gcCallback(Persistent<Value> val, void *parm)
{
	PDFJSImpGCObj *gco = reinterpret_cast<PDFJSImpGCObj *>(parm);
	PDFJSImpType *vType = gco->type;
	HandleScope scope;
	Persistent<Object> obj = Persistent<Object>::Cast(val);

	Local<External> owrap = Local<External>::Cast(obj->GetInternalField(0));
	vType->dtr(vType->imp->jsctx, owrap->Value());
	vType->imp->gclist.erase(gco);
	delete gco; /* Disposes of the persistent handle */
}

extern "C" pdf_jsimp_obj *pdf_jsimp_new_obj(pdf_jsimp *imp, pdf_jsimp_type *type, void *natobj)
{
	PDFJSImpType *vType = reinterpret_cast<PDFJSImpType *>(type);
	HandleScope scope;
	Local<Object> obj = vType->templ->NewInstance();
	obj->SetInternalField(0, External::New(natobj));

	/* Arrange for destructor to be called on the client sire object
	 * when the v8 object is garbage collected */
	if (vType->dtr)
	{
		PDFJSImpGCObj *gco = new PDFJSImpGCObj(obj, vType);
		vType->imp->gclist.insert(gco);
		gco->pobj.MakeWeak(gco, gcCallback);
	}

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