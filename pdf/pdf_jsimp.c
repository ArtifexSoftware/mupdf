#include "fitz-internal.h"
#include "mupdf-internal.h"

struct pdf_jsimp_s
{
	int x;
};

struct pdf_jsimp_type_s
{
	int x;
};

struct pdf_jsimp_obj_s
{
	int x;
};


pdf_jsimp *pdf_new_jsimp(fz_context *ctx, void *jsctx)
{
	return NULL;
}

void pdf_drop_jsimp(pdf_jsimp *imp)
{
}

pdf_jsimp_type *pdf_jsimp_new_type(pdf_jsimp *imp, pdf_jsimp_dtr *dtr)
{
	return NULL;
}

void pdf_jsimp_addmethod(pdf_jsimp *imp, pdf_jsimp_type *type, char *name, pdf_jsimp_method *meth)
{
}

void pdf_jsimp_addproperty(pdf_jsimp *imp, pdf_jsimp_type *type, char *name, pdf_jsimp_getter *get, pdf_jsimp_setter *set)
{
}

pdf_jsimp_obj *pdf_jsimp_new_obj(pdf_jsimp *imp, pdf_jsimp_type *type, void *obj)
{
	return NULL;
}

void pdf_jsimp_set_this(pdf_jsimp *imp, pdf_jsimp_obj *obj)
{
}

pdf_jsimp_obj *pdf_jsimp_fromString(pdf_jsimp *imp, char *str)
{
	return NULL;
}

char *pdf_jsimp_toString(pdf_jsimp *imp, pdf_jsimp_obj *obj)
{
	return NULL;
}