#include <fitz.h>

extern void fz_droparray(fz_obj *array);
extern void fz_dropdict(fz_obj *dict);

#define NEWOBJ(KIND,SIZE)		\
	fz_obj *o;			\
	o = *op = fz_malloc(SIZE);	\
	if (!o) return fz_outofmem;	\
	o->kind = KIND;			\
	o->refcount = 1

fz_error *
fz_newnull(fz_obj **op)
{
	NEWOBJ(FZ_NULL, sizeof (fz_obj));
	return nil;
}

fz_error *
fz_newbool(fz_obj **op, int b)
{
	NEWOBJ(FZ_BOOL, sizeof (fz_obj));
	o->u.b = b;
	return nil;
}

fz_error *
fz_newint(fz_obj **op, int i)
{
	NEWOBJ(FZ_INT, sizeof (fz_obj));
	o->u.i = i;
	return nil;
}

fz_error *
fz_newreal(fz_obj **op, float f)
{
	NEWOBJ(FZ_REAL, sizeof (fz_obj));
	o->u.f = f;
	return nil;
}

fz_error *
fz_newstring(fz_obj **op, char *str, int len)
{
	NEWOBJ(FZ_STRING, offsetof(fz_obj, u.s.buf) + len);
	o->u.s.len = len;
	memcpy(o->u.s.buf, str, len);
	return nil;
}

fz_error *
fz_newname(fz_obj **op, char *str)
{
	NEWOBJ(FZ_NAME, offsetof(fz_obj, u.n) + strlen(str) + 1);
	strcpy(o->u.n, str);
	return nil;
}

fz_error *
fz_newindirect(fz_obj **op, int objid, int genid)
{
	NEWOBJ(FZ_INDIRECT, sizeof (fz_obj));
	o->u.r.oid = objid;
	o->u.r.gid = genid;
	return nil;
}

fz_error *
fz_newpointer(fz_obj **op, void *p)
{
	NEWOBJ(FZ_POINTER, sizeof (fz_obj));
        o->u.p = p;
        return nil;
}

fz_obj *
fz_keepobj(fz_obj *o)
{
	o->refcount ++;
	return o;
}

fz_obj *
fz_dropobj(fz_obj *o)
{
	o->refcount --;
	if (o->refcount == 0) {
		if (o->kind == FZ_ARRAY)
			fz_droparray(o);
		else if (o->kind == FZ_DICT)
			fz_dropdict(o);
		else
			fz_free(o);
	}
	return nil;
}

int
fz_isnull(fz_obj *obj)
{
	return obj ? obj->kind == FZ_NULL : 0;
}

int
fz_isbool(fz_obj *obj)
{
	return obj ? obj->kind == FZ_BOOL : 0;
}

int
fz_isint(fz_obj *obj)
{
	return obj ? obj->kind == FZ_INT : 0;
}

int
fz_isreal(fz_obj *obj)
{
	return obj ? obj->kind == FZ_REAL : 0;
}

int
fz_isstring(fz_obj *obj)
{
	return obj ? obj->kind == FZ_STRING : 0;
}

int
fz_isname(fz_obj *obj)
{
	return obj ? obj->kind == FZ_NAME : 0;
}

int
fz_isarray(fz_obj *obj)
{
	return obj ? obj->kind == FZ_ARRAY : 0;
}

int
fz_isdict(fz_obj *obj)
{
	return obj ? obj->kind == FZ_DICT : 0;
}

int
fz_isindirect(fz_obj *obj)
{
	return obj ? obj->kind == FZ_INDIRECT : 0;
}

int
fz_ispointer(fz_obj *obj)
{
	return obj ? obj->kind == FZ_POINTER : 0;
}

int
fz_tobool(fz_obj *obj)
{
	if (fz_isbool(obj))
		return obj->u.b;
	return 0;
}

int
fz_toint(fz_obj *obj)
{
	if (fz_isint(obj))
		return obj->u.i;
	return 0;
}

float
fz_toreal(fz_obj *obj)
{
	if (fz_isreal(obj))
		return obj->u.f;
	if (fz_isint(obj))
		return obj->u.i;
	return 0;
}

char *
fz_toname(fz_obj *obj)
{
	if (fz_isname(obj))
		return obj->u.n;
	return "";
}

char *
fz_tostringbuf(fz_obj *obj)
{
	if (fz_isstring(obj))
		return obj->u.s.buf;
	return "";
}

int
fz_tostringlen(fz_obj *obj)
{
	if (fz_isstring(obj))
		return obj->u.s.len;
	return 0;
}

int
fz_tonum(fz_obj *obj)
{
	if (fz_isindirect(obj))
		return obj->u.r.oid;
	return 0;
}

int
fz_togen(fz_obj *obj)
{
	if (fz_isindirect(obj))
		return obj->u.r.gid;
	return 0;
}

void *
fz_topointer(fz_obj *obj)
{
	if (fz_ispointer(obj))
		return obj->u.p;
	return nil;
}

