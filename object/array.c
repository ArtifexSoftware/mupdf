#include <fitz.h>

fz_error *
fz_newarray(fz_obj **op, int initialcap)
{
	fz_obj *obj;
	int i;

	obj = *op = fz_malloc(sizeof (fz_obj));
	if (!obj) return fz_outofmem;

	obj->kind = FZ_ARRAY;
	obj->refcount = 1;	

	obj->u.a.len = 0;
	obj->u.a.cap = initialcap > 0 ? initialcap : 6;

	obj->u.a.items = fz_malloc(sizeof (fz_obj*) * obj->u.a.cap);
	if (!obj->u.a.items) { fz_free(obj); return fz_outofmem; }

	for (i = 0; i < obj->u.a.cap; i++)
		obj->u.a.items[i] = nil;

	return nil;
}

fz_error *
fz_copyarray(fz_obj **op, fz_obj *obj)
{
	fz_error *err;
	fz_obj *new;
	int i;

	if (!fz_isarray(obj))
		return fz_throw("typecheck in copyarray");

	err = fz_newarray(&new, fz_arraylen(obj));
	if (err) return err;
	*op = new;

	for (i = 0; i < fz_arraylen(obj); i++) {
		err = fz_arraypush(new, fz_arrayget(obj, i));
		if (err) { fz_freearray(new); return err; }
	}

	return nil;
}

fz_error *
fz_deepcopyarray(fz_obj **op, fz_obj *obj)
{
	fz_error *err;
	fz_obj *new;
	fz_obj *val;
	int i;

	if (!fz_isarray(obj))
		return fz_throw("typecheck in deepcopyarray");

	err = fz_newarray(&new, fz_arraylen(obj));
	if (err) return err;
	*op = new;

	for (i = 0; i < fz_arraylen(obj); i++)
	{
		val = fz_arrayget(obj, i);

		if (fz_isarray(val)) {
			err = fz_deepcopyarray(&val, val);
			if (err) { fz_freearray(new); return err; }
			err = fz_arraypush(new, val);
			if (err) { fz_dropobj(val); fz_freearray(new); return err; }
			fz_dropobj(val);
		}

		else if (fz_isdict(val)) {
			err = fz_deepcopydict(&val, val);
			if (err) { fz_freearray(new); return err; }
			err = fz_arraypush(new, val);
			if (err) { fz_dropobj(val); fz_freearray(new); return err; }
			fz_dropobj(val);
		}

		else {
			err = fz_arraypush(new, val);
			if (err) { fz_freearray(new); return err; }
		}
	}

	return nil;
}

int
fz_arraylen(fz_obj *obj)
{
	if (!fz_isarray(obj))
		return 0;
	return obj->u.a.len;
}

fz_obj *
fz_arrayget(fz_obj *obj, int i)
{
	if (!fz_isarray(obj))
		return nil;

	if (i < 0 || i >= obj->u.a.len)
		return nil;

	return obj->u.a.items[i];
}

fz_error *
fz_arrayput(fz_obj *obj, int i, fz_obj *item)
{
	if (!fz_isarray(obj))
		return fz_throw("typecheck in arrayput");
	if (i < 0)
		return fz_throw("rangecheck in arrayput: %d < 0", i);
	if (i >= obj->u.a.len)
		return fz_throw("rangecheck in arrayput: %d > %d", i, obj->u.a.len);

	if (obj->u.a.items[i])
		fz_dropobj(obj->u.a.items[i]);
	obj->u.a.items[i] = fz_keepobj(item);

	return nil;
}

static fz_error *
growarray(fz_obj *obj)
{
	fz_obj **newitems;
	int newcap;
	int i;

	newcap = obj->u.a.cap * 2;
	newitems = fz_realloc(obj->u.a.items, sizeof (fz_obj*) * newcap);
	if (!newitems) return fz_outofmem;

	obj->u.a.items = newitems;
	for (i = obj->u.a.cap ; i < newcap; i++)
		obj->u.a.items[i] = nil;
	obj->u.a.cap = newcap;

	return nil;
}

fz_error *
fz_arraypush(fz_obj *obj, fz_obj *item)
{
	fz_error *err;

	if (!fz_isarray(obj))
		return fz_throw("typecheck in arraypush");

	if (obj->u.a.len + 1 > obj->u.a.cap) {
		err = growarray(obj);
		if (err) return err;
	}

	obj->u.a.items[obj->u.a.len] = fz_keepobj(item);
	obj->u.a.len++;

	return nil;
}

void
fz_freearray(fz_obj *obj)
{
	int i;

	assert(obj->kind == FZ_ARRAY);

	for (i = 0; i < obj->u.a.len; i++)
		if (obj->u.a.items[i])
			fz_dropobj(obj->u.a.items[i]);

	fz_free(obj->u.a.items);
	fz_free(obj);
}

