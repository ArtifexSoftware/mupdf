#include <fitz.h>

void fz_dropdict(fz_obj *obj);

fz_error *
fz_newdict(fz_obj **op, int initialcap)
{
	fz_obj *obj;
	int i;

	obj = *op = fz_malloc(sizeof (fz_obj));
	if (!obj) return fz_outofmem;

	obj->kind = FZ_DICT;
	obj->refcount = 1;  

	obj->u.d.len = 0;
	obj->u.d.cap = initialcap > 0 ? initialcap : 10;

	obj->u.d.items = fz_malloc(sizeof(struct fz_keyval_s) * obj->u.d.cap);
	if (!obj->u.d.items) { fz_free(obj); return fz_outofmem; }

	for (i = 0; i < obj->u.d.cap; i++) {
		obj->u.d.items[i].k = nil;
		obj->u.d.items[i].v = nil;
	}

	return nil;
}

fz_error *
fz_copydict(fz_obj **op, fz_obj *obj)
{
	fz_error *err;
	fz_obj *new;
	int i;

	if (!fz_isdict(obj))
		return fz_throw("typecheck in copydict");

	err = fz_newdict(&new, obj->u.d.cap);
	if (err) return err;
	*op = new;

	for (i = 0; i < fz_dictlen(obj); i++) {
		err = fz_dictput(new, fz_dictgetkey(obj, i), fz_dictgetval(obj, i));
		if (err) { fz_dropdict(new); return err; }
	}

	return nil;
}

fz_error *
fz_deepcopydict(fz_obj **op, fz_obj *obj)
{
	fz_error *err;
	fz_obj *new;
	fz_obj *val;
	int i;

	if (!fz_isdict(obj))
		return fz_throw("typecheck in deepcopydict");

	err = fz_newdict(&new, obj->u.d.cap);
	if (err) return err;
	*op = new;

	for (i = 0; i < fz_dictlen(obj); i++)
	{
		val = fz_dictgetval(obj, i);

		if (fz_isarray(val)) {
			err = fz_deepcopyarray(&val, val);
			if (err) { fz_dropdict(new); return err; }
			err = fz_dictput(new, fz_dictgetkey(obj, i), val);
			if (err) { fz_dropobj(val); fz_dropdict(new); return err; }
			fz_dropobj(val);
		}

		else if (fz_isdict(val)) {
			err = fz_deepcopydict(&val, val);
			if (err) { fz_dropdict(new); return err; }
			err = fz_dictput(new, fz_dictgetkey(obj, i), val);
			if (err) { fz_dropobj(val); fz_dropdict(new); return err; }
			fz_dropobj(val);
		}

		else {
			err = fz_dictput(new, fz_dictgetkey(obj, i), val);
			if (err) { fz_dropdict(new); return err; }
		}
	}

	return nil;
}

static fz_error *
growdict(fz_obj *obj)
{
	struct fz_keyval_s *newitems;
	int newcap;
	int i;

	newcap = obj->u.d.cap * 2;

	newitems = fz_realloc(obj->u.d.items, sizeof(struct fz_keyval_s) * newcap);
	if (!newitems) return fz_outofmem;

	obj->u.d.items = newitems;
	for (i = obj->u.d.cap; i < newcap; i++) {
		obj->u.d.items[i].k = nil;
		obj->u.d.items[i].v = nil;
	}
	obj->u.d.cap = newcap;

	return nil;
}

int
fz_dictlen(fz_obj *obj)
{
	if (!fz_isdict(obj))
		return 0;
	return obj->u.d.len;
}

fz_obj *
fz_dictgetkey(fz_obj *obj, int i)
{
	if (!fz_isdict(obj))
                return nil;

        if (i < 0 || i >= obj->u.d.len)
                return nil;

	return obj->u.d.items[i].k;
}

fz_obj *
fz_dictgetval(fz_obj *obj, int i)
{
	if (!fz_isdict(obj))
                return nil;

        if (i < 0 || i >= obj->u.d.len)
                return nil;

	return obj->u.d.items[i].v;
}

fz_obj *
fz_dictgets(fz_obj *obj, char *key)
{
	int i;

	if (!fz_isdict(obj))
		return nil;

	for (i = 0; i < obj->u.d.len; i++)
		if (strcmp(fz_toname(obj->u.d.items[i].k), key) == 0)
			return obj->u.d.items[i].v;

	return nil;
}

fz_obj *
fz_dictget(fz_obj *obj, fz_obj *key)
{
	return fz_dictgets(obj, fz_toname(key));
}

fz_obj *
fz_dictgetsa(fz_obj *obj, char *key, char *abbrev)
{
	fz_obj *v;
	v = fz_dictgets(obj, key);
	if (v)
		return v;
	return fz_dictgets(obj, abbrev);
}

fz_error *
fz_dictput(fz_obj *obj, fz_obj *key, fz_obj *val)
{
	fz_error *err;
	int i;
	char *s;

	if (!fz_isdict(obj))
		return fz_throw("typecheck in dictput");
	if (!fz_isname(key))
		return fz_throw("typecheck in dictput");

	s = fz_toname(key);

	for (i = 0; i < obj->u.d.len; i++) {
		if (strcmp(fz_toname(obj->u.d.items[i].k), s) == 0) {
			fz_dropobj(obj->u.d.items[i].v);
			obj->u.d.items[i].v = fz_keepobj(val);
			return nil;
		}
	}

	if (obj->u.d.len + 1 > obj->u.d.cap) {
		err = growdict(obj);
		if (err) return err;
	}

	obj->u.d.items[obj->u.d.len].k = fz_keepobj(key);
	obj->u.d.items[obj->u.d.len].v = fz_keepobj(val);
	obj->u.d.len ++;

	return nil;
}

fz_error *
fz_dictputs(fz_obj *obj, char *key, fz_obj *val)
{
	fz_error *err;
	fz_obj *keyobj;
	err = fz_newname(&keyobj, key);
	if (err) return err;
	err = fz_dictput(obj, keyobj, val);
	fz_dropobj(keyobj);
	return err;
}

fz_error *
fz_dictdels(fz_obj *obj, char *key)
{
	int i;

	if (!fz_isdict(obj))
		return fz_throw("typecheck in dictdel");

	for (i = 0; i < obj->u.d.len; i++) {
		if (strcmp(fz_toname(obj->u.d.items[i].k), key) == 0) {
			fz_dropobj(obj->u.d.items[i].k);
			fz_dropobj(obj->u.d.items[i].v);
			obj->u.d.items[i] = obj->u.d.items[obj->u.d.len-1];
			obj->u.d.len --;
		}
	}

	return nil;
}

fz_error *
fz_dictdel(fz_obj *obj, fz_obj *key)
{
	return fz_dictdels(obj, fz_toname(key));
}

void
fz_dropdict(fz_obj *obj)
{
	int i;

	if (!fz_isdict(obj))
		return;

	for (i = 0; i < obj->u.d.len; i++) {
		if (obj->u.d.items[i].k)
			fz_dropobj(obj->u.d.items[i].k);
		if (obj->u.d.items[i].v)
			fz_dropobj(obj->u.d.items[i].v);
	}

	fz_free(obj->u.d.items);
	fz_free(obj);
}

