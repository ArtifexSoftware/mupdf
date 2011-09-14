#include "fitz.h"

#if defined(_WIN32) || defined(_WIN64)
#define MISSING_QSORT_R
#endif

typedef enum fz_objkind_e
{
	FZ_NULL,
	FZ_BOOL,
	FZ_INT,
	FZ_REAL,
	FZ_STRING,
	FZ_NAME,
	FZ_ARRAY,
	FZ_DICT,
	FZ_INDIRECT
} fz_objkind;

struct keyval
{
	fz_obj *k;
	fz_obj *v;
};

struct fz_obj_s
{
	int refs;
	fz_objkind kind;
	union
	{
		int b;
		int i;
		float f;
		struct {
			unsigned short len;
			char buf[1];
		} s;
		char n[1];
		struct {
			int len;
			int cap;
			fz_obj **items;
		} a;
		struct {
			char sorted;
			int len;
			int cap;
			struct keyval *items;
		} d;
		struct {
			int num;
			int gen;
			struct pdf_xref_s *xref;
		} r;
	} u;
};

fz_obj *
fz_new_null(fz_context *ctx)
{
	fz_obj *obj = fz_malloc(ctx, sizeof(fz_obj));
	obj->refs = 1;
	obj->kind = FZ_NULL;
	return obj;
}

fz_obj *
fz_new_bool(fz_context *ctx, int b)
{
	fz_obj *obj = fz_malloc(ctx, sizeof(fz_obj));
	obj->refs = 1;
	obj->kind = FZ_BOOL;
	obj->u.b = b;
	return obj;
}

fz_obj *
fz_new_int(fz_context *ctx, int i)
{
	fz_obj *obj = fz_malloc(ctx, sizeof(fz_obj));
	obj->refs = 1;
	obj->kind = FZ_INT;
	obj->u.i = i;
	return obj;
}

fz_obj *
fz_new_real(fz_context *ctx, float f)
{
	fz_obj *obj = fz_malloc(ctx, sizeof(fz_obj));
	obj->refs = 1;
	obj->kind = FZ_REAL;
	obj->u.f = f;
	return obj;
}

fz_obj *
fz_new_string(fz_context *ctx, char *str, int len)
{
	fz_obj *obj = fz_malloc(ctx, offsetof(fz_obj, u.s.buf) + len + 1);
	obj->refs = 1;
	obj->kind = FZ_STRING;
	obj->u.s.len = len;
	memcpy(obj->u.s.buf, str, len);
	obj->u.s.buf[len] = '\0';
	return obj;
}

fz_obj *
fz_new_name(fz_context *ctx, char *str)
{
	fz_obj *obj = fz_malloc(ctx, offsetof(fz_obj, u.n) + strlen(str) + 1);
	obj->refs = 1;
	obj->kind = FZ_NAME;
	strcpy(obj->u.n, str);
	return obj;
}

fz_obj *
fz_new_indirect(fz_context *ctx, int num, int gen, void *xref)
{
	fz_obj *obj = fz_malloc(ctx, sizeof(fz_obj));
	obj->refs = 1;
	obj->kind = FZ_INDIRECT;
	obj->u.r.num = num;
	obj->u.r.gen = gen;
	obj->u.r.xref = xref;
	return obj;
}

fz_obj *
fz_keep_obj(fz_obj *obj)
{
	assert(obj != NULL);
	obj->refs ++;
	return obj;
}

int fz_is_indirect(fz_obj *obj)
{
	return obj ? obj->kind == FZ_INDIRECT : 0;
}

int fz_is_null(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	return obj ? obj->kind == FZ_NULL : 0;
}

int fz_is_bool(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	return obj ? obj->kind == FZ_BOOL : 0;
}

int fz_is_int(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	return obj ? obj->kind == FZ_INT : 0;
}

int fz_is_real(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	return obj ? obj->kind == FZ_REAL : 0;
}

int fz_is_string(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	return obj ? obj->kind == FZ_STRING : 0;
}

int fz_is_name(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	return obj ? obj->kind == FZ_NAME : 0;
}

int fz_is_array(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	return obj ? obj->kind == FZ_ARRAY : 0;
}

int fz_is_dict(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	return obj ? obj->kind == FZ_DICT : 0;
}

int fz_to_bool(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	if (fz_is_bool(ctx, obj))
		return obj->u.b;
	return 0;
}

int fz_to_int(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	if (fz_is_int(ctx, obj))
		return obj->u.i;
	if (fz_is_real(ctx, obj))
		return obj->u.f;
	return 0;
}

float fz_to_real(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	if (fz_is_real(ctx, obj))
		return obj->u.f;
	if (fz_is_int(ctx, obj))
		return obj->u.i;
	return 0;
}

char *fz_to_name(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	if (fz_is_name(ctx, obj))
		return obj->u.n;
	return "";
}

char *fz_to_str_buf(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	if (fz_is_string(ctx, obj))
		return obj->u.s.buf;
	return "";
}

int fz_to_str_len(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	if (fz_is_string(ctx, obj))
		return obj->u.s.len;
	return 0;
}

/* for use by pdf_crypt_obj_imp to decrypt AES string in place */
void fz_set_str_len(fz_context *ctx, fz_obj *obj, int newlen)
{
	obj = fz_resolve_indirect(ctx, obj);
	if (fz_is_string(ctx, obj))
		if (newlen < obj->u.s.len)
			obj->u.s.len = newlen;
}

int fz_to_num(fz_obj *obj)
{
	if (fz_is_indirect(obj))
		return obj->u.r.num;
	return 0;
}

int fz_to_gen(fz_obj *obj)
{
	if (fz_is_indirect(obj))
		return obj->u.r.gen;
	return 0;
}

void *fz_get_indirect_xref(fz_obj *obj)
{
	if (fz_is_indirect(obj))
		return obj->u.r.xref;
	return NULL;
}

int
fz_objcmp(fz_obj *a, fz_obj *b)
{
	int i;

	if (a == b)
		return 0;

	if (!a || !b)
		return 1;

	if (a->kind != b->kind)
		return 1;

	switch (a->kind)
	{
	case FZ_NULL:
		return 0;

	case FZ_BOOL:
		return a->u.b - b->u.b;

	case FZ_INT:
		return a->u.i - b->u.i;

	case FZ_REAL:
		if (a->u.f < b->u.f)
			return -1;
		if (a->u.f > b->u.f)
			return 1;
		return 0;

	case FZ_STRING:
		if (a->u.s.len < b->u.s.len)
		{
			if (memcmp(a->u.s.buf, b->u.s.buf, a->u.s.len) <= 0)
				return -1;
			return 1;
		}
		if (a->u.s.len > b->u.s.len)
		{
			if (memcmp(a->u.s.buf, b->u.s.buf, b->u.s.len) >= 0)
				return 1;
			return -1;
		}
		return memcmp(a->u.s.buf, b->u.s.buf, a->u.s.len);

	case FZ_NAME:
		return strcmp(a->u.n, b->u.n);

	case FZ_INDIRECT:
		if (a->u.r.num == b->u.r.num)
			return a->u.r.gen - b->u.r.gen;
		return a->u.r.num - b->u.r.num;

	case FZ_ARRAY:
		if (a->u.a.len != b->u.a.len)
			return a->u.a.len - b->u.a.len;
		for (i = 0; i < a->u.a.len; i++)
			if (fz_objcmp(a->u.a.items[i], b->u.a.items[i]))
				return 1;
		return 0;

	case FZ_DICT:
		if (a->u.d.len != b->u.d.len)
			return a->u.d.len - b->u.d.len;
		for (i = 0; i < a->u.d.len; i++)
		{
			if (fz_objcmp(a->u.d.items[i].k, b->u.d.items[i].k))
				return 1;
			if (fz_objcmp(a->u.d.items[i].v, b->u.d.items[i].v))
				return 1;
		}
		return 0;

	}
	return 1;
}

static char *
fz_objkindstr(fz_obj *obj)
{
	if (obj == NULL)
		return "<NULL>";
	switch (obj->kind)
	{
	case FZ_NULL: return "null";
	case FZ_BOOL: return "boolean";
	case FZ_INT: return "integer";
	case FZ_REAL: return "real";
	case FZ_STRING: return "string";
	case FZ_NAME: return "name";
	case FZ_ARRAY: return "array";
	case FZ_DICT: return "dictionary";
	case FZ_INDIRECT: return "reference";
	}
	return "<unknown>";
}

fz_obj *
fz_new_array(fz_context *ctx, int initialcap)
{
	fz_obj *obj;
	int i;

	obj = fz_malloc(ctx, sizeof(fz_obj));
	obj->refs = 1;
	obj->kind = FZ_ARRAY;

	obj->u.a.len = 0;
	obj->u.a.cap = initialcap > 1 ? initialcap : 6;

	obj->u.a.items = fz_calloc(ctx, obj->u.a.cap, sizeof(fz_obj*));
	for (i = 0; i < obj->u.a.cap; i++)
		obj->u.a.items[i] = NULL;

	return obj;
}

fz_obj *
fz_copy_array(fz_context *ctx, fz_obj *obj)
{
	fz_obj *new;
	int i;
	int n;

	if (fz_is_indirect(obj) || !fz_is_array(ctx, obj))
		fz_warn("assert: not an array (%s)", fz_objkindstr(obj));

	new = fz_new_array(ctx, fz_array_len(ctx, obj));
	n = fz_array_len(ctx, obj);
	for (i = 0; i < n; i++)
		fz_array_push(ctx, new, fz_array_get(ctx, obj, i));

	return new;
}

int
fz_array_len(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	if (!fz_is_array(ctx, obj))
		return 0;
	return obj->u.a.len;
}

fz_obj *
fz_array_get(fz_context *ctx, fz_obj *obj, int i)
{
	obj = fz_resolve_indirect(ctx, obj);

	if (!fz_is_array(ctx, obj))
		return NULL;

	if (i < 0 || i >= obj->u.a.len)
		return NULL;

	return obj->u.a.items[i];
}

void
fz_array_put(fz_context *ctx, fz_obj *obj, int i, fz_obj *item)
{
	obj = fz_resolve_indirect(ctx, obj);

	if (!fz_is_array(ctx, obj))
		fz_warn("assert: not an array (%s)", fz_objkindstr(obj));
	else if (i < 0)
		fz_warn("assert: index %d < 0", i);
	else if (i >= obj->u.a.len)
		fz_warn("assert: index %d > length %d", i, obj->u.a.len);
	else
	{
		if (obj->u.a.items[i])
			fz_drop_obj(ctx, obj->u.a.items[i]);
		obj->u.a.items[i] = fz_keep_obj(item);
	}
}

void
fz_array_push(fz_context *ctx, fz_obj *obj, fz_obj *item)
{
	obj = fz_resolve_indirect(ctx, obj);

	if (!fz_is_array(ctx, obj))
		fz_warn("assert: not an array (%s)", fz_objkindstr(obj));
	else
	{
		if (obj->u.a.len + 1 > obj->u.a.cap)
		{
			int i;
			obj->u.a.cap = (obj->u.a.cap * 3) / 2;
			obj->u.a.items = fz_realloc(ctx, obj->u.a.items, obj->u.a.cap * sizeof(fz_obj*));
			for (i = obj->u.a.len ; i < obj->u.a.cap; i++)
				obj->u.a.items[i] = NULL;
		}
		obj->u.a.items[obj->u.a.len] = fz_keep_obj(item);
		obj->u.a.len++;
	}
}

void
fz_array_insert(fz_context *ctx, fz_obj *obj, fz_obj *item)
{
	obj = fz_resolve_indirect(ctx, obj);

	if (!fz_is_array(ctx, obj))
		fz_warn("assert: not an array (%s)", fz_objkindstr(obj));
	else
	{
		if (obj->u.a.len + 1 > obj->u.a.cap)
		{
			int i;
			obj->u.a.cap = (obj->u.a.cap * 3) / 2;
			obj->u.a.items = fz_realloc(ctx, obj->u.a.items, obj->u.a.cap * sizeof(fz_obj*));
			for (i = obj->u.a.len ; i < obj->u.a.cap; i++)
				obj->u.a.items[i] = NULL;
		}
		memmove(obj->u.a.items + 1, obj->u.a.items, obj->u.a.len * sizeof(fz_obj*));
		obj->u.a.items[0] = fz_keep_obj(item);
		obj->u.a.len++;
	}
}

/* dicts may only have names as keys! */

static int keyvalcmp(void *ctxp, const void *ap, const void *bp)
{
	fz_context *ctx = (fz_context *)ctxp;
	const struct keyval *a = ap;
	const struct keyval *b = bp;
	return strcmp(fz_to_name(ctx, a->k), fz_to_name(ctx, b->k));
}

#ifdef MISSING_QSORT_R
static void *qsort_r_hack;
static int keyvalcmp_hack(const void *ap, const void *bp)
{
	return keyvalcmp(qsort_r_hack, ap, bp);
}
#endif

fz_obj *
fz_new_dict(fz_context *ctx, int initialcap)
{
	fz_obj *obj;
	int i;

	obj = fz_malloc(ctx, sizeof(fz_obj));
	obj->refs = 1;
	obj->kind = FZ_DICT;

	obj->u.d.sorted = 1;
	obj->u.d.len = 0;
	obj->u.d.cap = initialcap > 1 ? initialcap : 10;

	obj->u.d.items = fz_calloc(ctx, obj->u.d.cap, sizeof(struct keyval));
	for (i = 0; i < obj->u.d.cap; i++)
	{
		obj->u.d.items[i].k = NULL;
		obj->u.d.items[i].v = NULL;
	}

	return obj;
}

fz_obj *
fz_copy_dict(fz_context *ctx, fz_obj *obj)
{
	fz_obj *new;
	int i, n;

	if (fz_is_indirect(obj) || !fz_is_dict(ctx, obj))
		fz_error_make("assert: not a dict (%s)", fz_objkindstr(obj));

	n = fz_dict_len(ctx, obj);
	new = fz_new_dict(ctx, n);
	for (i = 0; i < n; i++)
		fz_dict_put(ctx, new, fz_dict_get_key(ctx, obj, i), fz_dict_get_val(ctx, obj, i));

	return new;
}

int
fz_dict_len(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	if (!fz_is_dict(ctx, obj))
		return 0;
	return obj->u.d.len;
}

fz_obj *
fz_dict_get_key(fz_context *ctx, fz_obj *obj, int i)
{
	obj = fz_resolve_indirect(ctx, obj);

	if (!fz_is_dict(ctx, obj))
		return NULL;

	if (i < 0 || i >= obj->u.d.len)
		return NULL;

	return obj->u.d.items[i].k;
}

fz_obj *
fz_dict_get_val(fz_context *ctx, fz_obj *obj, int i)
{
	obj = fz_resolve_indirect(ctx, obj);

	if (!fz_is_dict(ctx, obj))
		return NULL;

	if (i < 0 || i >= obj->u.d.len)
		return NULL;

	return obj->u.d.items[i].v;
}

static int
fz_dict_finds(fz_context *ctx, fz_obj *obj, char *key)
{
	if (obj->u.d.sorted)
	{
		int l = 0;
		int r = obj->u.d.len - 1;
		while (l <= r)
		{
			int m = (l + r) >> 1;
			int c = -strcmp(fz_to_name(ctx, obj->u.d.items[m].k), key);
			if (c < 0)
				r = m - 1;
			else if (c > 0)
				l = m + 1;
			else
				return m;
		}
	}

	else
	{
		int i;
		for (i = 0; i < obj->u.d.len; i++)
			if (strcmp(fz_to_name(ctx, obj->u.d.items[i].k), key) == 0)
				return i;
	}

	return -1;
}

fz_obj *
fz_dict_gets(fz_context *ctx, fz_obj *obj, char *key)
{
	int i;

	obj = fz_resolve_indirect(ctx, obj);

	if (!fz_is_dict(ctx, obj))
		return NULL;

	i = fz_dict_finds(ctx, obj, key);
	if (i >= 0)
		return obj->u.d.items[i].v;

	return NULL;
}

fz_obj *
fz_dict_get(fz_context *ctx, fz_obj *obj, fz_obj *key)
{
	if (fz_is_name(ctx, key))
		return fz_dict_gets(ctx, obj, fz_to_name(ctx, key));
	return NULL;
}

fz_obj *
fz_dict_getsa(fz_context *ctx, fz_obj *obj, char *key, char *abbrev)
{
	fz_obj *v;
	v = fz_dict_gets(ctx, obj, key);
	if (v)
		return v;
	return fz_dict_gets(ctx, obj, abbrev);
}

void
fz_dict_put(fz_context *ctx, fz_obj *obj, fz_obj *key, fz_obj *val)
{
	char *s;
	int i;

	obj = fz_resolve_indirect(ctx, obj);

	if (!fz_is_dict(ctx, obj))
	{
		fz_warn("assert: not a dict (%s)", fz_objkindstr(obj));
		return;
	}

	if (fz_is_name(ctx, key))
		s = fz_to_name(ctx, key);
	else
	{
		fz_warn("assert: key is not a name (%s)", fz_objkindstr(obj));
		return;
	}

	if (!val)
	{
		fz_warn("assert: val does not exist for key (%s)", s);
		return;
	}

	i = fz_dict_finds(ctx, obj, s);
	if (i >= 0)
	{
		fz_drop_obj(ctx, obj->u.d.items[i].v);
		obj->u.d.items[i].v = fz_keep_obj(val);
		return;
	}

	if (obj->u.d.len + 1 > obj->u.d.cap)
	{
		obj->u.d.cap = (obj->u.d.cap * 3) / 2;
		obj->u.d.items = fz_realloc(ctx, obj->u.d.items, obj->u.d.cap * sizeof(struct keyval));
		for (i = obj->u.d.len; i < obj->u.d.cap; i++)
		{
			obj->u.d.items[i].k = NULL;
			obj->u.d.items[i].v = NULL;
		}
	}

	/* borked! */
	if (obj->u.d.len)
		if (strcmp(fz_to_name(ctx, obj->u.d.items[obj->u.d.len - 1].k), s) > 0)
			obj->u.d.sorted = 0;

	obj->u.d.items[obj->u.d.len].k = fz_keep_obj(key);
	obj->u.d.items[obj->u.d.len].v = fz_keep_obj(val);
	obj->u.d.len ++;
}

void
fz_dict_puts(fz_context *ctx, fz_obj *obj, char *key, fz_obj *val)
{
	fz_obj *keyobj = fz_new_name(ctx, key);
	fz_dict_put(ctx, obj, keyobj, val);
	fz_drop_obj(ctx, keyobj);
}

void
fz_dict_dels(fz_context *ctx, fz_obj *obj, char *key)
{
	obj = fz_resolve_indirect(ctx, obj);

	if (!fz_is_dict(ctx, obj))
		fz_warn("assert: not a dict (%s)", fz_objkindstr(obj));
	else
	{
		int i = fz_dict_finds(ctx, obj, key);
		if (i >= 0)
		{
			fz_drop_obj(ctx, obj->u.d.items[i].k);
			fz_drop_obj(ctx, obj->u.d.items[i].v);
			obj->u.d.sorted = 0;
			obj->u.d.items[i] = obj->u.d.items[obj->u.d.len-1];
			obj->u.d.len --;
		}
	}
}

void
fz_dict_del(fz_context *ctx, fz_obj *obj, fz_obj *key)
{
	if (fz_is_name(ctx, key))
		fz_dict_dels(ctx, obj, fz_to_name(ctx, key));
	else
		fz_warn("assert: key is not a name (%s)", fz_objkindstr(obj));
}

void
fz_sort_dict(fz_context *ctx, fz_obj *obj)
{
	obj = fz_resolve_indirect(ctx, obj);
	if (!fz_is_dict(ctx, obj))
		return;
	if (!obj->u.d.sorted)
	{
#ifdef MISSING_QSORT_R
		qsort_r_hack = ctx;
		qsort(obj->u.d.items, obj->u.d.len, sizeof(struct keyval), keyvalcmp_hack);
#else
		qsort_r(obj->u.d.items, obj->u.d.len, sizeof(struct keyval), ctx, keyvalcmp);
#endif
				obj->u.d.sorted = 1;
	}
}

static void
fz_free_array(fz_context *ctx, fz_obj *obj)
{
	int i;

	for (i = 0; i < obj->u.a.len; i++)
		if (obj->u.a.items[i])
			fz_drop_obj(ctx, obj->u.a.items[i]);

	fz_free(ctx, obj->u.a.items);
	fz_free(ctx, obj);
}

static void
fz_free_dict(fz_context *ctx, fz_obj *obj)
{
	int i;

	for (i = 0; i < obj->u.d.len; i++) {
		if (obj->u.d.items[i].k)
			fz_drop_obj(ctx, obj->u.d.items[i].k);
		if (obj->u.d.items[i].v)
			fz_drop_obj(ctx, obj->u.d.items[i].v);
	}

	fz_free(ctx, obj->u.d.items);
	fz_free(ctx, obj);
}

void
fz_drop_obj(fz_context *ctx, fz_obj *obj)
{
	assert(obj != NULL);
	if (--obj->refs == 0)
	{
		if (obj->kind == FZ_ARRAY)
			fz_free_array(ctx, obj);
		else if (obj->kind == FZ_DICT)
			fz_free_dict(ctx, obj);
		else
			fz_free(ctx, obj);
	}
}
