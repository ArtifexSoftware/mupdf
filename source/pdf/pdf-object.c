#include "mupdf/pdf.h"

#include "pdf-name-table.h"

#include <stdarg.h>

typedef enum pdf_objkind_e
{
	PDF_INT = 'i',
	PDF_REAL = 'f',
	PDF_STRING = 's',
	PDF_NAME = 'n',
	PDF_ARRAY = 'a',
	PDF_DICT = 'd',
	PDF_INDIRECT = 'r'
} pdf_objkind;

struct keyval
{
	pdf_obj *k;
	pdf_obj *v;
};

enum
{
	PDF_FLAGS_MARKED = 1,
	PDF_FLAGS_SORTED = 2,
	PDF_FLAGS_MEMO = 4,
	PDF_FLAGS_MEMO_BOOL = 8,
	PDF_FLAGS_DIRTY = 16
};

struct pdf_obj_s
{
	int refs;
	unsigned char kind;
	unsigned char flags;
	pdf_document *doc; /* KEEP */
	int parent_num;
	union
	{
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
			pdf_obj **items;
		} a;
		struct {
			int len;
			int cap;
			struct keyval *items;
		} d;
		struct {
			int num;
			int gen;
		} r;
	} u;
};

pdf_obj *
pdf_new_null(fz_context *ctx, pdf_document *doc)
{
	return PDF_OBJ_NULL;
}

pdf_obj *
pdf_new_bool(fz_context *ctx, pdf_document *doc, int b)
{
	return b ? PDF_OBJ_TRUE : PDF_OBJ_FALSE;
}

pdf_obj *
pdf_new_int(fz_context *ctx, pdf_document *doc, int i)
{
	pdf_obj *obj;
	obj = Memento_label(fz_malloc(ctx, sizeof(pdf_obj)), "pdf_obj(int)");
	obj->doc = doc;
	obj->refs = 1;
	obj->kind = PDF_INT;
	obj->flags = 0;
	obj->parent_num = 0;
	obj->u.i = i;
	return obj;
}

pdf_obj *
pdf_new_real(fz_context *ctx, pdf_document *doc, float f)
{
	pdf_obj *obj;
	obj = Memento_label(fz_malloc(ctx, sizeof(pdf_obj)), "pdf_obj(real)");
	obj->doc = doc;
	obj->refs = 1;
	obj->kind = PDF_REAL;
	obj->flags = 0;
	obj->parent_num = 0;
	obj->u.f = f;
	return obj;
}

pdf_obj *
pdf_new_string(fz_context *ctx, pdf_document *doc, const char *str, int len)
{
	pdf_obj *obj;
	obj = Memento_label(fz_malloc(ctx, offsetof(pdf_obj, u.s.buf) + len + 1), "pdf_obj(string)");
	obj->doc = doc;
	obj->refs = 1;
	obj->kind = PDF_STRING;
	obj->flags = 0;
	obj->parent_num = 0;
	obj->u.s.len = len;
	memcpy(obj->u.s.buf, str, len);
	obj->u.s.buf[len] = '\0';
	return obj;
}

static int
namecmp(const void *key, const void *name)
{
	return strcmp((char *)key, *(char **)name);
}

pdf_obj *
pdf_new_name(fz_context *ctx, pdf_document *doc, const char *str)
{
	pdf_obj *obj;
	char **stdname;

	stdname = bsearch(str, &PDF_NAMES[1], PDF_OBJ_ENUM_NAME__LIMIT-1, sizeof(char *), namecmp);
	if (stdname != NULL)
		return (pdf_obj *)(intptr_t)(stdname - &PDF_NAMES[0]);

	obj = Memento_label(fz_malloc(ctx, offsetof(pdf_obj, u.n) + strlen(str) + 1), "pdf_obj(name)");
	obj->doc = doc;
	obj->refs = 1;
	obj->kind = PDF_NAME;
	obj->flags = 0;
	obj->parent_num = 0;
	strcpy(obj->u.n, str);
	return obj;
}

pdf_obj *
pdf_new_indirect(fz_context *ctx, pdf_document *doc, int num, int gen)
{
	pdf_obj *obj;
	obj = Memento_label(fz_malloc(ctx, sizeof(pdf_obj)), "pdf_obj(indirect)");
	obj->doc = doc;
	obj->refs = 1;
	obj->kind = PDF_INDIRECT;
	obj->flags = 0;
	obj->parent_num = 0;
	obj->u.r.num = num;
	obj->u.r.gen = gen;
	return obj;
}

pdf_obj *
pdf_keep_obj(fz_context *ctx, pdf_obj *obj)
{
	if (obj >= PDF_OBJ__LIMIT)
		obj->refs ++;
	return obj;
}

int pdf_is_indirect(fz_context *ctx, pdf_obj *obj)
{
	return obj >= PDF_OBJ__LIMIT ? obj->kind == PDF_INDIRECT : 0;
}

#define RESOLVE(obj) \
	if (obj >= PDF_OBJ__LIMIT && obj->kind == PDF_INDIRECT) \
		obj = pdf_resolve_indirect(ctx, obj); \

int pdf_is_null(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	return obj == PDF_OBJ_NULL;
}

int pdf_is_bool(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	return obj == PDF_OBJ_TRUE || obj == PDF_OBJ_FALSE;
}

int pdf_is_int(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	return obj >= PDF_OBJ__LIMIT ? obj->kind == PDF_INT : 0;
}

int pdf_is_real(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	return obj >= PDF_OBJ__LIMIT ? obj->kind == PDF_REAL : 0;
}

int pdf_is_number(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	return obj >= PDF_OBJ__LIMIT ? (obj->kind == PDF_REAL || obj->kind == PDF_INT) : 0;
}

int pdf_is_string(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	return obj >= PDF_OBJ__LIMIT ? obj->kind == PDF_STRING : 0;
}

int pdf_is_name(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT)
		return obj != NULL && obj < PDF_OBJ_NAME__LIMIT;
	return obj->kind == PDF_NAME;
}

int pdf_is_array(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	return obj >= PDF_OBJ__LIMIT ? obj->kind == PDF_ARRAY : 0;
}

int pdf_is_dict(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	return obj >= PDF_OBJ__LIMIT ? obj->kind == PDF_DICT : 0;
}

int pdf_to_bool(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	return obj == PDF_OBJ_TRUE;
}

int pdf_to_int(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT)
		return 0;
	if (obj->kind == PDF_INT)
		return obj->u.i;
	if (obj->kind == PDF_REAL)
		return (int)(obj->u.f + 0.5f); /* No roundf in MSVC */
	return 0;
}

float pdf_to_real(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT)
		return 0;
	if (obj->kind == PDF_REAL)
		return obj->u.f;
	if (obj->kind == PDF_INT)
		return obj->u.i;
	return 0;
}

char *pdf_to_name(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (!obj)
		return "";
	if (obj < PDF_OBJ_NAME__LIMIT)
		return PDF_NAMES[(intptr_t)obj];
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_NAME)
		return "";
	return obj->u.n;
}

char *pdf_to_str_buf(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_STRING)
		return "";
	return obj->u.s.buf;
}

int pdf_to_str_len(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_STRING)
		return 0;
	return obj->u.s.len;
}

void pdf_set_int(fz_context *ctx, pdf_obj *obj, int i)
{
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_INT)
		return;
	obj->u.i = i;
}

/* for use by pdf_crypt_obj_imp to decrypt AES string in place */
void pdf_set_str_len(fz_context *ctx, pdf_obj *obj, int newlen)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_STRING)
		return; /* This should never happen */
	if (newlen > obj->u.s.len)
		return; /* This should never happen */
	obj->u.s.len = newlen;
}

pdf_obj *pdf_to_dict(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	return (obj >= PDF_OBJ__LIMIT && obj->kind == PDF_DICT ? obj : NULL);
}

int pdf_to_num(fz_context *ctx, pdf_obj *obj)
{
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_INDIRECT)
		return 0;
	return obj->u.r.num;
}

int pdf_to_gen(fz_context *ctx, pdf_obj *obj)
{
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_INDIRECT)
		return 0;
	return obj->u.r.gen;
}

pdf_document *pdf_get_indirect_document(fz_context *ctx, pdf_obj *obj)
{
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_INDIRECT)
		return NULL;
	return obj->doc;
}

int pdf_objcmp_resolve(fz_context *ctx, pdf_obj *a, pdf_obj *b)
{
	RESOLVE(a);
	RESOLVE(b);
	return pdf_objcmp(ctx, a, b);
}

int
pdf_objcmp(fz_context *ctx, pdf_obj *a, pdf_obj *b)
{
	int i;

	if (a == b)
		return 0;

	if (!a || !b)
		return 1;

	if (a < PDF_OBJ_NAME__LIMIT)
	{
		if (b < PDF_OBJ_NAME__LIMIT)
			return a != b;

		if (b->kind != PDF_NAME)
			return 1;
		return strcmp(b->u.n, PDF_NAMES[(intptr_t)a]);
	}

	if (b < PDF_OBJ_NAME__LIMIT)
	{
		if (a->kind != PDF_NAME)
			return 1;
		return strcmp(a->u.n, PDF_NAMES[(intptr_t)b]);
	}

	if (a < PDF_OBJ__LIMIT || b < PDF_OBJ__LIMIT)
		return a != b;

	if (a->kind != b->kind)
		return 1;

	switch (a->kind)
	{
	case PDF_INT:
		return a->u.i - b->u.i;

	case PDF_REAL:
		if (a->u.f < b->u.f)
			return -1;
		if (a->u.f > b->u.f)
			return 1;
		return 0;

	case PDF_STRING:
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

	case PDF_NAME:
		return strcmp(a->u.n, b->u.n);

	case PDF_INDIRECT:
		if (a->u.r.num == b->u.r.num)
			return a->u.r.gen - b->u.r.gen;
		return a->u.r.num - b->u.r.num;

	case PDF_ARRAY:
		if (a->u.a.len != b->u.a.len)
			return a->u.a.len - b->u.a.len;
		for (i = 0; i < a->u.a.len; i++)
			if (pdf_objcmp(ctx, a->u.a.items[i], b->u.a.items[i]))
				return 1;
		return 0;

	case PDF_DICT:
		if (a->u.d.len != b->u.d.len)
			return a->u.d.len - b->u.d.len;
		for (i = 0; i < a->u.d.len; i++)
		{
			if (pdf_objcmp(ctx, a->u.d.items[i].k, b->u.d.items[i].k))
				return 1;
			if (pdf_objcmp(ctx, a->u.d.items[i].v, b->u.d.items[i].v))
				return 1;
		}
		return 0;

	}
	return 1;
}

static char *
pdf_objkindstr(pdf_obj *obj)
{
	if (!obj)
		return "<NULL>";
	if (obj < PDF_OBJ_NAME__LIMIT)
		return "name";
	if (obj == PDF_OBJ_TRUE || obj == PDF_OBJ_FALSE)
		return "boolean";
	if (obj == PDF_OBJ_NULL)
		return "null";

	switch (obj->kind)
	{
	case PDF_INT: return "integer";
	case PDF_REAL: return "real";
	case PDF_STRING: return "string";
	case PDF_NAME: return "name";
	case PDF_ARRAY: return "array";
	case PDF_DICT: return "dictionary";
	case PDF_INDIRECT: return "reference";
	}
	return "<unknown>";
}

pdf_obj *
pdf_new_array(fz_context *ctx, pdf_document *doc, int initialcap)
{
	pdf_obj *obj;
	int i;

	obj = Memento_label(fz_malloc(ctx, sizeof(pdf_obj)), "pdf_obj(array)");
	obj->doc = doc;
	obj->refs = 1;
	obj->kind = PDF_ARRAY;
	obj->flags = 0;
	obj->parent_num = 0;

	obj->u.a.len = 0;
	obj->u.a.cap = initialcap > 1 ? initialcap : 6;

	fz_try(ctx)
	{
		obj->u.a.items = Memento_label(fz_malloc_array(ctx, obj->u.a.cap, sizeof(pdf_obj*)), "pdf_obj(array items)");
	}
	fz_catch(ctx)
	{
		fz_free(ctx, obj);
		fz_rethrow(ctx);
	}
	for (i = 0; i < obj->u.a.cap; i++)
		obj->u.a.items[i] = NULL;

	return obj;
}

static void
pdf_array_grow(fz_context *ctx, pdf_obj *obj)
{
	int i;
	int new_cap = (obj->u.a.cap * 3) / 2;

	obj->u.a.items = fz_resize_array(ctx, obj->u.a.items, new_cap, sizeof(pdf_obj*));
	obj->u.a.cap = new_cap;

	for (i = obj->u.a.len ; i < obj->u.a.cap; i++)
		obj->u.a.items[i] = NULL;
}

pdf_obj *
pdf_copy_array(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj)
	{
		pdf_document *doc = obj->doc;

		pdf_obj *arr;
		int i;
		int n;

		if (obj->kind != PDF_ARRAY)
			fz_warn(ctx, "assert: not an array (%s)", pdf_objkindstr(obj));

		arr = pdf_new_array(ctx, doc, pdf_array_len(ctx, obj));
		n = pdf_array_len(ctx, obj);
		for (i = 0; i < n; i++)
			pdf_array_push(ctx, arr, pdf_array_get(ctx, obj, i));

		return arr;
	}
	return NULL; /* Can't warn :( */
}

int
pdf_array_len(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_ARRAY)
		return 0;
	return obj->u.a.len;
}

pdf_obj *
pdf_array_get(fz_context *ctx, pdf_obj *obj, int i)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_ARRAY)
		return NULL;
	if (i < 0 || i >= obj->u.a.len)
		return NULL;
	return obj->u.a.items[i];
}

static void object_altered(fz_context *ctx, pdf_obj *obj, pdf_obj *val)
{
	pdf_document *doc = obj->doc;

	/*
		parent_num = 0 while an object is being parsed from the file.
		No further action is necessary.
	*/
	if (obj->parent_num == 0 || doc->freeze_updates)
		return;

	/*
		Otherwise we need to ensure that the containing hierarchy of objects
		has been moved to the incremental xref section and the newly linked
		object needs to record the parent_num
	*/
	pdf_xref_ensure_incremental_object(ctx, doc, obj->parent_num);
	pdf_set_obj_parent(ctx, val, obj->parent_num);
}

void
pdf_array_put(fz_context *ctx, pdf_obj *obj, int i, pdf_obj *item)
{
	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		if (obj->kind != PDF_ARRAY)
			fz_warn(ctx, "assert: not an array (%s)", pdf_objkindstr(obj));
		else if (i < 0)
			fz_warn(ctx, "assert: index %d < 0", i);
		else if (i >= obj->u.a.len)
			fz_warn(ctx, "assert: index %d > length %d", i, obj->u.a.len);
		else
		{
			pdf_drop_obj(ctx, obj->u.a.items[i]);
			obj->u.a.items[i] = pdf_keep_obj(ctx, item);
		}

		object_altered(ctx, obj, item);
	}
	return; /* Can't warn :( */
}

void
pdf_array_put_drop(fz_context *ctx, pdf_obj *obj, int i, pdf_obj *item)
{
	pdf_array_put(ctx, obj, i, item);
	pdf_drop_obj(ctx, item);
}

void
pdf_array_push(fz_context *ctx, pdf_obj *obj, pdf_obj *item)
{
	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		if (obj->kind != PDF_ARRAY)
			fz_warn(ctx, "assert: not an array (%s)", pdf_objkindstr(obj));
		else
		{
			if (obj->u.a.len + 1 > obj->u.a.cap)
				pdf_array_grow(ctx, obj);
			obj->u.a.items[obj->u.a.len] = pdf_keep_obj(ctx, item);
			obj->u.a.len++;
		}

		object_altered(ctx, obj, item);
	}
	return; /* Can't warn :( */
}

void
pdf_array_push_drop(fz_context *ctx, pdf_obj *obj, pdf_obj *item)
{
	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		fz_try(ctx)
			pdf_array_push(ctx, obj, item);
		fz_always(ctx)
			pdf_drop_obj(ctx, item);
		fz_catch(ctx)
			fz_rethrow(ctx);
	}
}

void
pdf_array_insert(fz_context *ctx, pdf_obj *obj, pdf_obj *item, int i)
{
	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		if (obj->kind != PDF_ARRAY)
			fz_warn(ctx, "assert: not an array (%s)", pdf_objkindstr(obj));
		else
		{
			if (i < 0 || i > obj->u.a.len)
				fz_throw(ctx, FZ_ERROR_GENERIC, "attempt to insert object %d in array of length %d", i, obj->u.a.len);
			if (obj->u.a.len + 1 > obj->u.a.cap)
				pdf_array_grow(ctx, obj);
			memmove(obj->u.a.items + i + 1, obj->u.a.items + i, (obj->u.a.len - i) * sizeof(pdf_obj*));
			obj->u.a.items[i] = pdf_keep_obj(ctx, item);
			obj->u.a.len++;
		}

		object_altered(ctx, obj, item);
	}
	return; /* Can't warn :( */
}

void
pdf_array_insert_drop(fz_context *ctx, pdf_obj *obj, pdf_obj *item, int i)
{
	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		fz_try(ctx)
			pdf_array_insert(ctx, obj, item, i);
		fz_always(ctx)
			pdf_drop_obj(ctx, item);
		fz_catch(ctx)
			fz_rethrow(ctx);
	}
}

void
pdf_array_delete(fz_context *ctx, pdf_obj *obj, int i)
{
	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		if (obj->kind != PDF_ARRAY)
			fz_warn(ctx, "assert: not an array (%s)", pdf_objkindstr(obj));
		else
		{
			pdf_drop_obj(ctx, obj->u.a.items[i]);
			obj->u.a.items[i] = 0;
			obj->u.a.len--;
			memmove(obj->u.a.items + i, obj->u.a.items + i + 1, (obj->u.a.len - i) * sizeof(pdf_obj*));
		}
	}
	return; /* Can't warn :( */
}

int
pdf_array_contains(fz_context *ctx, pdf_obj *arr, pdf_obj *obj)
{
	int i, len;

	len = pdf_array_len(ctx, arr);
	for (i = 0; i < len; i++)
		if (!pdf_objcmp(ctx, pdf_array_get(ctx, arr, i), obj))
			return 1;

	return 0;
}

pdf_obj *pdf_new_rect(fz_context *ctx, pdf_document *doc, const fz_rect *rect)
{
	pdf_obj *arr = NULL;
	pdf_obj *item = NULL;

	fz_var(arr);
	fz_var(item);
	fz_try(ctx)
	{
		arr = pdf_new_array(ctx, doc, 4);

		item = pdf_new_real(ctx, doc, rect->x0);
		pdf_array_push(ctx, arr, item);
		pdf_drop_obj(ctx, item);
		item = NULL;

		item = pdf_new_real(ctx, doc, rect->y0);
		pdf_array_push(ctx, arr, item);
		pdf_drop_obj(ctx, item);
		item = NULL;

		item = pdf_new_real(ctx, doc, rect->x1);
		pdf_array_push(ctx, arr, item);
		pdf_drop_obj(ctx, item);
		item = NULL;

		item = pdf_new_real(ctx, doc, rect->y1);
		pdf_array_push(ctx, arr, item);
		pdf_drop_obj(ctx, item);
		item = NULL;
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, item);
		pdf_drop_obj(ctx, arr);
		fz_rethrow(ctx);
	}

	return arr;
}

pdf_obj *pdf_new_matrix(fz_context *ctx, pdf_document *doc, const fz_matrix *mtx)
{
	pdf_obj *arr = NULL;
	pdf_obj *item = NULL;

	fz_var(arr);
	fz_var(item);
	fz_try(ctx)
	{
		arr = pdf_new_array(ctx, doc, 6);

		item = pdf_new_real(ctx, doc, mtx->a);
		pdf_array_push(ctx, arr, item);
		pdf_drop_obj(ctx, item);
		item = NULL;

		item = pdf_new_real(ctx, doc, mtx->b);
		pdf_array_push(ctx, arr, item);
		pdf_drop_obj(ctx, item);
		item = NULL;

		item = pdf_new_real(ctx, doc, mtx->c);
		pdf_array_push(ctx, arr, item);
		pdf_drop_obj(ctx, item);
		item = NULL;

		item = pdf_new_real(ctx, doc, mtx->d);
		pdf_array_push(ctx, arr, item);
		pdf_drop_obj(ctx, item);
		item = NULL;

		item = pdf_new_real(ctx, doc, mtx->e);
		pdf_array_push(ctx, arr, item);
		pdf_drop_obj(ctx, item);
		item = NULL;

		item = pdf_new_real(ctx, doc, mtx->f);
		pdf_array_push(ctx, arr, item);
		pdf_drop_obj(ctx, item);
		item = NULL;
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, item);
		pdf_drop_obj(ctx, arr);
		fz_rethrow(ctx);
	}

	return arr;
}

/* dicts may only have names as keys! */

static int keyvalcmp(const void *ap, const void *bp)
{
	const struct keyval *a = ap;
	const struct keyval *b = bp;
	const char *an;
	const char *bn;

	/* We should never get a->k == NULL or b->k == NULL. If we
	 * do, then they match. */
	if (a->k < PDF_OBJ_NAME__LIMIT)
		an = PDF_NAMES[(intptr_t)a->k];
	else if (a->k >= PDF_OBJ__LIMIT && a->k->kind == PDF_NAME)
		an = a->k->u.n;
	else
		return 0;

	if (b->k < PDF_OBJ_NAME__LIMIT)
		bn = PDF_NAMES[(intptr_t)b->k];
	else if (b->k >= PDF_OBJ__LIMIT && b->k->kind == PDF_NAME)
		bn = b->k->u.n;
	else
		return 0;

	return strcmp(an, bn);
}

pdf_obj *
pdf_new_dict(fz_context *ctx, pdf_document *doc, int initialcap)
{
	pdf_obj *obj;
	int i;

	obj = Memento_label(fz_malloc(ctx, sizeof(pdf_obj)), "pdf_obj(dict)");
	obj->doc = doc;
	obj->refs = 1;
	obj->kind = PDF_DICT;
	obj->flags = 0;
	obj->parent_num = 0;

	obj->u.d.len = 0;
	obj->u.d.cap = initialcap > 1 ? initialcap : 10;

	fz_try(ctx)
	{
		obj->u.d.items = Memento_label(fz_malloc_array(ctx, obj->u.d.cap, sizeof(struct keyval)), "pdf_obj(dict items)");
	}
	fz_catch(ctx)
	{
		fz_free(ctx, obj);
		fz_rethrow(ctx);
	}
	for (i = 0; i < obj->u.d.cap; i++)
	{
		obj->u.d.items[i].k = NULL;
		obj->u.d.items[i].v = NULL;
	}

	return obj;
}

static void
pdf_dict_grow(fz_context *ctx, pdf_obj *obj)
{
	int i;
	int new_cap = (obj->u.d.cap * 3) / 2;

	obj->u.d.items = fz_resize_array(ctx, obj->u.d.items, new_cap, sizeof(struct keyval));
	obj->u.d.cap = new_cap;

	for (i = obj->u.d.len; i < obj->u.d.cap; i++)
	{
		obj->u.d.items[i].k = NULL;
		obj->u.d.items[i].v = NULL;
	}
}

pdf_obj *
pdf_copy_dict(fz_context *ctx, pdf_obj *obj)
{
	pdf_obj *dict;
	int i, n;

	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		pdf_document *doc = obj->doc;

		if (obj->kind != PDF_DICT)
			fz_warn(ctx, "assert: not a dict (%s)", pdf_objkindstr(obj));

		n = pdf_dict_len(ctx, obj);
		dict = pdf_new_dict(ctx, doc, n);
		for (i = 0; i < n; i++)
			pdf_dict_put(ctx, dict, pdf_dict_get_key(ctx, obj, i), pdf_dict_get_val(ctx, obj, i));

		return dict;
	}
	return NULL; /* Can't warn :( */
}

int
pdf_dict_len(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_DICT)
		return 0;
	return obj->u.d.len;
}

pdf_obj *
pdf_dict_get_key(fz_context *ctx, pdf_obj *obj, int i)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_DICT)
		return NULL;
	if (i < 0 || i >= obj->u.d.len)
		return NULL;
	return obj->u.d.items[i].k;
}

pdf_obj *
pdf_dict_get_val(fz_context *ctx, pdf_obj *obj, int i)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_DICT)
		return NULL;
	if (i < 0 || i >= obj->u.d.len)
		return NULL;
	return obj->u.d.items[i].v;
}

void
pdf_dict_put_val_drop(fz_context *ctx, pdf_obj *obj, int i, pdf_obj *new_obj)
{
	RESOLVE(obj);
	if (!obj || obj->kind != PDF_DICT)
	{
		pdf_drop_obj(ctx, new_obj);
		return;
	}
	if (i < 0 || i >= obj->u.d.len)
	{
		/* FIXME: Should probably extend the dict here */
		pdf_drop_obj(ctx, new_obj);
		return;
	}
	pdf_drop_obj(ctx, obj->u.d.items[i].v);
	obj->u.d.items[i].v = new_obj;
}

static int
pdf_dict_finds(fz_context *ctx, pdf_obj *obj, const char *key, int *location)
{
	if ((obj->flags & PDF_FLAGS_SORTED) && obj->u.d.len > 0)
	{
		int l = 0;
		int r = obj->u.d.len - 1;

		if (strcmp(pdf_to_name(ctx, obj->u.d.items[r].k), key) < 0)
		{
			if (location)
				*location = r + 1;
			return -1;
		}

		while (l <= r)
		{
			int m = (l + r) >> 1;
			int c = -strcmp(pdf_to_name(ctx, obj->u.d.items[m].k), key);
			if (c < 0)
				r = m - 1;
			else if (c > 0)
				l = m + 1;
			else
				return m;

			if (location)
				*location = l;
		}
	}

	else
	{
		int i;
		for (i = 0; i < obj->u.d.len; i++)
			if (strcmp(pdf_to_name(ctx, obj->u.d.items[i].k), key) == 0)
				return i;


		if (location)
			*location = obj->u.d.len;
	}

	return -1;
}

static int
pdf_dict_find(fz_context *ctx, pdf_obj *obj, pdf_obj *key, int *location)
{
	if ((obj->flags & PDF_FLAGS_SORTED) && obj->u.d.len > 0)
	{
		int l = 0;
		int r = obj->u.d.len - 1;
		pdf_obj *k = obj->u.d.items[r].k;

		if (k == key || (k >= PDF_OBJ__LIMIT && strcmp(k->u.n, PDF_NAMES[(intptr_t)key]) < 0))
		{
			if (location)
				*location = r + 1;
			return -1;
		}

		while (l <= r)
		{
			int m = (l + r) >> 1;
			int c;

			k = obj->u.d.items[m].k;
			c = (k < PDF_OBJ__LIMIT ? key-k : -strcmp(k->u.n, PDF_NAMES[(intptr_t)key]));
			if (c < 0)
				r = m - 1;
			else if (c > 0)
				l = m + 1;
			else
				return m;

			if (location)
				*location = l;
		}
	}
	else
	{
		int i;
		for (i = 0; i < obj->u.d.len; i++)
		{
			pdf_obj *k = obj->u.d.items[i].k;
			if (k < PDF_OBJ__LIMIT)
			{
				if (k == key)
					return i;
			}
			else
			{
				if (!strcmp(PDF_NAMES[(intptr_t)key], k->u.n))
					return i;
			}
		}

		if (location)
			*location = obj->u.d.len;
	}

	return -1;
}

pdf_obj *
pdf_dict_gets(fz_context *ctx, pdf_obj *obj, const char *key)
{
	int i;

	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_DICT)
		return NULL;

	i = pdf_dict_finds(ctx, obj, key, NULL);
	if (i >= 0)
		return obj->u.d.items[i].v;

	return NULL;
}

pdf_obj *
pdf_dict_getp(fz_context *ctx, pdf_obj *obj, const char *keys)
{
	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		char buf[256];
		char *k, *e;

		if (strlen(keys)+1 > 256)
			fz_throw(ctx, FZ_ERROR_GENERIC, "buffer overflow in pdf_dict_getp");

		strcpy(buf, keys);

		e = buf;
		while (*e && obj)
		{
			k = e;
			while (*e != '/' && *e != '\0')
				e++;

			if (*e == '/')
			{
				*e = '\0';
				e++;
			}

			obj = pdf_dict_gets(ctx, obj, k);
		}

		return obj;
	}
	return NULL; /* Can't warn */
}

pdf_obj *
pdf_dict_getl(fz_context *ctx, pdf_obj *obj, ...)
{
	va_list keys;
	pdf_obj *key;

	va_start(keys, obj);

	while (obj != NULL && (key = va_arg(keys, pdf_obj *)) != NULL)
	{
		obj = pdf_dict_get(ctx, obj, key);
	}

	va_end(keys);
	return obj;
}


pdf_obj *
pdf_dict_get(fz_context *ctx, pdf_obj *obj, pdf_obj *key)
{
	int i;

	if (key >= PDF_OBJ__LIMIT)
	{
		if (key->kind != PDF_NAME)
			return NULL;

		return pdf_dict_gets(ctx, obj, pdf_to_name(ctx, key));
	}

	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_DICT)
		return NULL;

	i = pdf_dict_find(ctx, obj, key, NULL);
	if (i >= 0)
		return obj->u.d.items[i].v;
	return NULL;
}

pdf_obj *
pdf_dict_getsa(fz_context *ctx, pdf_obj *obj, const char *key, const char *abbrev)
{
	pdf_obj *v;
	v = pdf_dict_gets(ctx, obj, key);
	if (v)
		return v;
	return pdf_dict_gets(ctx, obj, abbrev);
}

pdf_obj *
pdf_dict_geta(fz_context *ctx, pdf_obj *obj, pdf_obj *key, pdf_obj *abbrev)
{
	pdf_obj *v;
	v = pdf_dict_get(ctx, obj, key);
	if (v)
		return v;
	return pdf_dict_get(ctx, obj, abbrev);
}

void
pdf_dict_put(fz_context *ctx, pdf_obj *obj, pdf_obj *key, pdf_obj *val)
{
	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		int location;
		char *s;
		int i;

		if (obj->kind != PDF_DICT)
		{
			fz_warn(ctx, "assert: not a dict (%s)", pdf_objkindstr(obj));
			return;
		}

		RESOLVE(key);
		if (!key || (key >= PDF_OBJ__LIMIT && key->kind != PDF_NAME))
		{
			fz_warn(ctx, "assert: key is not a name (%s)", pdf_objkindstr(obj));
			return;
		}
		else
			s = pdf_to_name(ctx, key);

		if (!val)
		{
			fz_warn(ctx, "assert: val does not exist for key (%s)", s);
			return;
		}

		if (obj->u.d.len > 100 && !(obj->flags & PDF_FLAGS_SORTED))
			pdf_sort_dict(ctx, obj);

		i = pdf_dict_finds(ctx, obj, s, &location);
		if (i >= 0 && i < obj->u.d.len)
		{
			if (obj->u.d.items[i].v != val)
			{
				pdf_obj *d = obj->u.d.items[i].v;
				obj->u.d.items[i].v = pdf_keep_obj(ctx, val);
				pdf_drop_obj(ctx, d);
			}
		}
		else
		{
			if (obj->u.d.len + 1 > obj->u.d.cap)
				pdf_dict_grow(ctx, obj);

			i = location;
			if ((obj->flags & PDF_FLAGS_SORTED) && obj->u.d.len > 0)
				memmove(&obj->u.d.items[i + 1],
						&obj->u.d.items[i],
						(obj->u.d.len - i) * sizeof(struct keyval));

			obj->u.d.items[i].k = pdf_keep_obj(ctx, key);
			obj->u.d.items[i].v = pdf_keep_obj(ctx, val);
			obj->u.d.len ++;
		}

		object_altered(ctx, obj, val);
	}
	return; /* Can't warn :( */
}

void
pdf_dict_put_drop(fz_context *ctx, pdf_obj *obj, pdf_obj *key, pdf_obj *val)
{
	fz_try(ctx)
		pdf_dict_put(ctx, obj, key, val);
	fz_always(ctx)
		pdf_drop_obj(ctx, val);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void
pdf_dict_puts(fz_context *ctx, pdf_obj *obj, const char *key, pdf_obj *val)
{
	pdf_document *doc = obj->doc;
	pdf_obj *keyobj = pdf_new_name(ctx, doc, key);

	fz_try(ctx)
		pdf_dict_put(ctx, obj, keyobj, val);
	fz_always(ctx)
		pdf_drop_obj(ctx, keyobj);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void
pdf_dict_puts_drop(fz_context *ctx, pdf_obj *obj, const char *key, pdf_obj *val)
{
	pdf_document *doc = obj->doc;
	pdf_obj *keyobj = NULL;

	fz_var(keyobj);

	fz_try(ctx)
	{
		keyobj = pdf_new_name(ctx, doc, key);
		pdf_dict_put(ctx, obj, keyobj, val);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, keyobj);
		pdf_drop_obj(ctx, val);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

void
pdf_dict_putp(fz_context *ctx, pdf_obj *obj, const char *keys, pdf_obj *val)
{
	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		pdf_document *doc = obj->doc;

		char buf[256];
		char *k, *e;
		pdf_obj *cobj = NULL;

		if (strlen(keys)+1 > 256)
			fz_throw(ctx, FZ_ERROR_GENERIC, "buffer overflow in pdf_dict_putp");

		strcpy(buf, keys);

		e = buf;
		while (*e)
		{
			k = e;
			while (*e != '/' && *e != '\0')
				e++;

			if (*e == '/')
			{
				*e = '\0';
				e++;
			}

			if (*e)
			{
				/* Not the last key in the key path. Create subdict if not already there. */
				cobj = pdf_dict_gets(ctx, obj, k);
				if (cobj == NULL)
				{
					cobj = pdf_new_dict(ctx, doc, 1);
					fz_try(ctx)
						pdf_dict_puts(ctx, obj, k, cobj);
					fz_always(ctx)
						pdf_drop_obj(ctx, cobj);
					fz_catch(ctx)
						fz_rethrow(ctx);
				}
				/* Move to subdict */
				obj = cobj;
			}
			else
			{
				/* Last key. Use it to store the value */
				/* Use val = NULL to request delete */
				if (val)
					pdf_dict_puts(ctx, obj, k, val);
				else
					pdf_dict_dels(ctx, obj, k);
			}
		}
	}
}

void
pdf_dict_putp_drop(fz_context *ctx, pdf_obj *obj, const char *keys, pdf_obj *val)
{
	fz_try(ctx)
		pdf_dict_putp(ctx, obj, keys, val);
	fz_always(ctx)
		pdf_drop_obj(ctx, val);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static void
pdf_dict_vputl(fz_context *ctx, pdf_obj *obj, pdf_obj *val, va_list keys)
{
	pdf_obj *key;
	pdf_obj *next_key;
	pdf_obj *next_obj;

	key = va_arg(keys, pdf_obj *);
	if (key == NULL)
		return;

	while ((next_key = va_arg(keys, pdf_obj *)) != NULL)
	{
		next_obj = pdf_dict_get(ctx, obj, key);
		if (next_obj == NULL)
			goto new_obj;
		obj = next_obj;
		key = next_key;
	}

	pdf_dict_put(ctx, obj, key, val);
	return;

new_obj:
	/* We have to create entries */
	do
	{
		next_obj = pdf_new_dict(ctx, obj->doc, 1);
		pdf_dict_put_drop(ctx, obj, key, next_obj);
		obj = next_obj;
		key = next_key;
	}
	while ((next_key = va_arg(keys, pdf_obj *)) != NULL);

	pdf_dict_put(ctx, obj, key, val);
	return;
}

void
pdf_dict_putl(fz_context *ctx, pdf_obj *obj, pdf_obj *val, ...)
{
	va_list keys;
	va_start(keys, val);

	fz_try(ctx)
		pdf_dict_vputl(ctx, obj, val, keys);
	fz_always(ctx)
		va_end(keys);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void
pdf_dict_putl_drop(fz_context *ctx, pdf_obj *obj, pdf_obj *val, ...)
{
	va_list keys;
	va_start(keys, val);

	fz_try(ctx)
		pdf_dict_vputl(ctx, obj, val, keys);
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, val);
		va_end(keys);
	}
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void
pdf_dict_dels(fz_context *ctx, pdf_obj *obj, const char *key)
{
	RESOLVE(obj);
	if (obj >= PDF_OBJ__LIMIT)
	{
		if (obj->kind != PDF_DICT)
			fz_warn(ctx, "assert: not a dict (%s)", pdf_objkindstr(obj));
		else
		{
			int i = pdf_dict_finds(ctx, obj, key, NULL);
			if (i >= 0)
			{
				pdf_drop_obj(ctx, obj->u.d.items[i].k);
				pdf_drop_obj(ctx, obj->u.d.items[i].v);
				obj->flags &= ~PDF_FLAGS_SORTED;
				obj->u.d.items[i] = obj->u.d.items[obj->u.d.len-1];
				obj->u.d.len --;
			}
		}

		object_altered(ctx, obj, NULL);
	}
	return; /* Can't warn :( */
}

void
pdf_dict_del(fz_context *ctx, pdf_obj *obj, pdf_obj *key)
{
	RESOLVE(key);
	if (!key)
		return; /* Can't warn */

	if (key < PDF_OBJ__LIMIT)
		pdf_dict_dels(ctx, obj, PDF_NAMES[(intptr_t)key]);
	else if (key->kind == PDF_NAME)
		pdf_dict_dels(ctx, obj, key->u.n);
	/* else Can't warn */
}

void
pdf_sort_dict(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT || obj->kind != PDF_DICT)
		return;
	if (!(obj->flags & PDF_FLAGS_SORTED))
	{
		qsort(obj->u.d.items, obj->u.d.len, sizeof(struct keyval), keyvalcmp);
		obj->flags |= PDF_FLAGS_SORTED;
	}
}

int
pdf_obj_marked(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT)
		return 0;
	return !!(obj->flags & PDF_FLAGS_MARKED);
}

int
pdf_mark_obj(fz_context *ctx, pdf_obj *obj)
{
	int marked;
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT)
		return 0;
	marked = !!(obj->flags & PDF_FLAGS_MARKED);
	obj->flags |= PDF_FLAGS_MARKED;
	return marked;
}

void
pdf_unmark_obj(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT)
		return;
	obj->flags &= ~PDF_FLAGS_MARKED;
}

void
pdf_set_obj_memo(fz_context *ctx, pdf_obj *obj, int memo)
{
	if (obj < PDF_OBJ__LIMIT)
		return;

	obj->flags |= PDF_FLAGS_MEMO;
	if (memo)
		obj->flags |= PDF_FLAGS_MEMO_BOOL;
	else
		obj->flags &= ~PDF_FLAGS_MEMO_BOOL;
}

int
pdf_obj_memo(fz_context *ctx, pdf_obj *obj, int *memo)
{
	if (obj < PDF_OBJ__LIMIT)
		return 0;
	if (!(obj->flags & PDF_FLAGS_MEMO))
		return 0;
	*memo = !!(obj->flags & PDF_FLAGS_MEMO_BOOL);
	return 1;
}

int pdf_obj_is_dirty(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT)
		return 0;
	return !!(obj->flags & PDF_FLAGS_DIRTY);
}

void pdf_dirty_obj(fz_context *ctx, pdf_obj *obj)
{
	RESOLVE(obj);
	if (obj < PDF_OBJ__LIMIT)
		return;
	obj->flags |= PDF_FLAGS_DIRTY;
}

void pdf_clean_obj(fz_context *ctx, pdf_obj *obj)
{
	if (obj < PDF_OBJ__LIMIT)
		return;
	obj->flags &= ~PDF_FLAGS_DIRTY;
}

static void
pdf_drop_array(fz_context *ctx, pdf_obj *obj)
{
	int i;

	for (i = 0; i < obj->u.a.len; i++)
		pdf_drop_obj(ctx, obj->u.a.items[i]);

	fz_free(ctx, obj->u.a.items);
	fz_free(ctx, obj);
}

static void
pdf_drop_dict(fz_context *ctx, pdf_obj *obj)
{
	int i;

	for (i = 0; i < obj->u.d.len; i++) {
		pdf_drop_obj(ctx, obj->u.d.items[i].k);
		pdf_drop_obj(ctx, obj->u.d.items[i].v);
	}

	fz_free(ctx, obj->u.d.items);
	fz_free(ctx, obj);
}

void
pdf_drop_obj(fz_context *ctx, pdf_obj *obj)
{
	if (obj >= PDF_OBJ__LIMIT)
	{
		if (--obj->refs)
			return;
		if (obj->kind == PDF_ARRAY)
			pdf_drop_array(ctx, obj);
		else if (obj->kind == PDF_DICT)
			pdf_drop_dict(ctx, obj);
		else
			fz_free(ctx, obj);
	}
}

void
pdf_set_obj_parent(fz_context *ctx, pdf_obj *obj, int num)
{
	int n, i;

	if (obj < PDF_OBJ__LIMIT)
		return;

	obj->parent_num = num;

	switch(obj->kind)
	{
	case PDF_ARRAY:
		n = pdf_array_len(ctx, obj);
		for (i = 0; i < n; i++)
			pdf_set_obj_parent(ctx, pdf_array_get(ctx, obj, i), num);
		break;
	case PDF_DICT:
		n = pdf_dict_len(ctx, obj);
		for (i = 0; i < n; i++)
			pdf_set_obj_parent(ctx, pdf_dict_get_val(ctx, obj, i), num);
		break;
	}
}

int pdf_obj_parent_num(fz_context *ctx, pdf_obj *obj)
{
	if (obj < PDF_OBJ__LIMIT)
		return 0;

	return obj->parent_num;
}

pdf_obj *pdf_new_obj_from_str(fz_context *ctx, pdf_document *doc, const char *src)
{
	pdf_obj *result;
	pdf_lexbuf lexbuf;
	fz_stream *stream = fz_open_memory(ctx, (unsigned char *)src, strlen(src));

	pdf_lexbuf_init(ctx, &lexbuf, PDF_LEXBUF_SMALL);
	fz_try(ctx)
	{
		result = pdf_parse_stm_obj(ctx, doc, stream, &lexbuf);
	}
	fz_always(ctx)
	{
		pdf_lexbuf_fin(ctx, &lexbuf);
		fz_drop_stream(ctx, stream);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return result;
}

/* Pretty printing objects */

struct fmt
{
	char *buf;
	int cap;
	int len;
	int indent;
	int tight;
	int col;
	int sep;
	int last;
};

static void fmt_obj(fz_context *ctx, struct fmt *fmt, pdf_obj *obj);

static inline int iswhite(int ch)
{
	return
		ch == '\000' ||
		ch == '\011' ||
		ch == '\012' ||
		ch == '\014' ||
		ch == '\015' ||
		ch == '\040';
}

static inline int isdelim(int ch)
{
	return
		ch == '(' || ch == ')' ||
		ch == '<' || ch == '>' ||
		ch == '[' || ch == ']' ||
		ch == '{' || ch == '}' ||
		ch == '/' ||
		ch == '%';
}

static inline void fmt_putc(fz_context *ctx, struct fmt *fmt, int c)
{
	if (fmt->sep && !isdelim(fmt->last) && !isdelim(c)) {
		fmt->sep = 0;
		fmt_putc(ctx, fmt, ' ');
	}
	fmt->sep = 0;

	if (fmt->buf && fmt->len < fmt->cap)
		fmt->buf[fmt->len] = c;

	if (c == '\n')
		fmt->col = 0;
	else
		fmt->col ++;

	fmt->len ++;

	fmt->last = c;
}

static inline void fmt_indent(fz_context *ctx, struct fmt *fmt)
{
	int i = fmt->indent;
	while (i--) {
		fmt_putc(ctx, fmt, ' ');
		fmt_putc(ctx, fmt, ' ');
	}
}

static inline void fmt_puts(fz_context *ctx, struct fmt *fmt, char *s)
{
	while (*s)
		fmt_putc(ctx, fmt, *s++);
}

static inline void fmt_sep(fz_context *ctx, struct fmt *fmt)
{
	fmt->sep = 1;
}

static void fmt_str(fz_context *ctx, struct fmt *fmt, pdf_obj *obj)
{
	char *s = pdf_to_str_buf(ctx, obj);
	int n = pdf_to_str_len(ctx, obj);
	int i, c;

	fmt_putc(ctx, fmt, '(');
	for (i = 0; i < n; i++)
	{
		c = (unsigned char)s[i];
		if (c == '\n')
			fmt_puts(ctx, fmt, "\\n");
		else if (c == '\r')
			fmt_puts(ctx, fmt, "\\r");
		else if (c == '\t')
			fmt_puts(ctx, fmt, "\\t");
		else if (c == '\b')
			fmt_puts(ctx, fmt, "\\b");
		else if (c == '\f')
			fmt_puts(ctx, fmt, "\\f");
		else if (c == '(')
			fmt_puts(ctx, fmt, "\\(");
		else if (c == ')')
			fmt_puts(ctx, fmt, "\\)");
		else if (c == '\\')
			fmt_puts(ctx, fmt, "\\\\");
		else if (c < 32 || c >= 127) {
			fmt_putc(ctx, fmt, '\\');
			fmt_putc(ctx, fmt, '0' + ((c / 64) & 7));
			fmt_putc(ctx, fmt, '0' + ((c / 8) & 7));
			fmt_putc(ctx, fmt, '0' + ((c) & 7));
		}
		else
			fmt_putc(ctx, fmt, c);
	}
	fmt_putc(ctx, fmt, ')');
}

static void fmt_hex(fz_context *ctx, struct fmt *fmt, pdf_obj *obj)
{
	char *s = pdf_to_str_buf(ctx, obj);
	int n = pdf_to_str_len(ctx, obj);
	int i, b, c;

	fmt_putc(ctx, fmt, '<');
	for (i = 0; i < n; i++) {
		b = (unsigned char) s[i];
		c = (b >> 4) & 0x0f;
		fmt_putc(ctx, fmt, c < 0xA ? c + '0' : c + 'A' - 0xA);
		c = (b) & 0x0f;
		fmt_putc(ctx, fmt, c < 0xA ? c + '0' : c + 'A' - 0xA);
	}
	fmt_putc(ctx, fmt, '>');
}

static void fmt_name(fz_context *ctx, struct fmt *fmt, pdf_obj *obj)
{
	unsigned char *s = (unsigned char *) pdf_to_name(ctx, obj);
	int i, c;

	fmt_putc(ctx, fmt, '/');

	for (i = 0; s[i]; i++)
	{
		if (isdelim(s[i]) || iswhite(s[i]) ||
			s[i] == '#' || s[i] < 32 || s[i] >= 127)
		{
			fmt_putc(ctx, fmt, '#');
			c = (s[i] >> 4) & 0xf;
			fmt_putc(ctx, fmt, c < 0xA ? c + '0' : c + 'A' - 0xA);
			c = s[i] & 0xf;
			fmt_putc(ctx, fmt, c < 0xA ? c + '0' : c + 'A' - 0xA);
		}
		else
		{
			fmt_putc(ctx, fmt, s[i]);
		}
	}
}

static void fmt_array(fz_context *ctx, struct fmt *fmt, pdf_obj *obj)
{
	int i, n;

	n = pdf_array_len(ctx, obj);
	if (fmt->tight) {
		fmt_putc(ctx, fmt, '[');
		for (i = 0; i < n; i++) {
			fmt_obj(ctx, fmt, pdf_array_get(ctx, obj, i));
			fmt_sep(ctx, fmt);
		}
		fmt_putc(ctx, fmt, ']');
	}
	else {
		fmt_puts(ctx, fmt, "[ ");
		for (i = 0; i < n; i++) {
			if (fmt->col > 60) {
				fmt_putc(ctx, fmt, '\n');
				fmt_indent(ctx, fmt);
			}
			fmt_obj(ctx, fmt, pdf_array_get(ctx, obj, i));
			fmt_putc(ctx, fmt, ' ');
		}
		fmt_putc(ctx, fmt, ']');
		fmt_sep(ctx, fmt);
	}
}

static void fmt_dict(fz_context *ctx, struct fmt *fmt, pdf_obj *obj)
{
	int i, n;
	pdf_obj *key, *val;

	n = pdf_dict_len(ctx, obj);
	if (fmt->tight) {
		fmt_puts(ctx, fmt, "<<");
		for (i = 0; i < n; i++) {
			fmt_obj(ctx, fmt, pdf_dict_get_key(ctx, obj, i));
			fmt_sep(ctx, fmt);
			fmt_obj(ctx, fmt, pdf_dict_get_val(ctx, obj, i));
			fmt_sep(ctx, fmt);
		}
		fmt_puts(ctx, fmt, ">>");
	}
	else {
		fmt_puts(ctx, fmt, "<<\n");
		fmt->indent ++;
		for (i = 0; i < n; i++) {
			key = pdf_dict_get_key(ctx, obj, i);
			val = pdf_dict_get_val(ctx, obj, i);
			fmt_indent(ctx, fmt);
			fmt_obj(ctx, fmt, key);
			fmt_putc(ctx, fmt, ' ');
			if (!pdf_is_indirect(ctx, val) && pdf_is_array(ctx, val))
				fmt->indent ++;
			fmt_obj(ctx, fmt, val);
			fmt_putc(ctx, fmt, '\n');
			if (!pdf_is_indirect(ctx, val) && pdf_is_array(ctx, val))
				fmt->indent --;
		}
		fmt->indent --;
		fmt_indent(ctx, fmt);
		fmt_puts(ctx, fmt, ">>");
	}
}

static void fmt_obj(fz_context *ctx, struct fmt *fmt, pdf_obj *obj)
{
	char buf[256];

	if (!obj)
		fmt_puts(ctx, fmt, "<NULL>");
	else if (pdf_is_indirect(ctx, obj))
	{
		fz_snprintf(buf, sizeof buf, "%d %d R", pdf_to_num(ctx, obj), pdf_to_gen(ctx, obj));
		fmt_puts(ctx, fmt, buf);
	}
	else if (pdf_is_null(ctx, obj))
		fmt_puts(ctx, fmt, "null");
	else if (pdf_is_bool(ctx, obj))
		fmt_puts(ctx, fmt, pdf_to_bool(ctx, obj) ? "true" : "false");
	else if (pdf_is_int(ctx, obj))
	{
		fz_snprintf(buf, sizeof buf, "%d", pdf_to_int(ctx, obj));
		fmt_puts(ctx, fmt, buf);
	}
	else if (pdf_is_real(ctx, obj))
	{
		fz_snprintf(buf, sizeof buf, "%g", pdf_to_real(ctx, obj));
		fmt_puts(ctx, fmt, buf);
	}
	else if (pdf_is_string(ctx, obj))
	{
		char *str = pdf_to_str_buf(ctx, obj);
		int len = pdf_to_str_len(ctx, obj);
		int added = 0;
		int i, c;
		for (i = 0; i < len; i++) {
			c = (unsigned char)str[i];
			if (c != 0 && strchr("()\\\n\r\t\b\f", c))
				added ++;
			else if (c < 32 || c >= 127)
				added += 3;
		}
		if (added < len)
			fmt_str(ctx, fmt, obj);
		else
			fmt_hex(ctx, fmt, obj);
	}
	else if (pdf_is_name(ctx, obj))
		fmt_name(ctx, fmt, obj);
	else if (pdf_is_array(ctx, obj))
		fmt_array(ctx, fmt, obj);
	else if (pdf_is_dict(ctx, obj))
		fmt_dict(ctx, fmt, obj);
	else
		fmt_puts(ctx, fmt, "<unknown object>");
}

int
pdf_sprint_obj(fz_context *ctx, char *s, int n, pdf_obj *obj, int tight)
{
	struct fmt fmt;

	fmt.indent = 0;
	fmt.col = 0;
	fmt.sep = 0;
	fmt.last = 0;

	fmt.tight = tight;
	fmt.buf = s;
	fmt.cap = n;
	fmt.len = 0;
	fmt_obj(ctx, &fmt, obj);

	if (fmt.buf && fmt.len < fmt.cap)
		fmt.buf[fmt.len] = '\0';

	return fmt.len;
}

int
pdf_fprint_obj(fz_context *ctx, FILE *fp, pdf_obj *obj, int tight)
{
	char buf[1024];
	char *ptr;
	int n;

	n = pdf_sprint_obj(ctx, NULL, 0, obj, tight);
	if ((n + 1) < sizeof buf)
	{
		pdf_sprint_obj(ctx, buf, sizeof buf, obj, tight);
		fputs(buf, fp);
		fputc('\n', fp);
	}
	else
	{
		ptr = fz_malloc(ctx, n + 1);
		pdf_sprint_obj(ctx, ptr, n + 1, obj, tight);
		fputs(ptr, fp);
		fputc('\n', fp);
		fz_free(ctx, ptr);
	}
	return n;
}

int pdf_output_obj(fz_context *ctx, fz_output *out, pdf_obj *obj, int tight)
{
	char buf[1024];
	char *ptr;
	int n;

	n = pdf_sprint_obj(ctx, NULL, 0, obj, tight);
	if ((n + 1) < sizeof buf)
	{
		pdf_sprint_obj(ctx, buf, sizeof buf, obj, tight);
		fz_puts(ctx, out, buf);
	}
	else
	{
		ptr = fz_malloc(ctx, n + 1);
		pdf_sprint_obj(ctx, ptr, n + 1, obj, tight);
		fz_puts(ctx, out, buf);
		fz_free(ctx, ptr);
	}
	return n;
}

#ifndef NDEBUG
void
pdf_print_obj(fz_context *ctx, pdf_obj *obj)
{
	pdf_fprint_obj(ctx, stdout, obj, 0);
}

void
pdf_print_ref(fz_context *ctx, pdf_obj *ref)
{
	pdf_print_obj(ctx, pdf_resolve_indirect(ctx, ref));
}
#endif

int pdf_obj_refs(fz_context *ctx, pdf_obj *ref)
{
	return (ref >= PDF_OBJ__LIMIT ? ref->refs : 0);
}
