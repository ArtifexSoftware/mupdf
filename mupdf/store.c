#include <fitz.h>
#include <mupdf.h>

typedef struct pdf_item_s pdf_item;

struct pdf_item_s
{
    pdf_itemkind kind;
    fz_obj *key;
    void *val;
	pdf_item *next;
};

struct pdf_store_s
{
	int len;
	int cap;
	pdf_item *root;
};

fz_error *
pdf_newstore(pdf_store **storep)
{
	pdf_store *store;

	store = fz_malloc(sizeof(pdf_store));
	if (!store)
		return fz_outofmem;

	store->root = nil;

	*storep = store;
	return nil;
}

void
pdf_dropstore(pdf_store *store)
{
	/* TODO */
}

fz_error *
pdf_storeitem(pdf_store *store, pdf_itemkind kind, fz_obj *key, void *val)
{
	pdf_item *item;

	item = fz_malloc(sizeof(pdf_item));
	if (!item)
		return fz_outofmem;

	pdf_logrsrc("store item %d: %p\n", kind, val);

	item->kind = kind;
	item->key = fz_keepobj(key);
	item->val = val;	/* heh. should do *keep() here */

	item->next = store->root;
	store->root = item;
	return nil;
}

void *
pdf_finditem(pdf_store *store, pdf_itemkind kind, fz_obj *key)
{
	pdf_item *item;

	if (key == nil)
		return nil;

	for (item = store->root; item; item = item->next)
	{
		if (item->kind == kind && !fz_cmpobj(item->key, key))
		{
			pdf_logrsrc("find item %d: %p\n", kind, item->val);
			return item->val;
		}
	}

	return nil;
}

