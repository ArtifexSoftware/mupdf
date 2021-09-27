// Copyright (C) 2004-2021 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 1305 Grant Avenue - Suite 200, Novato,
// CA 94945, U.S.A., +1(415)492-9861, for further information.

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

static void
pdf_test_outline(fz_context *ctx, pdf_document *doc, pdf_obj *dict, pdf_obj *mark_list, pdf_obj *parent)
{
	pdf_obj *obj, *prev = NULL;

	while (dict && pdf_is_dict(ctx, dict))
	{
		if (pdf_mark_obj(ctx, dict))
			fz_throw(ctx, FZ_ERROR_GENERIC, "Cycle detected in outlines");
		pdf_array_push(ctx, mark_list, dict);

		obj = pdf_dict_get(ctx, dict, PDF_NAME(Prev));
		if (pdf_objcmp(ctx, prev, obj))
			fz_throw(ctx, FZ_ERROR_GENERIC, "Bad or missing pointer in outline tree");
		prev = dict;

		obj = pdf_dict_get(ctx, dict, PDF_NAME(Parent));
		if (pdf_objcmp(ctx, parent, obj))
			fz_throw(ctx, FZ_ERROR_GENERIC, "Bad or missing parent pointer in outline tree");

		obj = pdf_dict_get(ctx, dict, PDF_NAME(First));
		if (obj)
			pdf_test_outline(ctx, doc, obj, mark_list, dict);

		dict = pdf_dict_get(ctx, dict, PDF_NAME(Next));
	}
}

fz_outline *
pdf_load_outline(fz_context *ctx, pdf_document *doc)
{
	/* Just appeal to the fz_ level. */
	return fz_load_outline(ctx, (fz_document *)doc);
}

enum {
	MOD_NONE = 0,
	MOD_BELOW = 1,
	MOD_AFTER = 2
};

typedef struct pdf_outline_iterator {
	fz_outline_iterator super;
	fz_outline_item item;
	pdf_obj *current;
	int modifier;
} pdf_outline_iterator;

static int
pdf_outline_iterator_next(fz_context *ctx, fz_outline_iterator *iter_)
{
	pdf_outline_iterator *iter = (pdf_outline_iterator *)iter_;
	pdf_obj *next;

	if (iter->modifier != MOD_NONE)
		return -1;
	next = pdf_dict_get(ctx, iter->current, PDF_NAME(Next));
	if (next == NULL)
	{
		iter->modifier = MOD_AFTER;
		return 1;
	}

	iter->modifier = MOD_NONE;
	iter->current = next;
	return 0;
}

static int
pdf_outline_iterator_prev(fz_context *ctx, fz_outline_iterator *iter_)
{
	pdf_outline_iterator *iter = (pdf_outline_iterator *)iter_;
	pdf_obj *prev;

	if (iter->modifier == MOD_BELOW)
		return -1;
	if (iter->modifier == MOD_AFTER)
	{
		iter->modifier = MOD_NONE;
		return 0;
	}
	prev = pdf_dict_get(ctx, iter->current, PDF_NAME(Prev));
	if (prev == NULL)
		return -1;

	iter->modifier = MOD_NONE;
	iter->current = prev;
	return 0;
}

static int
pdf_outline_iterator_up(fz_context *ctx, fz_outline_iterator *iter_)
{
	pdf_outline_iterator *iter = (pdf_outline_iterator *)iter_;
	pdf_obj *up;

	if (iter->modifier == MOD_BELOW)
	{
		iter->modifier = MOD_NONE;
		return 0;
	}
	up = pdf_dict_get(ctx, iter->current, PDF_NAME(Parent));
	if (up == NULL)
		return -1;

	iter->modifier = MOD_NONE;
	iter->current = up;
	return 0;
}

static int
pdf_outline_iterator_down(fz_context *ctx, fz_outline_iterator *iter_)
{
	pdf_outline_iterator *iter = (pdf_outline_iterator *)iter_;
	pdf_obj *down;

	if (iter->modifier != MOD_NONE)
		return -1;
	down = pdf_dict_get(ctx, iter->current, PDF_NAME(First));
	if (down == NULL)
	{
		iter->modifier = MOD_BELOW;
		return 1;
	}

	iter->modifier = MOD_NONE;
	iter->current = down;
	return 0;
}

static void
do_outline_update(fz_context *ctx, pdf_obj *obj, fz_outline_item *item, int is_new_node)
{
	int count;
	int open_delta = 0;
	pdf_obj *parent, *up;

	/* If the open/closed state changes, update. */
	count = pdf_dict_get_int(ctx, obj, PDF_NAME(Count));
	if ((count < 0 && item->is_open) || (count > 0 && !item->is_open))
	{
		pdf_dict_put_int(ctx, obj, PDF_NAME(Count), -count);
		open_delta = -count;
	}
	else if (is_new_node && item->is_open)
		open_delta = 1;

	up = obj;
	while ((parent = pdf_dict_get(ctx, up, PDF_NAME(Parent))) != NULL)
	{
		pdf_obj *cobj = pdf_dict_get(ctx, up, PDF_NAME(Count));
		count = pdf_to_int(ctx, cobj);
		if (open_delta || cobj == NULL)
			pdf_dict_put_int(ctx, up, PDF_NAME(Count), count > 0 ? count + open_delta : count - open_delta);
		up = parent;
	}

	if (item->title)
		pdf_dict_put_text_string(ctx, obj, PDF_NAME(Title), item->title);
	else
		pdf_dict_del(ctx, obj, PDF_NAME(Title));

	pdf_dict_del(ctx, obj, PDF_NAME(A));
	pdf_dict_del(ctx, obj, PDF_NAME(Dest));
	if (item->uri)
	{
		pdf_document *doc = pdf_get_bound_document(ctx, obj);

		if (fz_is_external_link(ctx, item->uri))
		{
			pdf_obj *a = pdf_dict_put_dict(ctx, obj, PDF_NAME(A), 4);
			pdf_dict_put(ctx, a, PDF_NAME(Type), PDF_NAME(Action));
			pdf_dict_put(ctx, a, PDF_NAME(S), PDF_NAME(URI));
			pdf_dict_put_text_string(ctx, a, PDF_NAME(URI), item->uri);
		}
		else
		{
			float x = -1, y = -1;
			int page = pdf_resolve_link(ctx, doc, item->uri, &x, &y);
			pdf_obj *arr = pdf_dict_put_array(ctx, obj, PDF_NAME(Dest), 4);
			pdf_array_push(ctx, arr, pdf_lookup_page_obj(ctx, doc, page));
			if (x == -1 && y == -1)
				pdf_array_push(ctx, arr, PDF_NAME(Fit));
			else
			{
				pdf_array_push(ctx, arr, PDF_NAME(XYZ));
				pdf_array_push_int(ctx, arr, x);
				pdf_array_push_int(ctx, arr, y);
				pdf_array_push_int(ctx, arr, 0);
			}
		}
	}
}

static int
pdf_outline_iterator_insert(fz_context *ctx, fz_outline_iterator *iter_, fz_outline_item *item)
{
	pdf_outline_iterator *iter = (pdf_outline_iterator *)iter_;
	pdf_document *doc = (pdf_document *)iter->super.doc;
	pdf_obj *obj;
	pdf_obj *prev;
	pdf_obj *parent;
	int result;

	obj = pdf_add_new_dict(ctx, doc, 4);
	fz_try(ctx)
	{
		if (iter->modifier == MOD_BELOW)
			parent = iter->current;
		else if (iter->modifier == MOD_NONE && iter->current == NULL)
		{
			pdf_obj *outlines, *root;
			root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME(Root));
			outlines = pdf_dict_get(ctx, root, PDF_NAME(Outlines));
			if (outlines == NULL)
			{
				/* No outlines entry, better make one. */
				outlines = pdf_dict_put_dict(ctx, root, PDF_NAME(Outlines), 4);
				pdf_dict_put(ctx, outlines, PDF_NAME(Type), PDF_NAME(Outlines));
			}
			iter->modifier = MOD_BELOW;
			iter->current = outlines;
			parent = outlines;
		}
		else
			parent = pdf_dict_get(ctx, iter->current, PDF_NAME(Parent));

		pdf_dict_put(ctx, obj, PDF_NAME(Parent), parent);

		do_outline_update(ctx, obj, item, 1);

		switch (iter->modifier)
		{
		case MOD_BELOW:
			pdf_dict_put(ctx, iter->current, PDF_NAME(First), obj);
			pdf_dict_put(ctx, iter->current, PDF_NAME(Last), obj);
			iter->current = obj;
			iter->modifier = MOD_AFTER;
			result = 1;
			break;
		case MOD_AFTER:
			pdf_dict_put(ctx, obj, PDF_NAME(Prev), iter->current);
			pdf_dict_put(ctx, iter->current, PDF_NAME(Next), obj);
			pdf_dict_put(ctx, parent, PDF_NAME(Last), obj);
			iter->current = obj;
			result = 1;
			break;
		default:
			prev = pdf_dict_get(ctx, iter->current, PDF_NAME(Prev));
			if (prev)
			{
				pdf_dict_put(ctx, prev, PDF_NAME(Next), obj);
				pdf_dict_put(ctx, obj, PDF_NAME(Prev), prev);
			}
			pdf_dict_put(ctx, iter->current, PDF_NAME(Prev), obj);
			pdf_dict_put(ctx, obj, PDF_NAME(Next), iter->current);
			result = 0;
			break;
		}
	}
	fz_always(ctx)
		pdf_drop_obj(ctx, obj);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return result;
}

static void
pdf_outline_iterator_update(fz_context *ctx, fz_outline_iterator *iter_, fz_outline_item *item)
{
	pdf_outline_iterator *iter = (pdf_outline_iterator *)iter_;

	if (iter->modifier != MOD_NONE || iter->current == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Can't update a non-existent outline item!");

	do_outline_update(ctx, iter->current, item, 0);
}

static int
pdf_outline_iterator_del(fz_context *ctx, fz_outline_iterator *iter_)
{
	pdf_outline_iterator *iter = (pdf_outline_iterator *)iter_;
	pdf_obj *next, *prev, *parent;
	int count;

	if (iter->modifier != MOD_NONE)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Can't delete a non-existent outline item!");

	prev = pdf_dict_get(ctx, iter->current, PDF_NAME(Prev));
	next = pdf_dict_get(ctx, iter->current, PDF_NAME(Next));
	parent = pdf_dict_get(ctx, iter->current, PDF_NAME(Parent));
	count = pdf_dict_get_int(ctx, iter->current, PDF_NAME(Count));

	if (count > 0)
	{
		pdf_obj *up = parent;
		while (up)
		{
			int c = pdf_dict_get_int(ctx, up, PDF_NAME(Count));
			pdf_dict_put_int(ctx, up, PDF_NAME(Count), (c > 0 ? c - count : c + count));
			up = pdf_dict_get(ctx, up, PDF_NAME(Parent));
		}
	}

	if (prev)
	{
		if (next)
			pdf_dict_put(ctx, prev, PDF_NAME(Next), next);
		else
			pdf_dict_del(ctx, prev, PDF_NAME(Next));
	}
	if (next)
	{
		if (prev)
			pdf_dict_put(ctx, next, PDF_NAME(Prev), prev);
		else
			pdf_dict_del(ctx, next, PDF_NAME(Prev));
		iter->current = next;
	}
	else if (prev)
	{
		iter->current = prev;
		pdf_dict_put(ctx, parent, PDF_NAME(Last), prev);
	}
	else
	{
		iter->current = parent;
		iter->modifier = MOD_BELOW;
		pdf_dict_del(ctx, parent, PDF_NAME(First));
		pdf_dict_del(ctx, parent, PDF_NAME(Last));
	}

	return 0;
}

static fz_outline_item *
pdf_outline_iterator_item(fz_context *ctx, fz_outline_iterator *iter_)
{
	pdf_outline_iterator *iter = (pdf_outline_iterator *)iter_;
	pdf_obj *obj;
	pdf_document *doc = (pdf_document *)iter->super.doc;

	if (iter->modifier != MOD_NONE || iter->current == NULL)
		return NULL;

	fz_free(ctx, iter->item.title);
	iter->item.title = NULL;
	fz_free(ctx, iter->item.uri);
	iter->item.uri = NULL;

	obj = pdf_dict_get(ctx, iter->current, PDF_NAME(Title));
	if (obj)
		iter->item.title = Memento_label(fz_strdup(ctx, pdf_to_text_string(ctx, obj)), "outline_title");
	obj = pdf_dict_get(ctx, iter->current, PDF_NAME(Dest));
	if (obj)
		iter->item.uri = Memento_label(fz_strdup(ctx, pdf_parse_link_dest(ctx, doc, obj)), "outline_uri");
	else
	{
		obj = pdf_dict_get(ctx, iter->current, PDF_NAME(A));
		if (obj)
			iter->item.uri = Memento_label(fz_strdup(ctx, pdf_parse_link_action(ctx, doc, obj, -1)), "outline_uri");
	}

	obj = pdf_dict_get(ctx, iter->current, PDF_NAME(Count));

	iter->item.is_open = (pdf_to_int(ctx, obj) > 0);

	return &iter->item;
}

static void
pdf_outline_iterator_drop(fz_context *ctx, fz_outline_iterator *iter_)
{
	pdf_outline_iterator *iter = (pdf_outline_iterator *)iter_;

	if (iter == NULL)
		return;

	fz_free(ctx, iter->item.title);
	fz_free(ctx, iter->item.uri);
}

fz_outline_iterator *pdf_new_outline_iterator(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *root, *obj, *first, *mark_list;
	pdf_outline_iterator *iter = NULL;
	int i;

	/* Walk the outlines to spot problems that might bite us later
	 * (in particular, for cycles). */
	mark_list = pdf_new_array(ctx, doc, 100);
	fz_try(ctx)
	{
		root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME(Root));
		obj = pdf_dict_get(ctx, root, PDF_NAME(Outlines));
		first = pdf_dict_get(ctx, obj, PDF_NAME(First));
		if (first)
		{
			/* cache page tree for fast link destination lookups */
			pdf_load_page_tree(ctx, doc);
			fz_try(ctx)
				pdf_test_outline(ctx, doc, first, mark_list, obj);
			fz_always(ctx)
				pdf_drop_page_tree(ctx, doc);
			fz_catch(ctx)
				fz_rethrow(ctx);
		}
	}
	fz_always(ctx)
	{
		int len = pdf_array_len(ctx, mark_list);
		for (i = 0; i < len; ++i)
			pdf_unmark_obj(ctx, pdf_array_get(ctx, mark_list, i));
		pdf_drop_obj(ctx, mark_list);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	iter = fz_new_derived_outline_iter(ctx, pdf_outline_iterator, &doc->super);
	iter->super.del = pdf_outline_iterator_del;
	iter->super.next = pdf_outline_iterator_next;
	iter->super.prev = pdf_outline_iterator_prev;
	iter->super.up = pdf_outline_iterator_up;
	iter->super.down = pdf_outline_iterator_down;
	iter->super.insert = pdf_outline_iterator_insert;
	iter->super.update = pdf_outline_iterator_update;
	iter->super.drop = pdf_outline_iterator_drop;
	iter->super.item = pdf_outline_iterator_item;
	iter->current = first;
	iter->modifier = MOD_NONE;

	return &iter->super;
}
