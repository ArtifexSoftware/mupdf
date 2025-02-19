// Copyright (C) 2004-2025 Artifex Software, Inc.
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
// Artifex Software, Inc., 39 Mesa Street, Suite 108A, San Francisco,
// CA 94129, USA, for further information.

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

typedef struct pdf_object_labels pdf_object_labels;
typedef struct pdf_object_label_node pdf_object_label_node;

struct pdf_object_label_node
{
	int num;
	char *path;
	pdf_object_label_node *next;
};

struct pdf_object_labels
{
	fz_pool *pool;
	int object_count;
	int root, info, encrypt;
	unsigned short *pages;
	char *seen;
	pdf_object_label_node **nodes;
};

static void
add_object_label(fz_context *ctx, pdf_object_labels *g, char *path, int a, int b)
{
	pdf_object_label_node *node, **root;

	node = fz_pool_alloc(ctx, g->pool, sizeof(pdf_object_label_node));
	node->path = fz_pool_strdup(ctx, g->pool, path);
	node->num = b;

	root = &g->nodes[a];
	node->next = *root;
	*root = node;
}

static void
scan_object_label_rec(fz_context *ctx, pdf_object_labels *g, char *root_path, pdf_obj *obj, int top)
{
	char path[100];
	int i, n;
	if (pdf_is_indirect(ctx, obj))
		;
	else if (pdf_is_dict(ctx, obj))
	{
		n = pdf_dict_len(ctx, obj);
		for (i = 0; i < n; ++i)
		{
			pdf_obj *key = pdf_dict_get_key(ctx, obj, i);
			pdf_obj *val = pdf_dict_get_val(ctx, obj, i);
			if (val && key != PDF_NAME(Parent) && key != PDF_NAME(P) && key != PDF_NAME(Prev) && key != PDF_NAME(Last))
			{
				if (pdf_is_indirect(ctx, val))
				{
					fz_snprintf(path, sizeof path, "%s/%s", root_path, pdf_to_name(ctx, key));
					add_object_label(ctx, g, path, pdf_to_num(ctx, val), top);
				}
				else if (pdf_is_dict(ctx, val) || pdf_is_array(ctx, val))
				{
					fz_snprintf(path, sizeof path, "%s/%s", root_path, pdf_to_name(ctx, key));
					scan_object_label_rec(ctx, g, path, val, top);
				}
			}
		}
	}
	else if (pdf_is_array(ctx, obj))
	{
		n = pdf_array_len(ctx, obj);
		for (i = 0; i < n; ++i)
		{
			pdf_obj *val = pdf_array_get(ctx, obj, i);
			if (val)
			{
				if (pdf_is_indirect(ctx, val))
				{
					fz_snprintf(path, sizeof path, "%s/%d", root_path, i+1);
					add_object_label(ctx, g, path, pdf_to_num(ctx, val), top);
				}
				else if (pdf_is_dict(ctx, val) || pdf_is_array(ctx, val))
				{
					fz_snprintf(path, sizeof path, "%s/%d", root_path, i+1);
					scan_object_label_rec(ctx, g, path, val, top);
				}
			}
		}
	}
}

static void
scan_object_label(fz_context *ctx, pdf_document *doc, pdf_object_labels *g, int num)
{
	pdf_obj *obj = pdf_load_object(ctx, doc, num);
	fz_try(ctx)
		scan_object_label_rec(ctx, g, "", obj, num);
	fz_always(ctx)
		pdf_drop_obj(ctx, obj);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

pdf_object_labels *
pdf_load_object_labels(fz_context *ctx, pdf_document *doc)
{
	pdf_object_labels *g = NULL;
	fz_pool *pool;
	int i, n, page_count;

	n = pdf_count_objects(ctx, doc);

	pool = fz_new_pool(ctx);
	fz_try(ctx)
	{
		g = fz_pool_alloc(ctx, pool, sizeof(pdf_object_labels));
		g->pool = pool;
		g->object_count = n;
		g->root = pdf_to_num(ctx, pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME(Root)));
		g->info = pdf_to_num(ctx, pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME(Info)));
		g->encrypt = pdf_to_num(ctx, pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME(Encrypt)));
		g->seen = fz_pool_alloc(ctx, pool, n);
		g->nodes = fz_pool_alloc(ctx, pool, g->object_count * sizeof(pdf_object_label_node*));
		g->pages = fz_pool_alloc(ctx, pool, g->object_count * sizeof(unsigned short));

		page_count = pdf_count_pages(ctx, doc);
		for (i = 0; i < page_count; ++i)
			g->pages[pdf_to_num(ctx, pdf_lookup_page_obj(ctx, doc, i))] = i+1;

		for (i = 1; i < n; ++i)
			scan_object_label(ctx, doc, g, i);
	}
	fz_catch(ctx)
	{
		fz_drop_pool(ctx, pool);
	}
	return g;
}

void
pdf_drop_object_labels(fz_context *ctx, pdf_object_labels *g)
{
	if (g)
		fz_drop_pool(ctx, g->pool);
}

static void
find_paths(fz_context *ctx, pdf_object_labels *g, int here, char *leaf_path, pdf_label_object_fn *callback, void *arg)
{
	char path[100];
	pdf_object_label_node *node;
	int next;
	if (here == g->root)
	{
		fz_snprintf(path, sizeof path, "trailer/Root%s", leaf_path);
		callback(ctx, arg, path);
		return;
	}
	if (here == g->info)
	{
		fz_snprintf(path, sizeof path, "trailer/Info%s", leaf_path);
		callback(ctx, arg, path);
		return;
	}
	if (here == g->encrypt)
	{
		fz_snprintf(path, sizeof path, "trailer/Encrypt%s", leaf_path);
		callback(ctx, arg, path);
		return;
	}
	if (g->pages[here])
	{
		fz_snprintf(path, sizeof path, "pages/%d%s", g->pages[here], leaf_path);
		callback(ctx, arg, path);
	}
	for (node = g->nodes[here]; node; node = node->next)
	{
		next = node->num;
		if (next < 1 || next >= g->object_count)
			continue;
		if (g->seen[next])
			continue;
		if (g->pages[next])
		{
			fz_snprintf(path, sizeof path, "pages/%d%s%s", g->pages[next], node->path, leaf_path);
			callback(ctx, arg, path);
		}
		else
		{
			g->seen[next] = 1;
			// if we can't fit "trailer/Root" prefix then stop searching and truncate the path
			if (fz_snprintf(path, sizeof path, "%s%s", node->path, leaf_path) < (sizeof path) - 13) {
				find_paths(ctx, g, next, path, callback, arg);
			} else {
				fz_snprintf(path, sizeof path, "...%s", leaf_path);
				callback(ctx, arg, path);
			}
			g->seen[next] = 0;
		}
	}
}

void
pdf_label_object(fz_context *ctx, pdf_object_labels *g, int num, pdf_label_object_fn *callback, void *arg)
{
	int i;
	if (num < 1 || num >= g->object_count)
		return;
	for (i = 1; i < g->object_count; ++i)
		g->seen[i] = 0;
	find_paths(ctx, g, num, "", callback, arg);
}
