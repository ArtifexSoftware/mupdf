// Copyright (C) 2026 Artifex Software, Inc.
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

#include <limits.h>

void *fz_push_list_imp(fz_context *ctx, void **list, int *list_len, int *list_cap, size_t item_size, int initial)
{
	int len = *list_len;
	int cap = *list_cap;
	uint8_t *p;

	if (len == cap)
	{
		int new_cap;
		if (fz_ckd_add_int(&new_cap, cap, cap))
		{
			new_cap = INT_MAX;
			if (new_cap == cap)
				fz_throw(ctx, FZ_ERROR_LIMIT, "integer overflow when appending to an array"); // Unlikely!
		}
		if (new_cap < initial)
			new_cap = initial;
		*list = Memento_label(fz_realloc_array_imp(ctx, *list, new_cap, item_size), "list");
		*list_cap = new_cap;
	}
	if (fz_ckd_add_int(&len, len, 1))
		fz_throw(ctx, FZ_ERROR_LIMIT, "integer overflow when appending to array");
	*list_len = len;
	p = ((uint8_t *)*list) + item_size * (len-1);
	/* We clear each element before we return it. It might be faster to
	 * clear the whole lot on alloc, but that doesn't allow for elements
	 * being deleted and the list shuffled outside of this routine. */
	memset(p, 0, item_size);
	return (void *)p;
}

void *fz_extend_list_imp(fz_context *ctx, void **list, int *list_len, int *list_cap, size_t item_size, int n, int initial)
{
	int len = *list_len;
	int cap = *list_cap;
	uint8_t *p;
	int new_len;

	if (fz_ckd_add_int(&new_len, len, n))
		fz_throw(ctx, FZ_ERROR_LIMIT, "integer overflow when expanding array");

	if (new_len > cap)
	{
		int new_cap;
		if (fz_ckd_add_int(&new_cap, cap, cap))
		{
			new_cap = INT_MAX;
			if (new_cap == cap)
				fz_throw(ctx, FZ_ERROR_LIMIT, "integer overflow when appending to an array"); // Unlikely!
		}
		else if (new_cap < new_len)
			new_cap = new_len;
		if (new_cap < initial)
			new_cap = initial;
		*list = Memento_label(fz_realloc_array_imp(ctx, *list, new_cap, item_size), "list");
		*list_cap = new_cap;
	}
	*list_len = new_len;
	p = ((uint8_t *)*list) + item_size * len;
	/* We clear each element before we return it. It might be faster to
	 * clear the whole lot on alloc, but that doesn't allow for elements
	 * being deleted and the list shuffled outside of this routine. */
	memset(p, 0, item_size * n);
	return (void *)p;
}

void *fz_extend_list_tight_imp(fz_context *ctx, void **list, int *list_len, int *list_cap, size_t item_size, int n)
{
	int len = *list_len;
	int cap = *list_cap;
	uint8_t *p;
	int new_len;

	if (fz_ckd_add_int(&new_len, len, n))
		fz_throw(ctx, FZ_ERROR_LIMIT, "integer overflow when expanding array");

	if (new_len > cap)
	{
		*list = Memento_label(fz_realloc_array_imp(ctx, *list, new_len, item_size), "list");
		*list_cap = new_len;
	}
	*list_len = new_len;
	p = ((uint8_t *)*list) + item_size * len;
	/* We clear each element before we return it. It might be faster to
	 * clear the whole lot on alloc, but that doesn't allow for elements
	 * being deleted and the list shuffled outside of this routine. */
	memset(p, 0, item_size * n);
	return (void *)p;
}

void fz_trim_list_imp(fz_context *ctx, void **list, int list_len, int *list_cap, size_t item_size)
{
	if (*list_cap == list_len)
		return;
	*list = Memento_label(fz_realloc_array_imp(ctx, *list, list_len, item_size), "list");
	*list_cap = list_len;
}
