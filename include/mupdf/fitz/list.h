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

#ifndef MUPDF_FITZ_LIST_H
#define MUPDF_FITZ_LIST_H

#include "mupdf/fitz/context.h"

/*
	These functions implement generic lists. They rely on
	3 variables, sharing a common root. The trick that these
	macros rely on, is that the naming of these different
	variables is standard.

	int foo_cap;
	int foo_len;
	<some type *>foo

	These can be local variables, or members of a struct.

	In all the functions below, we pass foo (or 'bar->foo',
	or 'bar.foo' etc), and foo_cap and foo_len are found by
	C preprocessor extending the name of the list.
*/

/*
	A macro to prettily instantiate a list.

	Declare a list of entries of type 'TYPE' referred to by
	'NAME'.
*/
#define fz_list(TYPE, NAME) \
	int NAME##_cap; int NAME##_len; TYPE *NAME

/*
	Push a new element onto a given list.

	Returns a pointer to the new element.
*/
#define fz_push_list(CTX, ELEM) \
	fz_push_list_init(CTX, ELEM, 32)

/*
	Push a new element onto a list, with a suggested
	initial size for the list.

	Returns a pointer to the new element.
*/
#define fz_push_list_init(CTX, ELEM, INITIAL) \
	fz_push_list_imp(CTX, (void **)&((ELEM)), &(ELEM##_len), &(ELEM##_cap), sizeof(*(ELEM)), (INITIAL))

/*
	Push n new elements onto a list.

	Returns a pointer to the first new element.
*/
#define fz_extend_list(CTX, ELEM, N) \
	fz_extend_list_init(CTX, ELEM, N, 32)

/*
	Push n new elements onto a list, with a suggested
	initial size.

	Returns a pointer to the first new element.
*/
#define fz_extend_list_init(CTX, ELEM, N, INITIAL) \
	fz_extend_list_imp(CTX, (void **)&((ELEM)), &(ELEM##_len), &(ELEM##_cap), sizeof(*(ELEM)), (N), (INITIAL))

/*
	Push n new elements onto a list, never growing the
	list further than it needs to be.

	Returns a pointer to the first new element.
*/
#define fz_extend_list_tight(CTX, ELEM, N) \
	fz_extend_list_tight_imp(CTX, (void **)&((ELEM)), &(ELEM##_len), &(ELEM##_cap), sizeof(*(ELEM)), (N))

/*
	Trim the storage for a list to remove any excess.
*/
#define fz_trim_list(CTX, ELEM) \
	fz_trim_list_imp(CTX, (void **)&((ELEM)), (ELEM##_len), &(ELEM##_cap), sizeof(*(ELEM)))

/*
	Functions used to implement the above macros.
*/
void *fz_push_list_imp(fz_context *ctx, void **list, int *list_len, int *list_cap, size_t z, int initial);
void *fz_extend_list_imp(fz_context *ctx, void **list, int *list_len, int *list_cap, size_t z, int n, int initial);
void *fz_extend_list_tight_imp(fz_context *ctx, void **list, int *list_len, int *list_cap, size_t z, int n);
void fz_trim_list_imp(fz_context *ctx, void **list, int list_len, int *list_cap, size_t z);

#endif /* MUPDF_FITZ_LIST_H */
