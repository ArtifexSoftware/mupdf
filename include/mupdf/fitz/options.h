// Copyright (C) 2025 Artifex Software, Inc.
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

#ifndef MUPDF_FITZ_OPTIONS_H
#define MUPDF_FITZ_OPTIONS_H

#include "mupdf/fitz/context.h"

/**
	An fz_options structure encapsulates a list of key, or
	key=value options, together with details such as whether
	they have been used or not.
*/
typedef struct fz_options fz_options;

/**
	Parse an option_string, and make an fz_options object from it.

	option_string can permissibly be NULL, and a non-NULL options
	struct will be returned.
*/
fz_options *fz_new_options_from_string(fz_context *ctx, const char *option_string);

/**
	Parse more options from an options string, and add them to
	an existing fz_options object.
*/
void fz_add_options_from_string(fz_context *ctx, fz_options *options, const char *option_string);

/**
	Take a new reference to the options struct.
*/
fz_options *fz_keep_options(fz_context *ctx, fz_options *opts);

/**
	Drop an fz_options object.
*/
void fz_drop_options(fz_context *ctx, fz_options *opts);

/**
	Check to see if a key is present in the options object.

	If it is not, then return 0.

	If val is non-NULL, *val will be updated to point to the value.

	The option will be recorded as having been accessed.
*/
int fz_options_has_key(fz_context *ctx, fz_options *options, const char *key, const char **val);

/**
	Check to see if a key is present, and is true.

	"no", "false", "0", "disabled" all count as false.
	Everything else counts as true.
*/
int fz_options_has_true_key(fz_context *ctx, fz_options *options, const char *key);

/**
	Check to see if a key is present, and is boolean.

	"no", "false", "0", "disabled" all count as false.
	"yes", "true", "1", "enabled " or nothing specified all count as true.

	Everything else counts as not being present.
*/
int fz_options_has_bool_key(fz_context *ctx, fz_options *options, const char *key, int *b);

/**
	If any options are set but not used, warn on them.
*/
void fz_warn_on_unused_options(fz_context *ctx, fz_options *options);

/**
	Count the number of options in an options structure.
*/
int fz_count_options(fz_context *ctx, fz_options *options);

/**
	Get an option by index.
*/
const char *fz_get_option(fz_context *ctx, fz_options *options, int i, const char **val);

/**
	Mark a given option index as being accessed.
*/
void fz_access_option(fz_context *ctx, fz_options *options, int i);

/**
	Implementation details: subject to change. Only public for
	SWIG built wrappers.
*/

typedef struct
{
	int flags;
	char *val;
	char key[FZ_FLEXIBLE_ARRAY];
} fz_option;

struct fz_options {
	int refs;
	int max;
	int len;
	fz_option **opts;
};

#endif
