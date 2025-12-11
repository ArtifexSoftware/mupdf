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

#include "mupdf/fitz.h"

enum
{
	ACCESSED = 1
};

static void
drop_opt(fz_context *ctx, fz_option *opt)
{
	fz_free(ctx, opt);
}

void
fz_drop_options(fz_context *ctx, fz_options *opts)
{
	if (fz_drop_imp(ctx, opts, &opts->refs))
	{
		int i;

		for (i = 0; i < opts->len; i++)
			drop_opt(ctx, opts->opts[i]);
		fz_free(ctx, opts->opts);
		fz_free(ctx, opts);
	}
}

fz_options *
fz_keep_options(fz_context *ctx, fz_options *opts)
{
	return fz_keep_imp(ctx, opts, &opts->refs);
}

static int
isws(char c)
{
	return c == 32 || c == 9 || c == 8 || c == 10 || c == 12 || c == 13;
}

static void
add_option(fz_context *ctx, fz_options *opts, const char *key_start, const char *key_end, const char *val_start, const char *val_end)
{
	size_t z = key_end - key_start + 1;
	fz_option *o;

	if (val_start != NULL)
		z += val_end - val_start + 1;

	o = fz_malloc_flexible(ctx, fz_option, key, z);

	memcpy(o->key, key_start, key_end - key_start);
	o->key[key_end - key_start] = 0;
	if (val_start)
	{
		o->val = o->key + (key_end - key_start) + 1;
		memcpy(o->val, val_start, val_end - val_start);
		o->val[val_end - val_start] = 0;
	}
	else
		o->val = NULL;

	if (opts->len == opts->max)
	{
		int newmax = opts->max * 2;
		if (newmax == 0)
			newmax = 4;
		fz_try(ctx)
		{
			opts->opts = fz_realloc(ctx, opts->opts, sizeof(opts->opts[0]) * newmax);
			opts->max = newmax;
		}
		fz_catch(ctx)
		{
			drop_opt(ctx, o);
			fz_rethrow(ctx);
		}
	}

	opts->opts[opts->len] = o;
	opts->len++;
}


void
fz_add_options_from_string(fz_context *ctx, fz_options *options, const char *option_string)
{
	const char *s;

	if (option_string == NULL)
		return;

	s = option_string;

	while (1)
	{
		const char *key_start, *key_end;
		const char *val_start = NULL;
		const char *val_end = NULL;
		/* Skip any whitespace */
		while (isws(*s))
			s++;

		/* Quit if we've hit the end. */
		if (*s == 0)
			break;

		if (*s == '=')
			fz_throw(ctx, FZ_ERROR_ARGUMENT, "Value with no Key found in options string");

		if (*s == '\"')
		{
			/* Quoted key. Weird, but we'll take it. */
			s++; /* Skip quote */
			key_start = s;
			/* Look for the end */
			while (*s && *s != '"')
				s++;
			if (*s == 0)
				fz_throw(ctx, FZ_ERROR_ARGUMENT, "Mismatched quotation in options string");
			key_end = s;
			s++; /* Skip quote */
			/* Skip whitespace */
			while (isws(*s))
				s++;
		}
		else
		{
			/* Look for the end */
			key_start = key_end = s;
			while (*s && *s != '=' && *s != ',')
			{
				if (!isws(*s))
					key_end = s+1;
				s++;
			}
		}
		if (key_start == key_end)
			fz_throw(ctx, FZ_ERROR_ARGUMENT, "Empty key found in options string");
		if (*s == '=')
		{
			s++; /* Skip '=' */
			/* Skip whitespace */
			while (isws(*s))
				s++;
			if (*s == '"')
			{
				/* Quoted value */
				s++; /* Skip quote */
				val_start = s;
				/* Look for the end */
				while (*s && *s != '"')
					s++;
				if (*s == 0)
					fz_throw(ctx, FZ_ERROR_ARGUMENT, "Mismatched quotation in options string");
				val_end = s;
				s++; /* Skip quote */
				/* Skip whitespace */
				while (isws(*s))
					s++;
			}
			else
			{
				/* Look for the end */
				val_start = val_end = s;
				while (*s && *s != '=' && *s != ',')
				{
					if (!isws(*s))
						val_end = s+1;
					s++;
				}
			}
		}
		if (val_start == val_end)
			val_start = val_end = NULL;
		add_option(ctx, options, key_start, key_end, val_start, val_end);
		if (*s == 0)
			break;
		s++; /* Skip the ',' */
	}
}

fz_options *
fz_new_options_from_string(fz_context *ctx, const char *option_string)
{
	fz_options *opts = fz_malloc_struct(ctx, fz_options);

	opts->refs = 1;

	fz_try(ctx)
	{
		fz_add_options_from_string(ctx, opts, option_string);
	}
	fz_catch(ctx)
	{
		fz_drop_options(ctx, opts);
		fz_rethrow(ctx);
	}

	return opts;
}

int
fz_options_has_key(fz_context *ctx, fz_options *options, const char *key, const char **val)
{
	int i;

	if (val)
		*val = NULL;

	if (!options)
		return 0;

	for (i = 0; i < options->len; i++)
		if (!strcmp(key, options->opts[i]->key))
		{
			if (val)
				*val = options->opts[i]->val;
			options->opts[i]->flags |= ACCESSED;
			return 1;
		}

	return 0;
}

int
fz_options_has_true_key(fz_context *ctx, fz_options *options, const char *key)
{
	char *val;

	if (!fz_options_has_key(ctx, options, key, &val))
		return 0;

	if (val == NULL)
		return 1;

	if (!strcmp(val, "0") ||
		!fz_strcasecmp(val, "false") ||
		!fz_strcasecmp(val, "no") ||
		!fz_strcasecmp(val, "disabled"))
		return 0;

	return 1;
}

int
fz_options_has_bool_key(fz_context *ctx, fz_options *options, const char *key, int *b)
{
	char *val;

	if (!fz_options_has_key(ctx, options, key, &val))
		return 0;

	if (val == NULL ||
		!strcmp(val, "1") ||
		!fz_strcasecmp(val, "true") ||
		!fz_strcasecmp(val, "yes") ||
		!fz_strcasecmp(val, "enabled"))
	{
		*b = 1;
	}
	else if (!strcmp(val, "0") ||
		!fz_strcasecmp(val, "false") ||
		!fz_strcasecmp(val, "no") ||
		!fz_strcasecmp(val, "disabled"))
	{
		*b = 0;
	}
	else
		return 0;

	return 1;
}

/**
	If any options are set but not used, warn on them.
*/
void fz_warn_on_unused_options(fz_context *ctx, fz_options *options)
{
	int i;

	if (!options)
		return;

	for (i = 0; i < options->len; i++)
		if ((options->opts[i]->flags & ACCESSED) == 0)
			fz_warn(ctx, "Unknown option: %s", options->opts[i]->key);
}

int fz_count_options(fz_context *ctx, fz_options *options)
{
	if (!options)
		return 0;

	return options->len;
}

const char *fz_get_option(fz_context *ctx, fz_options *options, int i, const char **val)
{
	if (!options || i < 0 || i >= options->len)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Invalid option");

	if (val)
		*val = options->opts[i]->val;

	return options->opts[i]->key;
}

void fz_access_option(fz_context *ctx, fz_options *options, int i)
{
	if (!options || i < 0 || i >= options->len)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Invalid option");

	options->opts[i]->flags |= ACCESSED;
}
