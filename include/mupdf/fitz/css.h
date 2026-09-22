// Copyright (C) 2004-2026 Artifex Software, Inc.
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

#ifndef MUPDF_FITZ_CSS_H
#define MUPDF_FITZ_CSS_H

#include "mupdf/fitz.h"

#define FZ_MAX_CSS_PROPS 68

typedef struct fz_css fz_css;
typedef struct fz_css_rule fz_css_rule;
typedef struct fz_css_match fz_css_match;
typedef struct fz_css_style fz_css_style;

typedef struct fz_css_selector fz_css_selector;
typedef struct fz_css_condition fz_css_condition;
typedef struct fz_css_property fz_css_property;
typedef struct fz_css_value fz_css_value;

struct fz_css
{
	fz_pool *pool;
	fz_css_rule *rule;
};

struct fz_css_rule
{
	fz_css_selector *selector;
	fz_css_property *declaration;
	fz_css_rule *next;
	int loaded;
};

struct fz_css_selector
{
	char *name;
	int combine;
	fz_css_condition *cond;
	fz_css_selector *left;
	fz_css_selector *right;
	fz_css_selector *next;
};

struct fz_css_condition
{
	int type;
	char *key;
	char *val;
	fz_css_condition *next;
};

struct fz_css_property
{
	int name;
	fz_css_value *value;
	short spec;
	short important;
	fz_css_property *next;
};

struct fz_css_value
{
	int type;
	char *data;
	fz_css_value *args; /* function arguments */
	fz_css_value *next;
};

struct fz_css_match
{
	fz_css_match *up;
	short spec[FZ_MAX_CSS_PROPS];
	fz_css_value *value[FZ_MAX_CSS_PROPS];
};

fz_css *fz_new_css(fz_context *ctx);
void fz_parse_css(fz_context *ctx, fz_css *css, const char *source, const char *file);
void fz_parse_css_in_svg(fz_context *ctx, fz_css *css, const char *source, const char *file);
fz_css_property *fz_parse_css_properties(fz_context *ctx, fz_pool *pool, const char *source);
fz_css_property *fz_parse_css_properties_in_svg(fz_context *ctx, fz_pool *pool, const char *source);
void fz_drop_css(fz_context *ctx, fz_css *css);
void fz_debug_css(fz_context *ctx, fz_css *css);
void fz_debug_css_in_svg(fz_context *ctx, fz_css *css);
const char *fz_css_property_name(int name);
const char *fz_css_property_name_in_svg(int name);

void fz_match_css(fz_context *ctx, fz_css_match *match, fz_css_match *up, fz_css *css, fz_xml *node, int pseudo, int publisher_css);
void fz_match_css_in_svg(fz_context *ctx, fz_css_match *match, fz_css_match *up, fz_css *css, fz_xml *node);

char *fz_string_from_css_value(fz_context *ctx, char *buf, int size, fz_css_value *value);

#endif /* MUPDF_FITZ_CSS_H */
