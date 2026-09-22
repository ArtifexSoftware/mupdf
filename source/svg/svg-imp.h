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
// Artifex Software, Inc., 39 Mesa Street, Suite 108A, San Francisco,
// CA 94129, USA, for further information.

#ifndef SOURCE_SVG_IMP_H
#define SOURCE_SVG_IMP_H

typedef struct svg_cycle_list svg_cycle_list;
struct svg_cycle_list {
	svg_cycle_list *up;
	fz_xml *symbol;
};

enum fz_svg_property_name
{
	SVG_ATT_FILL,
	SVG_ATT_FILL_OPACITY,
	SVG_ATT_FILL_RULE,
	SVG_ATT_FONT_FAMILY,
	SVG_ATT_FONT_SIZE,
	SVG_ATT_FONT_STYLE,
	SVG_ATT_FONT_WEIGHT,
	SVG_ATT_HEIGHT,
	SVG_ATT_OPACITY,
	SVG_ATT_STOP_COLOR,
	SVG_ATT_STOP_OPACITY,
	SVG_ATT_STROKE,
	SVG_ATT_STROKE_LINECAP,
	SVG_ATT_STROKE_LINEJOIN,
	SVG_ATT_STROKE_MITERLIMIT,
	SVG_ATT_STROKE_OPACITY,
	SVG_ATT_STROKE_WIDTH,
	SVG_ATT_TEXT_ANCHOR,
	SVG_ATT_TRANSFORM,
	SVG_ATT_WIDTH,

	SVG_NUM_PROPERTIES
};

#if SVG_NUM_PROPERTIES > FZ_MAX_CSS_PROPS
#error "FZ_MAX_CSS_PROPS is too small!"
#endif

typedef struct svg_document svg_document;

struct svg_document
{
	fz_document super;
	fz_xml_doc *xml;
	fz_xml *root;
	fz_tree *idmap;
	float width;
	float height;
	svg_cycle_list *cycle; /* for detecting mutual recursive <use> invocations */
	fz_archive *zip; /* for locating external resources */
	char base_uri[2048];
};

typedef enum
{
	SVG_MATERIAL_NONE,
	SVG_MATERIAL_COLOR,
	SVG_MATERIAL_SHADE
} svg_material_type;

typedef struct
{
	svg_material_type type;
	union {
		float color[3];
		struct
		{
			fz_shade *shade;
			int use_obb;
		} s;
	} u;
} svg_material;

void svg_drop_material(fz_context *ctx, svg_material *mat);

const char *svg_lex_number(float *fp, const char *str);
float svg_parse_number(const char *str, float min, float max, float inherit);

void svg_apply_css_cascade(fz_context *ctx, fz_pool *pool, fz_css *css, fz_xml *xml);

/*
	Return length/coordinate in points.
*/
float svg_parse_length(const char *str, float percent, float font_size);
float svg_parse_angle(const char *str);

void svg_parse_color_from_style(fz_context *ctx, svg_document *doc, const char *str,
	svg_material *fill, float *fill_opacity, svg_material *stroke, float *stroke_opacity);
void svg_parse_color(fz_context *ctx, svg_document *doc, const char *str, svg_material *mat, float *opacity);
fz_matrix svg_parse_transform(fz_context *ctx, svg_document *doc, const char *str, fz_matrix transform);

int svg_is_whitespace_or_comma(int c);
int svg_is_whitespace(int c);
int svg_is_alpha(int c);
int svg_is_digit(int c);

void svg_parse_document_bounds(fz_context *ctx, svg_document *doc, fz_xml *root);
void svg_run_document(fz_context *ctx, svg_document *doc, fz_xml *root, fz_device *dev, fz_matrix ctm);

#endif
