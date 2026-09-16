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

#include "mupdf/fitz.h"
#include "svg-imp.h"

#include <string.h>

/* Color keywords (white, blue, fuchsia)
 * System color keywords (ActiveBorder, ButtonFace -- need to find reasonable defaults)
 * #fb0 (expand to #ffbb00)
 * #ffbb00
 * rgb(255,255,255)
 * rgb(100%,100%,100%)
 *
 * "red icc-color(profileName,255,0,0)" (not going to support for now)
 */

static struct
{
	const char *name;
	float red, green, blue;
}
svg_predefined_colors[] =
{
	{ "aliceblue", 240, 248, 255 },
	{ "antiquewhite", 250, 235, 215 },
	{ "aqua", 0, 255, 255 },
	{ "aquamarine", 127, 255, 212 },
	{ "azure", 240, 255, 255 },
	{ "beige", 245, 245, 220 },
	{ "bisque", 255, 228, 196 },
	{ "black", 0, 0, 0 },
	{ "blanchedalmond", 255, 235, 205 },
	{ "blue", 0, 0, 255 },
	{ "blueviolet", 138, 43, 226 },
	{ "brown", 165, 42, 42 },
	{ "burlywood", 222, 184, 135 },
	{ "cadetblue", 95, 158, 160 },
	{ "chartreuse", 127, 255, 0 },
	{ "chocolate", 210, 105, 30 },
	{ "coral", 255, 127, 80 },
	{ "cornflowerblue", 100, 149, 237 },
	{ "cornsilk", 255, 248, 220 },
	{ "crimson", 220, 20, 60 },
	{ "cyan", 0, 255, 255 },
	{ "darkblue", 0, 0, 139 },
	{ "darkcyan", 0, 139, 139 },
	{ "darkgoldenrod", 184, 134, 11 },
	{ "darkgray", 169, 169, 169 },
	{ "darkgreen", 0, 100, 0 },
	{ "darkgrey", 169, 169, 169 },
	{ "darkkhaki", 189, 183, 107 },
	{ "darkmagenta", 139, 0, 139 },
	{ "darkolivegreen", 85, 107, 47 },
	{ "darkorange", 255, 140, 0 },
	{ "darkorchid", 153, 50, 204 },
	{ "darkred", 139, 0, 0 },
	{ "darksalmon", 233, 150, 122 },
	{ "darkseagreen", 143, 188, 143 },
	{ "darkslateblue", 72, 61, 139 },
	{ "darkslategray", 47, 79, 79 },
	{ "darkslategrey", 47, 79, 79 },
	{ "darkturquoise", 0, 206, 209 },
	{ "darkviolet", 148, 0, 211 },
	{ "deeppink", 255, 20, 147 },
	{ "deepskyblue", 0, 191, 255 },
	{ "dimgray", 105, 105, 105 },
	{ "dimgrey", 105, 105, 105 },
	{ "dodgerblue", 30, 144, 255 },
	{ "firebrick", 178, 34, 34 },
	{ "floralwhite", 255, 250, 240 },
	{ "forestgreen", 34, 139, 34 },
	{ "fuchsia", 255, 0, 255 },
	{ "gainsboro", 220, 220, 220 },
	{ "ghostwhite", 248, 248, 255 },
	{ "gold", 255, 215, 0 },
	{ "goldenrod", 218, 165, 32 },
	{ "gray", 128, 128, 128 },
	{ "green", 0, 128, 0 },
	{ "greenyellow", 173, 255, 47 },
	{ "grey", 128, 128, 128 },
	{ "honeydew", 240, 255, 240 },
	{ "hotpink", 255, 105, 180 },
	{ "indianred", 205, 92, 92 },
	{ "indigo", 75, 0, 130 },
	{ "ivory", 255, 255, 240 },
	{ "khaki", 240, 230, 140 },
	{ "lavender", 230, 230, 250 },
	{ "lavenderblush", 255, 240, 245 },
	{ "lawngreen", 124, 252, 0 },
	{ "lemonchiffon", 255, 250, 205 },
	{ "lightblue", 173, 216, 230 },
	{ "lightcoral", 240, 128, 128 },
	{ "lightcyan", 224, 255, 255 },
	{ "lightgoldenrodyellow", 250, 250, 210 },
	{ "lightgray", 211, 211, 211 },
	{ "lightgreen", 144, 238, 144 },
	{ "lightgrey", 211, 211, 211 },
	{ "lightpink", 255, 182, 193 },
	{ "lightsalmon", 255, 160, 122 },
	{ "lightseagreen", 32, 178, 170 },
	{ "lightskyblue", 135, 206, 250 },
	{ "lightslategray", 119, 136, 153 },
	{ "lightslategrey", 119, 136, 153 },
	{ "lightsteelblue", 176, 196, 222 },
	{ "lightyellow", 255, 255, 224 },
	{ "lime", 0, 255, 0 },
	{ "limegreen", 50, 205, 50 },
	{ "linen", 250, 240, 230 },
	{ "magenta", 255, 0, 255 },
	{ "maroon", 128, 0, 0 },
	{ "mediumaquamarine", 102, 205, 170 },
	{ "mediumblue", 0, 0, 205 },
	{ "mediumorchid", 186, 85, 211 },
	{ "mediumpurple", 147, 112, 219 },
	{ "mediumseagreen", 60, 179, 113 },
	{ "mediumslateblue", 123, 104, 238 },
	{ "mediumspringgreen", 0, 250, 154 },
	{ "mediumturquoise", 72, 209, 204 },
	{ "mediumvioletred", 199, 21, 133 },
	{ "midnightblue", 25, 25, 112 },
	{ "mintcream", 245, 255, 250 },
	{ "mistyrose", 255, 228, 225 },
	{ "moccasin", 255, 228, 181 },
	{ "navajowhite", 255, 222, 173 },
	{ "navy", 0, 0, 128 },
	{ "oldlace", 253, 245, 230 },
	{ "olive", 128, 128, 0 },
	{ "olivedrab", 107, 142, 35 },
	{ "orange", 255, 165, 0 },
	{ "orangered", 255, 69, 0 },
	{ "orchid", 218, 112, 214 },
	{ "palegoldenrod", 238, 232, 170 },
	{ "palegreen", 152, 251, 152 },
	{ "paleturquoise", 175, 238, 238 },
	{ "palevioletred", 219, 112, 147 },
	{ "papayawhip", 255, 239, 213 },
	{ "peachpuff", 255, 218, 185 },
	{ "peru", 205, 133, 63 },
	{ "pink", 255, 192, 203 },
	{ "plum", 221, 160, 221 },
	{ "powderblue", 176, 224, 230 },
	{ "purple", 128, 0, 128 },
	{ "red", 255, 0, 0 },
	{ "rosybrown", 188, 143, 143 },
	{ "royalblue", 65, 105, 225 },
	{ "saddlebrown", 139, 69, 19 },
	{ "salmon", 250, 128, 114 },
	{ "sandybrown", 244, 164, 96 },
	{ "seagreen", 46, 139, 87 },
	{ "seashell", 255, 245, 238 },
	{ "sienna", 160, 82, 45 },
	{ "silver", 192, 192, 192 },
	{ "skyblue", 135, 206, 235 },
	{ "slateblue", 106, 90, 205 },
	{ "slategray", 112, 128, 144 },
	{ "slategrey", 112, 128, 144 },
	{ "snow", 255, 250, 250 },
	{ "springgreen", 0, 255, 127 },
	{ "steelblue", 70, 130, 180 },
	{ "tan", 210, 180, 140 },
	{ "teal", 0, 128, 128 },
	{ "thistle", 216, 191, 216 },
	{ "tomato", 255, 99, 71 },
	{ "turquoise", 64, 224, 208 },
	{ "violet", 238, 130, 238 },
	{ "wheat", 245, 222, 179 },
	{ "white", 255, 255, 255 },
	{ "whitesmoke", 245, 245, 245 },
	{ "yellow", 255, 255, 0 },
	{ "yellowgreen", 154, 205, 50 },
};

static int unhex(int chr)
{
	const char *hextable = "0123456789abcdef";
	return strchr(hextable, (chr|32)) - hextable;
}

static int ishex(int chr)
{
	if (chr >= '0' && chr <= '9') return 1;
	if (chr >= 'A' && chr <= 'F') return 1;
	if (chr >= 'a' && chr <= 'f') return 1;
	return 0;
}

static int
svg_parse_simple_color(fz_context *ctx, svg_document *doc, const char *str, float *rgb, float *opacity)
{
	int i, l, m, r, cmp;
	size_t n;

	if (!str)
		return 0;

	/* Crack hex-coded RGB */

	if (str[0] == '#')
	{
		str ++;

		n = strlen(str);
		if (n == 3 || (n > 3 && !ishex(str[3])))
		{
			rgb[0] = (unhex(str[0]) * 16 + unhex(str[0])) / 255.0f;
			rgb[1] = (unhex(str[1]) * 16 + unhex(str[1])) / 255.0f;
			rgb[2] = (unhex(str[2]) * 16 + unhex(str[2])) / 255.0f;
			return 1;
		}

		if (n >= 6)
		{
			rgb[0] = (unhex(str[0]) * 16 + unhex(str[1])) / 255.0f;
			rgb[1] = (unhex(str[2]) * 16 + unhex(str[3])) / 255.0f;
			rgb[2] = (unhex(str[4]) * 16 + unhex(str[5])) / 255.0f;
			return 1;
		}

		rgb[0] = 0.0f;
		rgb[1] = 0.0f;
		rgb[2] = 0.0f;

		return 1;
	}

	/* rgb(X,Y,Z) -- whitespace allowed around numbers */

	else if (strstr(str, "rgb("))
	{
		int numberlen = 0;
		char numberbuf[50];

		str = str + 4;

		rgb[0] = 0.0f;
		rgb[1] = 0.0f;
		rgb[2] = 0.0f;

		for (i = 0; i < 3; i++)
		{
			while (svg_is_whitespace_or_comma(*str))
				str ++;

			if (svg_is_digit(*str))
			{
				numberlen = 0;
				while (svg_is_digit(*str) && numberlen < (int)sizeof(numberbuf) - 1)
					numberbuf[numberlen++] = *str++;
				numberbuf[numberlen] = 0;

				if (*str == '%')
				{
					str ++;
					rgb[i] = fz_atof(numberbuf) / 100.0f;
				}
				else
				{
					rgb[i] = fz_atof(numberbuf) / 255.0f;
				}
			}
		}

		return 1;
	}

	else if (strstr(str, "rgba("))
	{
		int numberlen = 0;
		char numberbuf[50];

		str = str + 5;

		rgb[0] = 0.0f;
		rgb[1] = 0.0f;
		rgb[2] = 0.0f;

		for (i = 0; i < 3; i++)
		{
			while (svg_is_whitespace_or_comma(*str))
				str ++;

			if (svg_is_digit(*str))
			{
				float *res;
				numberlen = 0;
				while (svg_is_digit(*str) && numberlen < (int)sizeof(numberbuf) - 1)
					numberbuf[numberlen++] = *str++;
				numberbuf[numberlen] = 0;

				if (i == 3)
					res = opacity;
				else
					res = &rgb[i];
				if (*str == '%')
				{
					str ++;
					*res = fz_atof(numberbuf) / 100.0f;
				}
				else
				{
					*res = fz_atof(numberbuf) / 255.0f;
				}
			}
		}

		return 1;
	}

	/* TODO: parse icc-profile(X,Y,Z,W) syntax */

	/* Search for a pre-defined color */

	else
	{
		char keyword[50], *p;
		fz_strlcpy(keyword, str, sizeof keyword);
		p = keyword;
		while ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))
			++p;
		*p = 0;

		l = 0;
		r = nelem(svg_predefined_colors) - 1;

		while (l <= r)
		{
			m = (l + r) / 2;
			cmp = fz_strcasecmp_ascii(svg_predefined_colors[m].name, keyword);
			if (cmp > 0)
				r = m - 1;
			else if (cmp < 0)
				l = m + 1;
			else
			{
				rgb[0] = svg_predefined_colors[m].red / 255.0f;
				rgb[1] = svg_predefined_colors[m].green / 255.0f;
				rgb[2] = svg_predefined_colors[m].blue / 255.0f;
				return 1;
			}
		}
	}

	return 0;
}

static float
my_atof(const char *str)
{
	float f;

	if (str == NULL)
		return 0;

	f = fz_atof(str);

	if (strchr(str, '%'))
		f /= 100;

	return f;
}

static const char *
find_style_value(const char *p, const char *m)
{
	size_t lm = strlen(m);

	if (!p)
		return NULL;

	while (*p)
	{
		while (*p && svg_is_whitespace(*p))
			p++;
		if (!strncmp(p, m, lm))
		{
			p += lm;
			while (*p && svg_is_whitespace(*p))
				p++;
			if (*p == ':')
			{
				p++;
				while (*p && svg_is_whitespace(*p))
					p++;
				return p;
			}
		}
		while (*p && *p != ';')
			p++;
		if (*p)
			p++;
	}

	return NULL;
}

static int
svg_parse_stop_color_from_style(fz_context *ctx, svg_document *doc, const char *p, float *color, float *opacity)
{
	char buf[100];
	const char *e;

	if (p == NULL)
		return 0;

	p = find_style_value(p, "stop-color");
	if (p == NULL)
		return 0;
	for (e = p; *e != 0 && *e != ';'; e++)
	{}
	if (e > p+sizeof(buf)-1)
		e = p+sizeof(buf)-1;
	memcpy(buf, p, e-p);
	buf[e-p] = 0;
	return svg_parse_simple_color(ctx, doc, buf, color, opacity);
}

static int
svg_parse_stop_opacity_from_style(fz_context *ctx, const char *p, float *opacity)
{
	if (p == NULL)
		return 0;

	p = find_style_value(p, "stop-opacity");
	if (p == NULL)
		return 0;
	*opacity = my_atof(p);
	return 1;
}

static fz_xml *
find_local_url(fz_context *ctx, svg_document *doc, const char *str)
{
	fz_xml *found;
	const char *match = str;

	if (match == NULL)
		return NULL;

	while (svg_is_whitespace(*match))
		match ++;
	if (*match != '#')
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Non-local URL in SVG");

	found = fz_tree_lookup(ctx, doc->idmap, match + 1);
	if (found == NULL)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Url '%s' not found", str);

	return found;
}

static fz_xml *
find_url(fz_context *ctx, svg_document *doc, const char *str)
{
	char *match;
	const char *e;
	fz_xml *ret;

	if (strncmp(str, "url(", 4))
		return NULL;

	str += 4;

	e = str;
	while (*e && *e != ')')
		e++;

	match = fz_malloc(ctx, e-str+1);
	memcpy(match, str, e-str);
	match[e-str] = 0;

	fz_try(ctx)
		ret = find_local_url(ctx, doc, match);
	fz_always(ctx)
		fz_free(ctx, match);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return ret;
}

static float
interp(float a, float b, float pos)
{
	return ((b-a)*pos + a);
}

static void
interp_fill(float *function, int o1, float *rgba1, int o2, float *rgba2)
{
	int n;
	int d = o2 - o1;
	float fd = (float)d;

	function += o1 * 4;

	for (n = 0; n < d; n++)
	{
		float pos = n / fd;
		*function++ = interp(rgba1[0], rgba2[0], pos);
		*function++ = interp(rgba1[1], rgba2[1], pos);
		*function++ = interp(rgba1[2], rgba2[2], pos);
		*function++ = interp(rgba1[3], rgba2[3], pos);
	}
}

static void fill_function_from_stops(fz_context *ctx, svg_document *doc, float *function, fz_xml *node)
{
	fz_xml *n;
	int o;
	int i;
	float prev_rgba[4];
	int stops = 0;

	n = fz_xml_find_down(node, "stop");
	if (n == NULL)
		return;

	o = 0;
	for (; n != NULL; n = fz_xml_find_next(n, "stop"))
	{
		float offset = my_atof(fz_xml_att(n, "offset"));
		float rgba[4] = { 0, 0, 0, 1 };
		char *style = fz_xml_att(n, "style");
		char *opacity = fz_xml_att(n, "stop-opacity");
		int o2;

		if (opacity)
			rgba[3] = fz_atof(opacity);
		else
			svg_parse_stop_opacity_from_style(ctx, style, &rgba[3]);

		if (!svg_parse_simple_color(ctx, doc, fz_xml_att(n, "stop-color"), rgba, &rgba[3]))
		{
			if (!svg_parse_stop_color_from_style(ctx, doc, style, rgba, &rgba[3]) && opacity != 0)
				continue; /* If we can't get a stop color from somewhere, ignore it. */
		}

		if (offset < 0)
			offset = 0;
		if (offset > 1)
			offset = 1;
		o2 = (int)((offset * 255) + 0.5f);
		if (o2 < o)
			o2 = o;

		for (i = 0; i < 4; i++)
			rgba[i] = fz_clamp(rgba[i], 0, 1);

		/* Fill in up to offset */
		if (stops == 0)
			memcpy(prev_rgba, rgba, 4 * sizeof(float));
		interp_fill(function, o, prev_rgba, o2, rgba);
		memcpy(prev_rgba, rgba, 4 * sizeof(float));
		o = o2;
		stops++;
	}

	if (stops != 0)
		interp_fill(function, o, prev_rgba, 256, prev_rgba);
}

typedef struct
{
	float x1, y1, x2, y2;
	int obb;
	fz_matrix tfm;
	float function[4*256];
} linear_gradient;

static void parse_linear_gradient(fz_context *ctx, svg_document *doc, fz_xml *url, linear_gradient *lg, int depth)
{
	const char *x1s = fz_xml_att(url, "x1");
	const char *y1s = fz_xml_att(url, "y1");
	const char *x2s = fz_xml_att(url, "x2");
	const char *y2s = fz_xml_att(url, "y2");
	const char *gu = fz_xml_att(url, "gradientUnits");
	const char *gt = fz_xml_att(url, "gradientTransform");

	fz_xml *xlink = find_local_url(ctx, doc, fz_xml_att_alt(url, "xlink:href", "href"));

	if (depth > 10)
	{
		fz_warn(ctx, "Cycle in linear gradients - rendering may be incorrect");
		return;
	}

	if (xlink)
		parse_linear_gradient(ctx, doc, xlink, lg, depth+1);

	if (x1s)
		lg->x1 = my_atof(x1s);
	if (y1s)
		lg->y1 = my_atof(y1s);
	if (x2s)
		lg->x2 = my_atof(x2s);
	if (y2s)
		lg->y2 = my_atof(y2s);

	if (gt)
		lg->tfm = svg_parse_transform(ctx, doc, gt, fz_identity);

	if (gu)
		lg->obb = !strcmp(gu, "objectBoundingBox");

	fill_function_from_stops(ctx, doc, lg->function, url);
}

typedef struct
{
	float fx, fy, fr, cx, cy, r;
	int obb;
	fz_matrix tfm;
	float function[4*256];
} radial_gradient;

static void
init_function(float *function)
{
	int i;

	for (i = 0; i < 1024; i += 4)
	{
		function[i] = 0;
		function[i+1] = 0;
		function[i+2] = 0;
		function[i+3] = 1;
	}
}

static void parse_radial_gradient(fz_context *ctx, svg_document *doc, fz_xml *url, radial_gradient *rg, int depth)
{
	const char *fxs = fz_xml_att(url, "fx");
	const char *fys = fz_xml_att(url, "fy");
	const char *frs = fz_xml_att(url, "fr");
	const char *cxs = fz_xml_att(url, "cx");
	const char *cys = fz_xml_att(url, "cy");
	const char *rs = fz_xml_att(url, "r");
	const char *gu = fz_xml_att(url, "gradientUnits");
	const char *gt = fz_xml_att(url, "gradientTransform");

	fz_xml *xlink = find_local_url(ctx, doc, fz_xml_att_alt(url, "xlink:href", "href"));

	if (depth > 10)
	{
		fz_warn(ctx, "Cycle in radial gradients - rendering may be incorrect");
		return;
	}

	if (xlink)
		parse_radial_gradient(ctx, doc, xlink, rg, depth+1);

	if (fxs)
		rg->fx = my_atof(fxs);
	if (fys)
		rg->fy = my_atof(fys);
	if (frs)
		rg->fr = my_atof(frs);
	if (cxs)
		rg->cx = my_atof(cxs);
	if (cys)
		rg->cy = my_atof(cys);
	if (rs)
		rg->r = my_atof(rs);

	if (gt)
		rg->tfm = svg_parse_transform(ctx, doc, gt, fz_identity);

	if (gu)
		rg->obb = !strcmp(gu, "objectBoundingBox");

	fill_function_from_stops(ctx, doc, rg->function, url);
}

static void
svg_parse_gradient(fz_context *ctx, svg_document *doc, fz_xml *url, svg_material *mat)
{
	char *tag = fz_xml_tag(url);

	if (tag && !strcmp(tag, "linearGradient"))
	{
		fz_shade *shade = NULL;
		linear_gradient lg = { 0 };
		lg.x2 = 1;
		lg.tfm = fz_identity;
		lg.obb = 1;

		init_function(lg.function);
		parse_linear_gradient(ctx, doc, url, &lg, 0);

		fz_var(shade);

		fz_try(ctx)
		{
			shade = fz_malloc_struct(ctx, fz_shade);
			FZ_INIT_STORABLE(shade, 1, fz_drop_shade_imp);
			shade->type = FZ_LINEAR;
			shade->use_background = 0;
			shade->matrix = lg.tfm;
			shade->bbox = fz_infinite_rect;

			shade->colorspace = fz_keep_colorspace(ctx, fz_device_rgb(ctx));

			shade->u.l_or_r.coords[0][0] = lg.x1;
			shade->u.l_or_r.coords[0][1] = lg.y1;
			shade->u.l_or_r.coords[1][0] = lg.x2;
			shade->u.l_or_r.coords[1][1] = lg.y2;

			shade->u.l_or_r.extend[0] = 1;
			shade->u.l_or_r.extend[1] = 1;
			shade->u.l_or_r.use_obb = lg.obb;

			shade->function_stride = 3 + 1; /* RGB + Alpha */
			shade->function = Memento_label(fz_calloc(ctx, 256 * shade->function_stride, sizeof(float)), "shade samples");
			memcpy(shade->function, lg.function, sizeof(lg.function));
		}
		fz_catch(ctx)
		{
			fz_drop_shade(ctx, shade);
			fz_rethrow(ctx);
		}

		mat->type = SVG_MATERIAL_SHADE;
		mat->u.shade = shade;
	}
	else if (tag && !strcmp(tag, "radialGradient"))
	{
		fz_shade *shade = NULL;
		radial_gradient rg = { 0 };
		rg.cx = 0.5f;
		rg.cy = 0.5f;
		rg.r = 0.5f;
		rg.fx = 0.5f; /* default value ? */
		rg.fy = 0.5f; /* default value ? */
		rg.fr = 0;
		rg.tfm = fz_identity;
		rg.obb = 1;

		init_function(rg.function);
		parse_radial_gradient(ctx, doc, url, &rg, 0);

		fz_var(shade);

		fz_try(ctx)
		{
			shade = fz_malloc_struct(ctx, fz_shade);
			FZ_INIT_STORABLE(shade, 1, fz_drop_shade_imp);
			shade->type = FZ_RADIAL;
			shade->use_background = 0;
			shade->matrix = rg.tfm;
			shade->bbox = fz_infinite_rect;

			shade->colorspace = fz_keep_colorspace(ctx, fz_device_rgb(ctx));

			shade->u.l_or_r.coords[0][0] = rg.fx;
			shade->u.l_or_r.coords[0][1] = rg.fy;
			shade->u.l_or_r.coords[0][2] = rg.fr;
			shade->u.l_or_r.coords[1][0] = rg.cx;
			shade->u.l_or_r.coords[1][1] = rg.cy;
			shade->u.l_or_r.coords[1][2] = rg.r;

			shade->u.l_or_r.extend[0] = 1;
			shade->u.l_or_r.extend[1] = 1;
			shade->u.l_or_r.use_obb = rg.obb;

			shade->function_stride = 3 + 1; /* RGB + Alpha */
			shade->function = Memento_label(fz_calloc(ctx, 256 * shade->function_stride, sizeof(float)), "shade samples");
			memcpy(shade->function, rg.function, sizeof(rg.function));
		}
		fz_catch(ctx)
		{
			fz_drop_shade(ctx, shade);
			fz_rethrow(ctx);
		}

		mat->type = SVG_MATERIAL_SHADE;
		mat->u.shade = shade;
	}
}

void
svg_parse_color(fz_context *ctx, svg_document *doc, const char *str, svg_material *mat, float *opacity)
{
	if (!strcmp(str, "inherit"))
		return;

	svg_drop_material(ctx, mat);

	if (!strcmp(str, "none"))
		return;

	if (svg_parse_simple_color(ctx, doc, str, mat->u.color, opacity))
	{
		mat->type = SVG_MATERIAL_COLOR;
		return;
	}

	else if (strstr(str, "url("))
	{
		svg_parse_gradient(ctx, doc, find_url(ctx, doc, str), mat);

		return;
	}

}

static void
svg_parse_color_from_style_string(fz_context *ctx, svg_document *doc, const char *p, svg_material *mat, float *opacity)
{
	char buf[100], *e;
	while (*p && svg_is_whitespace(*p))
		++p;
	fz_strlcpy(buf, p, sizeof buf);
	e = strchr(buf, ';');
	if (e)
		*e = 0;
	svg_parse_color(ctx, doc, buf, mat, opacity);
}

void
svg_parse_color_from_style(fz_context *ctx, svg_document *doc, const char *str,
	svg_material *fill_mat, float *fill_opacity, svg_material *stroke_mat, float *stroke_opacity)
{
	const char *p;

	p = strstr(str, "fill:");
	if (p)
	{
		svg_parse_color_from_style_string(ctx, doc, p+5, fill_mat, fill_opacity);
	}

	p = strstr(str, "stroke:");
	if (p)
	{
		svg_parse_color_from_style_string(ctx, doc, p+7, stroke_mat, stroke_opacity);
	}
}
