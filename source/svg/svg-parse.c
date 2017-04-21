#include "mupdf/fitz.h"
#include "svg-imp.h"

#include <string.h>
#include <math.h>

int svg_is_whitespace_or_comma(int c)
{
	 return (c == 0x20) || (c == 0x9) || (c == 0xD) || (c == 0xA) || (c == ',');
}

int svg_is_whitespace(int c)
{
	return (c == 0x20) || (c == 0x9) || (c == 0xD) || (c == 0xA);
}

int svg_is_alpha(int c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

int svg_is_digit(int c)
{
	return (c >= '0' && c <= '9') ||
		(c == 'e') || (c == 'E') ||
		(c == '+') || (c == '-') || (c == '.');
}

const char *
svg_lex_number(float *fp, const char *ss)
{
	const char *s = ss;
	if (*s == '-')
		++s;
	while (*s >= '0' && *s <= '9')
		++s;
	if (*s == '.') {
		++s;
		while (*s >= '0' && *s <= '9')
			++s;
	}
	if (*s == 'e' || *s == 'E') {
		++s;
		if (*s == '+' || *s == '-')
			++s;
		while (*s >= '0' && *s <= '9')
			++s;
	}
	*fp = fz_atof(ss);
	return s;
}

float
svg_parse_number(const char *str, float min, float max, float inherit)
{
	float x;
	if (!strcmp(str, "inherit"))
		return inherit;
	x = fz_atof(str);
	if (x < min) return min;
	if (x > max) return max;
	return x;
}

/* Return length/coordinate in points */
float
svg_parse_length(const char *str, float percent, float font_size)
{
	char *end;
	float val;

	val = (float)fz_strtod(str, &end);
	if (end == str)
		return 0; /* failed */

	if (!strcmp(end, "px")) return val;

	if (!strcmp(end, "pt")) return val * 1.0;
	if (!strcmp(end, "pc")) return val * 12.0;
	if (!strcmp(end, "mm")) return val * 2.83464567;
	if (!strcmp(end, "cm")) return val * 28.3464567;
	if (!strcmp(end, "in")) return val * 72.0;

	if (!strcmp(end, "em")) return val * font_size;
	if (!strcmp(end, "ex")) return val * font_size * 0.5;

	if (!strcmp(end, "%"))
		return val * percent * 0.01;

	if (end[0] == 0)
		return val;

	return 0;
}

/* Return angle in degrees */
float
svg_parse_angle(const char *str)
{
	char *end;
	float val;

	val = (float)fz_strtod(str, &end);
	if (end == str)
		return 0; /* failed */

	if (!strcmp(end, "deg"))
		return val;

	if (!strcmp(end, "grad"))
		return val * 0.9;

	if (!strcmp(end, "rad"))
		return val * 57.2957795;

	return val;
}

/* Coordinate transformations */
void
svg_parse_transform(fz_context *ctx, svg_document *doc, char *str, fz_matrix *transform)
{
	char keyword[20];
	int keywordlen;
	char number[20];
	int numberlen;
	float args[6];
	int nargs;
	int first = 1;

	nargs = 0;
	keywordlen = 0;

	while (*str)
	{
		while (svg_is_whitespace(*str))
			str ++;
		if (*str == 0)
			break;

		if (!first)
		{
			if (*str == ',')
				str ++;

			while (svg_is_whitespace(*str))
				str ++;
		}
		first = 0;

		/*
		 * Parse keyword and opening parenthesis.
		 */

		if (!svg_is_alpha(*str))
			fz_throw(ctx, FZ_ERROR_GENERIC, "syntax error in transform attribute - expected keyword");

		keywordlen = 0;
		while (svg_is_alpha(*str) && keywordlen < sizeof(keyword) - 1)
			keyword[keywordlen++] = *str++;
		keyword[keywordlen] = 0;

		if (keywordlen == 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "syntax error in transform attribute - no keyword");

		while (svg_is_whitespace(*str))
			str ++;

		if (*str != '(')
			fz_throw(ctx, FZ_ERROR_GENERIC, "syntax error in transform attribute - no open paren");
		str ++;

		/*
		 * Parse list of numbers until closing parenthesis
		 */

		nargs = 0;
		while (*str && *str != ')' && nargs < 6)
		{
			if (nargs > 0)
			{
				if (*str != ',')
					fz_throw(ctx, FZ_ERROR_GENERIC, "syntax error in transform attribute - no comma between numbers");
				str ++;
			}

			while (svg_is_whitespace(*str))
				str ++;

			if (!svg_is_digit(*str))
				fz_throw(ctx, FZ_ERROR_GENERIC, "syntax error in transform attribute - number required");

			numberlen = 0;
			while (svg_is_digit(*str) && numberlen < sizeof(number) - 1)
				number[numberlen++] = *str++;
			number[numberlen] = 0;
			args[nargs++] = fz_atof(number);

			while (svg_is_whitespace(*str))
				str ++;
		}

		if (*str == 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "syntax error in transform attribute - no close paren");
		if (*str != ')')
			fz_throw(ctx, FZ_ERROR_GENERIC, "syntax error in transform attribute - expected close paren");
		str ++;

		/*
		 * Execute the transform.
		 */

		if (!strcmp(keyword, "matrix"))
		{
			fz_matrix m;

			if (nargs != 6)
				fz_throw(ctx, FZ_ERROR_GENERIC, "wrong number of arguments to matrix(): %d", nargs);

			m.a = args[0];
			m.b = args[1];
			m.c = args[2];
			m.d = args[3];
			m.e = args[4];
			m.f = args[5];

			fz_concat(transform, transform, &m);
		}

		else if (!strcmp(keyword, "translate"))
		{
			if (nargs != 2)
				fz_throw(ctx, FZ_ERROR_GENERIC, "wrong number of arguments to translate(): %d", nargs);

			fz_pre_translate(transform, args[0], args[1]);
		}

		else if (!strcmp(keyword, "scale"))
		{
			if (nargs == 1)
				fz_pre_scale(transform, args[0], args[0]);
			else if (nargs == 2)
				fz_pre_scale(transform, args[0], args[1]);
			else
				fz_throw(ctx, FZ_ERROR_GENERIC, "wrong number of arguments to scale(): %d", nargs);
		}

		else if (!strcmp(keyword, "rotate"))
		{
			if (nargs != 1)
				fz_throw(ctx, FZ_ERROR_GENERIC, "wrong number of arguments to rotate(): %d", nargs);
			fz_pre_rotate(transform, args[0]);
		}

		else if (!strcmp(keyword, "skewX"))
		{
			fz_matrix m;

			if (nargs != 1)
				fz_throw(ctx, FZ_ERROR_GENERIC, "wrong number of arguments to skewX(): %d", nargs);

			m.a = 1;
			m.b = 0;
			m.c = tanf(args[0] * 0.0174532925);
			m.d = 1;
			m.e = 0;
			m.f = 0;

			fz_concat(transform, transform, &m);
		}

		else if (!strcmp(keyword, "skewY"))
		{
			fz_matrix m;

			if (nargs != 1)
				fz_throw(ctx, FZ_ERROR_GENERIC, "wrong number of arguments to skewY(): %d", nargs);

			m.a = 1;
			m.b = tanf(args[0] * 0.0174532925);
			m.c = 0;
			m.d = 1;
			m.e = 0;
			m.f = 0;

			fz_concat(transform, transform, &m);
		}

		else
		{
			fz_throw(ctx, FZ_ERROR_GENERIC, "unknown transform function: %s", keyword);
		}
	}
}
