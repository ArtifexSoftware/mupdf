// Copyright (C) 2004-2024 Artifex Software, Inc.
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

#include <string.h>
#include <math.h>
#include <float.h>
#include <limits.h>

static pdf_function *pdf_load_function_imp(fz_context *ctx, pdf_obj *dict, int in, int out, pdf_cycle_list *cycle);

#define DIV_BY_ZERO(a, b, min, max) (((a) < 0) ^ ((b) < 0) ? (min) : (max))

enum
{
	MAX_N = FZ_MAX_COLORS,
	MAX_M = FZ_MAX_COLORS
};

enum
{
	SAMPLE = 0,
	EXPONENTIAL = 2,
	STITCHING = 3,
	POSTSCRIPT = 4
};

typedef struct
{
	int type;
	union
	{
		int b;				/* boolean (stack only) */
		int i;				/* integer (stack and code) */
		float f;			/* real (stack and code) */
		int op;				/* operator (code only) */
		int block;			/* if/ifelse block pointer (code only) */
	} u;
} psobj;

struct pdf_function
{
	fz_function super;

	float domain[MAX_M][2]; /* even index : min value, odd index : max value */
	float range[MAX_N][2];  /* even index : min value, odd index : max value */
	int has_range;
};

typedef struct
{
	pdf_function super;

	unsigned short bps;
	int size[MAX_M];
	float encode[MAX_M][2];
	float decode[MAX_N][2];
	float *samples;
} pdf_function_sa;

typedef struct
{
	pdf_function super;

	float n;
	float c0[MAX_N];
	float c1[MAX_N];
} pdf_function_e;

typedef struct
{
	pdf_function super;

	int k;
	pdf_function **funcs; /* k */
	float *bounds; /* k - 1 */
	float *encode; /* k * 2 */
} pdf_function_st;

typedef struct
{
	pdf_function super;

	psobj *code;
	int cap;
} pdf_function_p;

pdf_function *
pdf_keep_function(fz_context *ctx, pdf_function *func)
{
	return (pdf_function *)fz_keep_function(ctx, &func->super);
}

void
pdf_drop_function(fz_context *ctx, pdf_function *func)
{
	fz_drop_function(ctx, &func->super);
}

size_t
pdf_function_size(fz_context *ctx, pdf_function *func)
{
	return fz_function_size(ctx, &func->super);
}

static inline float lerp(float x, float xmin, float xmax, float ymin, float ymax)
{
	if (xmin == xmax)
		return ymin;
	if (ymin == ymax)
		return ymin;
	return ymin + (x - xmin) * (ymax - ymin) / (xmax - xmin);
}

/*
 * PostScript calculator
 */

enum { PS_BOOL, PS_INT, PS_REAL, PS_OPERATOR, PS_BLOCK };

enum
{
	PS_OP_ABS, PS_OP_ADD, PS_OP_AND, PS_OP_ATAN, PS_OP_BITSHIFT,
	PS_OP_CEILING, PS_OP_COPY, PS_OP_COS, PS_OP_CVI, PS_OP_CVR,
	PS_OP_DIV, PS_OP_DUP, PS_OP_EQ, PS_OP_EXCH, PS_OP_EXP,
	PS_OP_FALSE, PS_OP_FLOOR, PS_OP_GE, PS_OP_GT, PS_OP_IDIV, PS_OP_IF,
	PS_OP_IFELSE, PS_OP_INDEX, PS_OP_LE, PS_OP_LN, PS_OP_LOG, PS_OP_LT,
	PS_OP_MOD, PS_OP_MUL, PS_OP_NE, PS_OP_NEG, PS_OP_NOT, PS_OP_OR,
	PS_OP_POP, PS_OP_RETURN, PS_OP_ROLL, PS_OP_ROUND, PS_OP_SIN,
	PS_OP_SQRT, PS_OP_SUB, PS_OP_TRUE, PS_OP_TRUNCATE, PS_OP_XOR
};

static char *ps_op_names[] =
{
	"abs", "add", "and", "atan", "bitshift", "ceiling", "copy",
	"cos", "cvi", "cvr", "div", "dup", "eq", "exch", "exp",
	"false", "floor", "ge", "gt", "idiv", "if", "ifelse", "index", "le", "ln",
	"log", "lt", "mod", "mul", "ne", "neg", "not", "or", "pop", "return",
	"roll", "round", "sin", "sqrt", "sub", "true", "truncate", "xor"
};

typedef struct
{
	psobj stack[100];
	int sp;
} ps_stack;

static void
ps_init_stack(ps_stack *st)
{
	memset(st->stack, 0, sizeof(st->stack));
	st->sp = 0;
}

static inline int ps_overflow(ps_stack *st, int n)
{
	return n < 0 || st->sp + n >= (int)nelem(st->stack);
}

static inline int ps_underflow(ps_stack *st, int n)
{
	return n < 0 || n > st->sp;
}

static inline int ps_is_type(ps_stack *st, int t)
{
	return !ps_underflow(st, 1) && st->stack[st->sp - 1].type == t;
}

static inline int ps_is_type2(ps_stack *st, int t)
{
	return !ps_underflow(st, 2) && st->stack[st->sp - 1].type == t && st->stack[st->sp - 2].type == t;
}

static void
ps_push_bool(ps_stack *st, int b)
{
	if (!ps_overflow(st, 1))
	{
		st->stack[st->sp].type = PS_BOOL;
		st->stack[st->sp].u.b = b;
		st->sp++;
	}
}

static void
ps_push_int(ps_stack *st, int n)
{
	if (!ps_overflow(st, 1))
	{
		st->stack[st->sp].type = PS_INT;
		st->stack[st->sp].u.i = n;
		st->sp++;
	}
}

static void
ps_push_real(ps_stack *st, float n)
{
	if (!ps_overflow(st, 1))
	{
		st->stack[st->sp].type = PS_REAL;
		if (isnan(n))
		{
			/* Push 1.0, as it's a small known value that won't
			 * cause a divide by 0. Same reason as in fz_atof. */
			n = 1.0f;
		}
		st->stack[st->sp].u.f = fz_clamp(n, -FLT_MAX, FLT_MAX);
		st->sp++;
	}
}

static int
ps_pop_bool(ps_stack *st)
{
	if (!ps_underflow(st, 1))
	{
		if (ps_is_type(st, PS_BOOL))
			return st->stack[--st->sp].u.b;
	}
	return 0;
}

static int
ps_pop_int(ps_stack *st)
{
	if (!ps_underflow(st, 1))
	{
		if (ps_is_type(st, PS_INT))
			return st->stack[--st->sp].u.i;
		if (ps_is_type(st, PS_REAL))
			return st->stack[--st->sp].u.f;
	}
	return 0;
}

static float
ps_pop_real(ps_stack *st)
{
	if (!ps_underflow(st, 1))
	{
		if (ps_is_type(st, PS_INT))
			return st->stack[--st->sp].u.i;
		if (ps_is_type(st, PS_REAL))
			return st->stack[--st->sp].u.f;
	}
	return 0;
}

static void
ps_copy(ps_stack *st, int n)
{
	if (!ps_underflow(st, n) && !ps_overflow(st, n))
	{
		memcpy(st->stack + st->sp, st->stack + st->sp - n, n * sizeof(psobj));
		st->sp += n;
	}
}

static void
ps_roll(ps_stack *st, int n, int j)
{
	psobj tmp;
	int i;

	if (ps_underflow(st, n) || j == 0 || n == 0)
		return;

	if (j >= 0)
	{
		j %= n;
	}
	else
	{
		j = -j % n;
		if (j != 0)
			j = n - j;
	}

	for (i = 0; i < j; i++)
	{
		tmp = st->stack[st->sp - 1];
		memmove(st->stack + st->sp - n + 1, st->stack + st->sp - n, n * sizeof(psobj));
		st->stack[st->sp - n] = tmp;
	}
}

static void
ps_index(ps_stack *st, int n)
{
	if (!ps_overflow(st, 1) && !ps_underflow(st, n + 1))
	{
		st->stack[st->sp] = st->stack[st->sp - n - 1];
		st->sp++;
	}
}

static void
ps_run(fz_context *ctx, psobj *code, ps_stack *st, int pc)
{
	int i1, i2;
	float r1, r2;
	int b1, b2;

	while (1)
	{
		switch (code[pc].type)
		{
		case PS_INT:
			ps_push_int(st, code[pc++].u.i);
			break;

		case PS_REAL:
			ps_push_real(st, code[pc++].u.f);
			break;

		case PS_OPERATOR:
			switch (code[pc++].u.op)
			{
			case PS_OP_ABS:
				if (ps_is_type(st, PS_INT))
					ps_push_int(st, fz_absi(ps_pop_int(st)));
				else
					ps_push_real(st, fz_abs(ps_pop_real(st)));
				break;

			case PS_OP_ADD:
				if (ps_is_type2(st, PS_INT)) {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_int(st, i1 + i2);
				}
				else {
					r2 = ps_pop_real(st);
					r1 = ps_pop_real(st);
					ps_push_real(st, r1 + r2);
				}
				break;

			case PS_OP_AND:
				if (ps_is_type2(st, PS_INT)) {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_int(st, i1 & i2);
				}
				else {
					b2 = ps_pop_bool(st);
					b1 = ps_pop_bool(st);
					ps_push_bool(st, b1 && b2);
				}
				break;

			case PS_OP_ATAN:
				r2 = ps_pop_real(st);
				r1 = ps_pop_real(st);
				r1 = atan2f(r1, r2) * FZ_RADIAN;
				if (r1 < 0)
					r1 += 360;
				ps_push_real(st, r1);
				break;

			case PS_OP_BITSHIFT:
				i2 = ps_pop_int(st);
				i1 = ps_pop_int(st);
				if (i2 > 0 && i2 < 8 * (int)sizeof (i2))
					ps_push_int(st, i1 << i2);
				else if (i2 < 0 && i2 > -8 * (int)sizeof (i2))
					ps_push_int(st, (int)((unsigned int)i1 >> -i2));
				else
					ps_push_int(st, i1);
				break;

			case PS_OP_CEILING:
				r1 = ps_pop_real(st);
				ps_push_real(st, ceilf(r1));
				break;

			case PS_OP_COPY:
				ps_copy(st, ps_pop_int(st));
				break;

			case PS_OP_COS:
				r1 = ps_pop_real(st);
				ps_push_real(st, cosf(r1/FZ_RADIAN));
				break;

			case PS_OP_CVI:
				ps_push_int(st, ps_pop_int(st));
				break;

			case PS_OP_CVR:
				ps_push_real(st, ps_pop_real(st));
				break;

			case PS_OP_DIV:
				r2 = ps_pop_real(st);
				r1 = ps_pop_real(st);
				if (fabsf(r2) >= FLT_EPSILON)
					ps_push_real(st, r1 / r2);
				else
					ps_push_real(st, DIV_BY_ZERO(r1, r2, -FLT_MAX, FLT_MAX));
				break;

			case PS_OP_DUP:
				ps_copy(st, 1);
				break;

			case PS_OP_EQ:
				if (ps_is_type2(st, PS_BOOL)) {
					b2 = ps_pop_bool(st);
					b1 = ps_pop_bool(st);
					ps_push_bool(st, b1 == b2);
				}
				else if (ps_is_type2(st, PS_INT)) {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_bool(st, i1 == i2);
				}
				else {
					r2 = ps_pop_real(st);
					r1 = ps_pop_real(st);
					ps_push_bool(st, r1 == r2);
				}
				break;

			case PS_OP_EXCH:
				ps_roll(st, 2, 1);
				break;

			case PS_OP_EXP:
				r2 = ps_pop_real(st);
				r1 = ps_pop_real(st);
				ps_push_real(st, powf(r1, r2));
				break;

			case PS_OP_FALSE:
				ps_push_bool(st, 0);
				break;

			case PS_OP_FLOOR:
				r1 = ps_pop_real(st);
				ps_push_real(st, floorf(r1));
				break;

			case PS_OP_GE:
				if (ps_is_type2(st, PS_INT)) {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_bool(st, i1 >= i2);
				}
				else {
					r2 = ps_pop_real(st);
					r1 = ps_pop_real(st);
					ps_push_bool(st, r1 >= r2);
				}
				break;

			case PS_OP_GT:
				if (ps_is_type2(st, PS_INT)) {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_bool(st, i1 > i2);
				}
				else {
					r2 = ps_pop_real(st);
					r1 = ps_pop_real(st);
					ps_push_bool(st, r1 > r2);
				}
				break;

			case PS_OP_IDIV:
				i2 = ps_pop_int(st);
				i1 = ps_pop_int(st);
				if (i2 != 0)
					ps_push_int(st, i1 / i2);
				else
					ps_push_int(st, DIV_BY_ZERO(i1, i2, INT_MIN, INT_MAX));
				break;

			case PS_OP_INDEX:
				ps_index(st, ps_pop_int(st));
				break;

			case PS_OP_LE:
				if (ps_is_type2(st, PS_INT)) {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_bool(st, i1 <= i2);
				}
				else {
					r2 = ps_pop_real(st);
					r1 = ps_pop_real(st);
					ps_push_bool(st, r1 <= r2);
				}
				break;

			case PS_OP_LN:
				r1 = ps_pop_real(st);
				/* Bug 692941 - logf as separate statement */
				r2 = logf(r1);
				ps_push_real(st, r2);
				break;

			case PS_OP_LOG:
				r1 = ps_pop_real(st);
				ps_push_real(st, log10f(r1));
				break;

			case PS_OP_LT:
				if (ps_is_type2(st, PS_INT)) {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_bool(st, i1 < i2);
				}
				else {
					r2 = ps_pop_real(st);
					r1 = ps_pop_real(st);
					ps_push_bool(st, r1 < r2);
				}
				break;

			case PS_OP_MOD:
				i2 = ps_pop_int(st);
				i1 = ps_pop_int(st);
				if (i2 != 0)
					ps_push_int(st, i1 % i2);
				else
					ps_push_int(st, DIV_BY_ZERO(i1, i2, INT_MIN, INT_MAX));
				break;

			case PS_OP_MUL:
				if (ps_is_type2(st, PS_INT)) {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_int(st, i1 * i2);
				}
				else {
					r2 = ps_pop_real(st);
					r1 = ps_pop_real(st);
					ps_push_real(st, r1 * r2);
				}
				break;

			case PS_OP_NE:
				if (ps_is_type2(st, PS_BOOL)) {
					b2 = ps_pop_bool(st);
					b1 = ps_pop_bool(st);
					ps_push_bool(st, b1 != b2);
				}
				else if (ps_is_type2(st, PS_INT)) {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_bool(st, i1 != i2);
				}
				else {
					r2 = ps_pop_real(st);
					r1 = ps_pop_real(st);
					ps_push_bool(st, r1 != r2);
				}
				break;

			case PS_OP_NEG:
				if (ps_is_type(st, PS_INT))
					ps_push_int(st, -ps_pop_int(st));
				else
					ps_push_real(st, -ps_pop_real(st));
				break;

			case PS_OP_NOT:
				if (ps_is_type(st, PS_BOOL))
					ps_push_bool(st, !ps_pop_bool(st));
				else
					ps_push_int(st, ~ps_pop_int(st));
				break;

			case PS_OP_OR:
				if (ps_is_type2(st, PS_BOOL)) {
					b2 = ps_pop_bool(st);
					b1 = ps_pop_bool(st);
					ps_push_bool(st, b1 || b2);
				}
				else {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_int(st, i1 | i2);
				}
				break;

			case PS_OP_POP:
				if (!ps_underflow(st, 1))
					st->sp--;
				break;

			case PS_OP_ROLL:
				i2 = ps_pop_int(st);
				i1 = ps_pop_int(st);
				ps_roll(st, i1, i2);
				break;

			case PS_OP_ROUND:
				if (!ps_is_type(st, PS_INT)) {
					r1 = ps_pop_real(st);
					ps_push_real(st, (r1 >= 0) ? floorf(r1 + 0.5f) : ceilf(r1 - 0.5f));
				}
				break;

			case PS_OP_SIN:
				r1 = ps_pop_real(st);
				ps_push_real(st, sinf(r1/FZ_RADIAN));
				break;

			case PS_OP_SQRT:
				r1 = ps_pop_real(st);
				ps_push_real(st, sqrtf(r1));
				break;

			case PS_OP_SUB:
				if (ps_is_type2(st, PS_INT)) {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_int(st, i1 - i2);
				}
				else {
					r2 = ps_pop_real(st);
					r1 = ps_pop_real(st);
					ps_push_real(st, r1 - r2);
				}
				break;

			case PS_OP_TRUE:
				ps_push_bool(st, 1);
				break;

			case PS_OP_TRUNCATE:
				if (!ps_is_type(st, PS_INT)) {
					r1 = ps_pop_real(st);
					ps_push_real(st, (r1 >= 0) ? floorf(r1) : ceilf(r1));
				}
				break;

			case PS_OP_XOR:
				if (ps_is_type2(st, PS_BOOL)) {
					b2 = ps_pop_bool(st);
					b1 = ps_pop_bool(st);
					ps_push_bool(st, b1 ^ b2);
				}
				else {
					i2 = ps_pop_int(st);
					i1 = ps_pop_int(st);
					ps_push_int(st, i1 ^ i2);
				}
				break;

			case PS_OP_IF:
				b1 = ps_pop_bool(st);
				if (b1)
					ps_run(ctx, code, st, code[pc + 1].u.block);
				pc = code[pc + 2].u.block;
				break;

			case PS_OP_IFELSE:
				b1 = ps_pop_bool(st);
				if (b1)
					ps_run(ctx, code, st, code[pc + 1].u.block);
				else
					ps_run(ctx, code, st, code[pc + 0].u.block);
				pc = code[pc + 2].u.block;
				break;

			case PS_OP_RETURN:
				return;

			default:
				fz_warn(ctx, "foreign operator in calculator function");
				return;
			}
			break;

		default:
			fz_warn(ctx, "foreign object in calculator function");
			return;
		}
	}
}

static void
resize_code(fz_context *ctx, pdf_function_p *func, int newsize)
{
	if (newsize >= func->cap)
	{
		int new_cap = func->cap + 64;
		func->code = fz_realloc_array(ctx, func->code, new_cap, psobj);
		func->cap = new_cap;
	}
}

static void
parse_code(fz_context *ctx, pdf_function_p *func, fz_stream *stream, int *codeptr, pdf_lexbuf *buf, int depth)
{
	pdf_token tok;
	int opptr, elseptr, ifptr;
	int a, b, mid, cmp;

	if (depth > 100)
		fz_throw(ctx, FZ_ERROR_SYNTAX, "too much nesting in calculator function");

	while (1)
	{
		tok = pdf_lex(ctx, stream, buf);

		switch (tok)
		{
		case PDF_TOK_EOF:
			fz_throw(ctx, FZ_ERROR_SYNTAX, "truncated calculator function");

		case PDF_TOK_INT:
			resize_code(ctx, func, *codeptr);
			func->code[*codeptr].type = PS_INT;
			func->code[*codeptr].u.i = buf->i;
			++*codeptr;
			break;

		case PDF_TOK_TRUE:
			resize_code(ctx, func, *codeptr);
			func->code[*codeptr].type = PS_BOOL;
			func->code[*codeptr].u.b = 1;
			++*codeptr;
			break;

		case PDF_TOK_FALSE:
			resize_code(ctx, func, *codeptr);
			func->code[*codeptr].type = PS_BOOL;
			func->code[*codeptr].u.b = 0;
			++*codeptr;
			break;

		case PDF_TOK_REAL:
			resize_code(ctx, func, *codeptr);
			func->code[*codeptr].type = PS_REAL;
			func->code[*codeptr].u.f = buf->f;
			++*codeptr;
			break;

		case PDF_TOK_OPEN_BRACE:
			opptr = *codeptr;
			*codeptr += 4;

			resize_code(ctx, func, *codeptr);

			ifptr = *codeptr;
			parse_code(ctx, func, stream, codeptr, buf, depth + 1);

			tok = pdf_lex(ctx, stream, buf);

			if (tok == PDF_TOK_OPEN_BRACE)
			{
				elseptr = *codeptr;
				parse_code(ctx, func, stream, codeptr, buf, depth + 1);

				tok = pdf_lex(ctx, stream, buf);
			}
			else
			{
				elseptr = -1;
			}

			if (tok != PDF_TOK_KEYWORD)
				fz_throw(ctx, FZ_ERROR_SYNTAX, "missing keyword in 'if-else' context");

			if (!strcmp(buf->scratch, "if"))
			{
				if (elseptr >= 0)
					fz_throw(ctx, FZ_ERROR_SYNTAX, "too many branches for 'if'");
				func->code[opptr].type = PS_OPERATOR;
				func->code[opptr].u.op = PS_OP_IF;
				func->code[opptr+2].type = PS_BLOCK;
				func->code[opptr+2].u.block = ifptr;
				func->code[opptr+3].type = PS_BLOCK;
				func->code[opptr+3].u.block = *codeptr;
			}
			else if (!strcmp(buf->scratch, "ifelse"))
			{
				if (elseptr < 0)
					fz_throw(ctx, FZ_ERROR_SYNTAX, "not enough branches for 'ifelse'");
				func->code[opptr].type = PS_OPERATOR;
				func->code[opptr].u.op = PS_OP_IFELSE;
				func->code[opptr+1].type = PS_BLOCK;
				func->code[opptr+1].u.block = elseptr;
				func->code[opptr+2].type = PS_BLOCK;
				func->code[opptr+2].u.block = ifptr;
				func->code[opptr+3].type = PS_BLOCK;
				func->code[opptr+3].u.block = *codeptr;
			}
			else
			{
				fz_throw(ctx, FZ_ERROR_SYNTAX, "unknown keyword in 'if-else' context: '%s'", buf->scratch);
			}
			break;

		case PDF_TOK_CLOSE_BRACE:
			resize_code(ctx, func, *codeptr);
			func->code[*codeptr].type = PS_OPERATOR;
			func->code[*codeptr].u.op = PS_OP_RETURN;
			++*codeptr;
			return;

		case PDF_TOK_KEYWORD:
			cmp = -1;
			a = -1;
			b = nelem(ps_op_names);
			while (b - a > 1)
			{
				mid = (a + b) / 2;
				cmp = strcmp(buf->scratch, ps_op_names[mid]);
				if (cmp > 0)
					a = mid;
				else if (cmp < 0)
					b = mid;
				else
					a = b = mid;
			}
			if (cmp != 0)
				fz_throw(ctx, FZ_ERROR_SYNTAX, "unknown operator: '%s'", buf->scratch);
			if (a == PS_OP_IFELSE)
				fz_throw(ctx, FZ_ERROR_SYNTAX, "illegally positioned ifelse operator in function");
			if (a == PS_OP_IF)
				fz_throw(ctx, FZ_ERROR_SYNTAX, "illegally positioned if operator in function");

			resize_code(ctx, func, *codeptr);
			func->code[*codeptr].type = PS_OPERATOR;
			func->code[*codeptr].u.op = a;
			++*codeptr;
			break;

		default:
			fz_throw(ctx, FZ_ERROR_SYNTAX, "calculator function syntax error");
		}
	}
}

static void
load_postscript_func(fz_context *ctx, pdf_function *func_, pdf_obj *dict)
{
	pdf_function_p *func = (pdf_function_p *)func_;
	fz_stream *stream = NULL;
	int codeptr;
	pdf_lexbuf buf;
	pdf_token tok;

	pdf_lexbuf_init(ctx, &buf, PDF_LEXBUF_SMALL);

	fz_var(stream);

	fz_try(ctx)
	{
		stream = pdf_open_stream(ctx, dict);

		tok = pdf_lex(ctx, stream, &buf);
		if (tok != PDF_TOK_OPEN_BRACE)
		{
			fz_throw(ctx, FZ_ERROR_SYNTAX, "stream is not a calculator function");
		}

		func->code = NULL;
		func->cap = 0;

		codeptr = 0;
		parse_code(ctx, func, stream, &codeptr, &buf, 0);
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, stream);
		pdf_lexbuf_fin(ctx, &buf);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	func->super.super.size += func->cap * sizeof(psobj);
}

static void
eval_postscript_func(fz_context *ctx, fz_function *func_, const float *in, float *out)
{
	pdf_function_p *func = (pdf_function_p *)func_;
	ps_stack st;
	float x;
	int i;

	ps_init_stack(&st);

	for (i = 0; i < func->super.super.m; i++)
	{
		x = fz_clamp(in[i], func->super.domain[i][0], func->super.domain[i][1]);
		ps_push_real(&st, x);
	}

	ps_run(ctx, func->code, &st, 0);

	for (i = func->super.super.n - 1; i >= 0; i--)
	{
		x = ps_pop_real(&st);
		out[i] = fz_clamp(x, func->super.range[i][0], func->super.range[i][1]);
	}
}

/*
 * Sample function
 */

#define MAX_SAMPLE_FUNCTION_SIZE (100 << 20)

static void
load_sample_func(fz_context *ctx, pdf_function *func_, pdf_obj *dict)
{
	pdf_function_sa *func = (pdf_function_sa *)func_;
	fz_stream *stream;
	pdf_obj *obj;
	int samplecount;
	int bps;
	int i;

	func->samples = NULL;

	obj = pdf_dict_get(ctx, dict, PDF_NAME(Size));
	if (pdf_array_len(ctx, obj) < func->super.super.m)
		fz_throw(ctx, FZ_ERROR_SYNTAX, "too few sample function dimension sizes");
	if (pdf_array_len(ctx, obj) > func->super.super.m)
		fz_warn(ctx, "too many sample function dimension sizes");
	for (i = 0; i < func->super.super.m; i++)
	{
		func->size[i] = pdf_array_get_int(ctx, obj, i);
		if (func->size[i] <= 0)
		{
			fz_warn(ctx, "non-positive sample function dimension size");
			func->size[i] = 1;
		}
	}

	func->bps = bps = pdf_dict_get_int(ctx, dict, PDF_NAME(BitsPerSample));

	for (i = 0; i < func->super.super.m; i++)
	{
		func->encode[i][0] = 0;
		func->encode[i][1] = func->size[i] - 1;
	}
	obj = pdf_dict_get(ctx, dict, PDF_NAME(Encode));
	if (pdf_is_array(ctx, obj))
	{
		int ranges = fz_mini(func->super.super.m, pdf_array_len(ctx, obj) / 2);
		if (ranges != func->super.super.m)
			fz_warn(ctx, "wrong number of sample function input mappings");

		for (i = 0; i < ranges; i++)
		{
			func->encode[i][0] = pdf_array_get_real(ctx, obj, i * 2 + 0);
			func->encode[i][1] = pdf_array_get_real(ctx, obj, i * 2 + 1);
		}
	}

	for (i = 0; i < func->super.super.n; i++)
	{
		func->decode[i][0] = func->super.range[i][0];
		func->decode[i][1] = func->super.range[i][1];
	}

	obj = pdf_dict_get(ctx, dict, PDF_NAME(Decode));
	if (pdf_is_array(ctx, obj))
	{
		int ranges = fz_mini(func->super.super.n, pdf_array_len(ctx, obj) / 2);
		if (ranges != func->super.super.n)
			fz_warn(ctx, "wrong number of sample function output mappings");

		for (i = 0; i < ranges; i++)
		{
			func->decode[i][0] = pdf_array_get_real(ctx, obj, i * 2 + 0);
			func->decode[i][1] = pdf_array_get_real(ctx, obj, i * 2 + 1);
		}
	}

	for (i = 0, samplecount = func->super.super.n; i < func->super.super.m; i++)
	{
		if (samplecount > MAX_SAMPLE_FUNCTION_SIZE / func->size[i])
			fz_throw(ctx, FZ_ERROR_SYNTAX, "sample function too large");
		samplecount *= func->size[i];
	}

	if (samplecount > MAX_SAMPLE_FUNCTION_SIZE)
		fz_throw(ctx, FZ_ERROR_SYNTAX, "sample function too large");

	func->samples = Memento_label(fz_malloc_array(ctx, samplecount, float), "function_samples");
	func->super.super.size += samplecount * sizeof(float);

	stream = pdf_open_stream(ctx, dict);

	fz_try(ctx)
	{
		/* read samples */
		for (i = 0; i < samplecount; i++)
		{
			float s;

			if (fz_is_eof_bits(ctx, stream))
				fz_throw(ctx, FZ_ERROR_SYNTAX, "truncated sample function stream");

			switch (bps)
			{
			case 1: s = fz_read_bits(ctx, stream, 1); break;
			case 2: s = fz_read_bits(ctx, stream, 2) / 3.0f; break;
			case 4: s = fz_read_bits(ctx, stream, 4) / 15.0f; break;
			case 8: s = fz_read_byte(ctx, stream) / 255.0f; break;
			case 12: s = fz_read_bits(ctx, stream, 12) / 4095.0f; break;
			case 16: s = fz_read_uint16(ctx, stream) / 65535.0f; break;
			case 24: s = fz_read_uint24(ctx, stream) / 16777215.0f; break;
			case 32: s = fz_read_uint32(ctx, stream) / 4294967295.0f; break;
			default: fz_throw(ctx, FZ_ERROR_SYNTAX, "sample stream bit depth %d unsupported", bps);
			}

			func->samples[i] = s;
		}
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, stream);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static float
interpolate_sample(pdf_function_sa *func, int *scale, int *e0, int *e1, float *efrac, int dim, int idx)
{
	float a, b;
	int idx0, idx1;

	idx0 = e0[dim] * scale[dim] + idx;
	idx1 = e1[dim] * scale[dim] + idx;

	if (dim == 0)
	{
		a = func->samples[idx0];
		b = func->samples[idx1];
	}
	else
	{
		a = interpolate_sample(func, scale, e0, e1, efrac, dim - 1, idx0);
		b = interpolate_sample(func, scale, e0, e1, efrac, dim - 1, idx1);
	}

	return a + (b - a) * efrac[dim];
}

static void
eval_sample_func(fz_context *ctx, fz_function *func_, const float *in, float *out)
{
	pdf_function_sa *func = (pdf_function_sa *)func_;
	int e0[MAX_M], e1[MAX_M], scale[MAX_M];
	float efrac[MAX_M];
	float x;
	int i;

	/* encode input coordinates */
	for (i = 0; i < func->super.super.m; i++)
	{
		x = fz_clamp(in[i], func->super.domain[i][0], func->super.domain[i][1]);
		x = lerp(x, func->super.domain[i][0], func->super.domain[i][1],
			func->encode[i][0], func->encode[i][1]);
		x = fz_clamp(x, 0, func->size[i] - 1);
		e0[i] = floorf(x);
		e1[i] = ceilf(x);
		efrac[i] = x - e0[i];
	}

	scale[0] = func->super.super.n;
	for (i = 1; i < func->super.super.m; i++)
		scale[i] = scale[i - 1] * func->size[i-1];

	for (i = 0; i < func->super.super.n; i++)
	{
		if (func->super.super.m == 1)
		{
			float a = func->samples[e0[0] * func->super.super.n + i];
			float b = func->samples[e1[0] * func->super.super.n + i];

			float ab = a + (b - a) * efrac[0];

			out[i] = lerp(ab, 0, 1, func->decode[i][0], func->decode[i][1]);
			out[i] = fz_clamp(out[i], func->super.range[i][0], func->super.range[i][1]);
		}

		else if (func->super.super.m == 2)
		{
			int s0 = func->super.super.n;
			int s1 = s0 * func->size[0];

			float a = func->samples[e0[0] * s0 + e0[1] * s1 + i];
			float b = func->samples[e1[0] * s0 + e0[1] * s1 + i];
			float c = func->samples[e0[0] * s0 + e1[1] * s1 + i];
			float d = func->samples[e1[0] * s0 + e1[1] * s1 + i];

			float ab = a + (b - a) * efrac[0];
			float cd = c + (d - c) * efrac[0];
			float abcd = ab + (cd - ab) * efrac[1];

			out[i] = lerp(abcd, 0, 1, func->decode[i][0], func->decode[i][1]);
			out[i] = fz_clamp(out[i], func->super.range[i][0], func->super.range[i][1]);
		}

		else
		{
			x = interpolate_sample(func, scale, e0, e1, efrac, func->super.super.m - 1, i);
			out[i] = lerp(x, 0, 1, func->decode[i][0], func->decode[i][1]);
			out[i] = fz_clamp(out[i], func->super.range[i][0], func->super.range[i][1]);
		}
	}
}

/*
 * Exponential function
 */

static void
load_exponential_func(fz_context *ctx, pdf_function *func_, pdf_obj *dict)
{
	pdf_function_e *func = (pdf_function_e *)func_;
	pdf_obj *obj;
	int i;

	if (func->super.super.m > 1)
		fz_warn(ctx, "exponential functions have at most one input");
	func->super.super.m = 1;

	func->n = pdf_dict_get_real(ctx, dict, PDF_NAME(N));

	/* See exponential functions (PDF 1.7 section 3.9.2) */
	if (func->n != (int) func->n)
	{
		/* If N is non-integer, input values may never be negative */
		for (i = 0; i < func->super.super.m; i++)
			if (func->super.domain[i][0] < 0 || func->super.domain[i][1] < 0)
				fz_warn(ctx, "exponential function input domain includes illegal negative input values");
	}
	else if (func->n < 0)
	{
		/* if N is negative, input values may never be zero */
		for (i = 0; i < func->super.super.m; i++)
			if (func->super.domain[i][0] == 0 || func->super.domain[i][1] == 0 ||
				(func->super.domain[i][0] < 0 && func->super.domain[i][1] > 0))
				fz_warn(ctx, "exponential function input domain includes illegal input value zero");
	}

	for (i = 0; i < func->super.super.n; i++)
	{
		func->c0[i] = 0;
		func->c1[i] = 1;
	}

	obj = pdf_dict_get(ctx, dict, PDF_NAME(C0));
	if (pdf_is_array(ctx, obj))
	{
		int ranges = fz_mini(func->super.super.n, pdf_array_len(ctx, obj));
		if (ranges != func->super.super.n)
			fz_warn(ctx, "wrong number of C0 constants for exponential function");

		for (i = 0; i < ranges; i++)
			func->c0[i] = pdf_array_get_real(ctx, obj, i);
	}

	obj = pdf_dict_get(ctx, dict, PDF_NAME(C1));
	if (pdf_is_array(ctx, obj))
	{
		int ranges = fz_mini(func->super.super.n, pdf_array_len(ctx, obj));
		if (ranges != func->super.super.n)
			fz_warn(ctx, "wrong number of C1 constants for exponential function");

		for (i = 0; i < ranges; i++)
			func->c1[i] = pdf_array_get_real(ctx, obj, i);
	}
}

static void
eval_exponential_func(fz_context *ctx, fz_function *func_, const float *in, float *out)
{
	pdf_function_e *func = (pdf_function_e *)func_;
	float x = *in;
	float tmp;
	int i;

	x = fz_clamp(x, func->super.domain[0][0], func->super.domain[0][1]);

	/* Default output is zero, which is suitable for violated constraints */
	if ((func->n != (int)func->n && x < 0) || (func->n < 0 && x == 0))
	{
		for (i = 0; i < func->super.super.n; i++)
			out[i] = 0;
		return;
	}

	tmp = powf(x, func->n);
	for (i = 0; i < func->super.super.n; i++)
	{
		out[i] = func->c0[i] + tmp * (func->c1[i] - func->c0[i]);
		if (func->super.has_range)
			out[i] = fz_clamp(out[i], func->super.range[i][0], func->super.range[i][1]);
	}
}

/*
 * Stitching function
 */

static void
load_stitching_func(fz_context *ctx, pdf_function *func_, pdf_obj *dict, pdf_cycle_list *cycle_up)
{
	pdf_function_st *func =  (pdf_function_st *)func_;
	pdf_function **funcs;
	pdf_obj *obj;
	pdf_obj *sub;
	int k;
	int i;

	func->k = 0;

	if (func->super.super.m > 1)
		fz_warn(ctx, "stitching functions have at most one input");
	func->super.super.m = 1;

	obj = pdf_dict_get(ctx, dict, PDF_NAME(Functions));
	if (!pdf_is_array(ctx, obj))
		fz_throw(ctx, FZ_ERROR_SYNTAX, "stitching function has no input functions");

	k = pdf_array_len(ctx, obj);

	func->funcs = Memento_label(fz_malloc_array(ctx, k, pdf_function*), "stitch_fns");
	func->bounds = Memento_label(fz_malloc_array(ctx, k - 1, float), "stitch_bounds");
	func->encode = Memento_label(fz_malloc_array(ctx, k * 2, float), "stitch_encode");
	funcs = func->funcs;

	for (i = 0; i < k; i++)
	{
		sub = pdf_array_get(ctx, obj, i);
		funcs[i] = pdf_load_function_imp(ctx, sub, 1, func->super.super.n, cycle_up);

		func->super.super.size += pdf_function_size(ctx, funcs[i]);
		func->k ++;

		if (funcs[i]->super.m != func->super.super.m)
			fz_warn(ctx, "wrong number of inputs for sub function %d", i);
		if (funcs[i]->super.n != func->super.super.n)
			fz_warn(ctx, "wrong number of outputs for sub function %d", i);
	}

	obj = pdf_dict_get(ctx, dict, PDF_NAME(Bounds));
	if (!pdf_is_array(ctx, obj))
		fz_throw(ctx, FZ_ERROR_SYNTAX, "stitching function has no bounds");
	{
		if (pdf_array_len(ctx, obj) < k - 1)
			fz_throw(ctx, FZ_ERROR_SYNTAX, "too few subfunction boundaries");
		if (pdf_array_len(ctx, obj) > k)
			fz_warn(ctx, "too many subfunction boundaries");

		for (i = 0; i < k - 1; i++)
		{
			func->bounds[i] = pdf_array_get_real(ctx, obj, i);
			if (i && func->bounds[i - 1] > func->bounds[i])
				fz_throw(ctx, FZ_ERROR_SYNTAX, "subfunction %d boundary out of range", i);
		}

		if (k > 1 && (func->super.domain[0][0] > func->bounds[0] ||
			func->super.domain[0][1] < func->bounds[k - 2]))
			fz_warn(ctx, "subfunction boundaries outside of input mapping");
	}

	for (i = 0; i < k; i++)
	{
		func->encode[i * 2 + 0] = 0;
		func->encode[i * 2 + 1] = 0;
	}

	obj = pdf_dict_get(ctx, dict, PDF_NAME(Encode));
	if (pdf_is_array(ctx, obj))
	{
		int ranges = fz_mini(k, pdf_array_len(ctx, obj) / 2);
		if (ranges != k)
			fz_warn(ctx, "wrong number of stitching function input mappings");

		for (i = 0; i < ranges; i++)
		{
			func->encode[i * 2 + 0] = pdf_array_get_real(ctx, obj, i * 2 + 0);
			func->encode[i * 2 + 1] = pdf_array_get_real(ctx, obj, i * 2 + 1);
		}
	}
}

static void
eval_stitching_func(fz_context *ctx, fz_function *func_, const float *inp, float *out)
{
	pdf_function_st *func = (pdf_function_st *)func_;
	float low, high;
	int k = func->k;
	float *bounds = func->bounds;
	int i;
	float in = fz_clamp(*inp, func->super.domain[0][0], func->super.domain[0][1]);

	for (i = 0; i < k - 1; i++)
	{
		if (in < bounds[i])
			break;
	}

	if (i == 0 && k == 1)
	{
		low = func->super.domain[0][0];
		high = func->super.domain[0][1];
	}
	else if (i == 0)
	{
		low = func->super.domain[0][0];
		high = bounds[0];
	}
	else if (i == k - 1)
	{
		low = bounds[k - 2];
		high = func->super.domain[0][1];
	}
	else
	{
		low = bounds[i - 1];
		high = bounds[i];
	}

	in = lerp(in, low, high, func->encode[i * 2 + 0], func->encode[i * 2 + 1]);

	pdf_eval_function(ctx, func->funcs[i], &in, 1, out, func->super.super.n);
}

/*
 * Common
 */

static void
pdf_drop_function_sa(fz_context *ctx, fz_storable *func_)
{
	pdf_function_sa *func = (pdf_function_sa *)func_;

	fz_free(ctx, func->samples);
	fz_free(ctx, func);
}

static void
pdf_drop_function_e(fz_context *ctx, fz_storable *func)
{
	fz_free(ctx, func);
}

static void
pdf_drop_function_st(fz_context *ctx, fz_storable *func_)
{
	pdf_function_st *func = (pdf_function_st *)func_;
	int i;

	for (i = 0; i < func->k; i++)
		pdf_drop_function(ctx, func->funcs[i]);
	fz_free(ctx, func->funcs);
	fz_free(ctx, func->bounds);
	fz_free(ctx, func->encode);
	fz_free(ctx, func);
}

static void
pdf_drop_function_p(fz_context *ctx, fz_storable *func_)
{
	pdf_function_p *func = (pdf_function_p *)func_;

	fz_free(ctx, func->code);
	fz_free(ctx, func);
}

void
pdf_eval_function(fz_context *ctx, pdf_function *func, const float *in, int inlen, float *out, int outlen)
{
	fz_eval_function(ctx, &func->super, in, inlen, out, outlen);
}

static pdf_function *
pdf_load_function_imp(fz_context *ctx, pdf_obj *dict, int in, int out, pdf_cycle_list *cycle_up)
{
	pdf_cycle_list cycle;
	pdf_function *func;
	pdf_obj *obj;
	int i;
	int type;
	fz_store_drop_fn *drop;

	if (pdf_cycle(ctx, &cycle, cycle_up, dict))
		fz_throw(ctx, FZ_ERROR_SYNTAX, "recursive function");

	type = pdf_dict_get_int(ctx, dict, PDF_NAME(FunctionType));

	switch (type)
	{
	case SAMPLE:
		drop = pdf_drop_function_sa;
		break;

	case EXPONENTIAL:
		drop = pdf_drop_function_e;
		break;

	case STITCHING:
		drop = pdf_drop_function_st;
		break;

	case POSTSCRIPT:
		drop = pdf_drop_function_p;
		break;

	default:
		fz_throw(ctx, FZ_ERROR_SYNTAX, "unknown function type (%d 0 R)", pdf_to_num(ctx, dict));
	}

	if ((func = pdf_find_item(ctx, drop, dict)) != NULL)
		return func;

	switch (type)
	{
	case SAMPLE:
		func = &fz_new_derived_function(ctx, pdf_function_sa, sizeof(pdf_function_sa), 1, 1, eval_sample_func, pdf_drop_function_sa)->super;
		break;

	case EXPONENTIAL:
		func = &fz_new_derived_function(ctx, pdf_function_e, sizeof(pdf_function_e), 1, 1, eval_exponential_func, pdf_drop_function_e)->super;
		break;

	case STITCHING:
		func = &fz_new_derived_function(ctx, pdf_function_st, sizeof(pdf_function_st), 1, 1, eval_stitching_func, pdf_drop_function_st)->super;
		break;

	case POSTSCRIPT:
		func = &fz_new_derived_function(ctx, pdf_function_p, sizeof(pdf_function_p), 1, 1, eval_postscript_func, pdf_drop_function_p)->super;
		break;
	}

	/* required for all */
	obj = pdf_dict_get(ctx, dict, PDF_NAME(Domain));
	func->super.m = fz_clampi(pdf_array_len(ctx, obj) / 2, 1, MAX_M);
	for (i = 0; i < func->super.m; i++)
	{
		func->domain[i][0] = pdf_array_get_real(ctx, obj, i * 2 + 0);
		func->domain[i][1] = pdf_array_get_real(ctx, obj, i * 2 + 1);
	}

	/* required for type0 and type4, optional otherwise */
	obj = pdf_dict_get(ctx, dict, PDF_NAME(Range));
	if (pdf_is_array(ctx, obj))
	{
		func->has_range = 1;
		func->super.n = fz_clampi(pdf_array_len(ctx, obj) / 2, 1, MAX_N);
		for (i = 0; i < func->super.n; i++)
		{
			func->range[i][0] = pdf_array_get_real(ctx, obj, i * 2 + 0);
			func->range[i][1] = pdf_array_get_real(ctx, obj, i * 2 + 1);
		}
	}
	else
	{
		func->has_range = 0;
		func->super.n = out;
	}

	if (func->super.m != in)
		fz_warn(ctx, "wrong number of function inputs");
	if (func->super.n != out)
		fz_warn(ctx, "wrong number of function outputs");

	fz_try(ctx)
	{
		switch (type)
		{
		case SAMPLE:
			load_sample_func(ctx, func, dict);
			break;

		case EXPONENTIAL:
			load_exponential_func(ctx, func, dict);
			break;

		case STITCHING:
			load_stitching_func(ctx, func, dict, &cycle);
			break;

		case POSTSCRIPT:
			load_postscript_func(ctx, func, dict);
			break;

		default:
			fz_throw(ctx, FZ_ERROR_SYNTAX, "unknown function type (%d 0 R)", pdf_to_num(ctx, dict));
		}

		pdf_store_item(ctx, dict, func, func->super.size);
	}
	fz_catch(ctx)
	{
		pdf_drop_function(ctx, func);
		fz_rethrow(ctx);
	}

	return func;
}

pdf_function *
pdf_load_function(fz_context *ctx, pdf_obj *dict, int in, int out)
{
	return pdf_load_function_imp(ctx, dict, in, out, NULL);
}
