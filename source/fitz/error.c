// Copyright (C) 2004-2022 Artifex Software, Inc.
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
// Artifex Software, Inc., 1305 Grant Avenue - Suite 200, Novato,
// CA 94945, U.S.A., +1(415)492-9861, for further information.

#include "mupdf/fitz.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#ifndef NDEBUG
#define USE_OUTPUT_DEBUG_STRING
#include <windows.h>
#endif
#endif

#ifdef __ANDROID__
#define USE_ANDROID_LOG
#include <android/log.h>
#endif

void fz_default_error_callback(void *user, const char *message)
{
	fprintf(stderr, "error: %s\n", message);
#ifdef USE_OUTPUT_DEBUG_STRING
	OutputDebugStringA("error: ");
	OutputDebugStringA(message);
	OutputDebugStringA("\n");
#endif
#ifdef USE_ANDROID_LOG
	__android_log_print(ANDROID_LOG_ERROR, "libmupdf", "%s", message);
#endif
}

void fz_default_warning_callback(void *user, const char *message)
{
	fprintf(stderr, "warning: %s\n", message);
#ifdef USE_OUTPUT_DEBUG_STRING
	OutputDebugStringA("warning: ");
	OutputDebugStringA(message);
	OutputDebugStringA("\n");
#endif
#ifdef USE_ANDROID_LOG
	__android_log_print(ANDROID_LOG_WARN, "libmupdf", "%s", message);
#endif
}

/* Warning context */

void fz_set_warning_callback(fz_context *ctx, fz_warning_cb *warning_cb, void *user)
{
	ctx->warn.print_user = user;
	ctx->warn.print = warning_cb;
}

fz_warning_cb *fz_warning_callback(fz_context *ctx, void **user)
{
	if (user)
		*user = ctx->warn.print_user;
	return ctx->warn.print;
}

void fz_var_imp(void *var)
{
	/* Do nothing */
}

void fz_flush_warnings(fz_context *ctx)
{
	if (ctx->warn.count > 1)
	{
		char buf[50];
		fz_snprintf(buf, sizeof buf, "... repeated %d times...", ctx->warn.count);
		if (ctx->warn.print)
			ctx->warn.print(ctx->warn.print_user, buf);
	}
	ctx->warn.message[0] = 0;
	ctx->warn.count = 0;
}

void fz_vwarn(fz_context *ctx, const char *fmt, va_list ap)
{
	char buf[sizeof ctx->warn.message];

	fz_vsnprintf(buf, sizeof buf, fmt, ap);
	buf[sizeof(buf) - 1] = 0;

	if (!strcmp(buf, ctx->warn.message))
	{
		ctx->warn.count++;
	}
	else
	{
		fz_flush_warnings(ctx);
		if (ctx->warn.print)
			ctx->warn.print(ctx->warn.print_user, buf);
		fz_strlcpy(ctx->warn.message, buf, sizeof ctx->warn.message);
		ctx->warn.count = 1;
	}
}

void fz_warn(fz_context *ctx, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fz_vwarn(ctx, fmt, ap);
	va_end(ap);
}

/* Error context */

void fz_set_error_callback(fz_context *ctx, fz_error_cb *error_cb, void *user)
{
	ctx->error.print_user = user;
	ctx->error.print = error_cb;
}

fz_error_cb *fz_error_callback(fz_context *ctx, void **user)
{
	if (user)
		*user = ctx->error.print_user;
	return ctx->error.print;
}

/* When we first setjmp, state is set to 0. Whenever we throw, we add 2 to
 * this state. Whenever we enter the always block, we add 1.
 *
 * fz_push_try sets state to 0.
 * If (fz_throw called within fz_try)
 *     fz_throw makes state = 2.
 *     If (no always block present)
 *         enter catch region with state = 2. OK.
 *     else
 *         fz_always entered as state < 3; Makes state = 3;
 *         if (fz_throw called within fz_always)
 *             fz_throw makes state = 5
 *             fz_always is not reentered.
 *             catch region entered with state = 5. OK.
 *         else
 *             catch region entered with state = 3. OK
 * else
 *     if (no always block present)
 *         catch region not entered as state = 0. OK.
 *     else
 *         fz_always entered as state < 3. makes state = 1
 *         if (fz_throw called within fz_always)
 *             fz_throw makes state = 3;
 *             fz_always NOT entered as state >= 3
 *             catch region entered with state = 3. OK.
 *         else
 *             catch region entered with state = 1.
 */

FZ_NORETURN static void throw(fz_context *ctx, int code)
{
	if (ctx->error.top > ctx->error.stack_base)
	{
		ctx->error.top->state += 2;
		if (ctx->error.top->code != FZ_ERROR_NONE)
			fz_warn(ctx, "clobbering previous error code and message (throw in always block?)");
		ctx->error.top->code = code;
		fz_longjmp(ctx->error.top->buffer, 1);
	}
	else
	{
		fz_flush_warnings(ctx);
		if (ctx->error.print)
			ctx->error.print(ctx->error.print_user, "aborting process from uncaught error!");
		exit(EXIT_FAILURE);
	}
}

fz_jmp_buf *fz_push_try(fz_context *ctx)
{
	/* If we would overflow the exception stack, throw an exception instead
	 * of entering the try block. We assume that we always have room for
	 * 1 extra level on the stack here - i.e. we throw the error on us
	 * starting to use the last level. */
	if (ctx->error.top + 2 >= ctx->error.stack_base + nelem(ctx->error.stack))
	{
		fz_strlcpy(ctx->error.message, "exception stack overflow!", sizeof ctx->error.message);

		fz_flush_warnings(ctx);
		if (ctx->error.print)
			ctx->error.print(ctx->error.print_user, ctx->error.message);

		/* We need to arrive in the always/catch block as if throw had taken place. */
		ctx->error.top++;
		ctx->error.top->state = 2;
		ctx->error.top->code = FZ_ERROR_GENERIC;
	}
	else
	{
		ctx->error.top++;
		ctx->error.top->state = 0;
		ctx->error.top->code = FZ_ERROR_NONE;
	}
	return &ctx->error.top->buffer;
}

int fz_do_try(fz_context *ctx)
{
#ifdef __COVERITY__
	return 1;
#else
	return ctx->error.top->state == 0;
#endif
}

int fz_do_always(fz_context *ctx)
{
#ifdef __COVERITY__
	return 1;
#else
	if (ctx->error.top->state < 3)
	{
		ctx->error.top->state++;
		return 1;
	}
	return 0;
#endif
}

int fz_do_catch(fz_context *ctx)
{
	ctx->error.errcode = ctx->error.top->code;
	return (ctx->error.top--)->state > 1;
}

int fz_caught(fz_context *ctx)
{
	assert(ctx && ctx->error.errcode >= FZ_ERROR_NONE);
	return ctx->error.errcode;
}

const char *fz_caught_message(fz_context *ctx)
{
	assert(ctx && ctx->error.errcode >= FZ_ERROR_NONE);
	return ctx->error.message;
}

/* coverity[+kill] */
FZ_NORETURN void fz_vthrow(fz_context *ctx, int code, const char *fmt, va_list ap)
{
	fz_vsnprintf(ctx->error.message, sizeof ctx->error.message, fmt, ap);
	ctx->error.message[sizeof(ctx->error.message) - 1] = 0;

	if (code != FZ_ERROR_ABORT && code != FZ_ERROR_TRYLATER)
	{
		fz_flush_warnings(ctx);
		if (ctx->error.print)
			ctx->error.print(ctx->error.print_user, ctx->error.message);
	}

	throw(ctx, code);
}

/* coverity[+kill] */
FZ_NORETURN void fz_throw(fz_context *ctx, int code, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fz_vthrow(ctx, code, fmt, ap);
	va_end(ap);
}

/* coverity[+kill] */
FZ_NORETURN void fz_rethrow(fz_context *ctx)
{
	assert(ctx && ctx->error.errcode >= FZ_ERROR_NONE);
	throw(ctx, ctx->error.errcode);
}

void fz_morph_error(fz_context *ctx, int fromerr, int toerr)
{
	assert(ctx && ctx->error.errcode >= FZ_ERROR_NONE);
	if (ctx->error.errcode == fromerr)
		ctx->error.errcode = toerr;
}

void fz_rethrow_if(fz_context *ctx, int err)
{
	assert(ctx && ctx->error.errcode >= FZ_ERROR_NONE);
	if (ctx->error.errcode == err)
		fz_rethrow(ctx);
}

void fz_start_throw_on_repair(fz_context *ctx)
{
	fz_lock(ctx, FZ_LOCK_ALLOC);
	ctx->throw_on_repair++;
	fz_unlock(ctx, FZ_LOCK_ALLOC);
}

void fz_end_throw_on_repair(fz_context *ctx)
{
	fz_lock(ctx, FZ_LOCK_ALLOC);
	ctx->throw_on_repair--;
	fz_unlock(ctx, FZ_LOCK_ALLOC);
}
