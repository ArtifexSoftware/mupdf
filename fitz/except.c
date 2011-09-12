#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "except.h"

static void do_throw(fz_except_context *ex)
{
    if(ex->depth >= 0)
        longjmp(ex->stack[ex->depth].buffer, 1);
    else {
        printf("Uncaught exception: %s\n", ex->except.mess);
        exit(EXIT_FAILURE);           /* Bale through normal channels */
    }
}

void fz_throw(fz_context *ctx, char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vsprintf(ctx->except->except.mess, fmt, args);
    va_end(args);
    do_throw(ctx->except);
}

fz_except *fz_caught(fz_context *ctx)
{
    return &ctx->except->except;
}

void fz_rethrow(fz_context *ctx)
{
    do_throw(ctx->except);
}

void fz_except_xxx_push(fz_except_context *ex)
{
    if(ex->depth+1 >= MAXDEPTH) {
        fprintf(stderr, "Exception stack overflow!\n");
        exit(EXIT_FAILURE);           /* Bale through normal channels */
    }
    ex->depth++;
}

void fz_var_xxx(void *e)
{
    /* Do nothing */
}
