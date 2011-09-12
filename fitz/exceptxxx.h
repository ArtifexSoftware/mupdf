#ifndef EXCEPTXXX_H
#define EXCEPTXXX_H

#include <setjmp.h>

#define fz_try(ctx)                                      \
if(fz_except_xxx_push(ctx->except),                      \
   !setjmp(ctx->except.stack[ctx->except.depth].buffer)) \
{

#define fz_catch(ctx)                               \
    ctx->except.stack[ctx->except.depth].failed = 0;\
}\
else\
{\
    ctx->except.stack[ctx->except.depth].failed = 1;\
}\
if(ex->stack[ex->depth--].failed)

typedef struct fz_except_xxx_stack
{
    int failed;
    jmp_buf buffer;
} fz_except_xxx_stack;

#define MAXDEPTH (20)

struct fz_except_context {
    fz_except_xxx_stack stack[MAXDEPTH];
    int depth;
    fz_except except;
};

void fz_except_xxx_push(fz_except_context *);

#endif /* EXCEPTXXX */
