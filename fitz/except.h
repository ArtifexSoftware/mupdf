#ifndef EXCEPT_H
#define EXCEPT_H

#include "fitz.h"

typedef struct fz_context fz_context;
typedef int fz_error;

typedef struct fz_except {
  char mess[256];
} fz_except;

#include "exceptxxx.h"
/*
    Macros for fz_try and fz_catch are defined in exceptxxx.h,
    but their definitions are best ignored.  Just use them as follows:

    fz_var(..);
    fz_var(..);

    fz_try(ctx)
    {
       .
       .
       .
    }
    fz_catch(ctx)
    {
       .
       .
       .
    }

    and don't return from within the try clause.
*/

void fz_throw(fz_context *, char *, ...);

fz_except *fz_caught(fz_context *);

void fz_rethrow(fz_context *);

#define fz_var(A) fz_var_xxx((void *)&(A))

void fz_var_xxx(void *x);

fz_error fz_except_init(fz_context *);

void fz_except_fin(fz_context *);

#endif /* EXCEPT */
