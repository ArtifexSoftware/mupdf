# Core

## Context

Almost all functions in the MuPDF library take a `fz_context` structure as
their first argument. The context is used for many things; primarily it holds
the exception stack for our `setjmp` based exception handling. It also holds
various caches and auxiliary contexts for font rendering and color management.

Here is the code to create a Fitz context. The first two arguments are used if
you need to use a custom memory allocator, and the third argument is a hint to
much memory the various caches should be allowed to grow. The limit is only a
soft limit. We may exceed it, but will start clearing out stale data to try to
stay below the limit when possible. Setting it to a lower value will prevent
the caches from growing out of hand if you are tight on memory.

	#include <mupdf/fitz.h>

	#include <stdio.h>
	#include <stdlib.h>

	main()
	{
		fz_context *ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
		if (!ctx) {
			fprintf(stderr, "Failed to create a new Fitz context!\n");
			return EXIT_FAILURE;
		}

		... do stuff ...

		fz_drop_context(ctx);
		return EXIT_SUCCESS;
	}

## Errors

MuPDF uses a `setjmp` based exception handling system. This is encapsulated by
the use of three macros: `fz_try`, `fz_always`, and `fz_catch`. When an error
is raised by `fz_throw`, or re-raised by `fz_rethrow`, execution will jump to
the enclosing always/catch block.

All functions you call should be guarded by a `fz_try` block to catch the
errors, or the program will call `exit()` on errors. You don't want that.

The `fz_always` block is optional. It is typically used to free memory or
release resources unconditionally, in both the case when the execution of the
try block succeeds, and when an error occurs.

	fz_try(ctx) {
		// Do stuff that may throw an exception.
	}
	fz_always(ctx) {
		// This (optional) block is always executed.
	}
	fz_catch(ctx) {
		// This block is only executed when recovering from an exception.
	}


Since the `fz_try` macro is based on `setjmp`, the same conditions that apply
to local variables in the presence of `setjmp` apply. Any locals written to
inside the try block may be restored to their pre-try state when an error
occurs. We provide a `fz_var()` macro to guard against this.

In the following example, if we don't guard `buf` with `fz_var`, then when an
error occurs the `buf` local variable might have be reset to its pre-try value
(`NULL`) and we would leak the memory.

	char *buf = NULL;

	fz_var(buf);

	fz_try(ctx) {
		buf = fz_malloc(ctx, 100);
		// Do stuff with buf that may throw an exception.
	}
	fz_always(ctx) {
		fz_free(ctx, buf);
	}
	fz_catch(ctx) {
		fz_rethrow(ctx);
	}

Carefully note that you should **never** return from within a `fz_try` or
`fz_always block`! Doing so will unbalance the exception stack, and things will
go catastrophically wrong. Instead, it is possible to break out of the `fz_try`
and `fz_always` block by using a break statement if you want to exit the block
early without throwing an exception.

Throwing a new exception can be done with `fz_throw`. Passing an exception
along after having cleaned up in the `fz_catch` block can be done with
`fz_rethrow`. `fz_throw` takes a `printf`-like formatting string.

	enum {
		FZ_ERROR_SYSTEM, // fatal out of memory or syscall error
		FZ_ERROR_LIBRARY, // unclassified error from third-party library
		FZ_ERROR_ARGUMENT, // invalid or out-of-range arguments to functions
		FZ_ERROR_LIMIT, // failed because of resource or other hard limits
		FZ_ERROR_UNSUPPORTED, // tried to use an unsupported feature
		FZ_ERROR_FORMAT, // syntax or format errors that are unrecoverable
		FZ_ERROR_SYNTAX, // syntax errors that should be diagnosed and ignored
	};

	void fz_throw(fz_context *ctx, int error_code, const char *fmt, ...);
	void fz_rethrow(fz_context *ctx);

## Memory

All memory in Fitz is allocated through an allocator, which allows you to use
a custom allocator instead of the system malloc if you need to.

### Malloc & Free

You should not need to do raw memory allocation using the Fitz context, but if
you do, here are the functions you need. These work just like the regular C
functions, but take a Fitz context and throw an exception if the allocation
fails. They will **not** return `NULL`; either they will succeed or they will
throw an exception.

	void *fz_malloc(fz_context *ctx, size_t size);
	void *fz_realloc(fz_context *ctx, void *old, size_t size);
	void *fz_calloc(fz_context *ctx, size_t count, size_t size);
	void fz_free(fz_context *ctx, void *ptr);

There are also some macros that allocate structures and arrays, together with a type cast to catch typing errors.

	T *fz_malloc_struct(fz_context *ctx, T); // Allocate and zero the memory.
	T *fz_malloc_array(fz_context *ctx, size_t count, T); // Allocate uninitialized memory!
	T *fz_realloc_array(fz_context *ctx, T *old, size_t count, T);

In the rare case that you need an allocation that returns `NULL` on failure,
there are variants for that too: `fz_malloc_no_throw`, etc.

### Pool Allocator

The pool allocator is used for allocating many small objects that live and die
together. All objects allocated from the pool will be freed when the pool is
freed.

	fz_pool *fz_new_pool(fz_context *ctx);
	void *fz_pool_alloc(fz_context *ctx, fz_pool *pool, size_t size);
	char *fz_pool_strdup(fz_context *ctx, fz_pool *pool, const char *s);
	void fz_drop_pool(fz_context *ctx, fz_pool *pool);

### Reference Counting

Most objects in MuPDF use reference counting to keep track of when they are no
longer used and can be freed. We use the verbs "keep" and "drop" to increment
and decrement the reference count. For simplicity, we also use the word "drop"
for non-reference counted objects (so that in case we change our minds and
decide to add reference counting to an object, the code that uses it need not
change).

## Math

We obviously need to deal with lots of points, rectangles, and transformations
in MuPDF.

### fz_point

Points are fairly self evident. The `fz_make_point` utility function is for use
with Visual Studio that doesn't yet support the C99 struct initializer syntax.

	typedef struct {
		float x, y;
	} fz_point;

	fz_point fz_make_point(float x, float y);

### fz_rect and fz_irect

Rectangles are represented by two pairs of coordinates. The `x0`, `y0` pair
have the smallest values, and in the normal coordinate space used by MuPDF that
is the upper left corner. The `x1`, `y1` pair have the largest values,
typically the lower right corner.

In order to represent an infinite unbounded area, we use an `x0` that is larger
than the `x1`.

	typedef struct {
		float x0, y0;
		float x1, y1;
	} fz_rect;

	const fz_rect fz_infinite_rect = { 1, 1, -1, -1 };
	const fz_rect fz_empty_rect = { 0, 0, 0, 0 };
	const fz_rect fz_unit_rect = { 0, 0, 1, 1 };

	fz_rect fz_make_rect(float x0, float y0, float x1, float y1);

### fz_matrix

Our matrix structure is a row-major 3x3 matrix with the last column always
`[ 0 0 1 ]`. This is represented as a struct with six fields, in the same order as
in PDF and Postscript. The identity matrix is a global constant, for easy
access.

	/ a b 0 \
	| c d 0 |
	\ e f 1 /

	typedef struct {
		float a, b, c, d, e, f;
	} fz_matrix;

	const fz_matrix fz_identity = { 1, 0, 0, 1, 0, 0 };

	fz_matrix fz_make_matrix(float a, float b, float c, float d, float e, float f);

### fz_quad

Sometimes we need to represent a non-axis aligned rectangular-ish area, such as
the area covered by some rotated text. For this we use a quad representation,
using a points for each of the upper/lower/left/right corners as seen from the
reading direction of the text represented.

	typedef struct {
		fz_point ul, ur, ll, lr;
	} fz_quad;

### List of math functions

These are simple mathematical operations that can not throw errors, so do not need a context argument.

#### float functions

`float fz_abs(float f)`
:	Abs for float.

`float fz_min(float a, float b)`
:	Min for float.

`float fz_max(float a, float b)`
:	Max for float.

`float fz_clamp(float f, float min, float max)`
:	Clamp for float.

#### int functions

`int fz_absi(int i)`
:	Abs for integer.

`int fz_mini(int a, int b)`
:	Min for integer.

`int fz_maxi(int a, int b)`
:	Max for integer.

`int fz_clampi(int i, int min, int max)`
:	Clamp for integer.

#### fz\_matrix functions

`fz_matrix fz_concat(fz_matrix left, fz_matrix right)`
:	Concat two matrices and returns a new matrix.

`fz_matrix fz_scale(float sx, float sy)`
:	Scale.

`fz_matrix fz_shear(float sx, float sy)`
:	Shear.

`fz_matrix fz_rotate(float degrees)`
:	Rotate.

`fz_matrix fz_translate(float tx, float ty)`
:	Translate.

`fz_matrix fz_invert_matrix(fz_matrix matrix)`
:	Invert a matrix.

#### fz\_point functions

`fz_point fz_transform_point(fz_point point, fz_matrix m)`
:	Transform a point according to the given matrix.

`fz_point fz_transform_vector(fz_point vector, fz_matrix m)`
:	Transform a vector according to the given matrix (ignores translation).

#### fz\_rect functions

`int fz_is_empty_rect(fz_rect r)`
:	Returns whether the supplied `fz_rect` is empty.

`int fz_is_infinite_rect(fz_rect r)`
:	Returns whether the supplied `fz_rect` is infinite.

`fz_rect fz_transform_rect(fz_rect rect, fz_matrix m)`
:	Transform a `fz_rect` according to the given matrix.

`int fz_is_point_inside_rect(fz_point p, fz_rect r)`
:	Returns whether the point is inside the supplied `fz_rect`.

#### fz\_quad functions

`fz_quad fz_transform_quad(fz_quad q, fz_matrix m)`
:	Transform a `fz_quad` according to the given matrix.

`int fz_is_point_inside_quad(fz_point p, fz_quad q)`
:	Returns whether the point is inside the supplied `fz_quad`.

#### page functions

`fz_matrix fz_transform_page(fz_rect mediabox, float resolution, float rotate)`
:	Create a transform matrix to draw a page at a given resolution and
	rotation. The scaling factors are adjusted so that the page covers a
	whole number of pixels. Resolution is given in dots per inch. Rotation
	is expressed in 90 degree increments (`0`, `90`, `180`, and `270` are
	valid values).
