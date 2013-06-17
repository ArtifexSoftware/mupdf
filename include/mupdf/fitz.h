#ifndef FITZ_H
#define FITZ_H

/*
	Include the standard libc headers.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>	/* INT_MAX & co */
#include <float.h> /* FLT_EPSILON, FLT_MAX & co */
#include <fcntl.h> /* O_RDONLY & co */
#include <time.h>

#include <setjmp.h>

#include "mupdf/memento.h"

#ifdef __APPLE__
#define HAVE_SIGSETJMP
#elif defined(__unix)
#define HAVE_SIGSETJMP
#endif

#ifdef __ANDROID__
#include <android/log.h>
#define LOG_TAG "libmupdf"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#else
#define LOGI(...) do {} while(0)
#define LOGE(...) do {} while(0)
#endif

#define nelem(x) (sizeof(x)/sizeof((x)[0]))

/*
	Some differences in libc can be smoothed over
*/

#ifdef _MSC_VER /* Microsoft Visual C */

#pragma warning( disable: 4244 ) /* conversion from X to Y, possible loss of data */
#pragma warning( disable: 4996 ) /* The POSIX name for this item is deprecated */
#pragma warning( disable: 4996 ) /* This function or variable may be unsafe */

#include <io.h>

int gettimeofday(struct timeval *tv, struct timezone *tz);

#define snprintf _snprintf
#define isnan _isnan
#define hypotf _hypotf

#define fopen fz_fopen_utf8

char *fz_utf8_from_wchar(const wchar_t *s);
wchar_t *fz_wchar_from_utf8(const char *s);

FILE *fz_fopen_utf8(const char *name, const char *mode);
char **fz_argv_from_wargv(int argc, wchar_t **wargv);
void fz_free_argv(int argc, char **argv);

#else /* Unix or close enough */

#include <unistd.h>

#ifndef O_BINARY
#define O_BINARY 0

#endif

#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef M_SQRT2
#define M_SQRT2 1.41421356237309504880
#endif

/*
	Variadic macros, inline and restrict keywords

	inline is standard in C++, so don't touch the definition in this case.
	For some compilers we can enable it within C too.
*/

#ifndef __cplusplus
#if __STDC_VERSION__ == 199901L /* C99 */
#elif _MSC_VER >= 1500 /* MSVC 9 or newer */
#define inline __inline
#elif __GNUC__ >= 3 /* GCC 3 or newer */
#define inline __inline
#else /* Unknown or ancient */
#define inline
#endif
#endif

/*
	restrict is standard in C99, but not in all C++ compilers. Enable
	where possible, disable if in doubt.
 */
#if __STDC_VERSION__ == 199901L /* C99 */
#elif _MSC_VER >= 1500 /* MSVC 9 or newer */
#define restrict __restrict
#elif __GNUC__ >= 3 /* GCC 3 or newer */
#define restrict __restrict
#else /* Unknown or ancient */
#define restrict
#endif

/* noreturn is a GCC extension */
#ifdef __GNUC__
#define FZ_NORETURN __attribute__((noreturn))
#else
#define FZ_NORETURN
#endif

/*
	GCC can do type checking of printf strings
*/

#ifndef __printflike
#if __GNUC__ > 2 || __GNUC__ == 2 && __GNUC_MINOR__ >= 7
#define __printflike(fmtarg, firstvararg) \
	__attribute__((__format__ (__printf__, fmtarg, firstvararg)))
#else
#define __printflike(fmtarg, firstvararg)
#endif
#endif

/*
	Shut the compiler up about unused variables
*/
#define UNUSED(x) do { x = x; } while (0)

/*
	Some standard math functions, done as static inlines for speed.
	People with compilers that do not adequately implement inlines may
	like to reimplement these using macros.
*/
static inline float fz_abs(float f)
{
	return (f < 0 ? -f : f);
}

static inline int fz_absi(int i)
{
	return (i < 0 ? -i : i);
}

static inline float fz_min(float a, float b)
{
	return (a < b ? a : b);
}

static inline int fz_mini(int a, int b)
{
	return (a < b ? a : b);
}

static inline float fz_max(float a, float b)
{
	return (a > b ? a : b);
}

static inline int fz_maxi(int a, int b)
{
	return (a > b ? a : b);
}

static inline float fz_clamp(float f, float min, float max)
{
	return (f > min ? (f < max ? f : max) : min);
}

static inline int fz_clampi(int i, int min, int max)
{
	return (i > min ? (i < max ? i : max) : min);
}

static inline double fz_clampd(double d, double min, double max)
{
	return (d > min ? (d < max ? d : max) : min);
}

static inline void *fz_clampp(void *p, void *min, void *max)
{
	return (p > min ? (p < max ? p : max) : min);
}

#define DIV_BY_ZERO(a, b, min, max) (((a) < 0) ^ ((b) < 0) ? (min) : (max))

/*
	Contexts
*/

typedef struct fz_alloc_context_s fz_alloc_context;
typedef struct fz_error_context_s fz_error_context;
typedef struct fz_id_context_s fz_id_context;
typedef struct fz_warn_context_s fz_warn_context;
typedef struct fz_font_context_s fz_font_context;
typedef struct fz_colorspace_context_s fz_colorspace_context;
typedef struct fz_aa_context_s fz_aa_context;
typedef struct fz_locks_context_s fz_locks_context;
typedef struct fz_store_s fz_store;
typedef struct fz_glyph_cache_s fz_glyph_cache;
typedef struct fz_context_s fz_context;

struct fz_alloc_context_s
{
	void *user;
	void *(*malloc)(void *, unsigned int);
	void *(*realloc)(void *, void *, unsigned int);
	void (*free)(void *, void *);
};

/*
	Where possible (i.e. on platforms on which they are provided), use
	sigsetjmp/siglongjmp in preference to setjmp/longjmp. We don't alter
	signal handlers within mupdf, so there is no need for us to
	store/restore them - hence we use the non-restoring variants. This
	makes a large speed difference on MacOSX (and probably other
	platforms too.
*/
#ifdef HAVE_SIGSETJMP
#define fz_setjmp(BUF) sigsetjmp(BUF, 0)
#define fz_longjmp(BUF,VAL) siglongjmp(BUF, VAL)
#define fz_jmp_buf sigjmp_buf
#else
#define fz_setjmp(BUF) setjmp(BUF)
#define fz_longjmp(BUF,VAL) longjmp(BUF,VAL)
#define fz_jmp_buf jmp_buf
#endif

struct fz_error_context_s
{
	int top;
	struct {
		int code;
		fz_jmp_buf buffer;
	} stack[256];
	char message[256];
};

void fz_var_imp(void *);
#define fz_var(var) fz_var_imp((void *)&(var))

/*
	Exception macro definitions. Just treat these as a black box - pay no
	attention to the man behind the curtain.
*/

#define fz_try(ctx) \
	if (fz_push_try(ctx->error) && \
		((ctx->error->stack[ctx->error->top].code = fz_setjmp(ctx->error->stack[ctx->error->top].buffer)) == 0))\
	{ do {

#define fz_always(ctx) \
		} while (0); \
	} \
	if (ctx->error->stack[ctx->error->top].code < 3) \
	{ \
		ctx->error->stack[ctx->error->top].code++; \
		do { \

#define fz_catch(ctx) \
		} while(0); \
	} \
	if (ctx->error->stack[ctx->error->top--].code > 1)

int fz_push_try(fz_error_context *ex);
void fz_throw(fz_context *, const char *, ...) __printflike(2, 3) FZ_NORETURN;
void fz_rethrow(fz_context *) FZ_NORETURN;
void fz_warn(fz_context *ctx, const char *fmt, ...) __printflike(2, 3);
const char *fz_caught(fz_context *ctx);

/*
	fz_flush_warnings: Flush any repeated warnings.

	Repeated warnings are buffered, counted and eventually printed
	along with the number of repetitions. Call fz_flush_warnings
	to force printing of the latest buffered warning and the
	number of repetitions, for example to make sure that all
	warnings are printed before exiting an application.

	Does not throw exceptions.
*/
void fz_flush_warnings(fz_context *ctx);

struct fz_context_s
{
	fz_alloc_context *alloc;
	fz_locks_context *locks;
	fz_id_context *id;
	fz_error_context *error;
	fz_warn_context *warn;
	fz_font_context *font;
	fz_colorspace_context *colorspace;
	fz_aa_context *aa;
	fz_store *store;
	fz_glyph_cache *glyph_cache;
};

/*
	Specifies the maximum size in bytes of the resource store in
	fz_context. Given as argument to fz_new_context.

	FZ_STORE_UNLIMITED: Let resource store grow unbounded.

	FZ_STORE_DEFAULT: A reasonable upper bound on the size, for
	devices that are not memory constrained.
*/
enum {
	FZ_STORE_UNLIMITED = 0,
	FZ_STORE_DEFAULT = 256 << 20,
};

/*
	fz_new_context: Allocate context containing global state.

	The global state contains an exception stack, resource store,
	etc. Most functions in MuPDF take a context argument to be
	able to reference the global state. See fz_free_context for
	freeing an allocated context.

	alloc: Supply a custom memory allocator through a set of
	function pointers. Set to NULL for the standard library
	allocator. The context will keep the allocator pointer, so the
	data it points to must not be modified or freed during the
	lifetime of the context.

	locks: Supply a set of locks and functions to lock/unlock
	them, intended for multi-threaded applications. Set to NULL
	when using MuPDF in a single-threaded applications. The
	context will keep the locks pointer, so the data it points to
	must not be modified or freed during the lifetime of the
	context.

	max_store: Maximum size in bytes of the resource store, before
	it will start evicting cached resources such as fonts and
	images. FZ_STORE_UNLIMITED can be used if a hard limit is not
	desired. Use FZ_STORE_DEFAULT to get a reasonable size.

	Does not throw exceptions, but may return NULL.
*/
fz_context *fz_new_context(fz_alloc_context *alloc, fz_locks_context *locks, unsigned int max_store);

/*
	fz_clone_context: Make a clone of an existing context.

	This function is meant to be used in multi-threaded
	applications where each thread requires its own context, yet
	parts of the global state, for example caching, is shared.

	ctx: Context obtained from fz_new_context to make a copy of.
	ctx must have had locks and lock/functions setup when created.
	The two contexts will share the memory allocator, resource
	store, locks and lock/unlock functions. They will each have
	their own exception stacks though.

	Does not throw exception, but may return NULL.
*/
fz_context *fz_clone_context(fz_context *ctx);

/*
	fz_free_context: Free a context and its global state.

	The context and all of its global state is freed, and any
	buffered warnings are flushed (see fz_flush_warnings). If NULL
	is passed in nothing will happen.

	Does not throw exceptions.
*/
void fz_free_context(fz_context *ctx);

/*
	fz_aa_level: Get the number of bits of antialiasing we are
	using. Between 0 and 8.
*/
int fz_aa_level(fz_context *ctx);

/*
	fz_set_aa_level: Set the number of bits of antialiasing we should use.

	bits: The number of bits of antialiasing to use (values are clamped
	to within the 0 to 8 range).
*/
void fz_set_aa_level(fz_context *ctx, int bits);

/*
	Locking functions

	MuPDF is kept deliberately free of any knowledge of particular
	threading systems. As such, in order for safe multi-threaded
	operation, we rely on callbacks to client provided functions.

	A client is expected to provide FZ_LOCK_MAX number of mutexes,
	and a function to lock/unlock each of them. These may be
	recursive mutexes, but do not have to be.

	If a client does not intend to use multiple threads, then it
	may pass NULL instead of a lock structure.

	In order to avoid deadlocks, we have one simple rule
	internally as to how we use locks: We can never take lock n
	when we already hold any lock i, where 0 <= i <= n. In order
	to verify this, we have some debugging code, that can be
	enabled by defining FITZ_DEBUG_LOCKING.
*/

struct fz_locks_context_s
{
	void *user;
	void (*lock)(void *user, int lock);
	void (*unlock)(void *user, int lock);
};

enum {
	FZ_LOCK_ALLOC = 0,
	FZ_LOCK_FILE,
	FZ_LOCK_FREETYPE,
	FZ_LOCK_GLYPHCACHE,
	FZ_LOCK_MAX
};

/*
	Memory Allocation and Scavenging:

	All calls to MuPDFs allocator functions pass through to the
	underlying allocators passed in when the initial context is
	created, after locks are taken (using the supplied locking function)
	to ensure that only one thread at a time calls through.

	If the underlying allocator fails, MuPDF attempts to make room for
	the allocation by evicting elements from the store, then retrying.

	Any call to allocate may then result in several calls to the underlying
	allocator, and result in elements that are only referred to by the
	store being freed.
*/

/*
	fz_malloc: Allocate a block of memory (with scavenging)

	size: The number of bytes to allocate.

	Returns a pointer to the allocated block. May return NULL if size is
	0. Throws exception on failure to allocate.
*/
void *fz_malloc(fz_context *ctx, unsigned int size);

/*
	fz_calloc: Allocate a zeroed block of memory (with scavenging)

	count: The number of objects to allocate space for.

	size: The size (in bytes) of each object.

	Returns a pointer to the allocated block. May return NULL if size
	and/or count are 0. Throws exception on failure to allocate.
*/
void *fz_calloc(fz_context *ctx, unsigned int count, unsigned int size);

/*
	fz_malloc_struct: Allocate storage for a structure (with scavenging),
	clear it, and (in Memento builds) tag the pointer as belonging to a
	struct of this type.

	CTX: The context.

	STRUCT: The structure type.

	Returns a pointer to allocated (and cleared) structure. Throws
	exception on failure to allocate.
*/
#define fz_malloc_struct(CTX, STRUCT) \
	((STRUCT *)Memento_label(fz_calloc(CTX,1,sizeof(STRUCT)), #STRUCT))

/*
	fz_malloc_array: Allocate a block of (non zeroed) memory (with
	scavenging). Equivalent to fz_calloc without the memory clearing.

	count: The number of objects to allocate space for.

	size: The size (in bytes) of each object.

	Returns a pointer to the allocated block. May return NULL if size
	and/or count are 0. Throws exception on failure to allocate.
*/
void *fz_malloc_array(fz_context *ctx, unsigned int count, unsigned int size);

/*
	fz_resize_array: Resize a block of memory (with scavenging).

	p: The existing block to resize

	count: The number of objects to resize to.

	size: The size (in bytes) of each object.

	Returns a pointer to the resized block. May return NULL if size
	and/or count are 0. Throws exception on failure to resize (original
	block is left unchanged).
*/
void *fz_resize_array(fz_context *ctx, void *p, unsigned int count, unsigned int size);

/*
	fz_strdup: Duplicate a C string (with scavenging)

	s: The string to duplicate.

	Returns a pointer to a duplicated string. Throws exception on failure
	to allocate.
*/
char *fz_strdup(fz_context *ctx, const char *s);

/*
	fz_free: Frees an allocation.

	Does not throw exceptions.
*/
void fz_free(fz_context *ctx, void *p);

/*
	fz_malloc_no_throw: Allocate a block of memory (with scavenging)

	size: The number of bytes to allocate.

	Returns a pointer to the allocated block. May return NULL if size is
	0. Returns NULL on failure to allocate.
*/
void *fz_malloc_no_throw(fz_context *ctx, unsigned int size);

/*
	fz_calloc_no_throw: Allocate a zeroed block of memory (with scavenging)

	count: The number of objects to allocate space for.

	size: The size (in bytes) of each object.

	Returns a pointer to the allocated block. May return NULL if size
	and/or count are 0. Returns NULL on failure to allocate.
*/
void *fz_calloc_no_throw(fz_context *ctx, unsigned int count, unsigned int size);

/*
	fz_malloc_array_no_throw: Allocate a block of (non zeroed) memory
	(with scavenging). Equivalent to fz_calloc_no_throw without the
	memory clearing.

	count: The number of objects to allocate space for.

	size: The size (in bytes) of each object.

	Returns a pointer to the allocated block. May return NULL if size
	and/or count are 0. Returns NULL on failure to allocate.
*/
void *fz_malloc_array_no_throw(fz_context *ctx, unsigned int count, unsigned int size);

/*
	fz_resize_array_no_throw: Resize a block of memory (with scavenging).

	p: The existing block to resize

	count: The number of objects to resize to.

	size: The size (in bytes) of each object.

	Returns a pointer to the resized block. May return NULL if size
	and/or count are 0. Returns NULL on failure to resize (original
	block is left unchanged).
*/
void *fz_resize_array_no_throw(fz_context *ctx, void *p, unsigned int count, unsigned int size);

/*
	fz_strdup_no_throw: Duplicate a C string (with scavenging)

	s: The string to duplicate.

	Returns a pointer to a duplicated string. Returns NULL on failure
	to allocate.
*/
char *fz_strdup_no_throw(fz_context *ctx, const char *s);

/*
	Safe string functions
*/
/*
	fz_strsep: Given a pointer to a C string (or a pointer to NULL) break
	it at the first occurence of a delimiter char (from a given set).

	stringp: Pointer to a C string pointer (or NULL). Updated on exit to
	point to the first char of the string after the delimiter that was
	found. The string pointed to by stringp will be corrupted by this
	call (as the found delimiter will be overwritten by 0).

	delim: A C string of acceptable delimiter characters.

	Returns a pointer to a C string containing the chars of stringp up
	to the first delimiter char (or the end of the string), or NULL.
*/
char *fz_strsep(char **stringp, const char *delim);

/*
	fz_strlcpy: Copy at most n-1 chars of a string into a destination
	buffer with null termination, returning the real length of the
	initial string (excluding terminator).

	dst: Destination buffer, at least n bytes long.

	src: C string (non-NULL).

	n: Size of dst buffer in bytes.

	Returns the length (excluding terminator) of src.
*/
int fz_strlcpy(char *dst, const char *src, int n);

/*
	fz_strlcat: Concatenate 2 strings, with a maximum length.

	dst: pointer to first string in a buffer of n bytes.

	src: pointer to string to concatenate.

	n: Size (in bytes) of buffer that dst is in.

	Returns the real length that a concatenated dst + src would have been
	(not including terminator).
*/
int fz_strlcat(char *dst, const char *src, int n);

/*
	fz_chartorune: UTF8 decode a single rune from a sequence of chars.

	rune: Pointer to an int to assign the decoded 'rune' to.

	str: Pointer to a UTF8 encoded string.

	Returns the number of bytes consumed. Does not throw exceptions.
*/
int fz_chartorune(int *rune, const char *str);

/*
	fz_runetochar: UTF8 encode a rune to a sequence of chars.

	str: Pointer to a place to put the UTF8 encoded character.

	rune: Pointer to a 'rune'.

	Returns the number of bytes the rune took to output. Does not throw
	exceptions.
*/
int fz_runetochar(char *str, int rune);

/*
	fz_runelen: Count how many chars are required to represent a rune.

	rune: The rune to encode.

	Returns the number of bytes required to represent this run in UTF8.
*/
int fz_runelen(int rune);

/*
	fz_gen_id: Generate an id (guaranteed unique within this family of
	contexts).
*/
int fz_gen_id(fz_context *ctx);

/*
	getopt: Simple functions/variables for use in tools.
*/
extern int fz_getopt(int nargc, char * const *nargv, const char *ostr);
extern int fz_optind;
extern char *fz_optarg;

/*
	XML document model
*/

typedef struct fz_xml_s fz_xml;

/*
	fz_parse_xml: Parse a zero-terminated string into a tree of xml nodes.
*/
fz_xml *fz_parse_xml(fz_context *ctx, unsigned char *buf, int len);

/*
	fz_xml_next: Return next sibling of XML node.
*/
fz_xml *fz_xml_next(fz_xml *item);

/*
	fz_xml_down: Return first child of XML node.
*/
fz_xml *fz_xml_down(fz_xml *item);

/*
	fz_xml_tag: Return tag of XML node. Return the empty string for text nodes.
*/
char *fz_xml_tag(fz_xml *item);

/*
	fz_xml_att: Return the value of an attribute of an XML node.
	NULL if the attribute doesn't exist.
*/
char *fz_xml_att(fz_xml *item, const char *att);

/*
	fz_xml_text: Return the text content of an XML node.
	NULL if the node is a tag.
*/
char *fz_xml_text(fz_xml *item);

/*
	fz_free_xml: Free the XML node and all its children and siblings.
*/
void fz_free_xml(fz_context *doc, fz_xml *item);

/*
	fz_detach_xml: Detach a node from the tree, unlinking it from its parent.
*/
void fz_detach_xml(fz_xml *node);

/*
	fz_debug_xml: Pretty-print an XML tree to stdout.
*/
void fz_debug_xml(fz_xml *item, int level);

/*
	fz_point is a point in a two-dimensional space.
*/
typedef struct fz_point_s fz_point;
struct fz_point_s
{
	float x, y;
};

/*
	fz_rect is a rectangle represented by two diagonally opposite
	corners at arbitrary coordinates.

	Rectangles are always axis-aligned with the X- and Y- axes.
	The relationship between the coordinates are that x0 <= x1 and
	y0 <= y1 in all cases except for infinte rectangles. The area
	of a rectangle is defined as (x1 - x0) * (y1 - y0). If either
	x0 > x1 or y0 > y1 is true for a given rectangle then it is
	defined to be infinite.

	To check for empty or infinite rectangles use fz_is_empty_rect
	and fz_is_infinite_rect.

	x0, y0: The top left corner.

	x1, y1: The botton right corner.
*/
typedef struct fz_rect_s fz_rect;
struct fz_rect_s
{
	float x0, y0;
	float x1, y1;
};

/*
	fz_rect_min: get the minimum point from a rectangle as an fz_point.
*/
static inline fz_point *fz_rect_min(fz_rect *f)
{
	return (fz_point *)(void *)&f->x0;
}

/*
	fz_rect_max: get the maximum point from a rectangle as an fz_point.
*/
static inline fz_point *fz_rect_max(fz_rect *f)
{
	return (fz_point *)(void *)&f->x1;
}

/*
	fz_irect is a rectangle using integers instead of floats.

	It's used in the draw device and for pixmap dimensions.
*/
typedef struct fz_irect_s fz_irect;
struct fz_irect_s
{
	int x0, y0;
	int x1, y1;
};

/*
	A rectangle with sides of length one.

	The bottom left corner is at (0, 0) and the top right corner
	is at (1, 1).
*/
extern const fz_rect fz_unit_rect;

/*
	An empty rectangle with an area equal to zero.

	Both the top left and bottom right corner are at (0, 0).
*/
extern const fz_rect fz_empty_rect;
extern const fz_irect fz_empty_irect;

/*
	An infinite rectangle with negative area.

	The corner (x0, y0) is at (1, 1) while the corner (x1, y1) is
	at (-1, -1).
*/
extern const fz_rect fz_infinite_rect;
extern const fz_irect fz_infinite_irect;

/*
	fz_is_empty_rect: Check if rectangle is empty.

	An empty rectangle is defined as one whose area is zero.
*/
static inline int
fz_is_empty_rect(const fz_rect *r)
{
	return ((r)->x0 == (r)->x1 || (r)->y0 == (r)->y1);
}

static inline int
fz_is_empty_irect(const fz_irect *r)
{
	return ((r)->x0 == (r)->x1 || (r)->y0 == (r)->y1);
}

/*
	fz_is_infinite: Check if rectangle is infinite.

	An infinite rectangle is defined as one where either of the
	two relationships between corner coordinates are not true.
*/
static inline int
fz_is_infinite_rect(const fz_rect *r)
{
	return ((r)->x0 > (r)->x1 || (r)->y0 > (r)->y1);
}

static inline int
fz_is_infinite_irect(const fz_irect *r)
{
	return ((r)->x0 > (r)->x1 || (r)->y0 > (r)->y1);
}

/*
	fz_matrix is a a row-major 3x3 matrix used for representing
	transformations of coordinates throughout MuPDF.

	Since all points reside in a two-dimensional space, one vector
	is always a constant unit vector; hence only some elements may
	vary in a matrix. Below is how the elements map between
	different representations.

	/ a b 0 \
	| c d 0 | normally represented as [ a b c d e f ].
	\ e f 1 /
*/
typedef struct fz_matrix_s fz_matrix;
struct fz_matrix_s
{
	float a, b, c, d, e, f;
};

/*
	fz_identity: Identity transform matrix.
*/
extern const fz_matrix fz_identity;

static inline fz_matrix *fz_copy_matrix(fz_matrix *restrict m, const fz_matrix *restrict s)
{
	*m = *s;
	return m;
}

/*
	fz_concat: Multiply two matrices.

	The order of the two matrices are important since matrix
	multiplication is not commutative.

	Returns result.

	Does not throw exceptions.
*/
fz_matrix *fz_concat(fz_matrix *result, const fz_matrix *left, const fz_matrix *right);

/*
	fz_scale: Create a scaling matrix.

	The returned matrix is of the form [ sx 0 0 sy 0 0 ].

	m: Pointer to the matrix to populate

	sx, sy: Scaling factors along the X- and Y-axes. A scaling
	factor of 1.0 will not cause any scaling along the relevant
	axis.

	Returns m.

	Does not throw exceptions.
*/
fz_matrix *fz_scale(fz_matrix *m, float sx, float sy);

/*
	fz_pre_scale: Scale a matrix by premultiplication.

	m: Pointer to the matrix to scale

	sx, sy: Scaling factors along the X- and Y-axes. A scaling
	factor of 1.0 will not cause any scaling along the relevant
	axis.

	Returns m (updated).

	Does not throw exceptions.
*/
fz_matrix *fz_pre_scale(fz_matrix *m, float sx, float sy);

/*
	fz_shear: Create a shearing matrix.

	The returned matrix is of the form [ 1 sy sx 1 0 0 ].

	m: pointer to place to store returned matrix

	sx, sy: Shearing factors. A shearing factor of 0.0 will not
	cause any shearing along the relevant axis.

	Returns m.

	Does not throw exceptions.
*/
fz_matrix *fz_shear(fz_matrix *m, float sx, float sy);

/*
	fz_pre_shear: Premultiply a matrix with a shearing matrix.

	The shearing matrix is of the form [ 1 sy sx 1 0 0 ].

	m: pointer to matrix to premultiply

	sx, sy: Shearing factors. A shearing factor of 0.0 will not
	cause any shearing along the relevant axis.

	Returns m (updated).

	Does not throw exceptions.
*/
fz_matrix *fz_pre_shear(fz_matrix *m, float sx, float sy);

/*
	fz_rotate: Create a rotation matrix.

	The returned matrix is of the form
	[ cos(deg) sin(deg) -sin(deg) cos(deg) 0 0 ].

	m: Pointer to place to store matrix

	degrees: Degrees of counter clockwise rotation. Values less
	than zero and greater than 360 are handled as expected.

	Returns m.

	Does not throw exceptions.
*/
fz_matrix *fz_rotate(fz_matrix *m, float degrees);

/*
	fz_pre_rotate: Rotate a transformation by premultiplying.

	The premultiplied matrix is of the form
	[ cos(deg) sin(deg) -sin(deg) cos(deg) 0 0 ].

	m: Pointer to matrix to premultiply.

	degrees: Degrees of counter clockwise rotation. Values less
	than zero and greater than 360 are handled as expected.

	Returns m (updated).

	Does not throw exceptions.
*/
fz_matrix *fz_pre_rotate(fz_matrix *m, float degrees);

/*
	fz_translate: Create a translation matrix.

	The returned matrix is of the form [ 1 0 0 1 tx ty ].

	m: A place to store the created matrix.

	tx, ty: Translation distances along the X- and Y-axes. A
	translation of 0 will not cause any translation along the
	relevant axis.

	Returns m.

	Does not throw exceptions.
*/
fz_matrix *fz_translate(fz_matrix *m, float tx, float ty);

/*
	fz_pre_translate: Translate a matrix by premultiplication.

	m: The matrix to translate

	tx, ty: Translation distances along the X- and Y-axes. A
	translation of 0 will not cause any translation along the
	relevant axis.

	Returns m.

	Does not throw exceptions.
*/
fz_matrix *fz_pre_translate(fz_matrix *m, float tx, float ty);

/*
	fz_invert_matrix: Create an inverse matrix.

	inverse: Place to store inverse matrix.

	matrix: Matrix to invert. A degenerate matrix, where the
	determinant is equal to zero, can not be inverted and the
	original matrix is returned instead.

	Returns inverse.

	Does not throw exceptions.
*/
fz_matrix *fz_invert_matrix(fz_matrix *inverse, const fz_matrix *matrix);

/*
	fz_is_rectilinear: Check if a transformation is rectilinear.

	Rectilinear means that no shearing is present and that any
	rotations present are a multiple of 90 degrees. Usually this
	is used to make sure that axis-aligned rectangles before the
	transformation are still axis-aligned rectangles afterwards.

	Does not throw exceptions.
*/
int fz_is_rectilinear(const fz_matrix *m);

/*
	fz_matrix_expansion: Calculate average scaling factor of matrix.
*/
float fz_matrix_expansion(const fz_matrix *m); /* sumatrapdf */

/*
	fz_intersect_rect: Compute intersection of two rectangles.

	Given two rectangles, update the first to be the smallest
	axis-aligned rectangle that covers the area covered by both
	given rectangles. If either rectangle is empty then the
	intersection is also empty. If either rectangle is infinite
	then the intersection is simply the non-infinite rectangle.
	Should both rectangles be infinite, then the intersection is
	also infinite.

	Does not throw exceptions.
*/
fz_rect *fz_intersect_rect(fz_rect *restrict a, const fz_rect *restrict b);

/*
	fz_intersect_irect: Compute intersection of two bounding boxes.

	Similar to fz_intersect_rect but operates on two bounding
	boxes instead of two rectangles.

	Does not throw exceptions.
*/
fz_irect *fz_intersect_irect(fz_irect *restrict a, const fz_irect *restrict b);

/*
	fz_union_rect: Compute union of two rectangles.

	Given two rectangles, update the first to be the smallest
	axis-aligned rectangle that encompasses both given rectangles.
	If either rectangle is infinite then the union is also infinite.
	If either rectangle is empty then the union is simply the
	non-empty rectangle. Should both rectangles be empty, then the
	union is also empty.

	Does not throw exceptions.
*/
fz_rect *fz_union_rect(fz_rect *restrict a, const fz_rect *restrict b);

/*
	fz_irect_from_rect: Convert a rect into the minimal bounding box
	that covers the rectangle.

	bbox: Place to store the returned bbox.

	rect: The rectangle to convert to a bbox.

	Coordinates in a bounding box are integers, so rounding of the
	rects coordinates takes place. The top left corner is rounded
	upwards and left while the bottom right corner is rounded
	downwards and to the right.

	Returns bbox (updated).

	Does not throw exceptions.
*/

fz_irect *fz_irect_from_rect(fz_irect *restrict bbox, const fz_rect *restrict rect);

/*
	fz_round_rect: Round rectangle coordinates.

	Coordinates in a bounding box are integers, so rounding of the
	rects coordinates takes place. The top left corner is rounded
	upwards and left while the bottom right corner is rounded
	downwards and to the right.

	This differs from fz_irect_from_rect, in that fz_irect_from_rect
	slavishly follows the numbers (i.e any slight over/under calculations
	can cause whole extra pixels to be added). fz_round_rect
	allows for a small amount of rounding error when calculating
	the bbox.

	Does not throw exceptions.
*/
fz_irect *fz_round_rect(fz_irect *restrict bbox, const fz_rect *restrict rect);

/*
	fz_rect_from_irect: Convert a bbox into a rect.

	For our purposes, a rect can represent all the values we meet in
	a bbox, so nothing can go wrong.

	rect: A place to store the generated rectangle.

	bbox: The bbox to convert.

	Returns rect (updated).

	Does not throw exceptions.
*/
fz_rect *fz_rect_from_irect(fz_rect *restrict rect, const fz_irect *restrict bbox);

/*
	fz_expand_rect: Expand a bbox by a given amount in all directions.

	Does not throw exceptions.
*/
fz_rect *fz_expand_rect(fz_rect *b, float expand);

/*
	fz_include_point_in_rect: Expand a bbox to include a given point.
	To create a rectangle that encompasses a sequence of points, the
	rectangle must first be set to be the empty rectangle at one of
	the points before including the others.
*/
fz_rect *fz_include_point_in_rect(fz_rect *r, const fz_point *p);

/*
	fz_translate_irect: Translate bounding box.

	Translate a bbox by a given x and y offset. Allows for overflow.

	Does not throw exceptions.
*/
fz_irect *fz_translate_irect(fz_irect *a, int xoff, int yoff);

/*
	fz_transform_point: Apply a transformation to a point.

	transform: Transformation matrix to apply. See fz_concat,
	fz_scale, fz_rotate and fz_translate for how to create a
	matrix.

	point: Pointer to point to update.

	Returns transform (unchanged).

	Does not throw exceptions.
*/
fz_point *fz_transform_point(fz_point *restrict point, const fz_matrix *restrict transform);

/*
	fz_transform_vector: Apply a transformation to a vector.

	transform: Transformation matrix to apply. See fz_concat,
	fz_scale and fz_rotate for how to create a matrix. Any
	translation will be ignored.

	vector: Pointer to vector to update.

	Does not throw exceptions.
*/
fz_point *fz_transform_vector(fz_point *restrict vector, const fz_matrix *restrict transform);

/*
	fz_transform_rect: Apply a transform to a rectangle.

	After the four corner points of the axis-aligned rectangle
	have been transformed it may not longer be axis-aligned. So a
	new axis-aligned rectangle is created covering at least the
	area of the transformed rectangle.

	transform: Transformation matrix to apply. See fz_concat,
	fz_scale and fz_rotate for how to create a matrix.

	rect: Rectangle to be transformed. The two special cases
	fz_empty_rect and fz_infinite_rect, may be used but are
	returned unchanged as expected.

	Does not throw exceptions.
*/
fz_rect *fz_transform_rect(fz_rect *restrict rect, const fz_matrix *restrict transform);

/*
	fz_normalize_vector: Normalize a vector to length one.
*/
void fz_normalize_vector(fz_point *p);

/*
	fz_buffer is a wrapper around a dynamically allocated array of bytes.

	Buffers have a capacity (the number of bytes storage immediately
	available) and a current size.
*/
typedef struct fz_buffer_s fz_buffer;

/*
	fz_keep_buffer: Increment the reference count for a buffer.

	buf: The buffer to increment the reference count for.

	Returns a pointer to the buffer. Does not throw exceptions.
*/
fz_buffer *fz_keep_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_drop_buffer: Decrement the reference count for a buffer.

	buf: The buffer to decrement the reference count for.
*/
void fz_drop_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_buffer_storage: Retrieve information on the storage currently used
	by a buffer.

	data: Pointer to place to retrieve data pointer.

	Returns length of stream.
*/
int fz_buffer_storage(fz_context *ctx, fz_buffer *buf, unsigned char **data);

/*
	fz_stream is a buffered reader capable of seeking in both
	directions.

	Streams are reference counted, so references must be dropped
	by a call to fz_close.

	Only the data between rp and wp is valid.
*/
typedef struct fz_stream_s fz_stream;

/*
	fz_open_file: Open the named file and wrap it in a stream.

	filename: Path to a file. On non-Windows machines the filename should
	be exactly as it would be passed to open(2). On Windows machines, the
	path should be UTF-8 encoded so that non-ASCII characters can be
	represented. Other platforms do the encoding as standard anyway (and
	in most cases, particularly for MacOS and Linux, the encoding they
	use is UTF-8 anyway).
*/
fz_stream *fz_open_file(fz_context *ctx, const char *filename);

/*
	fz_open_file_w: Open the named file and wrap it in a stream.

	This function is only available when compiling for Win32.

	filename: Wide character path to the file as it would be given
	to _wopen().
*/
fz_stream *fz_open_file_w(fz_context *ctx, const wchar_t *filename);

/*
	fz_open_fd: Wrap an open file descriptor in a stream.

	file: An open file descriptor supporting bidirectional
	seeking. The stream will take ownership of the file
	descriptor, so it may not be modified or closed after the call
	to fz_open_fd. When the stream is closed it will also close
	the file descriptor.
*/
fz_stream *fz_open_fd(fz_context *ctx, int file);

/*
	fz_open_memory: Open a block of memory as a stream.

	data: Pointer to start of data block. Ownership of the data block is
	NOT passed in.

	len: Number of bytes in data block.

	Returns pointer to newly created stream. May throw exceptions on
	failure to allocate.
*/
fz_stream *fz_open_memory(fz_context *ctx, unsigned char *data, int len);

/*
	fz_open_buffer: Open a buffer as a stream.

	buf: The buffer to open. Ownership of the buffer is NOT passed in
	(this function takes it's own reference).

	Returns pointer to newly created stream. May throw exceptions on
	failure to allocate.
*/
fz_stream *fz_open_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_close: Close an open stream.

	Drops a reference for the stream. Once no references remain
	the stream will be closed, as will any file descriptor the
	stream is using.

	Does not throw exceptions.
*/
void fz_close(fz_stream *stm);

/*
	fz_tell: return the current reading position within a stream
*/
int fz_tell(fz_stream *stm);

/*
	fz_seek: Seek within a stream.

	stm: The stream to seek within.

	offset: The offset to seek to.

	whence: From where the offset is measured (see fseek).
*/
void fz_seek(fz_stream *stm, int offset, int whence);

/*
	fz_read: Read from a stream into a given data block.

	stm: The stream to read from.

	data: The data block to read into.

	len: The length of the data block (in bytes).

	Returns the number of bytes read. May throw exceptions.
*/
int fz_read(fz_stream *stm, unsigned char *data, int len);

/*
	fz_read_all: Read all of a stream into a buffer.

	stm: The stream to read from

	initial: Suggested initial size for the buffer.

	Returns a buffer created from reading from the stream. May throw
	exceptions on failure to allocate.
*/
fz_buffer *fz_read_all(fz_stream *stm, int initial);

/*
	Bitmaps have 1 bit per component. Only used for creating halftoned
	versions of contone buffers, and saving out. Samples are stored msb
	first, akin to pbms.
*/
typedef struct fz_bitmap_s fz_bitmap;

/*
	fz_keep_bitmap: Take a reference to a bitmap.

	bit: The bitmap to increment the reference for.

	Returns bit. Does not throw exceptions.
*/
fz_bitmap *fz_keep_bitmap(fz_context *ctx, fz_bitmap *bit);

/*
	fz_drop_bitmap: Drop a reference and free a bitmap.

	Decrement the reference count for the bitmap. When no
	references remain the pixmap will be freed.

	Does not throw exceptions.
*/
void fz_drop_bitmap(fz_context *ctx, fz_bitmap *bit);

/*
	An fz_colorspace object represents an abstract colorspace. While
	this should be treated as a black box by callers of the library at
	this stage, know that it encapsulates knowledge of how to convert
	colors to and from the colorspace, any lookup tables generated, the
	number of components in the colorspace etc.
*/
typedef struct fz_colorspace_s fz_colorspace;

/*
	fz_lookup_device_colorspace: Find a standard colorspace based upon
	it's name.
*/
fz_colorspace *fz_lookup_device_colorspace(fz_context *ctx, char *name);

/*
	fz_colorspace_is_indexed: Return true, iff a given colorspace is
	indexed.
*/
int fz_colorspace_is_indexed(fz_colorspace *cs);

/*
	fz_device_gray: Get colorspace representing device specific gray.
*/
fz_colorspace *fz_device_gray(fz_context *ctx);

/*
	fz_device_rgb: Get colorspace representing device specific rgb.
*/
fz_colorspace *fz_device_rgb(fz_context *ctx);

/*
	fz_device_bgr: Get colorspace representing device specific bgr.
*/
fz_colorspace *fz_device_bgr(fz_context *ctx);

/*
	fz_device_cmyk: Get colorspace representing device specific CMYK.
*/
fz_colorspace *fz_device_cmyk(fz_context *ctx);

/*
	fz_set_device_gray: Set colorspace representing device specific gray.
*/
void fz_set_device_gray(fz_context *ctx, fz_colorspace *cs);

/*
	fz_set_device_rgb: Set colorspace representing device specific rgb.
*/
void fz_set_device_rgb(fz_context *ctx, fz_colorspace *cs);

/*
	fz_set_device_bgr: Set colorspace representing device specific bgr.
*/
void fz_set_device_bgr(fz_context *ctx, fz_colorspace *cs);

/*
	fz_set_device_cmyk: Set colorspace representing device specific CMYK.
*/
void fz_set_device_cmyk(fz_context *ctx, fz_colorspace *cs);

/*
	Pixmaps represent a set of pixels for a 2 dimensional region of a
	plane. Each pixel has n components per pixel, the last of which is
	always alpha. The data is in premultiplied alpha when rendering, but
	non-premultiplied for colorspace conversions and rescaling.
*/
typedef struct fz_pixmap_s fz_pixmap;

/*
	fz_pixmap_bbox: Return the bounding box for a pixmap.
*/
fz_irect *fz_pixmap_bbox(fz_context *ctx, fz_pixmap *pix, fz_irect *bbox);

/*
	fz_pixmap_width: Return the width of the pixmap in pixels.
*/
int fz_pixmap_width(fz_context *ctx, fz_pixmap *pix);

/*
	fz_pixmap_height: Return the height of the pixmap in pixels.
*/
int fz_pixmap_height(fz_context *ctx, fz_pixmap *pix);

/*
	fz_new_pixmap: Create a new pixmap, with it's origin at (0,0)

	cs: The colorspace to use for the pixmap, or NULL for an alpha
	plane/mask.

	w: The width of the pixmap (in pixels)

	h: The height of the pixmap (in pixels)

	Returns a pointer to the new pixmap. Throws exception on failure to
	allocate.
*/
fz_pixmap *fz_new_pixmap(fz_context *ctx, fz_colorspace *cs, int w, int h);

/*
	fz_new_pixmap_with_bbox: Create a pixmap of a given size,
	location and pixel format.

	The bounding box specifies the size of the created pixmap and
	where it will be located. The colorspace determines the number
	of components per pixel. Alpha is always present. Pixmaps are
	reference counted, so drop references using fz_drop_pixmap.

	colorspace: Colorspace format used for the created pixmap. The
	pixmap will keep a reference to the colorspace.

	bbox: Bounding box specifying location/size of created pixmap.

	Returns a pointer to the new pixmap. Throws exception on failure to
	allocate.
*/
fz_pixmap *fz_new_pixmap_with_bbox(fz_context *ctx, fz_colorspace *colorspace, const fz_irect *bbox);

/*
	fz_new_pixmap_with_data: Create a new pixmap, with it's origin at
	(0,0) using the supplied data block.

	cs: The colorspace to use for the pixmap, or NULL for an alpha
	plane/mask.

	w: The width of the pixmap (in pixels)

	h: The height of the pixmap (in pixels)

	samples: The data block to keep the samples in.

	Returns a pointer to the new pixmap. Throws exception on failure to
	allocate.
*/
fz_pixmap *fz_new_pixmap_with_data(fz_context *ctx, fz_colorspace *colorspace, int w, int h, unsigned char *samples);

/*
	fz_new_pixmap_with_bbox_and_data: Create a pixmap of a given size,
	location and pixel format, using the supplied data block.

	The bounding box specifies the size of the created pixmap and
	where it will be located. The colorspace determines the number
	of components per pixel. Alpha is always present. Pixmaps are
	reference counted, so drop references using fz_drop_pixmap.

	colorspace: Colorspace format used for the created pixmap. The
	pixmap will keep a reference to the colorspace.

	bbox: Bounding box specifying location/size of created pixmap.

	samples: The data block to keep the samples in.

	Returns a pointer to the new pixmap. Throws exception on failure to
	allocate.
*/
fz_pixmap *fz_new_pixmap_with_bbox_and_data(fz_context *ctx, fz_colorspace *colorspace, const fz_irect *rect, unsigned char *samples);

/*
	fz_keep_pixmap: Take a reference to a pixmap.

	pix: The pixmap to increment the reference for.

	Returns pix. Does not throw exceptions.
*/
fz_pixmap *fz_keep_pixmap(fz_context *ctx, fz_pixmap *pix);

/*
	fz_drop_pixmap: Drop a reference and free a pixmap.

	Decrement the reference count for the pixmap. When no
	references remain the pixmap will be freed.

	Does not throw exceptions.
*/
void fz_drop_pixmap(fz_context *ctx, fz_pixmap *pix);

/*
	fz_pixmap_colorspace: Return the colorspace of a pixmap

	Returns colorspace. Does not throw exceptions.
*/
fz_colorspace *fz_pixmap_colorspace(fz_context *ctx, fz_pixmap *pix);

/*
	fz_pixmap_components: Return the number of components in a pixmap.

	Returns the number of components. Does not throw exceptions.
*/
int fz_pixmap_components(fz_context *ctx, fz_pixmap *pix);

/*
	fz_pixmap_samples: Returns a pointer to the pixel data of a pixmap.

	Returns the pointer. Does not throw exceptions.
*/
unsigned char *fz_pixmap_samples(fz_context *ctx, fz_pixmap *pix);

void fz_pixmap_set_resolution(fz_pixmap *pix, int res);

/*
	fz_clear_pixmap_with_value: Clears a pixmap with the given value.

	pix: The pixmap to clear.

	value: Values in the range 0 to 255 are valid. Each component
	sample for each pixel in the pixmap will be set to this value,
	while alpha will always be set to 255 (non-transparent).

	Does not throw exceptions.
*/
void fz_clear_pixmap_with_value(fz_context *ctx, fz_pixmap *pix, int value);

/*
	fz_clear_pixmap_with_value: Clears a subrect of a pixmap with the given value.

	pix: The pixmap to clear.

	value: Values in the range 0 to 255 are valid. Each component
	sample for each pixel in the pixmap will be set to this value,
	while alpha will always be set to 255 (non-transparent).

	r: the rectangle.

	Does not throw exceptions.
*/
void fz_clear_pixmap_rect_with_value(fz_context *ctx, fz_pixmap *pix, int value, const fz_irect *r);

/*
	fz_clear_pixmap_with_value: Sets all components (including alpha) of
	all pixels in a pixmap to 0.

	pix: The pixmap to clear.

	Does not throw exceptions.
*/
void fz_clear_pixmap(fz_context *ctx, fz_pixmap *pix);

/*
	fz_invert_pixmap: Invert all the pixels in a pixmap. All components
	of all pixels are inverted (except alpha, which is unchanged).

	Does not throw exceptions.
*/
void fz_invert_pixmap(fz_context *ctx, fz_pixmap *pix);

/*
	fz_invert_pixmap: Invert all the pixels in a given rectangle of a
	pixmap. All components of all pixels in the rectangle are inverted
	(except alpha, which is unchanged).

	Does not throw exceptions.
*/
void fz_invert_pixmap_rect(fz_pixmap *image, const fz_irect *rect);

/*
	fz_gamma_pixmap: Apply gamma correction to a pixmap. All components
	of all pixels are modified (except alpha, which is unchanged).

	gamma: The gamma value to apply; 1.0 for no change.

	Does not throw exceptions.
*/
void fz_gamma_pixmap(fz_context *ctx, fz_pixmap *pix, float gamma);

/*
	fz_unmultiply_pixmap: Convert a pixmap from premultiplied to
	non-premultiplied format.

	Does not throw exceptions.
*/
void fz_unmultiply_pixmap(fz_context *ctx, fz_pixmap *pix);

/*
	fz_convert_pixmap: Convert from one pixmap to another (assumed to be
	the same size, but possibly with a different colorspace).

	dst: the source pixmap.

	src: the destination pixmap.
*/
void fz_convert_pixmap(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src);

/*
	fz_write_pixmap: Save a pixmap out.

	name: The prefix for the name of the pixmap. The pixmap will be saved
	as "name.png" if the pixmap is RGB or Greyscale, "name.pam" otherwise.

	rgb: If non zero, the pixmap is converted to rgb (if possible) before
	saving.
*/
void fz_write_pixmap(fz_context *ctx, fz_pixmap *img, char *name, int rgb);

/*
	fz_write_pnm: Save a pixmap as a pnm

	filename: The filename to save as (including extension).
*/
void fz_write_pnm(fz_context *ctx, fz_pixmap *pixmap, char *filename);

/*
	fz_write_pam: Save a pixmap as a pam

	filename: The filename to save as (including extension).
*/
void fz_write_pam(fz_context *ctx, fz_pixmap *pixmap, char *filename, int savealpha);

/*
	fz_write_png: Save a pixmap as a png

	filename: The filename to save as (including extension).
*/
void fz_write_png(fz_context *ctx, fz_pixmap *pixmap, char *filename, int savealpha);

typedef struct fz_pwg_options_s fz_pwg_options;

struct fz_pwg_options_s
{
	/* These are not interpreted as CStrings by the writing code, but
	 * are rather copied directly out. */
	char media_class[64];
	char media_color[64];
	char media_type[64];
	char output_type[64];

	unsigned int advance_distance;
	int advance_media;
	int collate;
	int cut_media;
	int duplex;
	int insert_sheet;
	int jog;
	int leading_edge;
	int manual_feed;
	unsigned int media_position;
	unsigned int media_weight;
	int mirror_print;
	int negative_print;
	unsigned int num_copies;
	int orientation;
	int output_face_up;
	unsigned int PageSize[2];
	int separations;
	int tray_switch;
	int tumble;

	int media_type_num;
	int compression;
	unsigned int row_count;
	unsigned int row_feed;
	unsigned int row_step;

	/* These are not interpreted as CStrings by the writing code, but
	 * are rather copied directly out. */
	char rendering_intent[64];
	char page_size_name[64];
};

/*
	fz_write_pwg: Save a pixmap as a pwg

	filename: The filename to save as (including extension).

	append: If non-zero, then append a new page to existing file.

	pwg: NULL, or a pointer to an options structure (initialised to zero
	before being filled in, for future expansion).
*/
void fz_write_pwg(fz_context *ctx, fz_pixmap *pixmap, char *filename, int append, const fz_pwg_options *pwg);

/*
	fz_write_pwg_bitmap: Save a bitmap as a pwg

	filename: The filename to save as (including extension).

	append: If non-zero, then append a new page to existing file.

	pwg: NULL, or a pointer to an options structure (initialised to zero
	before being filled in, for future expansion).
*/
void fz_write_pwg_bitmap(fz_context *ctx, fz_bitmap *bitmap, char *filename, int append, const fz_pwg_options *pwg);

/*
	fz_write_pbm: Save a bitmap as a pbm

	filename: The filename to save as (including extension).
*/
void fz_write_pbm(fz_context *ctx, fz_bitmap *bitmap, char *filename);

/*
	fz_md5_pixmap: Return the md5 digest for a pixmap

	filename: The filename to save as (including extension).
*/
void fz_md5_pixmap(fz_pixmap *pixmap, unsigned char digest[16]);

/*
	Images are storable objects from which we can obtain fz_pixmaps.
	These may be implemented as simple wrappers around a pixmap, or as
	more complex things that decode at different subsample settings on
	demand.
*/
typedef struct fz_image_s fz_image;

/*
	fz_image_to_pixmap: Called to get a handle to a pixmap from an image.

	image: The image to retrieve a pixmap from.

	w: The desired width (in pixels). This may be completely ignored, but
	may serve as an indication of a suitable subsample factor to use for
	image types that support this.

	h: The desired height (in pixels). This may be completely ignored, but
	may serve as an indication of a suitable subsample factor to use for
	image types that support this.

	Returns a non NULL pixmap pointer. May throw exceptions.
*/
fz_pixmap *fz_image_to_pixmap(fz_context *ctx, fz_image *image, int w, int h);

/*
	fz_drop_image: Drop a reference to an image.

	image: The image to drop a reference to.
*/
void fz_drop_image(fz_context *ctx, fz_image *image);

/*
	fz_keep_image: Increment the reference count of an image.

	image: The image to take a reference to.

	Returns a pointer to the image.
*/
fz_image *fz_keep_image(fz_context *ctx, fz_image *image);

/*
	A halftone is a set of threshold tiles, one per component. Each
	threshold tile is a pixmap, possibly of varying sizes and phases.
	Currently, we only provide one 'default' halftone tile for operating
	on 1 component plus alpha pixmaps (where the alpha is ignored). This
	is signified by an fz_halftone pointer to NULL.
*/
typedef struct fz_halftone_s fz_halftone;

/*
	fz_halftone_pixmap: Make a bitmap from a pixmap and a halftone.

	pix: The pixmap to generate from. Currently must be a single color
	component + alpha (where the alpha is assumed to be solid).

	ht: The halftone to use. NULL implies the default halftone.

	Returns the resultant bitmap. Throws exceptions in the case of
	failure to allocate.
*/
fz_bitmap *fz_halftone_pixmap(fz_context *ctx, fz_pixmap *pix, fz_halftone *ht);

/*
	An abstract font handle. Currently there are no public API functions
	for handling these.
*/
typedef struct fz_font_s fz_font;

/*
	Generic output streams - generalise between outputting to a file,
	a buffer, etc.
*/
typedef struct fz_output_s fz_output;

struct fz_output_s
{
	fz_context *ctx;
	void *opaque;
	int (*printf)(fz_output *, const char *, va_list ap);
	int (*write)(fz_output *, const void *, int n);
	void (*close)(fz_output *);
};

/*
	fz_new_output_with_file: Open an output stream onto a FILE *.

	The stream does NOT take ownership of the FILE *.
*/
fz_output *fz_new_output_with_file(fz_context *, FILE *);

/*
	fz_new_output_with_buffer: Open an output stream onto a buffer.

	The stream does NOT take ownership of the buffer.
*/
fz_output *fz_new_output_with_buffer(fz_context *, fz_buffer *);

/*
	fz_printf: fprintf equivalent for output streams.
*/
int fz_printf(fz_output *, const char *, ...);

/*
	fz_puts: fputs equivalent for output streams.
*/
int fz_puts(fz_output *, const char *);

/*
	fz_write: fwrite equivalent for output streams.
*/
int fz_write(fz_output *out, const void *data, int len);

/*
	Output a pixmap to an output stream as a png.
*/
void fz_output_png(fz_output *out, const fz_pixmap *pixmap, int savealpha);

/*
	Output a pixmap to an output stream as a pwg raster.
*/
void fz_output_pwg(fz_output *out, const fz_pixmap *pixmap, const fz_pwg_options *pwg);

/*
	Output the file header to a pwg stream, ready for pages to follow it.
*/
void fz_output_pwg_file_header(fz_output *out);

/*
	Output a page to a pwg stream to follow a header, or other pages.
*/
void fz_output_pwg_page(fz_output *out, const fz_pixmap *pixmap, const fz_pwg_options *pwg);

/*
	Output a bitmap page to a pwg stream to follow a header, or other pages.
*/
void fz_output_pwg_bitmap_page(fz_output *out, const fz_bitmap *bitmap, const fz_pwg_options *pwg);

/*
	Get an image as a png in a buffer.
*/
fz_buffer *fz_image_as_png(fz_context *ctx, fz_image *image, int w, int h);

/*
	fz_close_output: Close a previously opened fz_output stream.

	Note: whether or not this closes the underlying output method is
	method dependent. FILE * streams created by fz_new_output_with_file
	are NOT closed.
*/
void fz_close_output(fz_output *);

/*
	The different format handlers (pdf, xps etc) interpret pages to a
	device. These devices can then process the stream of calls they
	recieve in various ways:
		The trace device outputs debugging information for the calls.
		The draw device will render them.
		The list device stores them in a list to play back later.
		The text device performs text extraction and searching.
		The bbox device calculates the bounding box for the page.
	Other devices can (and will) be written in future.
*/
typedef struct fz_device_s fz_device;

/*
	fz_free_device: Free a devices of any type and its resources.
*/
void fz_free_device(fz_device *dev);

/*
	fz_new_trace_device: Create a device to print a debug trace of
	all device calls.
*/
fz_device *fz_new_trace_device(fz_context *ctx);

/*
	fz_new_bbox_device: Create a device to compute the bounding
	box of all marks on a page.

	The returned bounding box will be the union of all bounding
	boxes of all objects on a page.
*/
fz_device *fz_new_bbox_device(fz_context *ctx, fz_rect *rectp);

/*
	fz_new_draw_device: Create a device to draw on a pixmap.

	dest: Target pixmap for the draw device. See fz_new_pixmap*
	for how to obtain a pixmap. The pixmap is not cleared by the
	draw device, see fz_clear_pixmap* for how to clear it prior to
	calling fz_new_draw_device. Free the device by calling
	fz_free_device.
*/
fz_device *fz_new_draw_device(fz_context *ctx, fz_pixmap *dest);

/*
	fz_new_draw_device_with_bbox: Create a device to draw on a pixmap.

	dest: Target pixmap for the draw device. See fz_new_pixmap*
	for how to obtain a pixmap. The pixmap is not cleared by the
	draw device, see fz_clear_pixmap* for how to clear it prior to
	calling fz_new_draw_device. Free the device by calling
	fz_free_device.

	clip: Bounding box to restrict any marking operations of the
	draw device.
*/
fz_device *fz_new_draw_device_with_bbox(fz_context *ctx, fz_pixmap *dest, const fz_irect *clip);

fz_device *fz_new_svg_device(fz_context *ctx, fz_output *out, float page_width, float page_height);

/*
	fz_enable_device_hints : Enable hints in a device.

	hints: mask of hints to enable.

	For example: By default the draw device renders shadings. For some
	purposes (perhaps rendering fast low quality thumbnails) you may want
	to tell it to ignore shadings. For this you would enable the
	FZ_IGNORE_SHADE hint.
*/
void fz_enable_device_hints(fz_device *dev, int hints);

/*
	fz_disable_device_hints : Disable hints in a device.

	hints: mask of hints to disable.

	For example: By default the text extraction device ignores images.
	For some purposes however (such as extracting HTML) you may want to
	enable the capturing of image data too. For this you would disable
	the FZ_IGNORE_IMAGE hint.
*/
void fz_disable_device_hints(fz_device *dev, int hints);

enum
{
	/* Hints */
	FZ_IGNORE_IMAGE = 1,
	FZ_IGNORE_SHADE = 2,
};

/*
	Text extraction device: Used for searching, format conversion etc.

	(In development - Subject to change in future versions)
*/

typedef struct fz_text_style_s fz_text_style;
typedef struct fz_text_char_s fz_text_char;
typedef struct fz_text_span_s fz_text_span;
typedef struct fz_text_line_s fz_text_line;
typedef struct fz_text_block_s fz_text_block;
typedef struct fz_image_block_s fz_image_block;
typedef struct fz_page_block_s fz_page_block;

typedef struct fz_text_sheet_s fz_text_sheet;
typedef struct fz_text_page_s fz_text_page;

/*
	fz_text_sheet: A text sheet contains a list of distinct text styles
	used on a page (or a series of pages).
*/
struct fz_text_sheet_s
{
	int maxid;
	fz_text_style *style;
};

/*
	fz_text_style: A text style contains details of a distinct text style
	used on a page.
*/
struct fz_text_style_s
{
	fz_text_style *next;
	int id;
	fz_font *font;
	float size;
	int wmode;
	int script;
	float ascender;
	float descender;
	/* etc... */
};

/*
	fz_text_page: A text page is a list of page blocks, together with
	an overall bounding box.
*/
struct fz_text_page_s
{
	fz_rect mediabox;
	int len, cap;
	fz_page_block *blocks;
	fz_text_page *next;
};

/*
	fz_page_block: A page block is a typed block pointer.
*/
struct fz_page_block_s
{
	int type;
	union
	{
		fz_text_block *text;
		fz_image_block *image;
	} u;
};

enum
{
	FZ_PAGE_BLOCK_TEXT = 0,
	FZ_PAGE_BLOCK_IMAGE = 1
};

/*
	fz_text_block: A text block is a list of lines of text. In typical
	cases this may correspond to a paragraph or a column of text. A
	collection of blocks makes up a page.
*/
struct fz_text_block_s
{
	fz_rect bbox;
	int len, cap;
	fz_text_line *lines;
};

enum { FZ_MAX_COLORS = 32 };

/*
	fz_image_block: An image block is an image, together with the  list of lines of text. In typical
	cases this may correspond to a paragraph or a column of text. A
	collection of blocks makes up a page.
*/
struct fz_image_block_s
{
	fz_rect bbox;
	fz_matrix mat;
	fz_image *image;
	fz_colorspace *cspace;
	float colors[FZ_MAX_COLORS];
};

/*
	fz_text_line: A text line is a list of text spans, with the same
	baseline. In typical cases this should correspond (as expected) to
	complete lines of text. A collection of lines makes up a block.
*/
struct fz_text_line_s
{
	fz_text_span *first_span, *last_span;

	/* Cached information */
	float distance; /* Perpendicular distance from previous line */
	fz_rect bbox;
	void *region; /* Opaque value for matching line masks */
};

/*
	fz_text_span: A text span is a list of characters that share a common
	baseline/transformation. In typical cases a single span may be enough
	to represent a complete line. In cases where the text has big gaps in
	it (perhaps as it crosses columns or tables), a line may be represented
	by multiple spans.
*/
struct fz_text_span_s
{
	int len, cap;
	fz_text_char *text;
	fz_point min; /* Device space */
	fz_point max; /* Device space */
	int wmode; /* 0 for horizontal, 1 for vertical */
	fz_matrix transform; /* e and f are always 0 here */
	float ascender_max; /* Document space */
	float descender_min; /* Document space */
	fz_rect bbox; /* Device space */

	/* Cached information */
	float base_offset; /* Perpendicular distance from baseline of line */
	float spacing; /* Distance along baseline from previous span in this line (or 0 if first) */
	int column; /* If non zero, the column that it's in */
	float column_width; /* Percentage */
	int align; /* 0 = left, 1 = centre, 2 = right */
	float indent; /* The indent position for this column. */

	fz_text_span *next;
};

/*
	fz_text_char: A text char is a unicode character, the style in which
	is appears, and the point at which it is positioned. Transform
	(and hence bbox) information is given by the enclosing span.
*/
struct fz_text_char_s
{
	fz_point p; /* Device space */
	int c;
	fz_text_style *style;
};

typedef struct fz_char_and_box_s fz_char_and_box;

struct fz_char_and_box_s
{
	int c;
	fz_rect bbox;
};

fz_char_and_box *fz_text_char_at(fz_char_and_box *cab, fz_text_page *page, int idx);

/*
	fz_text_char_bbox: Return the bbox of a text char. Calculated from
	the supplied enclosing span.

	bbox: A place to store the bbox

	span: The enclosing span

	idx: The index of the char within the span

	Returns bbox (updated)

	Does not throw exceptions
*/
fz_rect *fz_text_char_bbox(fz_rect *bbox, fz_text_span *span, int idx);

/*
	fz_new_text_device: Create a device to extract the text on a page.

	Gather and sort the text on a page into spans of uniform style,
	arranged into lines and blocks by reading order. The reading order
	is determined by various heuristics, so may not be accurate.

	sheet: The text sheet to which styles should be added. This can
	either be a newly created (empty) text sheet, or one containing
	styles from a previous text device. The same sheet cannot be used
	in multiple threads simultaneously.

	page: The text page to which content should be added. This will
	usually be a newly created (empty) text page, but it can be one
	containing data already (for example when merging multiple pages, or
	watermarking).
*/
fz_device *fz_new_text_device(fz_context *ctx, fz_text_sheet *sheet, fz_text_page *page);

/*
	fz_new_text_sheet: Create an empty style sheet.

	The style sheet is filled out by the text device, creating
	one style for each unique font, color, size combination that
	is used.
*/
fz_text_sheet *fz_new_text_sheet(fz_context *ctx);
void fz_free_text_sheet(fz_context *ctx, fz_text_sheet *sheet);

/*
	fz_new_text_page: Create an empty text page.

	The text page is filled out by the text device to contain the blocks,
	lines and spans of text on the page.
*/
fz_text_page *fz_new_text_page(fz_context *ctx);
void fz_free_text_page(fz_context *ctx, fz_text_page *page);

void fz_analyze_text(fz_context *ctx, fz_text_sheet *sheet, fz_text_page *page);

/*
	fz_print_text_sheet: Output a text sheet to a file as CSS.
*/
void fz_print_text_sheet(fz_context *ctx, fz_output *out, fz_text_sheet *sheet);

/*
	fz_print_text_page_html: Output a page to a file in HTML format.
*/
void fz_print_text_page_html(fz_context *ctx, fz_output *out, fz_text_page *page);

/*
	fz_print_text_page_xml: Output a page to a file in XML format.
*/
void fz_print_text_page_xml(fz_context *ctx, fz_output *out, fz_text_page *page);

/*
	fz_print_text_page: Output a page to a file in UTF-8 format.
*/
void fz_print_text_page(fz_context *ctx, fz_output *out, fz_text_page *page);

/*
	fz_search_text_page: Search for occurrence of 'needle' in text page.

	Return the number of hits and store hit bboxes in the passed in array.

	NOTE: This is an experimental interface and subject to change without notice.
*/
int fz_search_text_page(fz_context *ctx, fz_text_page *text, const char *needle, fz_rect *hit_bbox, int hit_max);

/*
	fz_highlight_selection: Return a list of rectangles to highlight given a selection rectangle.

	NOTE: This is an experimental interface and subject to change without notice.
*/
int fz_highlight_selection(fz_context *ctx, fz_text_page *page, fz_rect rect, fz_rect *hit_bbox, int hit_max);

/*
	fz_copy_selection: Return a newly allocated UTF-8 string with the text for a given selection rectangle.

	NOTE: This is an experimental interface and subject to change without notice.
*/
char *fz_copy_selection(fz_context *ctx, fz_text_page *page, fz_rect rect);

/*
	Cookie support - simple communication channel between app/library.
*/

typedef struct fz_cookie_s fz_cookie;

/*
	Provide two-way communication between application and library.
	Intended for multi-threaded applications where one thread is
	rendering pages and another thread wants read progress
	feedback or abort a job that takes a long time to finish. The
	communication is unsynchronized without locking.

	abort: The appliation should set this field to 0 before
	calling fz_run_page to render a page. At any point when the
	page is being rendered the application my set this field to 1
	which will cause the rendering to finish soon. This field is
	checked periodically when the page is rendered, but exactly
	when is not known, therefore there is no upper bound on
	exactly when the the rendering will abort. If the application
	did not provide a set of locks to fz_new_context, it must also
	await the completion of fz_run_page before issuing another
	call to fz_run_page. Note that once the application has set
	this field to 1 after it called fz_run_page it may not change
	the value again.

	progress: Communicates rendering progress back to the
	application and is read only. Increments as a page is being
	rendered. The value starts out at 0 and is limited to less
	than or equal to progress_max, unless progress_max is -1.

	progress_max: Communicates the known upper bound of rendering
	back to the application and is read only. The maximum value
	that the progress field may take. If there is no known upper
	bound on how long the rendering may take this value is -1 and
	progress is not limited. Note that the value of progress_max
	may change from -1 to a positive value once an upper bound is
	known, so take this into consideration when comparing the
	value of progress to that of progress_max.

	errors: count of errors during current rendering.
*/
struct fz_cookie_s
{
	int abort;
	int progress;
	int progress_max; /* -1 for unknown */
	int errors;
};

/*
	Display list device -- record and play back device commands.
*/

/*
	fz_display_list is a list containing drawing commands (text,
	images, etc.). The intent is two-fold: as a caching-mechanism
	to reduce parsing of a page, and to be used as a data
	structure in multi-threading where one thread parses the page
	and another renders pages.

	Create a displaylist with fz_new_display_list, hand it over to
	fz_new_list_device to have it populated, and later replay the
	list (once or many times) by calling fz_run_display_list. When
	the list is no longer needed drop it with fz_drop_display_list.
*/
typedef struct fz_display_list_s fz_display_list;

/*
	fz_new_display_list: Create an empty display list.

	A display list contains drawing commands (text, images, etc.).
	Use fz_new_list_device for populating the list.
*/
fz_display_list *fz_new_display_list(fz_context *ctx);

/*
	fz_new_list_device: Create a rendering device for a display list.

	When the device is rendering a page it will populate the
	display list with drawing commsnds (text, images, etc.). The
	display list can later be reused to render a page many times
	without having to re-interpret the page from the document file
	for each rendering. Once the device is no longer needed, free
	it with fz_free_device.

	list: A display list that the list device takes ownership of.
*/
fz_device *fz_new_list_device(fz_context *ctx, fz_display_list *list);

/*
	fz_run_display_list: (Re)-run a display list through a device.

	list: A display list, created by fz_new_display_list and
	populated with objects from a page by running fz_run_page on a
	device obtained from fz_new_list_device.

	dev: Device obtained from fz_new_*_device.

	ctm: Transform to apply to display list contents. May include
	for example scaling and rotation, see fz_scale, fz_rotate and
	fz_concat. Set to fz_identity if no transformation is desired.

	area: Only the part of the contents of the display list
	visible within this area will be considered when the list is
	run through the device. This does not imply for tile objects
	contained in the display list.

	cookie: Communication mechanism between caller and library
	running the page. Intended for multi-threaded applications,
	while single-threaded applications set cookie to NULL. The
	caller may abort an ongoing page run. Cookie also communicates
	progress information back to the caller. The fields inside
	cookie are continually updated while the page is being run.
*/
void fz_run_display_list(fz_display_list *list, fz_device *dev, const fz_matrix *ctm, const fz_rect *area, fz_cookie *cookie);

/*
	fz_keep_display_list: Keep a reference to a display list.

	Does not throw exceptions.
*/
fz_display_list *fz_keep_display_list(fz_context *ctx, fz_display_list *list);

/*
	fz_drop_display_list: Drop a reference to a display list, freeing it
	if the reference count reaches zero.

	Does not throw exceptions.
*/
void fz_drop_display_list(fz_context *ctx, fz_display_list *list);

/*
	Links

	NOTE: The link destination struct is scheduled for imminent change!
	Use at your own peril.
*/

typedef struct fz_link_s fz_link;

typedef struct fz_link_dest_s fz_link_dest;

typedef enum fz_link_kind_e
{
	FZ_LINK_NONE = 0,
	FZ_LINK_GOTO,
	FZ_LINK_URI,
	FZ_LINK_LAUNCH,
	FZ_LINK_NAMED,
	FZ_LINK_GOTOR
} fz_link_kind;

enum {
	fz_link_flag_l_valid = 1, /* lt.x is valid */
	fz_link_flag_t_valid = 2, /* lt.y is valid */
	fz_link_flag_r_valid = 4, /* rb.x is valid */
	fz_link_flag_b_valid = 8, /* rb.y is valid */
	fz_link_flag_fit_h = 16, /* Fit horizontally */
	fz_link_flag_fit_v = 32, /* Fit vertically */
	fz_link_flag_r_is_zoom = 64 /* rb.x is actually a zoom figure */
};

/*
	fz_link_dest: This structure represents the destination of
	an fz_link; this may be a page to display, a new file to open,
	a javascript action to perform, etc.

	kind: This identifies the kind of link destination. Different
	kinds use different sections of the union.

	For FZ_LINK_GOTO or FZ_LINK_GOTOR:

		gotor.page: The target page number to move to (0 being the
		first page in the document).

		gotor.flags: A bitfield consisting of fz_link_flag_*
		describing the validity and meaning of the different parts
		of gotor.lt and gotor.rb. Link destinations are constructed
		(as far as possible) so that lt and rb can be treated as a
		bounding box, though the validity flags indicate which of the
		values was actually specified in the file.

		gotor.lt: The top left corner of the destination bounding box.

		gotor.rb: The bottom right corner of the destination bounding
		box. If fz_link_flag_r_is_zoom is set, then the r figure
		should actually be interpretted as a zoom ratio.

		gotor.file_spec: If set, this destination should cause a new
		file to be opened; this field holds a pointer to a remote
		file specification (UTF-8). Always NULL in the FZ_LINK_GOTO
		case.

		gotor.new_window: If true, the destination should open in a
		new window.

	For FZ_LINK_URI:

		uri.uri: A UTF-8 encoded URI to launch.

		uri.is_map: If true, the x and y coords (as ints, in user
		space) should be appended to the URI before launch.

	For FZ_LINK_LAUNCH:

		launch.file_spec: A UTF-8 file specification to launch.

		launch.new_window: If true, the destination should be launched
		in a new window.

	For FZ_LINK_NAMED:

		named.named: The named action to perform. Likely to be
		client specific.
*/
struct fz_link_dest_s
{
	fz_link_kind kind;
	union
	{
		struct
		{
			int page;
			int flags;
			fz_point lt;
			fz_point rb;
			char *file_spec;
			int new_window;
		}
		gotor;
		struct
		{
			char *uri;
			int is_map;
		}
		uri;
		struct
		{
			char *file_spec;
			int new_window;
		}
		launch;
		struct
		{
			char *named;
		}
		named;
	}
	ld;
};

/*
	fz_link is a list of interactive links on a page.

	There is no relation between the order of the links in the
	list and the order they appear on the page. The list of links
	for a given page can be obtained from fz_load_links.

	A link is reference counted. Dropping a reference to a link is
	done by calling fz_drop_link.

	rect: The hot zone. The area that can be clicked in
	untransformed coordinates.

	dest: Link destinations come in two forms: Page and area that
	an application should display when this link is activated. Or
	as an URI that can be given to a browser.

	next: A pointer to the next link on the same page.
*/
struct fz_link_s
{
	int refs;
	fz_rect rect;
	fz_link_dest dest;
	fz_link *next;
};

fz_link *fz_new_link(fz_context *ctx, const fz_rect *bbox, fz_link_dest dest);
fz_link *fz_keep_link(fz_context *ctx, fz_link *link);

/*
	fz_drop_link: Drop and free a list of links.

	Does not throw exceptions.
*/
void fz_drop_link(fz_context *ctx, fz_link *link);

void fz_free_link_dest(fz_context *ctx, fz_link_dest *dest);

/* Outline */

typedef struct fz_outline_s fz_outline;

/*
	fz_outline is a tree of the outline of a document (also known
	as table of contents).

	title: Title of outline item using UTF-8 encoding. May be NULL
	if the outline item has no text string.

	dest: Destination in the document to be displayed when this
	outline item is activated. May be FZ_LINK_NONE if the outline
	item does not have a destination.

	next: The next outline item at the same level as this outline
	item. May be NULL if no more outline items exist at this level.

	down: The outline items immediate children in the hierarchy.
	May be NULL if no children exist.
*/
struct fz_outline_s
{
	char *title;
	fz_link_dest dest;
	fz_outline *next;
	fz_outline *down;
};

/*
	fz_print_outline_xml: Dump the given outlines as (pseudo) XML.

	out: The file handle to output to.

	outline: The outlines to output.
*/
void fz_print_outline_xml(fz_context *ctx, fz_output *out, fz_outline *outline);

/*
	fz_print_outline: Dump the given outlines to as text.

	out: The file handle to output to.

	outline: The outlines to output.
*/
void fz_print_outline(fz_context *ctx, fz_output *out, fz_outline *outline);

/*
	fz_free_outline: Free hierarchical outline.

	Free an outline obtained from fz_load_outline.

	Does not throw exceptions.
*/
void fz_free_outline(fz_context *ctx, fz_outline *outline);

/* Transition support */
typedef struct fz_transition_s fz_transition;

enum {
	FZ_TRANSITION_NONE = 0, /* aka 'R' or 'REPLACE' */
	FZ_TRANSITION_SPLIT,
	FZ_TRANSITION_BLINDS,
	FZ_TRANSITION_BOX,
	FZ_TRANSITION_WIPE,
	FZ_TRANSITION_DISSOLVE,
	FZ_TRANSITION_GLITTER,
	FZ_TRANSITION_FLY,
	FZ_TRANSITION_PUSH,
	FZ_TRANSITION_COVER,
	FZ_TRANSITION_UNCOVER,
	FZ_TRANSITION_FADE
};

struct fz_transition_s
{
	int type;
	float duration; /* Effect duration (seconds) */

	/* Parameters controlling the effect */
	int vertical; /* 0 or 1 */
	int outwards; /* 0 or 1 */
	int direction; /* Degrees */
	/* Potentially more to come */

	/* State variables for use of the transition code */
	int state0;
	int state1;
};

/*
	fz_generate_transition: Generate a frame of a transition.

	tpix: Target pixmap
	opix: Old pixmap
	npix: New pixmap
	time: Position within the transition (0 to 256)
	trans: Transition details

	Returns 1 if successfully generated a frame.
*/
int fz_generate_transition(fz_pixmap *tpix, fz_pixmap *opix, fz_pixmap *npix, int time, fz_transition *trans);

/*
	Document interface
*/
typedef struct fz_document_s fz_document;
typedef struct fz_page_s fz_page;

/*
	fz_open_document: Open a PDF, XPS or CBZ document.

	Open a document file and read its basic structure so pages and
	objects can be located. MuPDF will try to repair broken
	documents (without actually changing the file contents).

	The returned fz_document is used when calling most other
	document related functions. Note that it wraps the context, so
	those functions implicitly can access the global state in
	context.

	filename: a path to a file as it would be given to open(2).
*/
fz_document *fz_open_document(fz_context *ctx, const char *filename);

/*
	fz_open_document_with_stream: Open a PDF, XPS or CBZ document.

	Open a document using the specified stream object rather than
	opening a file on disk.

	magic: a string used to detect document type; either a file name or mime-type.
*/
fz_document *fz_open_document_with_stream(fz_context *ctx, const char *magic, fz_stream *stream);

/*
	fz_close_document: Close and free an open document.

	The resource store in the context associated with fz_document
	is emptied, and any allocations for the document are freed.

	Does not throw exceptions.
*/
void fz_close_document(fz_document *doc);

/*
	fz_needs_password: Check if a document is encrypted with a
	non-blank password.

	Does not throw exceptions.
*/
int fz_needs_password(fz_document *doc);

/*
	fz_authenticate_password: Test if the given password can
	decrypt the document.

	password: The password string to be checked. Some document
	specifications do not specify any particular text encoding, so
	neither do we.

	Does not throw exceptions.
*/
int fz_authenticate_password(fz_document *doc, char *password);

/*
	fz_load_outline: Load the hierarchical document outline.

	Should be freed by fz_free_outline.
*/
fz_outline *fz_load_outline(fz_document *doc);

/*
	fz_count_pages: Return the number of pages in document

	May return 0 for documents with no pages.
*/
int fz_count_pages(fz_document *doc);

/*
	fz_load_page: Load a page.

	After fz_load_page is it possible to retrieve the size of the
	page using fz_bound_page, or to render the page using
	fz_run_page_*. Free the page by calling fz_free_page.

	number: page number, 0 is the first page of the document.
*/
fz_page *fz_load_page(fz_document *doc, int number);

/*
	fz_load_links: Load the list of links for a page.

	Returns a linked list of all the links on the page, each with
	its clickable region and link destination. Each link is
	reference counted so drop and free the list of links by
	calling fz_drop_link on the pointer return from fz_load_links.

	page: Page obtained from fz_load_page.
*/
fz_link *fz_load_links(fz_document *doc, fz_page *page);

/*
	fz_bound_page: Determine the size of a page at 72 dpi.

	Does not throw exceptions.
*/
fz_rect *fz_bound_page(fz_document *doc, fz_page *page, fz_rect *rect);

/*
	fz_annot: opaque pointer to annotation details.
*/
typedef struct fz_annot_s fz_annot;

typedef enum
{
	FZ_ANNOT_TEXT,
	FZ_ANNOT_LINK,
	FZ_ANNOT_FREETEXT,
	FZ_ANNOT_LINE,
	FZ_ANNOT_SQUARE,
	FZ_ANNOT_CIRCLE,
	FZ_ANNOT_POLYGON,
	FZ_ANNOT_POLYLINE,
	FZ_ANNOT_HIGHLIGHT,
	FZ_ANNOT_UNDERLINE,
	FZ_ANNOT_SQUIGGLY,
	FZ_ANNOT_STRIKEOUT,
	FZ_ANNOT_STAMP,
	FZ_ANNOT_CARET,
	FZ_ANNOT_INK,
	FZ_ANNOT_POPUP,
	FZ_ANNOT_FILEATTACHMENT,
	FZ_ANNOT_SOUND,
	FZ_ANNOT_MOVIE,
	FZ_ANNOT_WIDGET,
	FZ_ANNOT_SCREEN,
	FZ_ANNOT_PRINTERMARK,
	FZ_ANNOT_TRAPNET,
	FZ_ANNOT_WATERMARK,
	FZ_ANNOT_3D
} fz_annot_type;

/*
	fz_get_annot_type: return the type of an annotation
*/
fz_annot_type fz_get_annot_type(fz_annot *annot);

/*
	fz_first_annot: Return a pointer to the first annotation on a page.

	Does not throw exceptions.
*/
fz_annot *fz_first_annot(fz_document *doc, fz_page *page);

/*
	fz_next_annot: Return a pointer to the next annotation on a page.

	Does not throw exceptions.
*/
fz_annot *fz_next_annot(fz_document *doc, fz_annot *annot);

/*
	fz_bound_annot: Return the bounding rectangle of the annotation.

	Does not throw exceptions.
*/
fz_rect *fz_bound_annot(fz_document *doc, fz_annot *annot, fz_rect *rect);

/*
	fz_run_page: Run a page through a device.

	page: Page obtained from fz_load_page.

	dev: Device obtained from fz_new_*_device.

	transform: Transform to apply to page. May include for example
	scaling and rotation, see fz_scale, fz_rotate and fz_concat.
	Set to fz_identity if no transformation is desired.

	cookie: Communication mechanism between caller and library
	rendering the page. Intended for multi-threaded applications,
	while single-threaded applications set cookie to NULL. The
	caller may abort an ongoing rendering of a page. Cookie also
	communicates progress information back to the caller. The
	fields inside cookie are continually updated while the page is
	rendering.
*/
void fz_run_page(fz_document *doc, fz_page *page, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie);

/*
	fz_run_page_contents: Run a page through a device. Just the main
	page content, without the annotations, if any.

	page: Page obtained from fz_load_page.

	dev: Device obtained from fz_new_*_device.

	transform: Transform to apply to page. May include for example
	scaling and rotation, see fz_scale, fz_rotate and fz_concat.
	Set to fz_identity if no transformation is desired.

	cookie: Communication mechanism between caller and library
	rendering the page. Intended for multi-threaded applications,
	while single-threaded applications set cookie to NULL. The
	caller may abort an ongoing rendering of a page. Cookie also
	communicates progress information back to the caller. The
	fields inside cookie are continually updated while the page is
	rendering.
*/
void fz_run_page_contents(fz_document *doc, fz_page *page, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie);

/*
	fz_run_annot: Run an annotation through a device.

	page: Page obtained from fz_load_page.

	annot: an annotation.

	dev: Device obtained from fz_new_*_device.

	transform: Transform to apply to page. May include for example
	scaling and rotation, see fz_scale, fz_rotate and fz_concat.
	Set to fz_identity if no transformation is desired.

	cookie: Communication mechanism between caller and library
	rendering the page. Intended for multi-threaded applications,
	while single-threaded applications set cookie to NULL. The
	caller may abort an ongoing rendering of a page. Cookie also
	communicates progress information back to the caller. The
	fields inside cookie are continually updated while the page is
	rendering.
*/
void fz_run_annot(fz_document *doc, fz_page *page, fz_annot *annot, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie);

/*
	fz_free_page: Free a loaded page.

	Does not throw exceptions.
*/
void fz_free_page(fz_document *doc, fz_page *page);

/*
	fz_meta: Perform a meta operation on a document.

	(In development - Subject to change in future versions)

	Meta operations provide a way to perform format specific
	operations on a document. The meta operation scheme is
	designed to be extensible so that new features can be
	transparently added in later versions of the library.

	doc: The document on which to perform the meta operation.

	key: The meta operation to try. If a particular operation
	is unsupported on a given document, the function will return
	FZ_META_UNKNOWN_KEY.

	ptr: An operation dependent (possibly NULL) pointer.

	size: An operation dependent integer. Often this will
	be the size of the block pointed to by ptr, but not always.

	Returns an operation dependent value; FZ_META_UNKNOWN_KEY
	always means "unknown operation for this document". In general
	FZ_META_OK should be used to indicate successful operation.
*/
int fz_meta(fz_document *doc, int key, void *ptr, int size);

enum
{
	FZ_META_UNKNOWN_KEY = -1,
	FZ_META_OK = 0,

	/*
		ptr: Pointer to block (uninitialised on entry)
		size: Size of block (at least 64 bytes)
		Returns: Document format as a brief text string.
		All formats should support this.
	*/
	FZ_META_FORMAT_INFO = 1,

	/*
		ptr: Pointer to block (uninitialised on entry)
		size: Size of block (at least 64 bytes)
		Returns: Encryption info as a brief text string.
	*/
	FZ_META_CRYPT_INFO = 2,

	/*
		ptr: NULL
		size: Which permission to check
		Returns: 1 if permitted, 0 otherwise.
	*/
	FZ_META_HAS_PERMISSION = 3,

	FZ_PERMISSION_PRINT = 0,
	FZ_PERMISSION_CHANGE = 1,
	FZ_PERMISSION_COPY = 2,
	FZ_PERMISSION_NOTES = 3,

	/*
		ptr: Pointer to block. First entry in the block is
		a pointer to a UTF8 string to lookup. The rest of the
		block is uninitialised on entry.
		size: size of the block in bytes.
		Returns: 0 if not found. 1 if found. The string
		result is copied into the block (truncated to size
		and NULL terminated)

	*/
	FZ_META_INFO = 4,
};

/*
	fz_page_presentation: Get the presentation details for a given page.

	duration: NULL, or a pointer to a place to set the page duration in
	seconds. (Will be set to 0 if unspecified).

	Returns: a pointer to a transition structure, or NULL if there isn't
	one.

	Does not throw exceptions.
*/
fz_transition *fz_page_presentation(fz_document *doc, fz_page *page, float *duration);



/*
	fz_javascript_supported: test whether a version of mupdf with
	a javascript engine is in use.
*/
int fz_javascript_supported(void);

typedef struct fz_write_options_s fz_write_options;

/*
	In calls to fz_write, the following options structure can be used
	to control aspects of the writing process. This structure may grow
	in future, and should be zero-filled to allow forwards compatiblity.
*/
struct fz_write_options_s
{
	int do_ascii; /* If non-zero then attempt (where possible) to make
				the output ascii. */
	int do_expand; /* Bitflags; each non zero bit indicates an aspect
				of the file that should be 'expanded' on
				writing. */
	int do_garbage; /* If non-zero then attempt (where possible) to
				garbage collect the file before writing. */
	int do_linear; /* If non-zero then write linearised. */
	int continue_on_error; /* If non-zero, errors are (optionally)
					counted and writing continues. */
	int *errors; /* Pointer to a place to store a count of errors */
};

/*	An enumeration of bitflags to use in the above 'do_expand' field of
	fz_write_options.
*/
enum
{
	fz_expand_images = 1,
	fz_expand_fonts = 2,
	fz_expand_all = -1
};

/*
	fz_write: Write a document out.

	(In development - Subject to change in future versions)

	Save a copy of the current document in its original format.
	Internally the document may change.

	doc: The document to save.

	filename: The filename to save to.

	opts: NULL, or a pointer to an options structure.

	May throw exceptions.
*/
void fz_write_document(fz_document *doc, char *filename, fz_write_options *opts);

/*
	PCL output
*/
typedef struct fz_pcl_options_s fz_pcl_options;

struct fz_pcl_options_s
{
	/* Features of a particular printer */
	int features;
	const char *odd_page_init;
	const char *even_page_init;

	/* Options for this job */
	int tumble;
	int duplex_set;
	int duplex;
	int paper_size;
	int manual_feed_set;
	int manual_feed;
	int media_position_set;
	int media_position;

	/* Updated as we move through the job */
	int page_count;
};

/*
	 fz_pcl_preset: Retrieve a set of fz_pcl_options suitable for a given
	 preset.

	 opts: pointer to options structure to populate.

	 preset: Preset to fetch. Currently defined presets include:
	 	ljet4	HP DeskJet
	 	dj500	HP DeskJet 500
	 	fs600	Kyocera FS-600
	 	lj	HP LaserJet, HP LaserJet Plus
	 	lj2	HP LaserJet IIp, HP LaserJet IId
	 	lj3	HP LaserJet III
	 	lj3d	HP LaserJet IIId
	 	lj4	HP LaserJet 4
	 	lj4pl	HP LaserJet 4 PL
	 	lj4d	HP LaserJet 4d
	 	lp2563b	HP 2563B line printer
	 	oce9050	Oce 9050 Line printer

	Throws exception on unknown preset.
*/ 
void fz_pcl_preset(fz_context *ctx, fz_pcl_options *opts, const char *preset);

/*
	fz_pcl_option: Set a given PCL option to a given value in the supplied
	options structure.

	opts: The option structure to modify,

	option: The option to change.

	val: The value that the option should be set to. Acceptable ranges of
	values depend on the option in question.

	Throws an exception on attempt to set an unknown option, or an illegal
	value.

	Currently defined options/values are as follows:

		spacing,0		No vertical spacing capability
		spacing,1		PCL 3 spacing (<ESC>*p+<n>Y)
		spacing,2		PCL 4 spacing (<ESC>*b<n>Y)
		spacing,3		PCL 5 spacing (<ESC>*b<n>Y and clear seed row)
		mode2,0 or 1		Disable/Enable mode 2 graphics compression
		mode3,0 or 1		Disable/Enable mode 3 graphics compression
		mode3,0 or 1		Disable/Enable mode 3 graphics compression
		eog_reset,0 or 1	End of graphics (<ESC>*rB) resets all parameters
		has_duplex,0 or 1	Duplex supported (<ESC>&l<duplex>S)
		has_papersize,0 or 1	Papersize setting supported (<ESC>&l<sizecode>A)
		has_copies,0 or 1	Number of copies supported (<ESC>&l<copies>X)
		is_ljet4pjl,0 or 1	Disable/Enable HP 4PJL model-specific output
		is_oce9050,0 or 1	Disable/Enable Oce 9050 model-specific output
*/ 
void fz_pcl_option(fz_context *ctx, fz_pcl_options *opts, const char *option, int val);

void fz_output_pcl(fz_output *out, const fz_pixmap *pixmap, fz_pcl_options *pcl);

void fz_output_pcl_bitmap(fz_output *out, const fz_bitmap *bitmap, fz_pcl_options *pcl);

void fz_write_pcl(fz_context *ctx, fz_pixmap *pixmap, char *filename, int append, fz_pcl_options *pcl);

void fz_write_pcl_bitmap(fz_context *ctx, fz_bitmap *bitmap, char *filename, int append, fz_pcl_options *pcl);

/* fitz-internal.h */

#ifdef _WIN32 /* Microsoft Visual C++ */

typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;
typedef __int64 int64_t;

typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t;

#else
#include <inttypes.h>
#endif

struct fz_warn_context_s
{
	char message[256];
	int count;
};

fz_context *fz_clone_context_internal(fz_context *ctx);

void fz_new_aa_context(fz_context *ctx);
void fz_free_aa_context(fz_context *ctx);
void fz_copy_aa_context(fz_context *dst, fz_context *src);

/* Default allocator */
extern fz_alloc_context fz_alloc_default;

/* Default locks */
extern fz_locks_context fz_locks_default;

#if defined(MEMENTO) || defined(DEBUG)
#define FITZ_DEBUG_LOCKING
#endif

#ifdef FITZ_DEBUG_LOCKING

void fz_assert_lock_held(fz_context *ctx, int lock);
void fz_assert_lock_not_held(fz_context *ctx, int lock);
void fz_lock_debug_lock(fz_context *ctx, int lock);
void fz_lock_debug_unlock(fz_context *ctx, int lock);

#else

#define fz_assert_lock_held(A,B) do { } while (0)
#define fz_assert_lock_not_held(A,B) do { } while (0)
#define fz_lock_debug_lock(A,B) do { } while (0)
#define fz_lock_debug_unlock(A,B) do { } while (0)

#endif /* !FITZ_DEBUG_LOCKING */

static inline void
fz_lock(fz_context *ctx, int lock)
{
	fz_lock_debug_lock(ctx, lock);
	ctx->locks->lock(ctx->locks->user, lock);
}

static inline void
fz_unlock(fz_context *ctx, int lock)
{
	fz_lock_debug_unlock(ctx, lock);
	ctx->locks->unlock(ctx->locks->user, lock);
}

/* ARM assembly specific defines */

#ifdef ARCH_ARM
#ifdef NDK_PROFILER
extern void __gnu_mcount_nc(void);
#define ENTER_PG "push {lr}\nbl __gnu_mcount_nc\n"
#else
#define ENTER_PG
#endif

/* If we're compiling as thumb code, then we need to tell the compiler
 * to enter and exit ARM mode around our assembly sections. If we move
 * the ARM functions to a separate file and arrange for it to be compiled
 * without thumb mode, we can save some time on entry.
 */
#ifdef ARCH_THUMB
#define ENTER_ARM ".balign 4\nmov r12,pc\nbx r12\n0:.arm\n" ENTER_PG
#define ENTER_THUMB "9:.thumb\n" ENTER_PG
#else
#define ENTER_ARM
#define ENTER_THUMB
#endif
#endif

/*
 * Basic runtime and utility functions
 */

#ifdef CLUSTER
#define LOCAL_TRIG_FNS
#endif

#ifdef LOCAL_TRIG_FNS
/*
 * Trig functions
 */
static float
my_atan_table[258] =
{
0.0000000000f, 0.00390623013f,0.00781234106f,0.0117182136f,
0.0156237286f, 0.0195287670f, 0.0234332099f, 0.0273369383f,
0.0312398334f, 0.0351417768f, 0.0390426500f, 0.0429423347f,
0.0468407129f, 0.0507376669f, 0.0546330792f, 0.0585268326f,
0.0624188100f, 0.0663088949f, 0.0701969711f, 0.0740829225f,
0.0779666338f, 0.0818479898f, 0.0857268758f, 0.0896031775f,
0.0934767812f, 0.0973475735f, 0.1012154420f, 0.1050802730f,
0.1089419570f, 0.1128003810f, 0.1166554350f, 0.1205070100f,
0.1243549950f, 0.1281992810f, 0.1320397620f, 0.1358763280f,
0.1397088740f, 0.1435372940f, 0.1473614810f, 0.1511813320f,
0.1549967420f, 0.1588076080f, 0.1626138290f, 0.1664153010f,
0.1702119250f, 0.1740036010f, 0.1777902290f, 0.1815717110f,
0.1853479500f, 0.1891188490f, 0.1928843120f, 0.1966442450f,
0.2003985540f, 0.2041471450f, 0.2078899270f, 0.2116268090f,
0.2153577000f, 0.2190825110f, 0.2228011540f, 0.2265135410f,
0.2302195870f, 0.2339192060f, 0.2376123140f, 0.2412988270f,
0.2449786630f, 0.2486517410f, 0.2523179810f, 0.2559773030f,
0.2596296290f, 0.2632748830f, 0.2669129880f, 0.2705438680f,
0.2741674510f, 0.2777836630f, 0.2813924330f, 0.2849936890f,
0.2885873620f, 0.2921733830f, 0.2957516860f, 0.2993222020f,
0.3028848680f, 0.3064396190f, 0.3099863910f, 0.3135251230f,
0.3170557530f, 0.3205782220f, 0.3240924700f, 0.3275984410f,
0.3310960770f, 0.3345853220f, 0.3380661230f, 0.3415384250f,
0.3450021770f, 0.3484573270f, 0.3519038250f, 0.3553416220f,
0.3587706700f, 0.3621909220f, 0.3656023320f, 0.3690048540f,
0.3723984470f, 0.3757830650f, 0.3791586690f, 0.3825252170f,
0.3858826690f, 0.3892309880f, 0.3925701350f, 0.3959000740f,
0.3992207700f, 0.4025321870f, 0.4058342930f, 0.4091270550f,
0.4124104420f, 0.4156844220f, 0.4189489670f, 0.4222040480f,
0.4254496370f, 0.4286857080f, 0.4319122350f, 0.4351291940f,
0.4383365600f, 0.4415343100f, 0.4447224240f, 0.4479008790f,
0.4510696560f, 0.4542287350f, 0.4573780990f, 0.4605177290f,
0.4636476090f, 0.4667677240f, 0.4698780580f, 0.4729785980f,
0.4760693300f, 0.4791502430f, 0.4822213240f, 0.4852825630f,
0.4883339510f, 0.4913754780f, 0.4944071350f, 0.4974289160f,
0.5004408130f, 0.5034428210f, 0.5064349340f, 0.5094171490f,
0.5123894600f, 0.5153518660f, 0.5183043630f, 0.5212469510f,
0.5241796290f, 0.5271023950f, 0.5300152510f, 0.5329181980f,
0.5358112380f, 0.5386943730f, 0.5415676050f, 0.5444309400f,
0.5472843810f, 0.5501279330f, 0.5529616020f, 0.5557853940f,
0.5585993150f, 0.5614033740f, 0.5641975770f, 0.5669819340f,
0.5697564530f, 0.5725211450f, 0.5752760180f, 0.5780210840f,
0.5807563530f, 0.5834818390f, 0.5861975510f, 0.5889035040f,
0.5915997100f, 0.5942861830f, 0.5969629370f, 0.5996299860f,
0.6022873460f, 0.6049350310f, 0.6075730580f, 0.6102014430f,
0.6128202020f, 0.6154293530f, 0.6180289120f, 0.6206188990f,
0.6231993300f, 0.6257702250f, 0.6283316020f, 0.6308834820f,
0.6334258830f, 0.6359588250f, 0.6384823300f, 0.6409964180f,
0.6435011090f, 0.6459964250f, 0.6484823880f, 0.6509590190f,
0.6534263410f, 0.6558843770f, 0.6583331480f, 0.6607726790f,
0.6632029930f, 0.6656241120f, 0.6680360620f, 0.6704388650f,
0.6728325470f, 0.6752171330f, 0.6775926450f, 0.6799591110f,
0.6823165550f, 0.6846650020f, 0.6870044780f, 0.6893350100f,
0.6916566220f, 0.6939693410f, 0.6962731940f, 0.6985682070f,
0.7008544080f, 0.7031318220f, 0.7054004770f, 0.7076604000f,
0.7099116190f, 0.7121541600f, 0.7143880520f, 0.7166133230f,
0.7188300000f, 0.7210381110f, 0.7232376840f, 0.7254287490f,
0.7276113330f, 0.7297854640f, 0.7319511710f, 0.7341084830f,
0.7362574290f, 0.7383980370f, 0.7405303370f, 0.7426543560f,
0.7447701260f, 0.7468776740f, 0.7489770290f, 0.7510682220f,
0.7531512810f, 0.7552262360f, 0.7572931160f, 0.7593519510f,
0.7614027700f, 0.7634456020f, 0.7654804790f, 0.7675074280f,
0.7695264800f, 0.7715376650f, 0.7735410110f, 0.7755365500f,
0.7775243100f, 0.7795043220f, 0.7814766150f, 0.7834412190f,
0.7853981630f, 0.7853981630f /* Extended by 1 for interpolation */
};

static inline float my_sinf(float x)
{
	float x2, xn;
	int i;
	/* Map x into the -PI to PI range. We could do this using:
	 * x = fmodf(x, (float)(2.0 * M_PI));
	 * but that's C99, and seems to misbehave with negative numbers
	 * on some platforms. */
	x -= (float)M_PI;
	i = x / (float)(2.0f * M_PI);
	x -= i * (float)(2.0f * M_PI);
	if (x < 0.0f)
		x += (float)(2.0f * M_PI);
	x -= (float)M_PI;
	if (x <= (float)(-M_PI/2.0))
		x = -(float)M_PI-x;
	else if (x >= (float)(M_PI/2.0))
		x = (float)M_PI-x;
	x2 = x*x;
	xn = x*x2/6.0f;
	x -= xn;
	xn *= x2/20.0f;
	x += xn;
	xn *= x2/42.0f;
	x -= xn;
	xn *= x2/72.0f;
	x += xn;
	return x;
}

static inline float my_atan2f(float o, float a)
{
	int negate = 0, flip = 0, i;
	float r, s;
	if (o == 0.0f)
	{
		if (a > 0)
			return 0.0f;
		else
			return (float)M_PI;
	}
	if (o < 0)
		o = -o, negate = 1;
	if (a < 0)
		a = -a, flip = 1;
	if (o < a)
		i = (int)(65536.0f*o/a + 0.5f);
	else
		i = (int)(65536.0f*a/o + 0.5f);
	r = my_atan_table[i>>8];
	s = my_atan_table[(i>>8)+1];
	r += (s-r)*(i&255)/256.0f;
	if (o >= a)
		r = (float)(M_PI/2.0f) - r;
	if (flip)
		r = (float)M_PI - r;
	if (negate)
		r = -r;
	return r;
}

#define sinf(x) my_sinf(x)
#define cosf(x) my_sinf(((float)(M_PI/2.0f)) + (x))
#define atan2f(x,y) my_atan2f((x),(y))
#endif

/* Range checking atof */
float fz_atof(const char *s);

/* atoi that copes with NULL */
int fz_atoi(const char *s);

/*
 * Generic hash-table with fixed-length keys.
 */

typedef struct fz_hash_table_s fz_hash_table;

fz_hash_table *fz_new_hash_table(fz_context *ctx, int initialsize, int keylen, int lock);
void fz_empty_hash(fz_context *ctx, fz_hash_table *table);
void fz_free_hash(fz_context *ctx, fz_hash_table *table);

void *fz_hash_find(fz_context *ctx, fz_hash_table *table, void *key);
void *fz_hash_insert(fz_context *ctx, fz_hash_table *table, void *key, void *val);
void *fz_hash_insert_with_pos(fz_context *ctx, fz_hash_table *table, void *key, void *val, unsigned *pos);
void fz_hash_remove(fz_context *ctx, fz_hash_table *table, void *key);
void fz_hash_remove_fast(fz_context *ctx, fz_hash_table *table, void *key, unsigned pos);

int fz_hash_len(fz_context *ctx, fz_hash_table *table);
void *fz_hash_get_key(fz_context *ctx, fz_hash_table *table, int idx);
void *fz_hash_get_val(fz_context *ctx, fz_hash_table *table, int idx);

#ifndef NDEBUG
void fz_print_hash(fz_context *ctx, FILE *out, fz_hash_table *table);
void fz_print_hash_details(fz_context *ctx, FILE *out, fz_hash_table *table, void (*details)(FILE *, void *));
#endif

/*
 * Math and geometry
 */

/* Multiply scaled two integers in the 0..255 range */
static inline int fz_mul255(int a, int b)
{
	/* see Jim Blinn's book "Dirty Pixels" for how this works */
	int x = a * b + 128;
	x += x >> 8;
	return x >> 8;
}

/* Expand a value A from the 0...255 range to the 0..256 range */
#define FZ_EXPAND(A) ((A)+((A)>>7))

/* Combine values A (in any range) and B (in the 0..256 range),
 * to give a single value in the same range as A was. */
#define FZ_COMBINE(A,B) (((A)*(B))>>8)

/* Combine values A and C (in the same (any) range) and B and D (in the
 * 0..256 range), to give a single value in the same range as A and C were. */
#define FZ_COMBINE2(A,B,C,D) (FZ_COMBINE((A), (B)) + FZ_COMBINE((C), (D)))

/* Blend SRC and DST (in the same range) together according to
 * AMOUNT (in the 0...256 range). */
#define FZ_BLEND(SRC, DST, AMOUNT) ((((SRC)-(DST))*(AMOUNT) + ((DST)<<8))>>8)

void fz_gridfit_matrix(fz_matrix *m);
float fz_matrix_max_expansion(const fz_matrix *m);

/*
 * Basic crypto functions.
 * Independent of the rest of fitz.
 * For further encapsulation in filters, or not.
 */

/* md5 digests */

typedef struct fz_md5_s fz_md5;

struct fz_md5_s
{
	unsigned int state[4];
	unsigned int count[2];
	unsigned char buffer[64];
};

void fz_md5_init(fz_md5 *state);
void fz_md5_update(fz_md5 *state, const unsigned char *input, unsigned inlen);
void fz_md5_final(fz_md5 *state, unsigned char digest[16]);

/* sha-256 digests */

typedef struct fz_sha256_s fz_sha256;

struct fz_sha256_s
{
	unsigned int state[8];
	unsigned int count[2];
	union {
		unsigned char u8[64];
		unsigned int u32[16];
	} buffer;
};

void fz_sha256_init(fz_sha256 *state);
void fz_sha256_update(fz_sha256 *state, const unsigned char *input, unsigned int inlen);
void fz_sha256_final(fz_sha256 *state, unsigned char digest[32]);

/* sha-512 digests */

typedef struct fz_sha512_s fz_sha512;

struct fz_sha512_s
{
	uint64_t state[8];
	unsigned int count[2];
	union {
		unsigned char u8[128];
		uint64_t u64[16];
	} buffer;
};

void fz_sha512_init(fz_sha512 *state);
void fz_sha512_update(fz_sha512 *state, const unsigned char *input, unsigned int inlen);
void fz_sha512_final(fz_sha512 *state, unsigned char digest[64]);

/* sha-384 digests */

typedef struct fz_sha512_s fz_sha384;

void fz_sha384_init(fz_sha384 *state);
void fz_sha384_update(fz_sha384 *state, const unsigned char *input, unsigned int inlen);
void fz_sha384_final(fz_sha384 *state, unsigned char digest[64]);

/* arc4 crypto */

typedef struct fz_arc4_s fz_arc4;

struct fz_arc4_s
{
	unsigned x;
	unsigned y;
	unsigned char state[256];
};

void fz_arc4_init(fz_arc4 *state, const unsigned char *key, unsigned len);
void fz_arc4_encrypt(fz_arc4 *state, unsigned char *dest, const unsigned char *src, unsigned len);

/* AES block cipher implementation from XYSSL */

typedef struct fz_aes_s fz_aes;

#define AES_DECRYPT 0
#define AES_ENCRYPT 1

struct fz_aes_s
{
	int nr; /* number of rounds */
	unsigned long *rk; /* AES round keys */
	unsigned long buf[68]; /* unaligned data */
};

int aes_setkey_enc( fz_aes *ctx, const unsigned char *key, int keysize );
int aes_setkey_dec( fz_aes *ctx, const unsigned char *key, int keysize );
void aes_crypt_cbc( fz_aes *ctx, int mode, int length,
	unsigned char iv[16],
	const unsigned char *input,
	unsigned char *output );

/*
	Resource store

	MuPDF stores decoded "objects" into a store for potential reuse.
	If the size of the store gets too big, objects stored within it can
	be evicted and freed to recover space. When MuPDF comes to decode
	such an object, it will check to see if a version of this object is
	already in the store - if it is, it will simply reuse it. If not, it
	will decode it and place it into the store.

	All objects that can be placed into the store are derived from the
	fz_storable type (i.e. this should be the first component of the
	objects structure). This allows for consistent (thread safe)
	reference counting, and includes a function that will be called to
	free the object as soon as the reference count reaches zero.

	Most objects offer fz_keep_XXXX/fz_drop_XXXX functions derived
	from fz_keep_storable/fz_drop_storable. Creation of such objects
	includes a call to FZ_INIT_STORABLE to set up the fz_storable header.
 */

typedef struct fz_storable_s fz_storable;

typedef void (fz_store_free_fn)(fz_context *, fz_storable *);

struct fz_storable_s {
	int refs;
	fz_store_free_fn *free;
};

#define FZ_INIT_STORABLE(S_,RC,FREE) \
	do { fz_storable *S = &(S_)->storable; S->refs = (RC); \
	S->free = (FREE); \
	} while (0)

void *fz_keep_storable(fz_context *, fz_storable *);
void fz_drop_storable(fz_context *, fz_storable *);

/*
	The store can be seen as a dictionary that maps keys to fz_storable
	values. In order to allow keys of different types to be stored, we
	have a structure full of functions for each key 'type'; this
	fz_store_type pointer is stored with each key, and tells the store
	how to perform certain operations (like taking/dropping a reference,
	comparing two keys, outputting details for debugging etc).

	The store uses a hash table internally for speed where possible. In
	order for this to work, we need a mechanism for turning a generic
	'key' into 'a hashable string'. For this purpose the type structure
	contains a make_hash_key function pointer that maps from a void *
	to an fz_store_hash structure. If make_hash_key function returns 0,
	then the key is determined not to be hashable, and the value is
	not stored in the hash table.
*/
typedef struct fz_store_hash_s fz_store_hash;

struct fz_store_hash_s
{
	fz_store_free_fn *free;
	union
	{
		struct
		{
			int i0;
			int i1;
		} i;
		struct
		{
			void *ptr;
			int i;
		} pi;
		struct
		{
			int id;
			float m[4];
		} im;
	} u;
};

typedef struct fz_store_type_s fz_store_type;

struct fz_store_type_s
{
	int (*make_hash_key)(fz_store_hash *, void *);
	void *(*keep_key)(fz_context *,void *);
	void (*drop_key)(fz_context *,void *);
	int (*cmp_key)(void *, void *);
#ifndef NDEBUG
	void (*debug)(FILE *, void *);
#endif
};

/*
	fz_store_new_context: Create a new store inside the context

	max: The maximum size (in bytes) that the store is allowed to grow
	to. FZ_STORE_UNLIMITED means no limit.
*/
void fz_new_store_context(fz_context *ctx, unsigned int max);

/*
	fz_drop_store_context: Drop a reference to the store.
*/
void fz_drop_store_context(fz_context *ctx);

/*
	fz_keep_store_context: Take a reference to the store.
*/
fz_store *fz_keep_store_context(fz_context *ctx);

/*
	fz_store_item: Add an item to the store.

	Add an item into the store, returning NULL for success. If an item
	with the same key is found in the store, then our item will not be
	inserted, and the function will return a pointer to that value
	instead. This function takes its own reference to val, as required
	(i.e. the caller maintains ownership of its own reference).

	key: The key to use to index the item.

	val: The value to store.

	itemsize: The size in bytes of the value (as counted towards the
	store size).

	type: Functions used to manipulate the key.
*/
void *fz_store_item(fz_context *ctx, void *key, void *val, unsigned int itemsize, fz_store_type *type);

/*
	fz_find_item: Find an item within the store.

	free: The function used to free the value (to ensure we get a value
	of the correct type).

	key: The key to use to index the item.

	type: Functions used to manipulate the key.

	Returns NULL for not found, otherwise returns a pointer to the value
	indexed by key to which a reference has been taken.
*/
void *fz_find_item(fz_context *ctx, fz_store_free_fn *free, void *key, fz_store_type *type);

/*
	fz_remove_item: Remove an item from the store.

	If an item indexed by the given key exists in the store, remove it.

	free: The function used to free the value (to ensure we get a value
	of the correct type).

	key: The key to use to find the item to remove.

	type: Functions used to manipulate the key.
*/
void fz_remove_item(fz_context *ctx, fz_store_free_fn *free, void *key, fz_store_type *type);

/*
	fz_empty_store: Evict everything from the store.
*/
void fz_empty_store(fz_context *ctx);

/*
	fz_store_scavenge: Internal function used as part of the scavenging
	allocator; when we fail to allocate memory, before returning a
	failure to the caller, we try to scavenge space within the store by
	evicting at least 'size' bytes. The allocator then retries.

	size: The number of bytes we are trying to have free.

	phase: What phase of the scavenge we are in. Updated on exit.

	Returns non zero if we managed to free any memory.
*/
int fz_store_scavenge(fz_context *ctx, unsigned int size, int *phase);

/*
	fz_print_store: Dump the contents of the store for debugging.
*/
#ifndef NDEBUG
void fz_print_store(fz_context *ctx, FILE *out);
void fz_print_store_locked(fz_context *ctx, FILE *out);
#endif

struct fz_buffer_s
{
	int refs;
	unsigned char *data;
	int cap, len;
	int unused_bits;
};

/*
	fz_new_buffer: Create a new buffer.

	capacity: Initial capacity.

	Returns pointer to new buffer. Throws exception on allocation
	failure.
*/
fz_buffer *fz_new_buffer(fz_context *ctx, int capacity);

/*
	fz_new_buffer: Create a new buffer.

	capacity: Initial capacity.

	Returns pointer to new buffer. Throws exception on allocation
	failure.
*/
fz_buffer *fz_new_buffer_from_data(fz_context *ctx, unsigned char *data, int size);

/*
	fz_resize_buffer: Ensure that a buffer has a given capacity,
	truncating data if required.

	buf: The buffer to alter.

	capacity: The desired capacity for the buffer. If the current size
	of the buffer contents is smaller than capacity, it is truncated.

*/
void fz_resize_buffer(fz_context *ctx, fz_buffer *buf, int capacity);

/*
	fz_grow_buffer: Make some space within a buffer (i.e. ensure that
	capacity > size).

	buf: The buffer to grow.

	May throw exception on failure to allocate.
*/
void fz_grow_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_trim_buffer: Trim wasted capacity from a buffer.

	buf: The buffer to trim.
*/
void fz_trim_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_buffer_cat: Concatenate buffers

	buf: first to concatenate and the holder of the result
	extra: second to concatenate

	May throw exception on failure to allocate.
*/
void fz_buffer_cat(fz_context *ctx, fz_buffer *buf, fz_buffer *extra);

void fz_write_buffer(fz_context *ctx, fz_buffer *buf, const void *data, int len);

void fz_write_buffer_byte(fz_context *ctx, fz_buffer *buf, int val);

void fz_write_buffer_rune(fz_context *ctx, fz_buffer *buf, int val);

void fz_write_buffer_bits(fz_context *ctx, fz_buffer *buf, int val, int bits);

void fz_write_buffer_pad(fz_context *ctx, fz_buffer *buf);

/*
	fz_buffer_printf: print formatted to a buffer. The buffer will grow
	as required.
*/
int fz_buffer_printf(fz_context *ctx, fz_buffer *buffer, const char *fmt, ...);
int fz_buffer_vprintf(fz_context *ctx, fz_buffer *buffer, const char *fmt, va_list args);

/*
	fz_buffer_printf: print a string formatted as a pdf string to a buffer.
	The buffer will grow.
*/
void
fz_buffer_cat_pdf_string(fz_context *ctx, fz_buffer *buffer, const char *text);

struct fz_stream_s
{
	fz_context *ctx;
	int refs;
	int error;
	int eof;
	int pos;
	int avail;
	int bits;
	unsigned char *bp, *rp, *wp, *ep;
	void *state;
	int (*read)(fz_stream *stm, unsigned char *buf, int len);
	void (*close)(fz_context *ctx, void *state);
	void (*seek)(fz_stream *stm, int offset, int whence);
	unsigned char buf[4096];
};

fz_stream *fz_new_stream(fz_context *ctx, void*, int(*)(fz_stream*, unsigned char*, int), void(*)(fz_context *, void *));
fz_stream *fz_keep_stream(fz_stream *stm);
void fz_fill_buffer(fz_stream *stm);

/*
	fz_read_best: Attempt to read a stream into a buffer. If truncated
	is NULL behaves as fz_read_all, otherwise does not throw exceptions
	in the case of failure, but instead sets a truncated flag.

	stm: The stream to read from.

	initial: Suggested initial size for the buffer.

	truncated: Flag to store success/failure indication in.

	Returns a buffer created from reading from the stream.
*/
fz_buffer *fz_read_best(fz_stream *stm, int initial, int *truncated);

void fz_read_line(fz_stream *stm, char *buf, int max);

static inline int fz_read_byte(fz_stream *stm)
{
	if (stm->rp == stm->wp)
	{
		fz_fill_buffer(stm);
		return stm->rp < stm->wp ? *stm->rp++ : EOF;
	}
	return *stm->rp++;
}

static inline int fz_peek_byte(fz_stream *stm)
{
	if (stm->rp == stm->wp)
	{
		fz_fill_buffer(stm);
		return stm->rp < stm->wp ? *stm->rp : EOF;
	}
	return *stm->rp;
}

static inline void fz_unread_byte(fz_stream *stm)
{
	if (stm->rp > stm->bp)
		stm->rp--;
}

static inline int fz_is_eof(fz_stream *stm)
{
	if (stm->rp == stm->wp)
	{
		if (stm->eof)
			return 1;
		return fz_peek_byte(stm) == EOF;
	}
	return 0;
}

static inline unsigned int fz_read_bits(fz_stream *stm, int n)
{
	unsigned int x;

	if (n <= stm->avail)
	{
		stm->avail -= n;
		x = (stm->bits >> stm->avail) & ((1 << n) - 1);
	}
	else
	{
		x = stm->bits & ((1 << stm->avail) - 1);
		n -= stm->avail;
		stm->avail = 0;

		while (n > 8)
		{
			x = (x << 8) | fz_read_byte(stm);
			n -= 8;
		}

		if (n > 0)
		{
			stm->bits = fz_read_byte(stm);
			stm->avail = 8 - n;
			x = (x << n) | (stm->bits >> stm->avail);
		}
	}

	return x;
}

static inline void fz_sync_bits(fz_stream *stm)
{
	stm->avail = 0;
}

static inline int fz_is_eof_bits(fz_stream *stm)
{
	return fz_is_eof(stm) && (stm->avail == 0 || stm->bits == EOF);
}

static inline int fz_write_int32be(fz_output *out, int x)
{
	char data[4];

	data[0] = x>>24;
	data[1] = x>>16;
	data[2] = x>>8;
	data[3] = x;

	return fz_write(out, data, 4);
}

static inline void
fz_write_byte(fz_output *out, int x)
{
	char data = x;

	fz_write(out, &data, 1);
}

/*
 * Data filters.
 */

fz_stream *fz_open_copy(fz_stream *chain);
fz_stream *fz_open_null(fz_stream *chain, int len, int offset);
fz_stream *fz_open_concat(fz_context *ctx, int max, int pad);
void fz_concat_push(fz_stream *concat, fz_stream *chain); /* Ownership of chain is passed in */
fz_stream *fz_open_arc4(fz_stream *chain, unsigned char *key, unsigned keylen);
fz_stream *fz_open_aesd(fz_stream *chain, unsigned char *key, unsigned keylen);
fz_stream *fz_open_a85d(fz_stream *chain);
fz_stream *fz_open_ahxd(fz_stream *chain);
fz_stream *fz_open_rld(fz_stream *chain);
fz_stream *fz_open_dctd(fz_stream *chain, int color_transform);
fz_stream *fz_open_resized_dctd(fz_stream *chain, int color_transform, int l2factor);
fz_stream *fz_open_faxd(fz_stream *chain,
	int k, int end_of_line, int encoded_byte_align,
	int columns, int rows, int end_of_block, int black_is_1);
fz_stream *fz_open_flated(fz_stream *chain);
fz_stream *fz_open_lzwd(fz_stream *chain, int early_change);
fz_stream *fz_open_predict(fz_stream *chain, int predictor, int columns, int colors, int bpc);
fz_stream *fz_open_jbig2d(fz_stream *chain, fz_buffer *global);

/*
 * Resources and other graphics related objects.
 */

int fz_lookup_blendmode(char *name);
char *fz_blendmode_name(int blendmode);

struct fz_bitmap_s
{
	int refs;
	int w, h, stride, n;
	int xres, yres;
	unsigned char *samples;
};

fz_bitmap *fz_new_bitmap(fz_context *ctx, int w, int h, int n, int xres, int yres);

void fz_bitmap_details(fz_bitmap *bitmap, int *w, int *h, int *n, int *stride);

void fz_clear_bitmap(fz_context *ctx, fz_bitmap *bit);

/*
	Pixmaps represent a set of pixels for a 2 dimensional region of a
	plane. Each pixel has n components per pixel, the last of which is
	always alpha. The data is in premultiplied alpha when rendering, but
	non-premultiplied for colorspace conversions and rescaling.

	x, y: The minimum x and y coord of the region in pixels.

	w, h: The width and height of the region in pixels.

	n: The number of color components in the image. Always
	includes a separate alpha channel. For mask images n=1, for greyscale
	(plus alpha) images n=2, for rgb (plus alpha) images n=3.

	interpolate: A boolean flag set to non-zero if the image
	will be drawn using linear interpolation, or set to zero if
	image will be using nearest neighbour sampling.

	xres, yres: Image resolution in dpi. Default is 96 dpi.

	colorspace: Pointer to a colorspace object describing the colorspace
	the pixmap is in. If NULL, the image is a mask.

	samples: A simple block of memory w * h * n bytes of memory in which
	the components are stored. The first n bytes are components 0 to n-1
	for the pixel at (x,y). Each successive n bytes gives another pixel
	in scanline order. Subsequent scanlines follow on with no padding.

	free_samples: Is zero when an application has provided its own
	buffer for pixel data through fz_new_pixmap_with_bbox_and_data.
	If not zero the buffer will be freed when fz_drop_pixmap is
	called for the pixmap.
*/
struct fz_pixmap_s
{
	fz_storable storable;
	int x, y, w, h, n;
	int interpolate;
	int xres, yres;
	fz_colorspace *colorspace;
	unsigned char *samples;
	int free_samples;
};

void fz_free_pixmap_imp(fz_context *ctx, fz_storable *pix);

void fz_copy_pixmap_rect(fz_context *ctx, fz_pixmap *dest, fz_pixmap *src, const fz_irect *r);
void fz_premultiply_pixmap(fz_context *ctx, fz_pixmap *pix);
fz_pixmap *fz_alpha_from_gray(fz_context *ctx, fz_pixmap *gray, int luminosity);
unsigned int fz_pixmap_size(fz_context *ctx, fz_pixmap *pix);

fz_pixmap *fz_scale_pixmap(fz_context *ctx, fz_pixmap *src, float x, float y, float w, float h, fz_irect *clip);

typedef struct fz_scale_cache_s fz_scale_cache;

fz_scale_cache *fz_new_scale_cache(fz_context *ctx);
void fz_free_scale_cache(fz_context *ctx, fz_scale_cache *cache);
fz_pixmap *fz_scale_pixmap_cached(fz_context *ctx, fz_pixmap *src, float x, float y, float w, float h, const fz_irect *clip, fz_scale_cache *cache_x, fz_scale_cache *cache_y);

void fz_subsample_pixmap(fz_context *ctx, fz_pixmap *tile, int factor);

fz_irect *fz_pixmap_bbox_no_ctx(fz_pixmap *src, fz_irect *bbox);

typedef struct fz_compression_params_s fz_compression_params;

typedef struct fz_compressed_buffer_s fz_compressed_buffer;
unsigned int fz_compressed_buffer_size(fz_compressed_buffer *buffer);

fz_stream *fz_open_compressed_buffer(fz_context *ctx, fz_compressed_buffer *);
fz_stream *fz_open_image_decomp_stream(fz_context *ctx, fz_compressed_buffer *, int *l2factor);

enum
{
	FZ_IMAGE_UNKNOWN = 0,
	FZ_IMAGE_JPEG = 1,
	FZ_IMAGE_JPX = 2, /* Placeholder until supported */
	FZ_IMAGE_FAX = 3,
	FZ_IMAGE_JBIG2 = 4, /* Placeholder until supported */
	FZ_IMAGE_RAW = 5,
	FZ_IMAGE_RLD = 6,
	FZ_IMAGE_FLATE = 7,
	FZ_IMAGE_LZW = 8,
	FZ_IMAGE_PNG = 9,
	FZ_IMAGE_TIFF = 10
};

struct fz_compression_params_s
{
	int type;
	union {
		struct {
			int color_transform;
		} jpeg;
		struct {
			int smask_in_data;
		} jpx;
		struct {
			int columns;
			int rows;
			int k;
			int end_of_line;
			int encoded_byte_align;
			int end_of_block;
			int black_is_1;
			int damaged_rows_before_error;
		} fax;
		struct
		{
			int columns;
			int colors;
			int predictor;
			int bpc;
		}
		flate;
		struct
		{
			int columns;
			int colors;
			int predictor;
			int bpc;
			int early_change;
		} lzw;
	} u;
};

struct fz_compressed_buffer_s
{
	fz_compression_params params;
	fz_buffer *buffer;
};

void fz_free_compressed_buffer(fz_context *ctx, fz_compressed_buffer *buf);

fz_image *fz_new_image(fz_context *ctx, int w, int h, int bpc, fz_colorspace *colorspace, int xres, int yres, int interpolate, int imagemask, float *decode, int *colorkey, fz_compressed_buffer *buffer, fz_image *mask);
fz_image *fz_new_image_from_pixmap(fz_context *ctx, fz_pixmap *pixmap, fz_image *mask);
fz_image *fz_new_image_from_data(fz_context *ctx, unsigned char *data, int len);
fz_image *fz_new_image_from_buffer(fz_context *ctx, fz_buffer *buffer);
fz_pixmap *fz_image_get_pixmap(fz_context *ctx, fz_image *image, int w, int h);
void fz_free_image(fz_context *ctx, fz_storable *image);
fz_pixmap *fz_decomp_image_from_stream(fz_context *ctx, fz_stream *stm, fz_image *image, int in_line, int indexed, int l2factor, int native_l2factor);
fz_pixmap *fz_expand_indexed_pixmap(fz_context *ctx, fz_pixmap *src);

struct fz_image_s
{
	fz_storable storable;
	int w, h, n, bpc;
	fz_image *mask;
	fz_colorspace *colorspace;
	fz_pixmap *(*get_pixmap)(fz_context *, fz_image *, int w, int h);
	fz_compressed_buffer *buffer;
	int colorkey[FZ_MAX_COLORS * 2];
	float decode[FZ_MAX_COLORS * 2];
	int imagemask;
	int interpolate;
	int usecolorkey;
	fz_pixmap *tile; /* Private to the implementation */
	int xres; /* As given in the image, not necessarily as rendered */
	int yres; /* As given in the image, not necessarily as rendered */
};

fz_pixmap *fz_load_jpx(fz_context *ctx, unsigned char *data, int size, fz_colorspace *cs, int indexed);
fz_pixmap *fz_load_png(fz_context *ctx, unsigned char *data, int size);
fz_pixmap *fz_load_tiff(fz_context *ctx, unsigned char *data, int size);

void fz_load_jpeg_info(fz_context *ctx, unsigned char *data, int size, int *w, int *h, int *xres, int *yres, fz_colorspace **cspace);
void fz_load_png_info(fz_context *ctx, unsigned char *data, int size, int *w, int *h, int *xres, int *yres, fz_colorspace **cspace);
void fz_load_tiff_info(fz_context *ctx, unsigned char *data, int size, int *w, int *h, int *xres, int *yres, fz_colorspace **cspace);

struct fz_halftone_s
{
	int refs;
	int n;
	fz_pixmap *comp[1];
};

fz_halftone *fz_new_halftone(fz_context *ctx, int num_comps);
fz_halftone *fz_default_halftone(fz_context *ctx, int num_comps);
void fz_drop_halftone(fz_context *ctx, fz_halftone *half);
fz_halftone *fz_keep_halftone(fz_context *ctx, fz_halftone *half);

struct fz_colorspace_s
{
	fz_storable storable;
	unsigned int size;
	char name[16];
	int n;
	void (*to_rgb)(fz_context *ctx, fz_colorspace *, float *src, float *rgb);
	void (*from_rgb)(fz_context *ctx, fz_colorspace *, float *rgb, float *dst);
	void (*free_data)(fz_context *Ctx, fz_colorspace *);
	void *data;
};

fz_colorspace *fz_new_colorspace(fz_context *ctx, char *name, int n);
fz_colorspace *fz_new_indexed_colorspace(fz_context *ctx, fz_colorspace *base, int high, unsigned char *lookup);
fz_colorspace *fz_keep_colorspace(fz_context *ctx, fz_colorspace *colorspace);
void fz_drop_colorspace(fz_context *ctx, fz_colorspace *colorspace);
void fz_free_colorspace_imp(fz_context *ctx, fz_storable *colorspace);

void fz_convert_color(fz_context *ctx, fz_colorspace *dsts, float *dstv, fz_colorspace *srcs, float *srcv);

void fz_new_colorspace_context(fz_context *ctx);
fz_colorspace_context *fz_keep_colorspace_context(fz_context *ctx);
void fz_drop_colorspace_context(fz_context *ctx);

typedef struct fz_color_converter_s fz_color_converter;

/* This structure is public because it allows us to avoid dynamic allocations.
 * Callers should only rely on the convert entry - the rest of the structure
 * is subject to change without notice.
 */
struct fz_color_converter_s
{
	void (*convert)(fz_color_converter *, float *, float *);
	fz_context *ctx;
	fz_colorspace *ds;
	fz_colorspace *ss;
};

void fz_lookup_color_converter(fz_color_converter *cc, fz_context *ctx, fz_colorspace *ds, fz_colorspace *ss);

/*
 * Fonts come in two variants:
 *	Regular fonts are handled by FreeType.
 *	Type 3 fonts have callbacks to the interpreter.
 */

char *ft_error_string(int err);

struct fz_font_s
{
	int refs;
	char name[32];

	void *ft_face; /* has an FT_Face if used */
	int ft_substitute; /* ... substitute metrics */
	int ft_bold; /* ... synthesize bold */
	int ft_italic; /* ... synthesize italic */
	int ft_hint; /* ... force hinting for DynaLab fonts */

	/* origin of font data */
	char *ft_file;
	unsigned char *ft_data;
	int ft_size;

	fz_matrix t3matrix;
	void *t3resources;
	fz_buffer **t3procs; /* has 256 entries if used */
	fz_display_list **t3lists; /* has 256 entries if used */
	float *t3widths; /* has 256 entries if used */
	char *t3flags; /* has 256 entries if used */
	void *t3doc; /* a pdf_document for the callback */
	void (*t3run)(void *doc, void *resources, fz_buffer *contents, fz_device *dev, const fz_matrix *ctm, void *gstate, int nestedDepth);
	void (*t3freeres)(void *doc, void *resources);

	fz_rect bbox;	/* font bbox is used only for t3 fonts */

	/* per glyph bounding box cache */
	int use_glyph_bbox;
	int bbox_count;
	fz_rect *bbox_table;

	/* substitute metrics */
	int width_count;
	int *width_table; /* in 1000 units */
};

void fz_new_font_context(fz_context *ctx);
fz_font_context *fz_keep_font_context(fz_context *ctx);
void fz_drop_font_context(fz_context *ctx);

fz_font *fz_new_type3_font(fz_context *ctx, char *name, const fz_matrix *matrix);

fz_font *fz_new_font_from_memory(fz_context *ctx, char *name, unsigned char *data, int len, int index, int use_glyph_bbox);
fz_font *fz_new_font_from_file(fz_context *ctx, char *name, char *path, int index, int use_glyph_bbox);

fz_font *fz_keep_font(fz_context *ctx, fz_font *font);
void fz_drop_font(fz_context *ctx, fz_font *font);

void fz_set_font_bbox(fz_context *ctx, fz_font *font, float xmin, float ymin, float xmax, float ymax);
fz_rect *fz_bound_glyph(fz_context *ctx, fz_font *font, int gid, const fz_matrix *trm, fz_rect *r);
int fz_glyph_cacheable(fz_context *ctx, fz_font *font, int gid);

#ifndef NDEBUG
void fz_print_font(fz_context *ctx, FILE *out, fz_font *font);
#endif

/*
 * Vector path buffer.
 * It can be stroked and dashed, or be filled.
 * It has a fill rule (nonzero or even_odd).
 *
 * When rendering, they are flattened, stroked and dashed straight
 * into the Global Edge List.
 */

typedef struct fz_path_s fz_path;
typedef struct fz_stroke_state_s fz_stroke_state;

typedef union fz_path_item_s fz_path_item;

typedef enum fz_path_item_kind_e
{
	FZ_MOVETO,
	FZ_LINETO,
	FZ_CURVETO,
	FZ_CLOSE_PATH
} fz_path_item_kind;

typedef enum fz_linecap_e
{
	FZ_LINECAP_BUTT = 0,
	FZ_LINECAP_ROUND = 1,
	FZ_LINECAP_SQUARE = 2,
	FZ_LINECAP_TRIANGLE = 3
} fz_linecap;

typedef enum fz_linejoin_e
{
	FZ_LINEJOIN_MITER = 0,
	FZ_LINEJOIN_ROUND = 1,
	FZ_LINEJOIN_BEVEL = 2,
	FZ_LINEJOIN_MITER_XPS = 3
} fz_linejoin;

union fz_path_item_s
{
	fz_path_item_kind k;
	float v;
};

struct fz_path_s
{
	int len, cap;
	fz_path_item *items;
	int last;
};

struct fz_stroke_state_s
{
	int refs;
	fz_linecap start_cap, dash_cap, end_cap;
	fz_linejoin linejoin;
	float linewidth;
	float miterlimit;
	float dash_phase;
	int dash_len;
	float dash_list[32];
};

fz_path *fz_new_path(fz_context *ctx);
fz_point fz_currentpoint(fz_context *ctx, fz_path *path);
void fz_moveto(fz_context*, fz_path*, float x, float y);
void fz_lineto(fz_context*, fz_path*, float x, float y);
void fz_curveto(fz_context*,fz_path*, float, float, float, float, float, float);
void fz_curvetov(fz_context*,fz_path*, float, float, float, float);
void fz_curvetoy(fz_context*,fz_path*, float, float, float, float);
void fz_closepath(fz_context*,fz_path*);
void fz_free_path(fz_context *ctx, fz_path *path);

void fz_transform_path(fz_context *ctx, fz_path *path, const fz_matrix *transform);

fz_path *fz_clone_path(fz_context *ctx, fz_path *old);

fz_rect *fz_bound_path(fz_context *ctx, fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, fz_rect *r);
fz_rect *fz_adjust_rect_for_stroke(fz_rect *r, const fz_stroke_state *stroke, const fz_matrix *ctm);

fz_stroke_state *fz_new_stroke_state(fz_context *ctx);
fz_stroke_state *fz_new_stroke_state_with_len(fz_context *ctx, int len);
fz_stroke_state *fz_keep_stroke_state(fz_context *ctx, fz_stroke_state *stroke);
void fz_drop_stroke_state(fz_context *ctx, fz_stroke_state *stroke);
fz_stroke_state *fz_unshare_stroke_state(fz_context *ctx, fz_stroke_state *shared);
fz_stroke_state *fz_unshare_stroke_state_with_len(fz_context *ctx, fz_stroke_state *shared, int len);

#ifndef NDEBUG
void fz_print_path(fz_context *ctx, FILE *out, fz_path *, int indent);
#endif

/*
 * Glyph cache
 */

void fz_new_glyph_cache_context(fz_context *ctx);
fz_glyph_cache *fz_keep_glyph_cache(fz_context *ctx);
void fz_drop_glyph_cache_context(fz_context *ctx);
void fz_purge_glyph_cache(fz_context *ctx);

fz_path *fz_outline_ft_glyph(fz_context *ctx, fz_font *font, int gid, const fz_matrix *trm);
fz_path *fz_outline_glyph(fz_context *ctx, fz_font *font, int gid, const fz_matrix *ctm);
fz_pixmap *fz_render_ft_glyph(fz_context *ctx, fz_font *font, int cid, const fz_matrix *trm, int aa);
fz_pixmap *fz_render_t3_glyph(fz_context *ctx, fz_font *font, int cid, const fz_matrix *trm, fz_colorspace *model, fz_irect scissor);
fz_pixmap *fz_render_ft_stroked_glyph(fz_context *ctx, fz_font *font, int gid, const fz_matrix *trm, const fz_matrix *ctm, fz_stroke_state *state);
fz_pixmap *fz_render_glyph(fz_context *ctx, fz_font*, int, const fz_matrix *, fz_colorspace *model, fz_irect scissor);
fz_pixmap *fz_render_stroked_glyph(fz_context *ctx, fz_font*, int, const fz_matrix *, const fz_matrix *, fz_stroke_state *stroke, fz_irect scissor);
void fz_render_t3_glyph_direct(fz_context *ctx, fz_device *dev, fz_font *font, int gid, const fz_matrix *trm, void *gstate, int nestedDepth);
void fz_prepare_t3_glyph(fz_context *ctx, fz_font *font, int gid, int nestedDepth);

/*
 * Text buffer.
 *
 * The trm field contains the a, b, c and d coefficients.
 * The e and f coefficients come from the individual elements,
 * together they form the transform matrix for the glyph.
 *
 * Glyphs are referenced by glyph ID.
 * The Unicode text equivalent is kept in a separate array
 * with indexes into the glyph array.
 */

typedef struct fz_text_s fz_text;
typedef struct fz_text_item_s fz_text_item;

struct fz_text_item_s
{
	float x, y;
	int gid; /* -1 for one gid to many ucs mappings */
	int ucs; /* -1 for one ucs to many gid mappings */
};

struct fz_text_s
{
	fz_font *font;
	fz_matrix trm;
	int wmode;
	int len, cap;
	fz_text_item *items;
};

fz_text *fz_new_text(fz_context *ctx, fz_font *face, const fz_matrix *trm, int wmode);
void fz_add_text(fz_context *ctx, fz_text *text, int gid, int ucs, float x, float y);
void fz_free_text(fz_context *ctx, fz_text *text);
fz_rect *fz_bound_text(fz_context *ctx, fz_text *text, const fz_stroke_state *stroke, const fz_matrix *ctm, fz_rect *r);
fz_text *fz_clone_text(fz_context *ctx, fz_text *old);
void fz_print_text(fz_context *ctx, FILE *out, fz_text*);

/*
 * The generic function support.
 */

typedef struct fz_function_s fz_function;

void fz_eval_function(fz_context *ctx, fz_function *func, float *in, int inlen, float *out, int outlen);
fz_function *fz_keep_function(fz_context *ctx, fz_function *func);
void fz_drop_function(fz_context *ctx, fz_function *func);
unsigned int fz_function_size(fz_function *func);
#ifndef DEBUG
void pdf_debug_function(fz_function *func);
#endif

enum
{
	FZ_FN_MAXN = FZ_MAX_COLORS,
	FZ_FN_MAXM = FZ_MAX_COLORS
};

struct fz_function_s
{
	fz_storable storable;
	unsigned int size;
	int m;					/* number of input values */
	int n;					/* number of output values */
	void (*evaluate)(fz_context *ctx, fz_function *func, float *in, float *out);
#ifndef NDEBUG
	void (*debug)(fz_function *func);
#endif
};

/*
 * The shading code uses gouraud shaded triangle meshes.
 */

enum
{
	FZ_FUNCTION_BASED = 1,
	FZ_LINEAR = 2,
	FZ_RADIAL = 3,
	FZ_MESH_TYPE4 = 4,
	FZ_MESH_TYPE5 = 5,
	FZ_MESH_TYPE6 = 6,
	FZ_MESH_TYPE7 = 7
};

typedef struct fz_shade_s fz_shade;

struct fz_shade_s
{
	fz_storable storable;

	fz_rect bbox;		/* can be fz_infinite_rect */
	fz_colorspace *colorspace;

	fz_matrix matrix;	/* matrix from pattern dict */
	int use_background;	/* background color for fills but not 'sh' */
	float background[FZ_MAX_COLORS];

	int use_function;
	float function[256][FZ_MAX_COLORS + 1];

	int type; /* function, linear, radial, mesh */
	union
	{
		struct
		{
			int extend[2];
			float coords[2][3]; /* (x,y,r) twice */
		} l_or_r;
		struct
		{
			int vprow;
			int bpflag;
			int bpcoord;
			int bpcomp;
			float x0, x1;
			float y0, y1;
			float c0[FZ_MAX_COLORS];
			float c1[FZ_MAX_COLORS];
		} m;
		struct
		{
			fz_matrix matrix;
			int xdivs;
			int ydivs;
			float domain[2][2];
			float *fn_vals;
		} f;
	} u;

	fz_compressed_buffer *buffer;
};

fz_shade *fz_keep_shade(fz_context *ctx, fz_shade *shade);
void fz_drop_shade(fz_context *ctx, fz_shade *shade);
void fz_free_shade_imp(fz_context *ctx, fz_storable *shade);

fz_rect *fz_bound_shade(fz_context *ctx, fz_shade *shade, const fz_matrix *ctm, fz_rect *r);
void fz_paint_shade(fz_context *ctx, fz_shade *shade, const fz_matrix *ctm, fz_pixmap *dest, const fz_irect *bbox);

/*
 *	Handy routine for processing mesh based shades
 */
typedef struct fz_vertex_s fz_vertex;

struct fz_vertex_s
{
	fz_point p;
	float c[FZ_MAX_COLORS];
};

typedef struct fz_mesh_processor_s fz_mesh_processor;

typedef void (fz_mesh_process_fn)(void *arg, fz_vertex *av, fz_vertex *bv, fz_vertex *cv);

struct fz_mesh_processor_s {
	fz_context *ctx;
	fz_shade *shade;
	fz_mesh_process_fn *process;
	void *process_arg;
	int ncomp;
};

void fz_process_mesh(fz_context *ctx, fz_shade *shade, const fz_matrix *ctm,
			fz_mesh_process_fn *process, void *process_arg);

#ifndef NDEBUG
void fz_print_shade(fz_context *ctx, FILE *out, fz_shade *shade);
#endif

/*
 * Scan converter
 */

typedef struct fz_gel_s fz_gel;

fz_gel *fz_new_gel(fz_context *ctx);
void fz_insert_gel(fz_gel *gel, float x0, float y0, float x1, float y1);
void fz_reset_gel(fz_gel *gel, const fz_irect *clip);
void fz_sort_gel(fz_gel *gel);
fz_irect *fz_bound_gel(const fz_gel *gel, fz_irect *bbox);
void fz_free_gel(fz_gel *gel);
int fz_is_rect_gel(fz_gel *gel);

void fz_scan_convert(fz_gel *gel, int eofill, const fz_irect *clip, fz_pixmap *pix, unsigned char *colorbv);

void fz_flatten_fill_path(fz_gel *gel, fz_path *path, const fz_matrix *ctm, float flatness);
void fz_flatten_stroke_path(fz_gel *gel, fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, float flatness, float linewidth);
void fz_flatten_dash_path(fz_gel *gel, fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, float flatness, float linewidth);

fz_irect *fz_bound_path_accurate(fz_context *ctx, fz_irect *bbox, const fz_irect *scissor, fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, float flatness, float linewidth);

/*
 * The device interface.
 */

fz_device *fz_new_draw_device_type3(fz_context *ctx, fz_pixmap *dest);

enum
{
	/* Flags */
	FZ_DEVFLAG_MASK = 1,
	FZ_DEVFLAG_COLOR = 2,
	FZ_DEVFLAG_UNCACHEABLE = 4,
	FZ_DEVFLAG_FILLCOLOR_UNDEFINED = 8,
	FZ_DEVFLAG_STROKECOLOR_UNDEFINED = 16,
	FZ_DEVFLAG_STARTCAP_UNDEFINED = 32,
	FZ_DEVFLAG_DASHCAP_UNDEFINED = 64,
	FZ_DEVFLAG_ENDCAP_UNDEFINED = 128,
	FZ_DEVFLAG_LINEJOIN_UNDEFINED = 256,
	FZ_DEVFLAG_MITERLIMIT_UNDEFINED = 512,
	FZ_DEVFLAG_LINEWIDTH_UNDEFINED = 1024,
	/* Arguably we should have a bit for the dash pattern itself being
	 * undefined, but that causes problems; do we assume that it should
	 * always be set to non-dashing at the start of every glyph? */
};

struct fz_device_s
{
	int hints;
	int flags;

	void *user;
	void (*free_user)(fz_device *);
	fz_context *ctx;

	void (*begin_page)(fz_device *, const fz_rect *rect, const fz_matrix *ctm);
	void (*end_page)(fz_device *);

	void (*fill_path)(fz_device *, fz_path *, int even_odd, const fz_matrix *, fz_colorspace *, float *color, float alpha);
	void (*stroke_path)(fz_device *, fz_path *, fz_stroke_state *, const fz_matrix *, fz_colorspace *, float *color, float alpha);
	void (*clip_path)(fz_device *, fz_path *, const fz_rect *rect, int even_odd, const fz_matrix *);
	void (*clip_stroke_path)(fz_device *, fz_path *, const fz_rect *rect, fz_stroke_state *, const fz_matrix *);

	void (*fill_text)(fz_device *, fz_text *, const fz_matrix *, fz_colorspace *, float *color, float alpha);
	void (*stroke_text)(fz_device *, fz_text *, fz_stroke_state *, const fz_matrix *, fz_colorspace *, float *color, float alpha);
	void (*clip_text)(fz_device *, fz_text *, const fz_matrix *, int accumulate);
	void (*clip_stroke_text)(fz_device *, fz_text *, fz_stroke_state *, const fz_matrix *);
	void (*ignore_text)(fz_device *, fz_text *, const fz_matrix *);

	void (*fill_shade)(fz_device *, fz_shade *shd, const fz_matrix *ctm, float alpha);
	void (*fill_image)(fz_device *, fz_image *img, const fz_matrix *ctm, float alpha);
	void (*fill_image_mask)(fz_device *, fz_image *img, const fz_matrix *ctm, fz_colorspace *, float *color, float alpha);
	void (*clip_image_mask)(fz_device *, fz_image *img, const fz_rect *rect, const fz_matrix *ctm);

	void (*pop_clip)(fz_device *);

	void (*begin_mask)(fz_device *, const fz_rect *, int luminosity, fz_colorspace *, float *bc);
	void (*end_mask)(fz_device *);
	void (*begin_group)(fz_device *, const fz_rect *, int isolated, int knockout, int blendmode, float alpha);
	void (*end_group)(fz_device *);

	int (*begin_tile)(fz_device *, const fz_rect *area, const fz_rect *view, float xstep, float ystep, const fz_matrix *ctm, int id);
	void (*end_tile)(fz_device *);

	int error_depth;
	char errmess[256];
};

void fz_begin_page(fz_device *dev, const fz_rect *rect, const fz_matrix *ctm);
void fz_end_page(fz_device *dev);
void fz_fill_path(fz_device *dev, fz_path *path, int even_odd, const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha);
void fz_stroke_path(fz_device *dev, fz_path *path, fz_stroke_state *stroke, const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha);
void fz_clip_path(fz_device *dev, fz_path *path, const fz_rect *rect, int even_odd, const fz_matrix *ctm);
void fz_clip_stroke_path(fz_device *dev, fz_path *path, const fz_rect *rect, fz_stroke_state *stroke, const fz_matrix *ctm);
void fz_fill_text(fz_device *dev, fz_text *text, const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha);
void fz_stroke_text(fz_device *dev, fz_text *text, fz_stroke_state *stroke, const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha);
void fz_clip_text(fz_device *dev, fz_text *text, const fz_matrix *ctm, int accumulate);
void fz_clip_stroke_text(fz_device *dev, fz_text *text, fz_stroke_state *stroke, const fz_matrix *ctm);
void fz_ignore_text(fz_device *dev, fz_text *text, const fz_matrix *ctm);
void fz_pop_clip(fz_device *dev);
void fz_fill_shade(fz_device *dev, fz_shade *shade, const fz_matrix *ctm, float alpha);
void fz_fill_image(fz_device *dev, fz_image *image, const fz_matrix *ctm, float alpha);
void fz_fill_image_mask(fz_device *dev, fz_image *image, const fz_matrix *ctm, fz_colorspace *colorspace, float *color, float alpha);
void fz_clip_image_mask(fz_device *dev, fz_image *image, const fz_rect *rect, const fz_matrix *ctm);
void fz_begin_mask(fz_device *dev, const fz_rect *area, int luminosity, fz_colorspace *colorspace, float *bc);
void fz_end_mask(fz_device *dev);
void fz_begin_group(fz_device *dev, const fz_rect *area, int isolated, int knockout, int blendmode, float alpha);
void fz_end_group(fz_device *dev);
void fz_begin_tile(fz_device *dev, const fz_rect *area, const fz_rect *view, float xstep, float ystep, const fz_matrix *ctm);
int fz_begin_tile_id(fz_device *dev, const fz_rect *area, const fz_rect *view, float xstep, float ystep, const fz_matrix *ctm, int id);
void fz_end_tile(fz_device *dev);

fz_device *fz_new_device(fz_context *ctx, void *user);

/*
 * Plotting functions.
 */

void fz_decode_tile(fz_pixmap *pix, float *decode);
void fz_decode_indexed_tile(fz_pixmap *pix, float *decode, int maxval);
void fz_unpack_tile(fz_pixmap *dst, unsigned char * restrict src, int n, int depth, int stride, int scale);

void fz_paint_solid_alpha(unsigned char * restrict dp, int w, int alpha);
void fz_paint_solid_color(unsigned char * restrict dp, int n, int w, unsigned char *color);

void fz_paint_span(unsigned char * restrict dp, unsigned char * restrict sp, int n, int w, int alpha);
void fz_paint_span_with_color(unsigned char * restrict dp, unsigned char * restrict mp, int n, int w, unsigned char *color);

void fz_paint_image(fz_pixmap *dst, const fz_irect *scissor, fz_pixmap *shape, fz_pixmap *img, const fz_matrix *ctm, int alpha);
void fz_paint_image_with_color(fz_pixmap *dst, const fz_irect *scissor, fz_pixmap *shape, fz_pixmap *img, const fz_matrix *ctm, unsigned char *colorbv);

void fz_paint_pixmap(fz_pixmap *dst, fz_pixmap *src, int alpha);
void fz_paint_pixmap_with_mask(fz_pixmap *dst, fz_pixmap *src, fz_pixmap *msk);
void fz_paint_pixmap_with_bbox(fz_pixmap *dst, fz_pixmap *src, int alpha, fz_irect bbox);

void fz_blend_pixmap(fz_pixmap *dst, fz_pixmap *src, int alpha, int blendmode, int isolated, fz_pixmap *shape);
void fz_blend_pixel(unsigned char dp[3], unsigned char bp[3], unsigned char sp[3], int blendmode);

enum
{
	/* PDF 1.4 -- standard separable */
	FZ_BLEND_NORMAL,
	FZ_BLEND_MULTIPLY,
	FZ_BLEND_SCREEN,
	FZ_BLEND_OVERLAY,
	FZ_BLEND_DARKEN,
	FZ_BLEND_LIGHTEN,
	FZ_BLEND_COLOR_DODGE,
	FZ_BLEND_COLOR_BURN,
	FZ_BLEND_HARD_LIGHT,
	FZ_BLEND_SOFT_LIGHT,
	FZ_BLEND_DIFFERENCE,
	FZ_BLEND_EXCLUSION,

	/* PDF 1.4 -- standard non-separable */
	FZ_BLEND_HUE,
	FZ_BLEND_SATURATION,
	FZ_BLEND_COLOR,
	FZ_BLEND_LUMINOSITY,

	/* For packing purposes */
	FZ_BLEND_MODEMASK = 15,
	FZ_BLEND_ISOLATED = 16,
	FZ_BLEND_KNOCKOUT = 32
};

struct fz_document_s
{
	void (*close)(fz_document *);
	int (*needs_password)(fz_document *doc);
	int (*authenticate_password)(fz_document *doc, char *password);
	fz_outline *(*load_outline)(fz_document *doc);
	int (*count_pages)(fz_document *doc);
	fz_page *(*load_page)(fz_document *doc, int number);
	fz_link *(*load_links)(fz_document *doc, fz_page *page);
	fz_rect *(*bound_page)(fz_document *doc, fz_page *page, fz_rect *);
	void (*run_page_contents)(fz_document *doc, fz_page *page, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie);
	void (*run_annot)(fz_document *doc, fz_page *page, fz_annot *annot, fz_device *dev, const fz_matrix *transform, fz_cookie *cookie);
	void (*free_page)(fz_document *doc, fz_page *page);
	int (*meta)(fz_document *doc, int key, void *ptr, int size);
	fz_transition *(*page_presentation)(fz_document *doc, fz_page *page, float *duration);
	void (*write)(fz_document *doc, char *filename, fz_write_options *opts);
	fz_annot *(*first_annot)(fz_document *doc, fz_page *page);
	fz_annot *(*next_annot)(fz_document *doc, fz_annot *annot);
	fz_rect *(*bound_annot)(fz_document *doc, fz_annot *annot, fz_rect *rect);
};

#endif
