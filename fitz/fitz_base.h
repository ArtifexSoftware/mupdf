#ifndef _FITZ_BASE_H_
#define _FITZ_BASE_H_

/*
 * Include the standard libc headers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>

#include <assert.h>
#include <errno.h>
#include <float.h>	/* FLT_EPSILON */
#include <fcntl.h>	/* O_RDONLY & co */

#define nil ((void*)0)

#define nelem(x) (sizeof(x)/sizeof((x)[0]))

/*
 * Some differences in libc can be smoothed over
 */

#ifdef _MSC_VER /* Microsoft Visual C */

#pragma warning( disable: 4244 ) /* conversion from X to Y, possible loss of data */
#pragma warning( disable: 4996 ) /* The POSIX name for this item is deprecated */
#pragma warning( disable: 4996 ) /* This function or variable may be unsafe */

#include <io.h>

int gettimeofday(struct timeval *tv, struct timezone *tz);

#define snprintf _snprintf
#define hypotf _hypotf
#define strtoll _strtoi64

#else /* Unix or close enough */

#include <unistd.h>

#define O_BINARY 0

#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef M_SQRT2
#define M_SQRT2 1.41421356237309504880
#endif

/*
 * Variadic macros, inline and restrict keywords
 */

#if __STDC_VERSION__ == 199901L /* C99 */

#define fz_throw(...) fz_throwimp(__FILE__, __LINE__, __func__, __VA_ARGS__)
#define fz_rethrow(cause, ...) fz_rethrowimp(__FILE__, __LINE__, __func__, cause, __VA_ARGS__)
#define fz_catch(cause, ...) fz_catchimp(__FILE__, __LINE__, __func__, cause, __VA_ARGS__)

#elif _MSC_VER >= 1500 /* MSVC 9 or newer */

#define inline __inline
#define restrict __restrict
#define fz_throw(...) fz_throwimp(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define fz_rethrow(cause, ...) fz_rethrowimp(__FILE__, __LINE__, __FUNCTION__, cause, __VA_ARGS__)
#define fz_catch(cause, ...) fz_catchimp(__FILE__, __LINE__, __FUNCTION__, cause, __VA_ARGS__)

#elif __GNUC__ >= 3 /* GCC 3 or newer */

#define inline __inline
#define restrict __restrict
#define fz_throw(fmt...) fz_throwimp(__FILE__, __LINE__, __FUNCTION__, fmt)
#define fz_rethrow(cause, fmt...) fz_rethrowimp(__FILE__, __LINE__, __FUNCTION__, cause, fmt)
#define fz_catch(cause, fmt...) fz_catchimp(__FILE__, __LINE__, __FUNCTION__, cause, fmt)

#else /* Unknown or ancient */

#define inline
#define restrict
#define fz_throw fz_throwimpx
#define fz_rethrow fz_rethrowimpx
#define fz_catch fz_catchimpx

#endif

/*
 * GCC can do type checking of printf strings
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
 * Error handling
 */

typedef int fz_error;

void fz_warn(char *fmt, ...) __printflike(1, 2);

fz_error fz_throwimp(const char *file, int line, const char *func, char *fmt, ...) __printflike(4, 5);
fz_error fz_rethrowimp(const char *file, int line, const char *func, fz_error cause, char *fmt, ...) __printflike(5, 6);
void fz_catchimp(const char *file, int line, const char *func, fz_error cause, char *fmt, ...) __printflike(5, 6);

fz_error fz_throwimpx(char *fmt, ...) __printflike(1, 2);
fz_error fz_rethrowimpx(fz_error cause, char *fmt, ...) __printflike(2, 3);
void fz_catchimpx(fz_error cause, char *fmt, ...) __printflike(2, 3);

#define fz_okay ((fz_error)0)

/*
 * Basic runtime and utility functions
 */

#define ABS(x) ( (x) < 0 ? -(x) : (x) )
#define MIN(a,b) ( (a) < (b) ? (a) : (b) )
#define MAX(a,b) ( (a) > (b) ? (a) : (b) )
#define CLAMP(x,a,b) ( (x) > (b) ? (b) : ( (x) < (a) ? (a) : (x) ) )

/* memory allocation */
void *fz_malloc(int n);
void *fz_realloc(void *p, int n);
void fz_free(void *p);
char *fz_strdup(char *s);

/* runtime (hah!) test for endian-ness */
int fz_isbigendian(void);

/* safe string functions */
char *fz_strsep(char **stringp, const char *delim);
int fz_strlcpy(char *dst, const char *src, int n);
int fz_strlcat(char *dst, const char *src, int n);

/* utf-8 encoding and decoding */
int chartorune(int *rune, char *str);
int runetochar(char *str, int *rune);
int runelen(int c);

/* getopt */
extern int fz_getopt(int nargc, char * const * nargv, const char *ostr);
extern int fz_optind;
extern char *fz_optarg;

/*
 * Generic hash-table with fixed-length keys.
 */

typedef struct fz_hashtable_s fz_hashtable;

fz_hashtable * fz_newhash(int initialsize, int keylen);
void fz_debughash(fz_hashtable *table);
void fz_emptyhash(fz_hashtable *table);
void fz_freehash(fz_hashtable *table);

void *fz_hashfind(fz_hashtable *table, void *key);
void fz_hashinsert(fz_hashtable *table, void *key, void *val);
void fz_hashremove(fz_hashtable *table, void *key);

int fz_hashlen(fz_hashtable *table);
void *fz_hashgetkey(fz_hashtable *table, int idx);
void *fz_hashgetval(fz_hashtable *table, int idx);

/*
 * Math and geometry
 */

/* multiply 8-bit fixpoint (0..1) so that 0*0==0 and 255*255==255 */
static inline int fz_mul255(int a, int b)
{
	int x = a * b + 0x80;
	x += x >> 8;
	return x >> 8;
}

typedef struct fz_matrix_s fz_matrix;
typedef struct fz_point_s fz_point;
typedef struct fz_rect_s fz_rect;
typedef struct fz_bbox_s fz_bbox;

extern const fz_rect fz_unitrect;
extern const fz_rect fz_emptyrect;
extern const fz_rect fz_infiniterect;

extern const fz_bbox fz_unitbbox;
extern const fz_bbox fz_emptybbox;
extern const fz_bbox fz_infinitebbox;

#define fz_isemptyrect(r) ((r).x0 == (r).x1)
#define fz_isinfiniterect(r) ((r).x0 > (r).x1)

/*
	/ a b 0 \
	| c d 0 |
	\ e f 1 /
*/
struct fz_matrix_s
{
	float a, b, c, d, e, f;
};

struct fz_point_s
{
	float x, y;
};

struct fz_rect_s
{
	float x0, y0;
	float x1, y1;
};

struct fz_bbox_s
{
	int x0, y0;
	int x1, y1;
};

void fz_invert3x3(float *dst, float *m);

fz_matrix fz_concat(fz_matrix one, fz_matrix two);
fz_matrix fz_identity(void);
fz_matrix fz_scale(float sx, float sy);
fz_matrix fz_rotate(float theta);
fz_matrix fz_translate(float tx, float ty);
fz_matrix fz_invertmatrix(fz_matrix m);
int fz_isrectilinear(fz_matrix m);
float fz_matrixexpansion(fz_matrix m);

fz_bbox fz_roundrect(fz_rect r);
fz_bbox fz_intersectbbox(fz_bbox a, fz_bbox b);
fz_bbox fz_unionbbox(fz_bbox a, fz_bbox b);

fz_point fz_transformpoint(fz_matrix m, fz_point p);
fz_point fz_transformvector(fz_matrix m, fz_point p);
fz_rect fz_transformrect(fz_matrix m, fz_rect r);

#endif

