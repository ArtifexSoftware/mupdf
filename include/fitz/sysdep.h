/*
 * Include the basic standard libc headers.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include <limits.h>	/* INT_MIN, MAX ... */
#include <float.h>	/* DBL_EPSILON */
#include <math.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>	/* O_RDONLY & co */

/* not supposed to be here, but printf debugging sorta needs it */
#include <stdio.h>

typedef unsigned char fz_u8;
typedef signed char fz_s8;
typedef unsigned short fz_u16;
typedef signed short fz_s16;
typedef unsigned long fz_u32;
typedef signed long fz_s32;
typedef unsigned long long fz_u64;
typedef signed long long fz_s64;

/*
 * Extras! Extras! Get them while they're hot!
 */

#ifdef __WIN32__
#define NEED_STRLCPY
#define NEED_STRSEP
#define NEED_GETOPT
#endif

#ifdef NEED_STRLCPY
extern int strlcpy(char *dst, const char *src, int n);
extern int strlcat(char *dst, const char *src, int n);
#endif

#ifdef NEED_STRSEP
extern char *strsep(char **stringp, const char *delim);
#endif

#ifdef NEED_GETOPT
extern int getopt(int nargc, char * const * nargv, const char *ostr);
extern int opterr, optind, optopt;
extern char *optarg;
#endif

