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

#ifdef WIN32
#define NEED_STRLCPY
#define NEED_STRSEP
#define NEED_GETOPT
#define M_PI 3.14159265358979323846
#define inline __inline
#define vsnprintf _vsnprintf
#endif

#include <errno.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <fcntl.h>	/* O_RDONLY & co */

/* not supposed to be here, but printf debugging sorta needs it */
#include <stdio.h>

/*
 * Extras! Extras! Get them while they're hot!
 */

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

