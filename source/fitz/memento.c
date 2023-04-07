/* Copyright (C) 2009-2022 Artifex Software, Inc.
   All Rights Reserved.

   This software is provided AS-IS with no warranty, either express or
   implied.

   This software is distributed under license and may not be copied, modified
   or distributed except as expressly authorized under the terms of that
   license. Refer to licensing information at http://www.artifex.com
   or contact Artifex Software, Inc.,  1305 Grant Avenue - Suite 200,
   Novato, CA 94945, U.S.A., +1(415)492-9861, for further information.
*/

#ifndef MEMENTO_CPP_EXTRAS_ONLY

/* Inspired by Fortify by Simon P Bullen. */

/* Set the following if we want to do a build specifically for memory
 * squeezing. We sacrifice some features for speed. */
/* #define MEMENTO_SQUEEZEBUILD */

/* Set the following if you're only looking for leaks, not memory overwrites
 * to speed the operation */
/* #define MEMENTO_LEAKONLY */

/* Unset the following if you don't want the speed/memory hit of tracking references. */
#ifndef MEMENTO_SQUEEZEBUILD
#define MEMENTO_TRACKREFS
#endif

/* Set the following to keep extra details about the history of blocks */
#ifndef MEMENTO_SQUEEZEBUILD
#define MEMENTO_DETAILS
#endif

/* Set what volume of memory blocks we keep around after it's been freed
 * to check for overwrites. */
#define MEMENTO_FREELIST_MAX 0x2000000

/* Don't keep blocks around if they'd mean losing more than a quarter of
 * the freelist. */
#define MEMENTO_FREELIST_MAX_SINGLE_BLOCK (MEMENTO_FREELIST_MAX/4)

#define COMPILING_MEMENTO_C

/* SHUT UP, MSVC. I KNOW WHAT I AM DOING. */
#define _CRT_SECURE_NO_WARNINGS

/* We have some GS specific tweaks; more for the GS build environment than
 * anything else. */
/* #define MEMENTO_GS_HACKS */

#ifdef MEMENTO_GS_HACKS
/* For GS we include malloc_.h. Anyone else would just include memento.h */
#include "malloc_.h"
#include "memory_.h"
int atexit(void (*)(void));
#else
#ifdef MEMENTO_MUPDF_HACKS
#include "mupdf/memento.h"
#else
#include "memento.h"
#endif
#include <stdio.h>
#endif
#ifndef _MSC_VER
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#ifdef __ANDROID__
#define MEMENTO_ANDROID
#include <stdio.h>
#endif

/* Workaround VS2012 (and earlier) missing va_copy. */
#ifdef _MSC_VER
# if _MSC_VER < 1800 /* Prior to 2013 */
#  ifndef va_copy
#   ifdef __va_copy
#    define va_copy(dst,src) __va_copy(dst,src)
#   else
#    define va_copy(dst,src) memcpy(&dst, &src, sizeof(va_list))
#   endif /* __va_copy */
#  endif /* va_copy */
# endif
#endif

/* Hacks to portably print large sizes */
#ifdef _MSC_VER
#define FMTZ "%llu"
#define FMTZ_CAST _int64
#define FMTP "0x%p"
typedef unsigned _int64 mem_uint64_t;
#else
#define FMTZ "%zu"
#define FMTZ_CAST size_t
#define FMTP "%p"
typedef long long mem_uint64_t;
#endif

#define UB(x) ((intptr_t)((x) & 0xFF))
#define B2I(x) (UB(x) | (UB(x)<<8) | (UB(x)<<16) | (UB(x)<<24))
#define B2P(x) ((void *)(B2I(x) | ((B2I(x)<<16)<<16)))
#define MEMENTO_PREFILL_UBYTE ((unsigned char)(MEMENTO_PREFILL))
#define MEMENTO_PREFILL_USHORT (((unsigned short)MEMENTO_PREFILL_UBYTE) | (((unsigned short)MEMENTO_PREFILL_UBYTE)<<8))
#define MEMENTO_PREFILL_UINT (((unsigned int)MEMENTO_PREFILL_USHORT) | (((unsigned int)MEMENTO_PREFILL_USHORT)<<16))
#define MEMENTO_PREFILL_PTR (void *)(((uintptr_t)MEMENTO_PREFILL_UINT) | ((((uintptr_t)MEMENTO_PREFILL_UINT)<<16)<<16))
#define MEMENTO_POSTFILL_UBYTE ((unsigned char)(MEMENTO_POSTFILL))
#define MEMENTO_POSTFILL_USHORT (((unsigned short)MEMENTO_POSTFILL_UBYTE) | (((unsigned short)MEMENTO_POSTFILL_UBYTE)<<8))
#define MEMENTO_POSTFILL_UINT (((unsigned int)MEMENTO_POSTFILL_USHORT) | (((unsigned int)MEMENTO_POSTFILL_USHORT)<<16))
#define MEMENTO_POSTFILL_PTR (void *)(((uintptr_t)MEMENTO_POSTFILL_UINT) | ((((uintptr_t)MEMENTO_POSTFILL_UINT)<<16)<<16))
#define MEMENTO_ALLOCFILL_UBYTE ((unsigned char)(MEMENTO_ALLOCFILL))
#define MEMENTO_ALLOCFILL_USHORT (((unsigned short)MEMENTO_ALLOCFILL_UBYTE) | (((unsigned short)MEMENTO_ALLOCFILL_UBYTE)<<8))
#define MEMENTO_ALLOCFILL_UINT (((unsigned int)MEMENTO_ALLOCFILL_USHORT) | (((unsigned int)MEMENTO_ALLOCFILL_USHORT)<<16))
#define MEMENTO_ALLOCFILL_PTR (void *)(((uintptr_t)MEMENTO_ALLOCFILL_UINT) | ((((uintptr_t)MEMENTO_ALLOCFILL_UINT)<<16)<<16))
#define MEMENTO_FREEFILL_UBYTE ((unsigned char)(MEMENTO_FREEFILL))
#define MEMENTO_FREEFILL_USHORT (((unsigned short)MEMENTO_FREEFILL_UBYTE) | (((unsigned short)MEMENTO_FREEFILL_UBYTE)<<8))
#define MEMENTO_FREEFILL_UINT (((unsigned int)MEMENTO_FREEFILL_USHORT) | (((unsigned int)MEMENTO_FREEFILL_USHORT)<<16))
#define MEMENTO_FREEFILL_PTR (void *)(((uintptr_t)MEMENTO_FREEFILL_UINT) | ((((uintptr_t)MEMENTO_FREEFILL_UINT)<<16)<<16))

#ifdef MEMENTO

#ifdef MEMENTO_ANDROID
#include <android/log.h>

static char log_buffer[4096];
static int log_fill = 0;

static char log_buffer2[4096];

static int
android_fprintf(FILE *file, const char *fmt, ...)
{
    va_list args;
    char *p, *q;

    va_start(args, fmt);
    vsnprintf(log_buffer2, sizeof(log_buffer2)-1, fmt, args);
    va_end(args);

    /* Ensure we are always null terminated */
    log_buffer2[sizeof(log_buffer2)-1] = 0;

    p = log_buffer2;
    q = p;
    do
    {
        /* Find the end of the string, or the next \n */
        while (*p && *p != '\n')
            p++;

        /* We need to output from q to p. Limit ourselves to what
         * will fit in the existing */
        if (p - q >= sizeof(log_buffer)-1 - log_fill)
                p = q + sizeof(log_buffer)-1 - log_fill;

        memcpy(&log_buffer[log_fill], q, p-q);
        log_fill += p-q;
        if (*p == '\n')
        {
            log_buffer[log_fill] = 0;
            __android_log_print(ANDROID_LOG_ERROR, "memento", "%s", log_buffer);
            usleep(1);
            log_fill = 0;
            p++; /* Skip over the \n */
        }
        else if (log_fill >= sizeof(log_buffer)-1)
        {
            log_buffer[sizeof(log_buffer2)-1] = 0;
            __android_log_print(ANDROID_LOG_ERROR, "memento", "%s", log_buffer);
            usleep(1);
            log_fill = 0;
        }
        q = p;
    }
    while (*p);

    return 0;
}

#define fprintf android_fprintf
#define MEMENTO_STACKTRACE_METHOD 3
#endif

/* _WIN64 defined implies _WIN32 will be */
#ifdef _WIN32
#include <windows.h>

static int
windows_fprintf(FILE *file, const char *fmt, ...)
{
    va_list args;
    char text[4096];
    int ret;

    va_start(args, fmt);
    ret = vfprintf(file, fmt, args);
    va_end(args);

    va_start(args, fmt);
    vsnprintf(text, 4096, fmt, args);
    OutputDebugStringA(text);
    va_end(args);

    return ret;
}

#define fprintf windows_fprintf
#endif

#ifndef MEMENTO_STACKTRACE_METHOD
#ifdef __GNUC__
#define MEMENTO_STACKTRACE_METHOD 1
#endif
#ifdef _WIN32
#define MEMENTO_STACKTRACE_METHOD 2
#endif
#endif

#if defined(__linux__) || defined(__OpenBSD__)
#define MEMENTO_HAS_FORK
#elif defined(__APPLE__) && defined(__MACH__)
#define MEMENTO_HAS_FORK
#endif

#if defined(_DLL) && defined(_MSC_VER)
#define MEMENTO_CRT_SPEC __declspec(dllimport)
#else
#define MEMENTO_CRT_SPEC
#endif

/* Define the underlying allocators, just in case */
MEMENTO_CRT_SPEC void *MEMENTO_UNDERLYING_MALLOC(size_t);
MEMENTO_CRT_SPEC void MEMENTO_UNDERLYING_FREE(void *);
MEMENTO_CRT_SPEC void *MEMENTO_UNDERLYING_REALLOC(void *,size_t);
MEMENTO_CRT_SPEC void *MEMENTO_UNDERLYING_CALLOC(size_t,size_t);

/* And some other standard functions we use. We don't include the header
 * files, just in case they pull in unexpected others. */
MEMENTO_CRT_SPEC int atoi(const char *);
MEMENTO_CRT_SPEC char *getenv(const char *);

/* How far to search for pointers in each block when calculating nestings */
/* mupdf needs at least 34000ish (sizeof(fz_shade))/ */
#define MEMENTO_PTRSEARCH 65536

#ifndef MEMENTO_MAXPATTERN
#define MEMENTO_MAXPATTERN 0
#endif

#ifdef MEMENTO_GS_HACKS
#include "valgrind.h"
#else
#ifdef HAVE_VALGRIND
#include "valgrind/memcheck.h"
#else
#define VALGRIND_MAKE_MEM_NOACCESS(p,s)  do { } while (0==1)
#define VALGRIND_MAKE_MEM_UNDEFINED(p,s)  do { } while (0==1)
#define VALGRIND_MAKE_MEM_DEFINED(p,s)  do { } while (0==1)
#endif
#endif

enum {
    Memento_PreSize  = 16,
    Memento_PostSize = 16
};

/* Some compile time checks */
typedef struct
{
    char MEMENTO_PRESIZE_MUST_BE_A_MULTIPLE_OF_4[Memento_PreSize & 3 ? -1 : 1];
    char MEMENTO_POSTSIZE_MUST_BE_A_MULTIPLE_OF_4[Memento_PostSize & 3 ? -1 : 1];
    char MEMENTO_POSTSIZE_MUST_BE_AT_LEAST_4[Memento_PostSize >= 4 ? 1 : -1];
    char MEMENTO_PRESIZE_MUST_BE_AT_LEAST_4[Memento_PreSize >= 4 ? 1 : -1];
} MEMENTO_SANITY_CHECK_STRUCT;

#define MEMENTO_UINT32 unsigned int
#define MEMENTO_UINT16 unsigned short

#define MEMENTO_PREFILL_UINT32  ((MEMENTO_UINT32)(MEMENTO_PREFILL  | (MEMENTO_PREFILL <<8) | (MEMENTO_PREFILL <<16) |(MEMENTO_PREFILL <<24)))
#define MEMENTO_POSTFILL_UINT16 ((MEMENTO_UINT16)(MEMENTO_POSTFILL | (MEMENTO_POSTFILL<<8)))
#define MEMENTO_POSTFILL_UINT32 ((MEMENTO_UINT32)(MEMENTO_POSTFILL | (MEMENTO_POSTFILL<<8) | (MEMENTO_POSTFILL<<16) |(MEMENTO_POSTFILL<<24)))
#define MEMENTO_FREEFILL_UINT16 ((MEMENTO_UINT16)(MEMENTO_FREEFILL | (MEMENTO_FREEFILL<<8)))
#define MEMENTO_FREEFILL_UINT32 ((MEMENTO_UINT32)(MEMENTO_FREEFILL | (MEMENTO_FREEFILL<<8) | (MEMENTO_FREEFILL<<16) |(MEMENTO_FREEFILL<<24)))

enum {
    Memento_Flag_OldBlock = 1,
    Memento_Flag_HasParent = 2,
    Memento_Flag_BreakOnFree = 4,
    Memento_Flag_BreakOnRealloc = 8,
    Memento_Flag_Freed = 16,
    Memento_Flag_KnownLeak = 32,
    Memento_Flag_Reported = 64,
    Memento_Flag_LastPhase = 0x80000000,
    Memento_Flag_PhaseMask = 0xFFFF0000
};

enum {
    Memento_EventType_malloc = 0,
    Memento_EventType_calloc = 1,
    Memento_EventType_realloc = 2,
    Memento_EventType_free = 3,
    Memento_EventType_new = 4,
    Memento_EventType_delete = 5,
    Memento_EventType_newArray = 6,
    Memento_EventType_deleteArray = 7,
    Memento_EventType_takeRef = 8,
    Memento_EventType_dropRef = 9,
    Memento_EventType_reference = 10,
    Memento_EventType_strdup = 11,
    Memento_EventType_asprintf = 12,
    Memento_EventType_vasprintf = 13
};

static const char *eventType[] =
{
    "malloc",
    "calloc",
    "realloc",
    "free",
    "new",
    "delete",
    "new[]",
    "delete[]",
    "takeRef",
    "dropRef",
    "reference",
    "strdup",
    "asprintf",
    "vasprintf"
};

/* When we list leaked blocks at the end of execution, we search for pointers
 * between blocks in order to be able to give a nice nested view.
 * Unfortunately, if you have are running your own allocator (such as
 * postscript's chunk allocator) you can often find that the header of the
 * block always contains pointers to next or previous blocks. This tends to
 * mean the nesting displayed is "uninteresting" at best :)
 *
 * As a hack to get around this, we have a define MEMENTO_SKIP_SEARCH that
 * indicates how many bytes to skip over at the start of the chunk.
 * This may cause us to miss true nestings, but such is life...
 */
#ifndef MEMENTO_SEARCH_SKIP
#ifdef MEMENTO_GS_HACKS
#define MEMENTO_SEARCH_SKIP (2*sizeof(void *))
#else
#define MEMENTO_SEARCH_SKIP 0
#endif
#endif

#define MEMENTO_CHILD_MAGIC   ((Memento_BlkHeader *)('M' | ('3' << 8) | ('m' << 16) | ('3' << 24)))
#define MEMENTO_SIBLING_MAGIC ((Memento_BlkHeader *)('n' | ('t' << 8) | ('0' << 16) | ('!' << 24)))

#ifdef MEMENTO_DETAILS
typedef struct Memento_hashedST Memento_hashedST;

struct Memento_hashedST
{
    Memento_hashedST *next;
    MEMENTO_UINT32    hash;
    int               count;
    void             *trace[1];
};

typedef struct Memento_BlkDetails Memento_BlkDetails;

struct Memento_BlkDetails
{
    Memento_BlkDetails *next;
    char                type;
    int                 sequence;
    Memento_hashedST   *trace;
};
#endif /* MEMENTO_DETAILS */

typedef struct Memento_BlkHeader Memento_BlkHeader;

struct Memento_BlkHeader
{
    size_t               rawsize;
    int                  sequence;
    int                  lastCheckedOK;
    int                  flags;

    const char          *label;

    /* Blocks are held in a linked list for LRU */
    Memento_BlkHeader   *next;
    Memento_BlkHeader   *prev; /* Reused as 'parent' when printing nested list */

    /* Blocks are held in a splay tree for position. */
    Memento_BlkHeader   *parent;
    Memento_BlkHeader   *left;
    Memento_BlkHeader   *right;

    /* Entries for nesting display calculations. Set to magic
     * values at all other time.  */
    Memento_BlkHeader   *child;
    Memento_BlkHeader   *sibling;

#ifdef MEMENTO_DETAILS
    Memento_BlkDetails  *details;
    Memento_BlkDetails **details_tail;
#endif

    /* On 64bit versions of windows, we need blocks to be returned
     * from malloc as 128bit aligned due to setjmp. Hence, add a
     * dummy padding block to make the entire struct a multiple of
     * 128bits. This has to go before the preblk. */
#if defined(WIN64)
    void *dummy;
#endif

    char                 preblk[Memento_PreSize];
};

/* In future this could (should) be a smarter data structure, like, say,
 * splay trees. For now, we use a list.
 */
typedef struct Memento_Blocks
{
    Memento_BlkHeader *head;
    Memento_BlkHeader *tail;
    Memento_BlkHeader *top;
} Memento_Blocks;

/* What sort of Mutex should we use? */
#ifdef MEMENTO_LOCKLESS
typedef int Memento_mutex;

static void Memento_initMutex(Memento_mutex *m)
{
    (void)m;
}

#define MEMENTO_DO_LOCK() do { } while (0)
#define MEMENTO_DO_UNLOCK() do { } while (0)

#else
#if defined(_WIN32) || defined(_WIN64)
/* Windows */
typedef CRITICAL_SECTION Memento_mutex;

static void Memento_initMutex(Memento_mutex *m)
{
    InitializeCriticalSection(m);
}

#define MEMENTO_DO_LOCK() \
    EnterCriticalSection(&memento.mutex)
#define MEMENTO_DO_UNLOCK() \
    LeaveCriticalSection(&memento.mutex)

#else
#include <pthread.h>
typedef pthread_mutex_t Memento_mutex;

static void Memento_initMutex(Memento_mutex *m)
{
    pthread_mutex_init(m, NULL);
}

#define MEMENTO_DO_LOCK() \
    pthread_mutex_lock(&memento.mutex)
#define MEMENTO_DO_UNLOCK() \
    pthread_mutex_unlock(&memento.mutex)

#endif
#endif

typedef struct {
    int begin;
    int end;
} Memento_range;

/* And our global structure */
static struct {
    int            inited;
    Memento_Blocks used;
    Memento_Blocks free;
    size_t         freeListSize;
    int            sequence;
    int            paranoia;
    int            paranoidAt;
    int            countdown;
    int            lastChecked;
    int            breakAt;
    int            failAt;
    int            failing;
    int            nextFailAt;
    int            squeezeAt;
    int            squeezing;
    int            segv;
    int            pattern;
    int            nextPattern;
    int            patternBit;
    int            leaking;
    int            showDetailedBlocks;
    int            hideMultipleReallocs;
    int            hideRefChangeBacktraces;
    int            abortOnLeak;
    int            abortOnCorruption;
    size_t         maxMemory;
    size_t         alloc;
    size_t         peakAlloc;
    mem_uint64_t   totalAlloc;
    size_t         numMallocs;
    size_t         numFrees;
    size_t         numReallocs;
    Memento_mutex  mutex;
    Memento_range *squeezes;
    int            squeezes_num;
    int            squeezes_pos;
    int            ignoreNewDelete;
    int            atexitFin;
    int            phasing;
    int            verbose;
    int            verboseNewlineSuppressed;
    void          *lastVerbosePtr;
    char         **backtraceLimitFnnames;
    int            backtraceLimitFnnamesNum;
#ifdef MEMENTO_DETAILS
    Memento_hashedST *stacktraces[256];
    int            hashCollisions;
#endif
} memento;

#define MEMENTO_EXTRASIZE (sizeof(Memento_BlkHeader) + Memento_PostSize)

/* Round up size S to the next multiple of N (where N is a power of 2) */
#define MEMENTO_ROUNDUP(S,N) ((S + N-1)&~(N-1))

#define MEMBLK_SIZE(s) MEMENTO_ROUNDUP(s + MEMENTO_EXTRASIZE, MEMENTO_MAXALIGN)

#define MEMBLK_FROMBLK(B)   (&((Memento_BlkHeader*)(void *)(B))[-1])
#define MEMBLK_TOBLK(B)     ((void*)(&((Memento_BlkHeader*)(void*)(B))[1]))
#define MEMBLK_POSTPTR(B) \
          (&((unsigned char *)(void *)(B))[(B)->rawsize + sizeof(Memento_BlkHeader)])

enum
{
    SkipStackBackTraceLevels = 4
};

#if defined(MEMENTO_STACKTRACE_METHOD) && MEMENTO_STACKTRACE_METHOD == 1
extern size_t backtrace(void **, int);
extern void backtrace_symbols_fd(void **, size_t, int);
extern char **backtrace_symbols(void **, size_t);

#define MEMENTO_BACKTRACE_MAX 256
static int (*print_stack_value)(void *address);

/* Libbacktrace gubbins - relies on us having libdl to load the .so */
#ifdef HAVE_LIBDL
#include <dlfcn.h>

typedef void (*backtrace_error_callback) (void *data, const char *msg, int errnum);

typedef struct backtrace_state *(*backtrace_create_state_type)(
    const char *filename, int threaded,
    backtrace_error_callback error_callback, void *data);

typedef int (*backtrace_full_callback) (void *data, uintptr_t pc,
                                        const char *filename, int lineno,
                                        const char *function);

typedef int (*backtrace_pcinfo_type)(struct backtrace_state *state,
                                     uintptr_t pc,
                                     backtrace_full_callback callback,
                                     backtrace_error_callback error_callback,
                                     void *data);

typedef void (*backtrace_syminfo_callback) (void *data, uintptr_t pc,
                                            const char *symname,
                                            uintptr_t symval,
                                            uintptr_t symsize);

typedef int (*backtrace_syminfo_type)(struct backtrace_state *state,
                                      uintptr_t addr,
                                      backtrace_syminfo_callback callback,
                                      backtrace_error_callback error_callback,
                                      void *data);

static backtrace_syminfo_type backtrace_syminfo;
static backtrace_create_state_type backtrace_create_state;
static backtrace_pcinfo_type backtrace_pcinfo;
static struct backtrace_state *my_backtrace_state;
static void *libbt;
static char backtrace_exe[4096];
static void *current_addr;

static void error2_cb(void *data, const char *msg, int errnum)
{
    (void)data;
    (void)msg;
    (void)errnum;
}

static void syminfo_cb(void *data, uintptr_t pc, const char *symname, uintptr_t symval, uintptr_t symsize)
{
    (void)data;
    (void)symval;
    (void)symsize;
    if (sizeof(void *) == 4)
        fprintf(stderr, "    0x%08lx %s\n", pc, symname?symname:"?");
    else
        fprintf(stderr, "    0x%016lx %s\n", pc, symname?symname:"?");
}

static void error_cb(void *data, const char *msg, int errnum)
{
    (void)data;
    (void)msg;
    (void)errnum;
    backtrace_syminfo(my_backtrace_state,
                     (uintptr_t)current_addr,
                     syminfo_cb,
                     error2_cb,
                     NULL);
}

static int full_cb(void *data, uintptr_t pc, const char *fname, int line, const char *fn)
{
    if (sizeof(void *) == 4)
        fprintf(stderr, "    0x%08lx %s(%s:%d)\n", pc, fn?fn:"?", fname?fname:"?", line);
    else
        fprintf(stderr, "    0x%016lx %s(%s:%d)\n", pc, fn?fn:"?", fname?fname:"?", line);
    if (fn) {
        int i;
        for (i=0; i<memento.backtraceLimitFnnamesNum; ++i) {
            if (!strcmp(fn, memento.backtraceLimitFnnames[i])) {
                *(int*) data = 1;
            }
        }
    }
    return 0;
}

static int print_stack_libbt(void *addr)
{
    int end = 0;
    current_addr = addr;
    backtrace_pcinfo(my_backtrace_state,
                     (uintptr_t)addr,
                     full_cb,
                     error_cb,
                     &end);
    return end;
}

static int print_stack_libbt_failed(void *addr)
{
    char **strings;
#if 0
    /* Let's use a hack from Julian Smith to call gdb to extract the information */
    /* Disabled for now, as I can't make this work. */
    static char command[1024];
    int e;
    static int gdb_invocation_failed = 0;

    if (gdb_invocation_failed == 0)
    {
        snprintf(command, sizeof(command),
                 //"gdb -q --batch -p=%i -ex 'info line *%p' -ex quit 2>/dev/null",
                 "gdb -q --batch -p=%i -ex 'info line *%p' -ex quit 2>/dev/null| egrep -v '(Thread debugging using)|(Using host libthread_db library)|(A debugging session is active)|(will be detached)|(Quit anyway)|(No such file or directory)|(^0x)|(^$)'",
                 getpid(), addr);
    printf("%s\n", command);
        e = system(command);
        if (e == 0)
            return; /* That'll do! */
        gdb_invocation_failed = 1; /* If it's failed once, it'll probably keep failing. */
    }
#endif

    /* We couldn't even get gdb! Make do. */
    strings = backtrace_symbols(&addr, 1);

    if (strings == NULL || strings[0] == NULL)
    {
        if (sizeof(void *) == 4)
            fprintf(stderr, "    [0x%08lx]\n", (uintptr_t)addr);
        else
            fprintf(stderr, "    [0x%016lx]\n", (uintptr_t)addr);
    }
    else
    {
        fprintf(stderr, "    %s\n", strings[0]);
    }
    (free)(strings);
    return 0;
}

static int init_libbt(void)
{
    static int libbt_inited = 0;

    if (libbt_inited)
        return 0;
    libbt_inited = 1;

    libbt = dlopen("libbacktrace.so", RTLD_LAZY);
    if (libbt == NULL)
        libbt = dlopen("/opt/lib/libbacktrace.so", RTLD_LAZY);
    if (libbt == NULL)
        libbt = dlopen("/lib/libbacktrace.so", RTLD_LAZY);
    if (libbt == NULL)
        libbt = dlopen("/usr/lib/libbacktrace.so", RTLD_LAZY);
    if (libbt == NULL)
        libbt = dlopen("/usr/local/lib/libbacktrace.so", RTLD_LAZY);
    if (libbt == NULL)
        goto fail;

    backtrace_create_state = dlsym(libbt, "backtrace_create_state");
    backtrace_syminfo      = dlsym(libbt, "backtrace_syminfo");
    backtrace_pcinfo       = dlsym(libbt, "backtrace_pcinfo");

    if (backtrace_create_state == NULL ||
        backtrace_syminfo == NULL ||
        backtrace_pcinfo == NULL)
    {
        goto fail;
    }

    my_backtrace_state = backtrace_create_state(backtrace_exe,
                                                1 /*BACKTRACE_SUPPORTS_THREADS*/,
                                                error_cb,
                                                NULL);
    if (my_backtrace_state == NULL)
        goto fail;

    print_stack_value = print_stack_libbt;

    return 1;

 fail:
    fprintf(stderr,
            "MEMENTO: libbacktrace.so failed to load; backtraces will be sparse.\n"
            "MEMENTO: See memento.h for how to rectify this.\n");
    libbt = NULL;
    backtrace_create_state = NULL;
    backtrace_syminfo = NULL;
    print_stack_value = print_stack_libbt_failed;
    return 0;
}
#endif

static int print_stack_default(void *addr)
{
    char **strings = backtrace_symbols(&addr, 1);

    if (strings == NULL || strings[0] == NULL)
    {
        fprintf(stderr, "    ["FMTP"]\n", addr);
    }
#ifdef HAVE_LIBDL
    else if (strchr(strings[0], ':') == NULL)
    {
        /* Probably a "path [address]" format string */
        char *s = strchr(strings[0], ' ');

        if (s != strings[0])
        {
            memcpy(backtrace_exe, strings[0], s - strings[0]);
            backtrace_exe[s-strings[0]] = 0;
            init_libbt();
            print_stack_value(addr);
        }
    }
#endif
    else
    {
        fprintf(stderr, "    %s\n", strings[0]);
    }
    free(strings);
    return 0;
}

static void Memento_initStacktracer(void)
{
    print_stack_value = print_stack_default;
}

static int Memento_getStacktrace(void **stack, int *skip)
{
    size_t num;

    num = backtrace(&stack[0], MEMENTO_BACKTRACE_MAX);

    *skip = SkipStackBackTraceLevels;
    if (num <= SkipStackBackTraceLevels)
        return 0;
    return (int)(num-SkipStackBackTraceLevels);
}

static void Memento_showStacktrace(void **stack, int numberOfFrames)
{
    int i;

    for (i = 0; i < numberOfFrames; i++)
    {
        if (print_stack_value(stack[i]))
            break;
    }
}
#elif defined(MEMENTO_STACKTRACE_METHOD) && MEMENTO_STACKTRACE_METHOD == 2
#include <Windows.h>

/* We use DbgHelp.dll rather than DbgHelp.lib. This avoids us needing
 * extra link time complications, and enables us to fall back gracefully
 * if the DLL cannot be found.
 *
 * To achieve this we have our own potted versions of the required types
 * inline here.
 */
#ifdef _WIN64
typedef DWORD64 DWORD_NATIVESIZED;
#else
typedef DWORD DWORD_NATIVESIZED;
#endif

#define MEMENTO_BACKTRACE_MAX 64

typedef USHORT (__stdcall *My_CaptureStackBackTraceType)(__in ULONG, __in ULONG, __out PVOID*, __out_opt PULONG);

typedef struct MY_IMAGEHLP_LINE {
    DWORD    SizeOfStruct;
    PVOID    Key;
    DWORD    LineNumber;
    PCHAR    FileName;
    DWORD_NATIVESIZED    Address;
} MY_IMAGEHLP_LINE, *MY_PIMAGEHLP_LINE;

typedef BOOL (__stdcall *My_SymGetLineFromAddrType)(HANDLE hProcess, DWORD_NATIVESIZED dwAddr, PDWORD pdwDisplacement, MY_PIMAGEHLP_LINE Line);

typedef struct MY_SYMBOL_INFO {
    ULONG       SizeOfStruct;
    ULONG       TypeIndex;        // Type Index of symbol
    ULONG64     Reserved[2];
    ULONG       info;
    ULONG       Size;
    ULONG64     ModBase;          // Base Address of module containing this symbol
    ULONG       Flags;
    ULONG64     Value;            // Value of symbol, ValuePresent should be 1
    ULONG64     Address;          // Address of symbol including base address of module
    ULONG       Register;         // register holding value or pointer to value
    ULONG       Scope;            // scope of the symbol
    ULONG       Tag;              // pdb classification
    ULONG       NameLen;          // Actual length of name
    ULONG       MaxNameLen;
    CHAR        Name[1];          // Name of symbol
} MY_SYMBOL_INFO, *MY_PSYMBOL_INFO;

typedef BOOL (__stdcall *My_SymFromAddrType)(HANDLE hProcess, DWORD64 Address, PDWORD64 Displacement, MY_PSYMBOL_INFO Symbol);
typedef BOOL (__stdcall *My_SymInitializeType)(HANDLE hProcess, PSTR UserSearchPath, BOOL fInvadeProcess);

static My_CaptureStackBackTraceType Memento_CaptureStackBackTrace;
static My_SymGetLineFromAddrType Memento_SymGetLineFromAddr;
static My_SymFromAddrType Memento_SymFromAddr;
static My_SymInitializeType Memento_SymInitialize;
static HANDLE Memento_process;

static void Memento_initStacktracer(void)
{
    HMODULE mod = LoadLibrary("kernel32.dll");

    if (mod == NULL)
        return;
    Memento_CaptureStackBackTrace = (My_CaptureStackBackTraceType)(GetProcAddress(mod, "RtlCaptureStackBackTrace"));
    if (Memento_CaptureStackBackTrace == NULL)
        return;
    mod = LoadLibrary("Dbghelp.dll");
    if (mod == NULL) {
        Memento_CaptureStackBackTrace = NULL;
        return;
    }
    Memento_SymGetLineFromAddr =
            (My_SymGetLineFromAddrType)(GetProcAddress(mod,
#ifdef _WIN64
                                                       "SymGetLineFromAddr64"
#else
                                                       "SymGetLineFromAddr"
#endif
                                        ));
    if (Memento_SymGetLineFromAddr == NULL) {
        Memento_CaptureStackBackTrace = NULL;
        return;
    }
    Memento_SymFromAddr = (My_SymFromAddrType)(GetProcAddress(mod, "SymFromAddr"));
    if (Memento_SymFromAddr == NULL) {
        Memento_CaptureStackBackTrace = NULL;
        return;
    }
    Memento_SymInitialize = (My_SymInitializeType)(GetProcAddress(mod, "SymInitialize"));
    if (Memento_SymInitialize == NULL) {
        Memento_CaptureStackBackTrace = NULL;
        return;
    }
    Memento_process = GetCurrentProcess();
    Memento_SymInitialize(Memento_process, NULL, TRUE);
}

static int Memento_getStacktrace(void **stack, int *skip)
{
    if (Memento_CaptureStackBackTrace == NULL)
        return 0;

    *skip = 0;
    /* Limit us to 63 levels due to windows bug */
    return Memento_CaptureStackBackTrace(SkipStackBackTraceLevels, 63-SkipStackBackTraceLevels, stack, NULL);
}

static void Memento_showStacktrace(void **stack, int numberOfFrames)
{
    MY_IMAGEHLP_LINE line;
    int i, j;
    char symbol_buffer[sizeof(MY_SYMBOL_INFO) + 1024 + 1];
    MY_SYMBOL_INFO *symbol = (MY_SYMBOL_INFO *)symbol_buffer;
    BOOL ok;
    int prefix = 1; /* Ignore a prefix of 'unknowns' */
    int suppressed = 0; /* How many unknowns we have suppressed. */

    symbol->MaxNameLen = 1024;
    symbol->SizeOfStruct = sizeof(MY_SYMBOL_INFO);
    line.SizeOfStruct = sizeof(MY_IMAGEHLP_LINE);
    for (i = 0; i < numberOfFrames; i++)
    {
        DWORD64 dwDisplacement64;
        DWORD dwDisplacement;
        ok = Memento_SymFromAddr(Memento_process, (DWORD64)(stack[i]), &dwDisplacement64, symbol);
        if (ok == 1)
            ok = Memento_SymGetLineFromAddr(Memento_process, (DWORD_NATIVESIZED)(stack[i]), &dwDisplacement, &line);
        if (ok == 1) {
            for (j = 0; j < suppressed; j++)
                fprintf(stderr, "    unknown\n");
            suppressed = 0;
            fprintf(stderr, "    %s in %s:%d\n", symbol->Name, line.FileName, line.LineNumber);
            prefix = 0;
        } else if (prefix == 0) {
            suppressed++;
        }
    }
}
#elif defined(MEMENTO_STACKTRACE_METHOD) && MEMENTO_STACKTRACE_METHOD == 3

#include <unwind.h>
#include <dlfcn.h>

/* From cxxabi.h */
extern char* __cxa_demangle(const char* mangled_name,
                            char*       output_buffer,
                            size_t*     length,
                            int*        status);

static void Memento_initStacktracer(void)
{
}

#define MEMENTO_BACKTRACE_MAX 256

typedef struct
{
    int count;
    void **addr;
} my_unwind_details;

static _Unwind_Reason_Code unwind_populate_callback(struct _Unwind_Context *context,
                                                    void *arg)
{
    my_unwind_details *uw = (my_unwind_details *)arg;
    int count = uw->count;

    if (count >= MEMENTO_BACKTRACE_MAX)
        return _URC_END_OF_STACK;

    uw->addr[count] = (void *)_Unwind_GetIP(context);
    uw->count++;

    return _URC_NO_REASON;
}

static int Memento_getStacktrace(void **stack, int *skip)
{
    my_unwind_details uw = { 0, stack };

    *skip = 0;

    /* Collect the backtrace. Deliberately only unwind once,
     * and avoid using malloc etc until this completes just
     * in case. */
    _Unwind_Backtrace(unwind_populate_callback, &uw);
    if (uw.count <= SkipStackBackTraceLevels)
        return 0;

    *skip = SkipStackBackTraceLevels;
    return uw.count-SkipStackBackTraceLevels;
}

static void Memento_showStacktrace(void **stack, int numberOfFrames)
{
    int i;

    for (i = 0; i < numberOfFrames; i++)
    {
        Dl_info info;
        if (dladdr(stack[i], &info))
        {
            int status = 0;
            const char *sym = info.dli_sname ? info.dli_sname : "<unknown>";
            char *demangled = __cxa_demangle(sym, NULL, 0, &status);
            int offset = stack[i] - info.dli_saddr;
            fprintf(stderr, "    ["FMTP"]%s(+0x%x)\n", stack[i], demangled && status == 0 ? demangled : sym, offset);
            free(demangled);
        }
        else
        {
            fprintf(stderr, "    ["FMTP"]\n", stack[i]);
        }
    }
}

#else
static void Memento_initStacktracer(void)
{
}

static int Memento_getStacktrace(void **stack, int *skip)
{
    *skip = 0;
    return 0;
}

static void Memento_showStacktrace(void **stack, int numberOfFrames)
{
}
#endif /* MEMENTO_STACKTRACE_METHOD */

#ifndef MEMENTO_BACKTRACE_MAX
#define MEMENTO_BACKTRACE_MAX 1
#endif

#ifdef MEMENTO_DETAILS
static MEMENTO_UINT32
hashStackTrace(void **stack, int count)
{
    int i;
    MEMENTO_UINT32 hash = 0;

    count *= sizeof(void *)/sizeof(unsigned int);
    for (i = 0; i < count; i++)
        hash = (hash>>5) ^ (hash<<27) ^ ((unsigned int *)stack)[i];

    return hash;
}

static Memento_hashedST oom_hashed_st =
{
    NULL, /* next */
    0,    /* hash */
    0,    /* count */
    {NULL}/* trace[0] */
};

static Memento_hashedST *Memento_getHashedStacktrace(void)
{
    void *stack[MEMENTO_BACKTRACE_MAX];
    MEMENTO_UINT32 hash;
    int count, skip;
    Memento_hashedST **h;

#ifdef MEMENTO_STACKTRACE_METHOD
    count = Memento_getStacktrace(stack, &skip);
#else
    skip = 0;
    count = 0;
#endif

    count -= skip;
    hash = hashStackTrace(&stack[skip], count);
    while (1) {
        h = &memento.stacktraces[hash & 0xff];
        while (*h) {
            if ((*h)->hash == hash)
                break;
            h = &(*h)->next;
        }
        if ((*h) == NULL)
            break; /* No match, fall through to make a new one. */
        if (count == (*h)->count &&
            memcmp((*h)->trace, &stack[skip], sizeof(void *) * count) == 0)
            return (*h); /* We match! Reuse this one. */
        /* Hash collision. */
        hash++;
        memento.hashCollisions++;
    }

    (*h) = MEMENTO_UNDERLYING_MALLOC(sizeof(Memento_hashedST) + sizeof(void *) * (count-1));
    if (*h == NULL)
        return &oom_hashed_st;

    (*h)->next = NULL;
    (*h)->hash = hash;
    (*h)->count = count;
    memcpy(&(*h)->trace[0], &stack[skip], count * sizeof(void *));

    return *h;
}

static void Memento_showHashedStacktrace(Memento_hashedST *trace)
{
    if (trace == NULL)
        return;

    Memento_showStacktrace(&trace->trace[0], trace->count);
}

static void Memento_storeDetails(Memento_BlkHeader *head, int type, Memento_hashedST *st)
{
    Memento_BlkDetails *details;

    if (head == NULL)
        return;

    details = MEMENTO_UNDERLYING_MALLOC(sizeof(*details));
    if (details == NULL)
        return;

    details->type = (char)type;
    details->sequence = memento.sequence;
    details->next = NULL;
    details->trace = st;
    VALGRIND_MAKE_MEM_DEFINED(&head->details_tail, sizeof(head->details_tail));
    *head->details_tail = details;
    head->details_tail = &details->next;
    VALGRIND_MAKE_MEM_NOACCESS(&head->details_tail, sizeof(head->details_tail));
}
#endif

void Memento_showHash(MEMENTO_UINT32 hash)
{
#ifdef MEMENTO_DETAILS
    Memento_hashedST *h;

    h = memento.stacktraces[hash & 0xff];
    while (h) {
        if (h->hash == hash)
            break;
        h = h->next;
    }

    Memento_showHashedStacktrace(h);
#endif
}

static void Memento_bt_internal(int skip2)
{
#ifdef MEMENTO_STACKTRACE_METHOD
    void *stack[MEMENTO_BACKTRACE_MAX];
    int count;
    int skip;

    count = Memento_getStacktrace(stack, &skip);
    Memento_showStacktrace(&stack[skip+skip2], count-skip-skip2);
#endif
}

void (Memento_bt)(void)
{
    Memento_bt_internal(0);
}

static int Memento_checkAllMemoryLocked(void);

void Memento_breakpoint(void)
{
    /* A handy externally visible function for breakpointing */
#if 0 /* Enable this to force automatic breakpointing */
#ifndef NDEBUG
#ifdef _MSC_VER
    __asm int 3;
#endif
#endif
#endif
}

static void Memento_init(void);

#define MEMENTO_LOCK() \
do { if (!memento.inited) Memento_init(); MEMENTO_DO_LOCK(); } while (0)

#define MEMENTO_UNLOCK() \
do { MEMENTO_DO_UNLOCK(); } while (0)

/* Do this as a macro to prevent another level in the callstack,
 * which is annoying while stepping. */
#define Memento_breakpointLocked() \
do { MEMENTO_UNLOCK(); Memento_breakpoint(); MEMENTO_LOCK(); } while (0)

/* Move the given node to the root of the tree, by
 * performing a series of the following rotations.
 * The key observation here is that all these
 * rotations preserve the ordering of the tree, and
 * result in 'x' getting higher.
 *
 * Case 1:   z          x           Case 1b:   z                   x
 *          # #        # #                    # #                 # #
 *         y   D      A   y                  A   y               y   D
 *        # #     =>     # #                    # #     =>      # #
 *       x   C          B   z                  B   x           z   C
 *      # #                # #                    # #         # #
 *     A   B              C   D                  C   D       A   B
 *
 * Case 2:   z             x        Case 2b:   z                  x
 *          # #          ## ##                # #               ## ##
 *         y   D        y     z              A   y             z     y
 *        # #     =>   # #   # #                # #     =>    # #   # #
 *       A   x        A   B C   D              x   D         A   B C   D
 *          # #                               # #
 *         B   C                             B   C
 *
 * Case 3:   y          x           Case 3b:  y                  x
 *          # #        # #                   # #                # #
 *         x   C  =>  A   y                 A   x       =>     y   C
 *        # #            # #                   # #            # #
 *       A   B          B   C                 B   C          A   B
 */
static void
move_to_root(Memento_BlkHeader *x)
{
    Memento_BlkHeader *y, *z;

    if (x == NULL)
        return;

    VALGRIND_MAKE_MEM_DEFINED(x, sizeof(*x));
    while ((y = x->parent) != NULL) {
        VALGRIND_MAKE_MEM_DEFINED(y, sizeof(*y));
        if ((z = y->parent) != NULL) {
            VALGRIND_MAKE_MEM_DEFINED(z, sizeof(*z));
            x->parent = z->parent;
            if (x->parent) {
                VALGRIND_MAKE_MEM_DEFINED(x->parent, sizeof(*x->parent));
                if (x->parent->left == z)
                    x->parent->left = x;
                else
                    x->parent->right  = x;
                VALGRIND_MAKE_MEM_NOACCESS(x->parent, sizeof(*x->parent));
            }
            y->parent = x;
            /* Case 1, 1b, 2 or 2b */
            if (y->left == x) {
                /* Case 1 or 2b */
                if (z->left == y) {
                    /* Case 1 */
                    y->left = x->right;
                    if (y->left) {
                        VALGRIND_MAKE_MEM_DEFINED(y->left, sizeof(*y->left));
                        y->left->parent = y;
                        VALGRIND_MAKE_MEM_NOACCESS(y->left, sizeof(*y->left));
                    }
                    z->left = y->right;
                    if (z->left) {
                        VALGRIND_MAKE_MEM_DEFINED(z->left, sizeof(*z->left));
                        z->left->parent = z;
                        VALGRIND_MAKE_MEM_NOACCESS(z->left, sizeof(*z->left));
                    }
                    y->right = z;
                    z->parent = y;
                } else {
                    /* Case 2b */
                    z->right = x->left;
                    if (z->right) {
                        VALGRIND_MAKE_MEM_DEFINED(z->right, sizeof(*z->right));
                        z->right->parent = z;
                        VALGRIND_MAKE_MEM_NOACCESS(z->right, sizeof(*z->right));
                    }
                    y->left = x->right;
                    if (y->left) {
                        VALGRIND_MAKE_MEM_DEFINED(y->left, sizeof(*y->left));
                        y->left->parent = y;
                        VALGRIND_MAKE_MEM_NOACCESS(y->left, sizeof(*y->left));
                    }
                    x->left = z;
                    z->parent = x;
                }
                x->right      = y;
            } else {
                /* Case 2 or 1b */
                if (z->left == y) {
                    /* Case 2 */
                    y->right = x->left;
                    if (y->right) {
                        VALGRIND_MAKE_MEM_DEFINED(y->right, sizeof(*y->right));
                        y->right->parent = y;
                        VALGRIND_MAKE_MEM_NOACCESS(y->right, sizeof(*y->right));
                    }
                    z->left = x->right;
                    if (z->left) {
                        VALGRIND_MAKE_MEM_DEFINED(z->left, sizeof(*z->left));
                        z->left->parent = z;
                        VALGRIND_MAKE_MEM_NOACCESS(z->left, sizeof(*z->left));
                    }
                    x->right = z;
                    z->parent = x;
                } else {
                    /* Case 1b */
                    z->right = y->left;
                    if (z->right) {
                        VALGRIND_MAKE_MEM_DEFINED(z->right, sizeof(*z->right));
                        z->right->parent = z;
                        VALGRIND_MAKE_MEM_NOACCESS(z->right, sizeof(*z->right));
                    }
                    y->right = x->left;
                    if (y->right) {
                        VALGRIND_MAKE_MEM_DEFINED(y->right, sizeof(*y->right));
                        y->right->parent = y;
                        VALGRIND_MAKE_MEM_NOACCESS(y->right, sizeof(*y->right));
                    }
                    y->left = z;
                    z->parent = y;
                }
                x->left = y;
            }
            VALGRIND_MAKE_MEM_NOACCESS(z, sizeof(*z));
        } else {
            /* Case 3 or 3b */
            x->parent = NULL;
            y->parent = x;
            if (y->left == x) {
                /* Case 3 */
                y->left = x->right;
                if (y->left) {
                    VALGRIND_MAKE_MEM_DEFINED(y->left, sizeof(*y->left));
                    y->left->parent = y;
                    VALGRIND_MAKE_MEM_NOACCESS(y->left, sizeof(*y->left));
                }
                x->right = y;
            } else {
                /* Case 3b */
                y->right = x->left;
                if (y->right) {
                    VALGRIND_MAKE_MEM_DEFINED(y->right, sizeof(*y->right));
                    y->right->parent = y;
                    VALGRIND_MAKE_MEM_NOACCESS(y->right, sizeof(*y->right));
                }
                x->left = y;
            }
        }
        VALGRIND_MAKE_MEM_NOACCESS(y, sizeof(*y));
    }
    VALGRIND_MAKE_MEM_NOACCESS(x, sizeof(*x));
}

static void Memento_removeBlockSplay(Memento_Blocks    *blks,
                                     Memento_BlkHeader *b)
{
    Memento_BlkHeader *replacement;

    VALGRIND_MAKE_MEM_DEFINED(b, sizeof(*b));
    if (b->left == NULL)
    {
        /* At most one child - easy */
        replacement = b->right;
    }
    else if (b->right == NULL)
    {
        /* Strictly one child - easy */
        replacement = b->left;
    }
    else
    {
        /* 2 Children - tricky */
        /* Find in-order predecessor to b */
        replacement = b->left;
        VALGRIND_MAKE_MEM_DEFINED(replacement, sizeof(*replacement));
        while (replacement->right)
        {
            Memento_BlkHeader *o = replacement;
            replacement = o->right;
            VALGRIND_MAKE_MEM_DEFINED(replacement, sizeof(*replacement));
            VALGRIND_MAKE_MEM_NOACCESS(o, sizeof(*o));
        }
        /* Remove replacement - easy as just one child */
        (void)Memento_removeBlockSplay(NULL, replacement);
        /* Replace b with replacement */
        VALGRIND_MAKE_MEM_DEFINED(b, sizeof(*b));
        if (b->left) {
            VALGRIND_MAKE_MEM_DEFINED(b->left, sizeof(*b->left));
            b->left->parent = replacement;
            VALGRIND_MAKE_MEM_NOACCESS(b->left, sizeof(*b->left));
        }
        VALGRIND_MAKE_MEM_DEFINED(b->right, sizeof(*b->right));
        b->right->parent = replacement;
        VALGRIND_MAKE_MEM_NOACCESS(b->right, sizeof(*b->right));
        VALGRIND_MAKE_MEM_DEFINED(replacement, sizeof(*replacement));
        replacement->left = b->left;
        replacement->right = b->right;
    }
    if (b->parent)
    {
        VALGRIND_MAKE_MEM_DEFINED(b->parent, sizeof(*b->parent));
        if (b->parent->left == b)
            b->parent->left = replacement;
        else
            b->parent->right = replacement;
            VALGRIND_MAKE_MEM_NOACCESS(b->parent, sizeof(*b->parent));
    } else {
        VALGRIND_MAKE_MEM_DEFINED(&blks->top, sizeof(blks->top));
        blks->top = replacement;
        VALGRIND_MAKE_MEM_NOACCESS(&blks->top, sizeof(blks->top));
    }
    if (replacement)
    {
        VALGRIND_MAKE_MEM_DEFINED(replacement, sizeof(*replacement));
        replacement->parent = b->parent;
        VALGRIND_MAKE_MEM_NOACCESS(replacement, sizeof(*replacement));
    }
    VALGRIND_MAKE_MEM_NOACCESS(b, sizeof(*b));
}

static void Memento_addBlockSplay(Memento_Blocks    *blks,
                                  Memento_BlkHeader *b)
{
    Memento_BlkHeader *parent = NULL;
    Memento_BlkHeader **n = &blks->top;

    /* Walk down, looking for a place to put b. */
    VALGRIND_MAKE_MEM_DEFINED(&blks->top, sizeof(blks->top));
    while (*n != NULL) {
        Memento_BlkHeader *o = parent;
        VALGRIND_MAKE_MEM_DEFINED(*n, sizeof(**n));
        parent = *n;
        if (o) VALGRIND_MAKE_MEM_NOACCESS(o, sizeof(*o));
        VALGRIND_MAKE_MEM_DEFINED(parent, sizeof(*parent));
        if (b < parent)
            n = &parent->left;
        else
            n = &parent->right;
    }
    /* Place b */
    *n = b;
    if (parent) VALGRIND_MAKE_MEM_NOACCESS(parent, sizeof(*parent));
    b->parent = parent;
    b->left = NULL;
    b->right = NULL;
    /* Now perform the splay magic */
    move_to_root(b);
    /* This always leaves b at the top. */
    blks->top = b;
    VALGRIND_MAKE_MEM_DEFINED(b, sizeof(*b));
    b->parent = NULL;
    VALGRIND_MAKE_MEM_NOACCESS(b, sizeof(*b));
    VALGRIND_MAKE_MEM_NOACCESS(&blks->top, sizeof(blks->top));
}

static void Memento_addBlockHead(Memento_Blocks    *blks,
                                 Memento_BlkHeader *b,
                                 int                type)
{
    Memento_addBlockSplay(blks, b);
    if (blks->tail == NULL)
        blks->tail = b;
    VALGRIND_MAKE_MEM_DEFINED(b, sizeof(*b));
    b->next    = blks->head;
    b->prev    = NULL;
    if (blks->head)
    {
        VALGRIND_MAKE_MEM_DEFINED(&blks->head->prev, sizeof(blks->head->prev));
        blks->head->prev = b;
        VALGRIND_MAKE_MEM_NOACCESS(&blks->head->prev, sizeof(blks->head->prev));
    }
    blks->head = b;
#ifndef MEMENTO_LEAKONLY
    memset(b->preblk, MEMENTO_PREFILL, Memento_PreSize);
    memset(MEMBLK_POSTPTR(b), MEMENTO_POSTFILL, Memento_PostSize);
#endif
    VALGRIND_MAKE_MEM_NOACCESS(MEMBLK_POSTPTR(b), Memento_PostSize);
    if (type == 0) { /* malloc */
        VALGRIND_MAKE_MEM_UNDEFINED(MEMBLK_TOBLK(b), b->rawsize);
    } else if (type == 1) { /* free */
      VALGRIND_MAKE_MEM_NOACCESS(MEMBLK_TOBLK(b), b->rawsize);
    }
    VALGRIND_MAKE_MEM_NOACCESS(b, sizeof(Memento_BlkHeader));
}

static void Memento_addBlockTail(Memento_Blocks    *blks,
                                 Memento_BlkHeader *b,
                                 int                type)
{
    Memento_addBlockSplay(blks, b);
    VALGRIND_MAKE_MEM_DEFINED(&blks->tail, sizeof(Memento_BlkHeader *));
    if (blks->head == NULL)
        blks->head = b;
    VALGRIND_MAKE_MEM_DEFINED(b, sizeof(*b));
    b->prev = blks->tail;
    b->next = NULL;
    if (blks->tail) {
        VALGRIND_MAKE_MEM_DEFINED(&blks->tail->next, sizeof(blks->tail->next));
        blks->tail->next = b;
        VALGRIND_MAKE_MEM_NOACCESS(&blks->tail->next, sizeof(blks->tail->next));
    }
    blks->tail = b;
#ifndef MEMENTO_LEAKONLY
    memset(b->preblk, MEMENTO_PREFILL, Memento_PreSize);
    memset(MEMBLK_POSTPTR(b), MEMENTO_POSTFILL, Memento_PostSize);
#endif
    VALGRIND_MAKE_MEM_NOACCESS(MEMBLK_POSTPTR(b), Memento_PostSize);
    if (type == 0) { /* malloc */
        VALGRIND_MAKE_MEM_UNDEFINED(MEMBLK_TOBLK(b), b->rawsize);
    } else if (type == 1) { /* free */
      VALGRIND_MAKE_MEM_NOACCESS(MEMBLK_TOBLK(b), b->rawsize);
    }
    VALGRIND_MAKE_MEM_NOACCESS(b, sizeof(Memento_BlkHeader));
    VALGRIND_MAKE_MEM_NOACCESS(&blks->tail, sizeof(Memento_BlkHeader *));
}

typedef struct BlkCheckData {
    /* found holds some bits:
     * Bit 0 (1) -> At least one block has been checked.
     * Bit 1 (2) -> We have found an "Allocated block".
     * Bit 2 (4) -> We have found a "Freed block".
     * Bit 3 (8) -> Trigger a breakpoint on completion.
     */
    int found;
    int preCorrupt;
    int postCorrupt;
    int freeCorrupt;
    size_t index;
} BlkCheckData;

#ifndef MEMENTO_LEAKONLY
static int Memento_Internal_checkAllocedBlock(Memento_BlkHeader *b, void *arg)
{
    int             i;
    MEMENTO_UINT32 *ip;
    unsigned char  *p;
    BlkCheckData   *data = (BlkCheckData *)arg;

    ip = (MEMENTO_UINT32 *)(void *)(b->preblk);
    i = Memento_PreSize>>2;
    do {
        if (*ip++ != MEMENTO_PREFILL_UINT32)
            goto pre_corrupt;
    } while (--i);
    if (0) {
pre_corrupt:
        data->preCorrupt = 1;
    }
    /* Postfill may not be aligned, so have to be slower */
    p = MEMBLK_POSTPTR(b);
    i = Memento_PostSize-4;
    if ((intptr_t)p & 1)
    {
        if (*p++ != MEMENTO_POSTFILL)
            goto post_corrupt;
        i--;
    }
    if ((intptr_t)p & 2)
    {
        if (*(MEMENTO_UINT16 *)p != MEMENTO_POSTFILL_UINT16)
            goto post_corrupt;
        p += 2;
        i -= 2;
    }
    do {
        if (*(MEMENTO_UINT32 *)p != MEMENTO_POSTFILL_UINT32)
            goto post_corrupt;
        p += 4;
        i -= 4;
    } while (i >= 0);
    if (i & 2)
    {
        if (*(MEMENTO_UINT16 *)p != MEMENTO_POSTFILL_UINT16)
            goto post_corrupt;
        p += 2;
    }
    if (i & 1)
    {
        if (*p != MEMENTO_POSTFILL)
            goto post_corrupt;
    }
    if (0) {
post_corrupt:
        data->postCorrupt = 1;
    }
    if ((data->freeCorrupt | data->preCorrupt | data->postCorrupt) == 0) {
        b->lastCheckedOK = memento.sequence;
    }
    data->found |= 1;
    return 0;
}

static int Memento_Internal_checkFreedBlock(Memento_BlkHeader *b, void *arg)
{
    size_t         i;
    unsigned char *p;
    BlkCheckData  *data = (BlkCheckData *)arg;

    p = MEMBLK_TOBLK(b); /* p will always be aligned */
    i = b->rawsize;
    /* Attempt to speed this up by checking an (aligned) int at a time */
    if (i >= 4) {
        i -= 4;
        do {
            if (*(MEMENTO_UINT32 *)p != MEMENTO_FREEFILL_UINT32)
                goto mismatch4;
            p += 4;
            i -= 4;
        } while (i > 0);
        i += 4;
    }
    if (i & 2) {
        if (*(MEMENTO_UINT16 *)p != MEMENTO_FREEFILL_UINT16)
            goto mismatch;
        p += 2;
        i -= 2;
    }
    if (0) {
mismatch4:
        i += 4;
    }
mismatch:
    while (i) {
        if (*p++ != (unsigned char)MEMENTO_FREEFILL)
            break;
        i--;
    }
    if (i) {
        data->freeCorrupt = 1;
        data->index       = b->rawsize-i;
    }
    return Memento_Internal_checkAllocedBlock(b, arg);
}
#endif /* MEMENTO_LEAKONLY */

static void Memento_removeBlock(Memento_Blocks    *blks,
                                Memento_BlkHeader *b)
{
    Memento_removeBlockSplay(blks, b);
    VALGRIND_MAKE_MEM_DEFINED(b, sizeof(*b));
    if (b->next) {
        VALGRIND_MAKE_MEM_DEFINED(&b->next->prev, sizeof(b->next->prev));
        b->next->prev = b->prev;
        VALGRIND_MAKE_MEM_NOACCESS(&b->next->prev, sizeof(b->next->prev));
    }
    if (b->prev) {
        VALGRIND_MAKE_MEM_DEFINED(&b->prev->next, sizeof(b->prev->next));
        b->prev->next = b->next;
        VALGRIND_MAKE_MEM_NOACCESS(&b->prev->next, sizeof(b->prev->next));
    }
    if (blks->tail == b)
        blks->tail = b->prev;
    if (blks->head == b)
        blks->head = b->next;
    VALGRIND_MAKE_MEM_NOACCESS(b, sizeof(*b));
}

static void free_block(Memento_BlkHeader *head)
{
#ifdef MEMENTO_DETAILS
    Memento_BlkDetails *details = head->details;

    while (details)
    {
        Memento_BlkDetails *next = details->next;
        MEMENTO_UNDERLYING_FREE(details);
        details = next;
    }
#endif
    MEMENTO_UNDERLYING_FREE(head);
}

static int Memento_Internal_makeSpace(size_t space)
{
    /* If too big, it can never go on the freelist */
    if (space > MEMENTO_FREELIST_MAX_SINGLE_BLOCK)
        return 0;
    /* Pretend we added it on. */
    memento.freeListSize += space;
    /* Ditch blocks until it fits within our limit */
    while (memento.freeListSize > MEMENTO_FREELIST_MAX) {
        Memento_BlkHeader *head = memento.free.head;
        VALGRIND_MAKE_MEM_DEFINED(head, sizeof(*head));
        memento.free.head = head->next;
        memento.freeListSize -= MEMBLK_SIZE(head->rawsize);
        Memento_removeBlockSplay(&memento.free, head);
        VALGRIND_MAKE_MEM_DEFINED(head, sizeof(*head));
        free_block(head);
    }
    /* Make sure we haven't just completely emptied the free list */
    /* (This should never happen, but belt and braces... */
    if (memento.free.head == NULL)
        memento.free.tail = NULL;
    return 1;
}

static int Memento_appBlocks(Memento_Blocks *blks,
                             int             (*app)(Memento_BlkHeader *,
                                                    void *),
                             void           *arg)
{
    Memento_BlkHeader *head = blks->head;
    Memento_BlkHeader *next;
    int                result;
    while (head) {
        VALGRIND_MAKE_MEM_DEFINED(head, sizeof(Memento_BlkHeader));
        VALGRIND_MAKE_MEM_DEFINED(MEMBLK_TOBLK(head),
                                  head->rawsize + Memento_PostSize);
        result = app(head, arg);
        next = head->next;
        VALGRIND_MAKE_MEM_NOACCESS(MEMBLK_POSTPTR(head), Memento_PostSize);
        VALGRIND_MAKE_MEM_NOACCESS(head, sizeof(Memento_BlkHeader));
        if (result)
            return result;
        head = next;
    }
    return 0;
}

static Memento_BlkHeader *
find_enclosing_block(Memento_Blocks *blks,
                     void *addr,
                     int *flags)
{
    Memento_BlkHeader *blk;

    VALGRIND_MAKE_MEM_DEFINED(&blks->top, sizeof(blks->top));
    blk = blks->top;
    while (blk)
    {
        Memento_BlkHeader *oblk = blk;
        char *blkstart;
        char *blkend;
        VALGRIND_MAKE_MEM_DEFINED(blk, sizeof(Memento_BlkHeader));
        if (addr < (void *)oblk) {
            blk = blk->left;
            VALGRIND_MAKE_MEM_UNDEFINED(oblk, sizeof(Memento_BlkHeader));
            continue;
        }
        blkstart = (char *)MEMBLK_TOBLK(blk);
        blkend = &blkstart[blk->rawsize];
        if (addr >= (void *)(blkend + Memento_PostSize)) {
            blk = blk->right;
            VALGRIND_MAKE_MEM_UNDEFINED(oblk, sizeof(Memento_BlkHeader));
            continue;
        }
        if (flags) {
            if (((void *)blkstart <= addr) && (addr < (void *)blkend))
                *flags = 1;
            else if (((void *)blk <= addr) && (addr < (void *)blkstart))
                *flags = 2;
            else
                *flags = 3;
        }
        VALGRIND_MAKE_MEM_UNDEFINED(oblk, sizeof(Memento_BlkHeader));
        return blk;
    }
    return NULL;
}

#ifndef MEMENTO_LEAKONLY
/* Distrustful - check the block is a real one */
static int Memento_appBlockUser(Memento_Blocks    *blks,
                                int                (*app)(Memento_BlkHeader *,
                                                          void *),
                                void              *arg,
                                Memento_BlkHeader *b)
{
    int result;
    Memento_BlkHeader *head = find_enclosing_block(blks, b, NULL);
    if (head == NULL)
        return 0;

    VALGRIND_MAKE_MEM_DEFINED(head, sizeof(Memento_BlkHeader));
    VALGRIND_MAKE_MEM_DEFINED(MEMBLK_TOBLK(head),
                              head->rawsize + Memento_PostSize);
    result = app(head, arg);
    VALGRIND_MAKE_MEM_NOACCESS(MEMBLK_POSTPTR(head), Memento_PostSize);
    VALGRIND_MAKE_MEM_NOACCESS(head, sizeof(Memento_BlkHeader));
    return result;
}

static int Memento_appBlock(Memento_Blocks    *blks,
                            int                (*app)(Memento_BlkHeader *,
                                                      void *),
                            void              *arg,
                            Memento_BlkHeader *b)
{
    int result;
    (void)blks;
    VALGRIND_MAKE_MEM_DEFINED(b, sizeof(Memento_BlkHeader));
    VALGRIND_MAKE_MEM_DEFINED(MEMBLK_TOBLK(b),
                              b->rawsize + Memento_PostSize);
    result = app(b, arg);
    VALGRIND_MAKE_MEM_NOACCESS(MEMBLK_POSTPTR(b), Memento_PostSize);
    VALGRIND_MAKE_MEM_NOACCESS(b, sizeof(Memento_BlkHeader));
    return result;
}
#endif /* MEMENTO_LEAKONLY */

static int showBlock(Memento_BlkHeader *b, int space)
{
    int seq;
    VALGRIND_MAKE_MEM_DEFINED(b, sizeof(Memento_BlkHeader));
    fprintf(stderr, FMTP":(size=" FMTZ ",num=%d)",
            MEMBLK_TOBLK(b), (FMTZ_CAST)b->rawsize, b->sequence);
    if (b->label)
        fprintf(stderr, "%c(%s)", space, b->label);
    if (b->flags & Memento_Flag_KnownLeak)
        fprintf(stderr, "(Known Leak)");
    seq = b->sequence;
    VALGRIND_MAKE_MEM_NOACCESS(b, sizeof(Memento_BlkHeader));
    return seq;
}

static void blockDisplay(Memento_BlkHeader *b, int n)
{
    n++;
    while (n > 40)
    {
            fprintf(stderr, "*");
            n -= 40;
    }
    while(n > 0)
    {
        int i = n;
        if (i > 32)
            i = 32;
        n -= i;
        fprintf(stderr, "%s", &"                                "[32-i]);
    }
    showBlock(b, '\t');
    fprintf(stderr, "\n");
}

static int Memento_listBlock(Memento_BlkHeader *b,
                             void              *arg)
{
    size_t *counts = (size_t *)arg;
    blockDisplay(b, 0);
    counts[0]++;
    VALGRIND_MAKE_MEM_DEFINED(b, sizeof(Memento_BlkHeader));
    counts[1]+= b->rawsize;
    VALGRIND_MAKE_MEM_NOACCESS(b, sizeof(Memento_BlkHeader));
    return 0;
}

static void doNestedDisplay(Memento_BlkHeader *b,
                            int depth,
                            int include_known_leaks
                            )
{
    /* Try and avoid recursion if we can help it */
    do {
        Memento_BlkHeader *c = NULL;
        if (!include_known_leaks && (b->flags & Memento_Flag_KnownLeak))
            ;
        else
            blockDisplay(b, depth);
        VALGRIND_MAKE_MEM_DEFINED(b, sizeof(Memento_BlkHeader));
        if (b->sibling) {
            c = b->child;
            b = b->sibling;
        } else {
            b = b->child;
            depth++;
        }
        VALGRIND_MAKE_MEM_NOACCESS(b, sizeof(Memento_BlkHeader));
        if (c)
            doNestedDisplay(c, depth+1, include_known_leaks);
    } while (b);
}

static int ptrcmp(const void *a_, const void *b_)
{
    const char **a = (const char **)a_;
    const char **b = (const char **)b_;
    return (int)(*a-*b);
}

static
int Memento_listBlocksNested(int include_known_leaks)
{
    int count, i, count_excluding_known_leaks, count_known_leaks;
    size_t size;
    size_t size_excluding_known_leaks, size_known_leaks;
    Memento_BlkHeader *b, *prev;
    void **blocks, *minptr, *maxptr;
    intptr_t mask;

    /* Count the blocks */
    count = 0;
    size = 0;
    count_excluding_known_leaks = 0;
    size_excluding_known_leaks = 0;
    count_known_leaks = 0;
    size_known_leaks = 0;
    for (b = memento.used.head; b; b = b->next) {
        VALGRIND_MAKE_MEM_DEFINED(b, sizeof(*b));
        count++;
        size += b->rawsize;
        if (b->flags & Memento_Flag_KnownLeak) {
            count_known_leaks += 1;
            size_known_leaks += b->rawsize;
        }
        else {
            count_excluding_known_leaks += 1;
            size_excluding_known_leaks += b->rawsize;
        }
    }

    if (memento.showDetailedBlocks)
    {
        /* Make our block list */
        blocks = MEMENTO_UNDERLYING_MALLOC(sizeof(void *) * count);
        if (blocks == NULL)
            return 1;

        /* Populate our block list */
        b = memento.used.head;
        minptr = maxptr = MEMBLK_TOBLK(b);
        mask = (intptr_t)minptr;
        for (i = 0; b; b = b->next, i++) {
            void *p = MEMBLK_TOBLK(b);
            mask &= (intptr_t)p;
            if (p < minptr)
                minptr = p;
            if (p > maxptr)
                maxptr = p;
            blocks[i] = p;
            b->flags &= ~Memento_Flag_HasParent;
            b->child   = NULL;
            b->sibling = NULL;
            b->prev    = NULL; /* parent */
        }
        qsort(blocks, count, sizeof(void *), ptrcmp);

        /* Now, calculate tree */
        for (b = memento.used.head; b; b = b->next) {
            char *p = MEMBLK_TOBLK(b);
            size_t end = (b->rawsize < MEMENTO_PTRSEARCH ? b->rawsize : MEMENTO_PTRSEARCH);
            size_t z;
            VALGRIND_MAKE_MEM_DEFINED(p, end);
            if (end > sizeof(void *)-1)
                end -= sizeof(void *)-1;
            else
                end = 0;
            for (z = MEMENTO_SEARCH_SKIP; z < end; z += sizeof(void *)) {
                void *q = *(void **)(&p[z]);
                void **r;

                /* Do trivial checks on pointer */
                if ((mask & (intptr_t)q) != mask || q < minptr || q > maxptr)
                    continue;

                /* Search for pointer */
                r = bsearch(&q, blocks, count, sizeof(void *), ptrcmp);
                if (r) {
                    /* Found child */
                    Memento_BlkHeader *child = MEMBLK_FROMBLK(*r);
                    Memento_BlkHeader *parent;

                    /* We're assuming tree structure, not graph - ignore second
                     * and subsequent pointers. */
                    if (child->prev != NULL) /* parent */
                        continue;
                    if (child->flags & Memento_Flag_HasParent)
                        continue;

                    /* Not interested in pointers to ourself! */
                    if (child == b)
                        continue;

                    /* We're also assuming acyclicness here. If this is one of
                     * our parents, ignore it. */
                    parent = b->prev; /* parent */
                    while (parent != NULL && parent != child)
                        parent = parent->prev; /* parent */
                    if (parent == child)
                        continue;

                    child->sibling = b->child;
                    b->child = child;
                    child->prev = b; /* parent */
                    child->flags |= Memento_Flag_HasParent;
                }
            }
        }

        /* Now display with nesting */
        for (b = memento.used.head; b; b = b->next) {
            if ((b->flags & Memento_Flag_HasParent) == 0)
                doNestedDisplay(b, 0, include_known_leaks);
        }

        MEMENTO_UNDERLYING_FREE(blocks);

        /* Now put the blocks back for valgrind, and restore the prev
         * and magic values. */
        prev = NULL;
        for (b = memento.used.head; b;) {
            Memento_BlkHeader *next = b->next;
            b->prev = prev;
            b->child = MEMENTO_CHILD_MAGIC;
            b->sibling = MEMENTO_SIBLING_MAGIC;
            prev = b;
            VALGRIND_MAKE_MEM_NOACCESS(b, sizeof(*b));
            b = next;
        }
    }

    fprintf(stderr, " Total number of blocks = %d\n", count);
    fprintf(stderr, " Total size of blocks = "FMTZ"\n", (FMTZ_CAST)size);
    if (!include_known_leaks) {
        fprintf(stderr, " Excluding known leaks:\n");
        fprintf(stderr, "   Number of blocks = %d\n", count_excluding_known_leaks);
        fprintf(stderr, "   Size of blocks = "FMTZ"\n", (FMTZ_CAST) size_excluding_known_leaks);
        fprintf(stderr, " Known leaks:\n");
        fprintf(stderr, "   Number of blocks = %d\n", count_known_leaks);
        fprintf(stderr, "   Size of blocks = "FMTZ"\n", (FMTZ_CAST) size_known_leaks);
    }

    return 0;
}

static void Memento_listBlocksInternal(int include_known_leaks)
{
    MEMENTO_LOCK();
    if (include_known_leaks)
        fprintf(stderr, "Allocated blocks:\n");
    else
        fprintf(stderr, "Allocated blocks (excluding known leaks):\n");
    if (Memento_listBlocksNested(include_known_leaks))
    {
        size_t counts[2];
        counts[0] = 0;
        counts[1] = 0;
        Memento_appBlocks(&memento.used, Memento_listBlock, &counts[0]);
        fprintf(stderr, " Total number of blocks = "FMTZ"\n", (FMTZ_CAST)counts[0]);
        fprintf(stderr, " Total size of blocks = "FMTZ"\n", (FMTZ_CAST)counts[1]);
    }
    MEMENTO_UNLOCK();
}

void Memento_listBlocks()
{
    Memento_listBlocksInternal(1 /*include_known_leaks*/);
}

static int Memento_listNewBlock(Memento_BlkHeader *b,
                                void              *arg)
{
    if (b->flags & Memento_Flag_OldBlock)
        return 0;
    b->flags |= Memento_Flag_OldBlock;
    return Memento_listBlock(b, arg);
}

void Memento_listNewBlocks(void)
{
    size_t counts[2];
    MEMENTO_LOCK();
    counts[0] = 0;
    counts[1] = 0;
    fprintf(stderr, "Blocks allocated and still extant since last list:\n");
    Memento_appBlocks(&memento.used, Memento_listNewBlock, &counts[0]);
    fprintf(stderr, "  Total number of blocks = "FMTZ"\n", (FMTZ_CAST)counts[0]);
    fprintf(stderr, "  Total size of blocks = "FMTZ"\n", (FMTZ_CAST)counts[1]);
    MEMENTO_UNLOCK();
}

typedef struct
{
    size_t counts[2];
    unsigned int phase;
} phased_t;

static int Memento_listPhasedBlock(Memento_BlkHeader *b,
                                   void              *arg)
{
    phased_t *phase = (phased_t *)arg;
    if ((b->flags & phase->phase) == 0)
        return 0;
    b->flags = (b->flags & ~Memento_Flag_PhaseMask) | ((b->flags >> 1) & Memento_Flag_PhaseMask);
    return Memento_listBlock(b, arg);
}

static int Memento_listNewPhasedBlock(Memento_BlkHeader *b,
                                      void              *arg)
{
    if ((b->flags & Memento_Flag_PhaseMask) != 0)
        return 0;
    b->flags |= Memento_Flag_LastPhase;
    return Memento_listBlock(b, arg);
}

static int Memento_startPhasing(Memento_BlkHeader *b,
                                void              *arg)
{
    b->flags |= *(int *)arg;
    return 0;
}

/* On the first call to this, we mark all blocks with the
 * lowest 'phase' bit, (call this phase m) so they will
 * never be reported.
 *
 * On subsequent calls, we:
 *   for (n = m-1; n > 0; n--)
 *     report all blocks in phase n, moving them to n+1.
 *   report all new blocks, and place them in phase 0.
 *
 * The upshot of this is that if you call Memento_listPhasedBlocks()
 * at a given point in the code, then you can watch for how long blocks
 * live between each time the code reaches that point.
 *
 * This is basically like Memento_listNewBlocks(), but allows for
 * the fact that sometimes blocks are freed just after the call.
 */
void Memento_listPhasedBlocks(void)
{
    phased_t phase;
    int num = 0;
    MEMENTO_LOCK();
    phase.phase = Memento_Flag_LastPhase;
    while ((phase.phase>>1) & Memento_Flag_PhaseMask)
        num++, phase.phase >>= 1;
    if (memento.phasing == 0)
    {
        fprintf(stderr, "Commencing Phasing:\n");
        memento.phasing = 1;
        Memento_appBlocks(&memento.used, Memento_startPhasing, &phase.phase);
    } else {
        phase.phase <<= 1;
        do
        {
            phase.counts[0] = 0;
            phase.counts[1] = 0;
            fprintf(stderr, "Blocks allocated and still extant: In phase %d (%x):\n", num, phase.phase);
            Memento_appBlocks(&memento.used, Memento_listPhasedBlock, &phase);
            fprintf(stderr, "  Total number of blocks = "FMTZ"\n", (FMTZ_CAST)phase.counts[0]);
            fprintf(stderr, "  Total size of blocks = "FMTZ"\n", (FMTZ_CAST)phase.counts[1]);
            phase.phase = phase.phase<<1;
            num--;
        }
        while (phase.phase != 0);
        phase.counts[0] = 0;
        phase.counts[1] = 0;
        fprintf(stderr, "Blocks allocated and still extant: In phase 0:\n");
        Memento_appBlocks(&memento.used, Memento_listNewPhasedBlock, &phase);
        fprintf(stderr, "  Total number of blocks = "FMTZ"\n", (FMTZ_CAST)phase.counts[0]);
        fprintf(stderr, "  Total size of blocks = "FMTZ"\n", (FMTZ_CAST)phase.counts[1]);
    }
    MEMENTO_UNLOCK();
}

static void Memento_endStats(void)
{
    fprintf(stderr, "Total memory malloced = "FMTZ" bytes\n", (FMTZ_CAST)memento.totalAlloc);
    fprintf(stderr, "Peak memory malloced = "FMTZ" bytes\n", (FMTZ_CAST)memento.peakAlloc);
    fprintf(stderr, FMTZ" mallocs, "FMTZ" frees, "FMTZ" reallocs\n", (FMTZ_CAST)memento.numMallocs,
            (FMTZ_CAST)memento.numFrees, (FMTZ_CAST)memento.numReallocs);
    fprintf(stderr, "Average allocation size "FMTZ" bytes\n", (FMTZ_CAST)
            (memento.numMallocs != 0 ? memento.totalAlloc/memento.numMallocs: 0));
#ifdef MEMENTO_DETAILS
    if (memento.hashCollisions)
        fprintf(stderr, "%d hash collisions\n", memento.hashCollisions);
#endif
}

void Memento_stats(void)
{
    MEMENTO_LOCK();
    fprintf(stderr, "Current memory malloced = "FMTZ" bytes\n", (FMTZ_CAST)memento.alloc);
    Memento_endStats();
    MEMENTO_UNLOCK();
}

#ifdef MEMENTO_DETAILS
static int showInfo(Memento_BlkHeader *b, void *arg)
{
    Memento_BlkDetails *details;

    int include_known_leaks = (arg) ? *(int*) arg : 1;

    fprintf(stderr, FMTP":(size="FMTZ",num=%d)",
            MEMBLK_TOBLK(b), (FMTZ_CAST)b->rawsize, b->sequence);
    if (b->label)
        fprintf(stderr, " (%s)", b->label);
    if (b->flags & Memento_Flag_KnownLeak)
        fprintf(stderr, "(Known Leak)");
    fprintf(stderr, "\nEvents:\n");

    for (details = b->details; details; details = details->next)
    {
        if (memento.hideMultipleReallocs &&
            details->type == Memento_EventType_realloc &&
            details->next &&
            details->next->type == Memento_EventType_realloc) {
            continue;
        }
        fprintf(stderr, "  Event %d (%s)\n", details->sequence, eventType[(int)details->type]);
        if (memento.hideRefChangeBacktraces && (
                details->type == Memento_EventType_takeRef
                || details->type == Memento_EventType_dropRef))
            continue;
        if (!include_known_leaks && (b->flags & Memento_Flag_KnownLeak))
            continue;
        Memento_showHashedStacktrace(details->trace);
        if (memento.showDetailedBlocks > 0) {
            memento.showDetailedBlocks -= 1;
            if (memento.showDetailedBlocks == 0) {
                fprintf(stderr, "Stopping display of block details because memento.showDetailedBlocks is now zero.\n");
                return 1;
            }
        }
    }
    return 0;
}
#endif

static void Memento_listBlockInfoInternal(int include_known_leaks)
{
#ifdef MEMENTO_DETAILS
    MEMENTO_LOCK();
    fprintf(stderr, "Details of allocated blocks:\n");
    Memento_appBlocks(&memento.used, showInfo, &include_known_leaks);
    MEMENTO_UNLOCK();
#endif
}

void Memento_listBlockInfo(void)
{
    Memento_listBlockInfoInternal(1 /*include_known_leaks*/);
}

void Memento_blockInfo(void *p)
{
#ifdef MEMENTO_DETAILS
    Memento_BlkHeader *blk;
    MEMENTO_LOCK();
    blk = find_enclosing_block(&memento.used, p, NULL);
    if (blk == NULL)
        blk = find_enclosing_block(&memento.free, p, NULL);
    if (blk)
        showInfo(blk, NULL);
    MEMENTO_UNLOCK();
#endif
}

static int Memento_nonLeakBlocksLeaked(void)
{
    Memento_BlkHeader *blk = memento.used.head;
    while (blk)
    {
        Memento_BlkHeader *next;
        int leaked;
        VALGRIND_MAKE_MEM_DEFINED(blk, sizeof(*blk));
        leaked = ((blk->flags & Memento_Flag_KnownLeak) == 0);
        next = blk->next;
        VALGRIND_MAKE_MEM_DEFINED(blk, sizeof(*blk));
        if (leaked)
            return 1;
        blk = next;
    }
    return 0;
}

void Memento_fin(void)
{
    int leaked = 0;
    Memento_checkAllMemory();
    if (!memento.segv)
    {
        Memento_endStats();
        if (Memento_nonLeakBlocksLeaked()) {
            Memento_listBlocksInternal(0 /*include_known_leaks*/);
#ifdef MEMENTO_DETAILS
            fprintf(stderr, "\n");
            if (memento.showDetailedBlocks)
                Memento_listBlockInfoInternal(0 /*include_known_leaks*/);
#endif
            Memento_breakpoint();
            leaked = 1;
        }
    }
    if (memento.squeezing) {
        if (memento.pattern == 0)
            fprintf(stderr, "Memory squeezing @ %d complete%s\n", memento.squeezeAt, memento.segv ? " (with SEGV)" : (leaked ? " (with leaks)" : ""));
        else
            fprintf(stderr, "Memory squeezing @ %d (%d) complete%s\n", memento.squeezeAt, memento.pattern, memento.segv ? " (with SEGV)" : (leaked ? " (with leaks)" : ""));
    } else if (memento.segv) {
        fprintf(stderr, "Memento completed (with SEGV)\n");
    }
    if (memento.failing)
    {
        fprintf(stderr, "MEMENTO_FAILAT=%d\n", memento.failAt);
        fprintf(stderr, "MEMENTO_PATTERN=%d\n", memento.pattern);
    }
    if (memento.nextFailAt != 0)
    {
        fprintf(stderr, "MEMENTO_NEXTFAILAT=%d\n", memento.nextFailAt);
        fprintf(stderr, "MEMENTO_NEXTPATTERN=%d\n", memento.nextPattern);
    }
    if (Memento_nonLeakBlocksLeaked() && memento.abortOnLeak) {
        fprintf(stderr, "Calling abort() because blocks were leaked and MEMENTO_ABORT_ON_LEAK is set.\n");
        abort();
    }
}

/* Reads number from <text> using strtol().
 *
 * Params:
 *     text:
 *         text to read.
 *     out:
 *         pointer to output value.
 *     relative:
 *         *relative set to 1 if <text> starts with '+' or '-', else set to 0.
 *     end:
 *         *end is set to point to next unread character after number.
 *
 * Returns 0 on success, else -1.
 */
static int read_number(const char *text, int *out, int *relative, char **end)
{
    if (text[0] == '+' || text[0] == '-')
        *relative = 1;
    else
        *relative = 0;
    errno = 0;
    *out = (int)strtol(text, end, 0 /*base*/);
    if (errno || *end == text)
    {
        fprintf(stderr, "Failed to parse number at start of '%s'.\n", text);
        return -1;
    }
    if (0)
         fprintf(stderr, "text='%s': *out=%i *relative=%i\n",
                 text, *out, *relative);
    return 0;
}

/* Reads number plus optional delta value from <text>.
 *
 * Evaluates <number> or <number>[+|-<delta>]. E.g. text='1234+2' sets *out=1236,
 * text='1234-1' sets *out=1233.
 *
 * Params:
 *     text:
 *         text to read.
 *     out:
 *         pointer to output value.
 *     end:
 *         *end is set to point to next unread character after number.
 *
 * Returns 0 on success, else -1.
 */
static int read_number_delta(const char *text, int *out, char **end)
{
    int e;
    int relative;

    e = read_number(text, out, &relative, end);
    if (e)
        return e;
    if (relative) {
        fprintf(stderr, "Base number should not start with '+' or '-' at start of '%s'.\n",
                text);
        return -1;
    }
    if (*end) {
        if (**end == '-' || **end == '+') {
            int delta;
            e = read_number(*end, &delta, &relative, end);
            if (e)
                return e;
            *out += delta;
        }
    }
    if (0) fprintf(stderr, "text='%s': *out=%i\n", text, *out);

    return 0;
}

/* Reads range.
 *
 * E.g.:
 *     text='115867-2' sets *begin=115865 *end=115866.
 *     text='115867-1..+3' sets *begin=115866 *end=115869.
 *
 * Supported patterns for text:
 *     <range>
 *         <value>             - returns *begin=value *end=*begin+1.
 *         <value1>..<value2>  - returns *begin=value1 *end=value2.
 *         <value>..+<number>  - returns *begin=value *end=*begin+number.
 *     <value>
 *         <number>
 *         <number>+<number>
 *         <number>-<number>
 *
 *     <number>: [0-9]+
 *
 * If not specified, *end defaults to *begin+1.
 *
 * Returns 0 on success, else -1, with *string_end pointing to first unused
 * character.
 */
static int read_number_range(const char *text, int *begin, int *end, char **string_end)
{
    int e;
    e = read_number_delta(text, begin, string_end);
    if (e)
        return e;
    if (string_end && (*string_end)[0] == '.' && (*string_end)[1] == '.') {
        int relative;
        e = read_number((*string_end) + 2, end, &relative, string_end);
        if (e)
            return e;
        if (relative)
            *end += *begin;
    } else {
        *end = *begin + 1;
    }
    if (*end < *begin) {
        fprintf(stderr, "Range %i..%i has negative extent, at start of '%s'.\n",
                *begin, *end, text);
        return -1;
    }
    if (0) fprintf(stderr, "text='%s': *begin=%i *end=%i\n", text, *begin, *end);

    return 0;
}

/* Format: <range>[,<range>]+
 *
 * For description of <range>, see read_number_range() above.
 *
 * E.g.:
 *     MEMENTO_SQUEEZES=1234-2..+4,2345,2350..+2
 */
static int Memento_add_squeezes(const char *text)
{
    int e = 0;
    for(;;) {
        int     begin;
        int     end;
        char   *string_end;
        if (!*text)
            break;
        e = read_number_range(text, &begin, &end, &string_end);
        if (e)
            break;
        if (*string_end && *string_end != ',') {
            fprintf(stderr, "Expecting comma at start of '%s'.\n", string_end);
            e = -1;
            break;
        }
        fprintf(stderr, "Adding squeeze range %i..%i.\n",
                begin, end);
        memento.squeezes_num += 1;
        memento.squeezes = MEMENTO_UNDERLYING_REALLOC(
                memento.squeezes,
                memento.squeezes_num * sizeof(*memento.squeezes)
                );
        if (!memento.squeezes) {
            fprintf(stderr, "Failed to allocate memory for memento.squeezes_num=%i\n",
                    memento.squeezes_num);
            e = -1;
            break;
        }
        memento.squeezes[memento.squeezes_num-1].begin = begin;
        memento.squeezes[memento.squeezes_num-1].end = end;

        if (*string_end == 0)
            break;
        text = string_end + 1;
    }

    return e;
}

#if defined(_WIN32) || defined(_WIN64)
static int Memento_fin_win(void)
{
    if (memento.atexitFin)
        Memento_fin();
    return 0;
}
#else
static void Memento_fin_unix(void)
{
    if (memento.atexitFin)
        Memento_fin();
}
#endif

static void Memento_init(void)
{
    char *env;
    memset(&memento, 0, sizeof(memento));
    memento.inited    = 1;
    memento.used.head = NULL;
    memento.used.tail = NULL;
    memento.free.head = NULL;
    memento.free.tail = NULL;
    memento.sequence  = 0;
    memento.countdown = 1024;
    memento.squeezes  = NULL;
    memento.squeezes_num = 0;
    memento.squeezes_pos = 0;
    memento.backtraceLimitFnnames = NULL;
    memento.backtraceLimitFnnamesNum = 0;

    env = getenv("MEMENTO_FAILAT");
    memento.failAt = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_BREAKAT");
    memento.breakAt = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_PARANOIA");
    memento.paranoia = (env ? atoi(env) : 0);
    if (memento.paranoia == 0)
        memento.paranoia = -1024;

    env = getenv("MEMENTO_PARANOIDAT");
    memento.paranoidAt = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_SQUEEZEAT");
    memento.squeezeAt = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_PATTERN");
    memento.pattern = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_SHOW_DETAILED_BLOCKS");
    memento.showDetailedBlocks = (env ? atoi(env) : -1);

    env = getenv("MEMENTO_HIDE_MULTIPLE_REALLOCS");
    memento.hideMultipleReallocs = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_HIDE_REF_CHANGE_BACKTRACES");
    memento.hideRefChangeBacktraces = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_ABORT_ON_LEAK");
    memento.abortOnLeak = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_ABORT_ON_CORRUPTION");
    memento.abortOnCorruption = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_SQUEEZES");
    if (env) {
        int e;
        fprintf(stderr, "Parsing squeeze ranges in MEMENTO_SQUEEZES=%s\n", env);
        e = Memento_add_squeezes(env);
        if (e) {
            fprintf(stderr, "Failed to parse MEMENTO_SQUEEZES=%s\n", env);
            exit(1);
        }
    }

    env = getenv("MEMENTO_MAXMEMORY");
    memento.maxMemory = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_VERBOSE");
    memento.verbose = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_IGNORENEWDELETE");
    memento.ignoreNewDelete = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_ATEXIT_FIN");
    memento.atexitFin = (env ? atoi(env) : 1);

    if (memento.atexitFin) {
        /* For Windows, we can _onexit rather than atexit. This is because
         * _onexit registered handlers are called when the DLL that they are
         * in is freed, rather than on complete closedown. This gives us a
         * higher chance of seeing Memento_fin called in a state when the
         * stack backtracing mechanism can still work. */
#if defined(_WIN32) || defined(_WIN64)
        _onexit(Memento_fin_win);
#else
        atexit(Memento_fin_unix);
#endif
    }

    Memento_initMutex(&memento.mutex);

    Memento_initStacktracer();

    Memento_breakpoint();
}

static void Memento_infoLocked(void *addr)
{
#ifdef MEMENTO_DETAILS
    Memento_BlkHeader *blk;

    blk = find_enclosing_block(&memento.used, addr, NULL);
    if (blk == NULL)
        blk = find_enclosing_block(&memento.free, addr, NULL);
    if (blk != NULL)
        showInfo(blk, NULL);
#else
    printf("Memento not compiled with details support\n");
#endif
}

void Memento_info(void *addr)
{
    MEMENTO_LOCK();
    Memento_infoLocked(addr);
    MEMENTO_UNLOCK();
}

#ifdef MEMENTO_HAS_FORK
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#ifdef MEMENTO_STACKTRACE_METHOD
#if MEMENTO_STACKTRACE_METHOD == 1
#include <signal.h>
#endif
#endif

/* FIXME: Find some portable way of getting this */
/* MacOSX has 10240, Ubuntu seems to have 256 */
#ifndef OPEN_MAX
#define OPEN_MAX 10240
#endif

/* stashed_map[j] = i means that file descriptor i-1 was duplicated to j */
int stashed_map[OPEN_MAX];

static void Memento_signal(int sig)
{
    (void)sig;
    fprintf(stderr, "SEGV at:\n");
    memento.segv = 1;
    Memento_bt_internal(0);

    exit(1);
}

static int squeeze(void)
{
    pid_t pid;
    int i, status;

    if (memento.patternBit < 0)
        return 1;
    if (memento.squeezing && memento.patternBit >= MEMENTO_MAXPATTERN)
        return 1;

    if (memento.patternBit == 0)
        memento.squeezeAt = memento.sequence;

    if (!memento.squeezing) {
        fprintf(stderr, "Memory squeezing @ %d\n", memento.squeezeAt);
    } else
        fprintf(stderr, "Memory squeezing @ %d (%x,%x)\n", memento.squeezeAt, memento.pattern, memento.patternBit);

    /* When we fork below, the child is going to snaffle all our file pointers
     * and potentially corrupt them. Let's make copies of all of them before
     * we fork, so we can restore them when we restart. */
    for (i = 0; i < OPEN_MAX; i++) {
        if (stashed_map[i] == 0) {
            int j = dup(i);
            if (j >= 0) {
                stashed_map[j] = i+1;
            }
        }
    }

    fprintf(stderr, "Failing at:\n");
    Memento_bt_internal(2);
    pid = fork();
    if (pid == 0) {
        /* Child */
        signal(SIGSEGV, Memento_signal);
        /* Close the dup-licated fds to avoid them getting corrupted by faulty
         * code. */
        for (i = 0; i < OPEN_MAX; i++) {
            if (stashed_map[i] != 0) {
                /* We close duplicated fds, just in case child has some bad
                 * code that modifies/closes random fds. */
                close(i);
            }
        }
        /* In the child, we always fail the next allocation. */
        if (memento.patternBit == 0) {
            memento.patternBit = 1;
        } else
            memento.patternBit <<= 1;
        memento.squeezing = 1;

        /* This is necessary to allow Memento_failThisEventLocked() near the
         * end to do 'return squeeze();'. */
        memento.squeezes_num = 0;

        return 1;
    }

    /* In the parent if we hit another allocation, pass it (and record the
     * fact we passed it in the pattern. */
    memento.pattern |= memento.patternBit;
    memento.patternBit <<= 1;

    /* Wait for pid to finish, with a timeout. */
    {
        struct timespec tm = { 0, 10 * 1000 * 1000 }; /* 10ms = 100th sec */
        int timeout = 30 * 1000 * 1000; /* time out in microseconds! */
        while (waitpid(pid, &status, WNOHANG) == 0) {
            nanosleep(&tm, NULL);
            timeout -= (int)(tm.tv_nsec/1000);
            tm.tv_nsec *= 2;
            if (tm.tv_nsec > 999999999)
                tm.tv_nsec = 999999999;
            if (timeout <= 0) {
                char text[32];
                fprintf(stderr, "Child is taking a long time to die. Killing it.\n");
                sprintf(text, "kill %d", pid);
                system(text);
                break;
            }
        }
    }

    if (status != 0) {
        fprintf(stderr, "Child status=%d\n", status);
    }

    /* Put the files back */
    for (i = 0; i < OPEN_MAX; i++) {
        if (stashed_map[i] != 0) {
            dup2(i, stashed_map[i]-1);
            close(i);
            stashed_map[i] = 0;
        }
    }

    return 0;
}
#else
#include <signal.h>

static void Memento_signal(int sig)
{
    (void)sig;
    memento.segv = 1;
    /* If we just return from this function the SEGV will be unhandled, and
     * we'll launch into whatever JIT debugging system the OS provides. At
     * least fprintf(stderr, something useful first. If MEMENTO_NOJIT is set, then
     * just exit to avoid the JIT (and get the usual atexit handling). */
    if (getenv("MEMENTO_NOJIT"))
        exit(1);
    else
        Memento_fin();
}

static int squeeze(void)
{
    fprintf(stderr, "Memento memory squeezing disabled as no fork!\n");
    return 0;
}
#endif

static void Memento_startFailing(void)
{
    if (!memento.failing) {
        fprintf(stderr, "Starting to fail...\n");
        Memento_bt();
        fflush(stderr);
        memento.failing = 1;
        memento.failAt = memento.sequence;
        memento.nextFailAt = memento.sequence+1;
        memento.patternBit = 0;
        signal(SIGSEGV, Memento_signal);
        signal(SIGABRT, Memento_signal);
        Memento_breakpointLocked();
    }
}

static int Memento_event(void)
{
    int ret = 0;

    memento.sequence++;
    if ((memento.sequence >= memento.paranoidAt) && (memento.paranoidAt != 0)) {
        memento.paranoia = 1;
        memento.countdown = 1;
    }
    if (--memento.countdown == 0) {
        ret = Memento_checkAllMemoryLocked();
        ret = (ret & 8) != 0;
        if (memento.paranoia > 0)
            memento.countdown = memento.paranoia;
        else
        {
            memento.countdown = -memento.paranoia;
            if (memento.paranoia > INT_MIN/2)
                memento.paranoia *= 2;
        }
    }

    if (memento.sequence == memento.breakAt) {
        fprintf(stderr, "Breaking at event %d\n", memento.breakAt);
        return 1;
    }
    return ret;
}

int Memento_sequence(void)
{
    return memento.sequence;
}

int Memento_breakAt(int event)
{
    MEMENTO_LOCK();
    memento.breakAt = event;
    MEMENTO_UNLOCK();
    return event;
}

static void *safe_find_block(void *ptr)
{
    Memento_BlkHeader *block;
    int valid;

    if (ptr == NULL)
        return NULL;

    block = MEMBLK_FROMBLK(ptr);
    /* Sometimes wrapping allocators can mean Memento_label
     * is called with a value within the block, rather than
     * at the start of the block. If we detect this, find it
     * the slow way. */
    VALGRIND_MAKE_MEM_DEFINED(&block->child, sizeof(block->child));
    VALGRIND_MAKE_MEM_DEFINED(&block->sibling, sizeof(block->sibling));
    valid = (block->child == MEMENTO_CHILD_MAGIC &&
             block->sibling == MEMENTO_SIBLING_MAGIC);
    if (valid) {
        VALGRIND_MAKE_MEM_NOACCESS(&block->child, sizeof(block->child));
        VALGRIND_MAKE_MEM_NOACCESS(&block->sibling, sizeof(block->sibling));
    }
    if (!valid)
    {
        block = find_enclosing_block(&memento.used, ptr, NULL);
    }
    return block;
}

void *Memento_label(void *ptr, const char *label)
{
    Memento_BlkHeader *block;

    if (ptr == NULL)
        return NULL;
    MEMENTO_LOCK();
    block = safe_find_block(ptr);
    if (block != NULL)
    {
        VALGRIND_MAKE_MEM_DEFINED(&block->label, sizeof(block->label));
        block->label = label;
        VALGRIND_MAKE_MEM_NOACCESS(&block->label, sizeof(block->label));
    }
    MEMENTO_UNLOCK();

    if (memento.verboseNewlineSuppressed) {
        if (memento.lastVerbosePtr == block) {
            fprintf(stderr, " (%s)", label);
        }
    }

    return ptr;
}

void Memento_tick(void)
{
    MEMENTO_LOCK();
    if (Memento_event()) Memento_breakpointLocked();
    MEMENTO_UNLOCK();
}

static int Memento_failThisEventLocked(void)
{
    int failThisOne;

    if (Memento_event()) Memento_breakpointLocked();

    if (!memento.squeezing && memento.squeezes_num) {
        /* Move to next relevant squeeze region if appropriate. */
        for ( ; memento.squeezes_pos != memento.squeezes_num; memento.squeezes_pos++) {
            if (memento.sequence < memento.squeezes[memento.squeezes_pos].end)
                break;
        }

        /* See whether memento.sequence is within this squeeze region. */
        if (memento.squeezes_pos < memento.squeezes_num) {
            int begin = memento.squeezes[memento.squeezes_pos].begin;
            int end   = memento.squeezes[memento.squeezes_pos].end;
            if (memento.sequence >= begin && memento.sequence < end) {
                if (1) {
                    fprintf(stderr,
                            "squeezes match memento.sequence=%i: memento.squeezes_pos=%i/%i %i..%i\n",
                            memento.sequence,
                            memento.squeezes_pos,
                            memento.squeezes_num,
                            memento.squeezes[memento.squeezes_pos].begin,
                            memento.squeezes[memento.squeezes_pos].end
                            );
                }
                return squeeze();
            }
        }
    }

    if ((memento.sequence >= memento.failAt) && (memento.failAt != 0))
        Memento_startFailing();
    if ((memento.squeezes_num==0) && (memento.sequence >= memento.squeezeAt) && (memento.squeezeAt != 0))
        return squeeze();

    if (!memento.failing)
        return 0;
    failThisOne = ((memento.patternBit & memento.pattern) == 0);
    /* If we are failing, and we've reached the end of the pattern and we've
     * still got bits available in the pattern word, and we haven't already
     * set a nextPattern, then extend the pattern. */
    if (memento.failing &&
        ((~(memento.patternBit-1) & memento.pattern) == 0) &&
        (memento.patternBit != 0) &&
        memento.nextPattern == 0)
    {
        /* We'll fail this one, and set the 'next' one to pass it. */
        memento.nextFailAt = memento.failAt;
        memento.nextPattern = memento.pattern | memento.patternBit;
    }
    memento.patternBit = (memento.patternBit ? memento.patternBit << 1 : 1);

    return failThisOne;
}

int Memento_failThisEvent(void)
{
    int ret;

    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    ret = Memento_failThisEventLocked();
    MEMENTO_UNLOCK();
    return ret;
}

static void *do_malloc(size_t s, int et)
{
    Memento_BlkHeader *memblk;
    size_t             smem = MEMBLK_SIZE(s);
#ifdef MEMENTO_DETAILS
    Memento_hashedST  *st;
#endif

    if (Memento_failThisEventLocked()) {
        errno = ENOMEM;
        return NULL;
    }

    if (s == 0)
        return NULL;

    memento.numMallocs++;

    if (memento.maxMemory != 0 && memento.alloc + s > memento.maxMemory) {
        errno = ENOMEM;
        return NULL;
    }

#ifdef MEMENTO_DETAILS
    st = Memento_getHashedStacktrace();
#endif

    memblk = MEMENTO_UNDERLYING_MALLOC(smem);
    if (memblk == NULL) {
        switch (memento.verbose) {
        default:
            if (memento.verboseNewlineSuppressed)
                fprintf(stderr, "\n");
            fprintf(stderr, "%s failed (size="FMTZ",num=%d",
                    eventType[et], (FMTZ_CAST)s, memento.sequence);
#ifdef MEMENTO_DETAILS
            fprintf(stderr, ",st=%x", st->hash);
#endif
            fprintf(stderr, ")");
            memento.verboseNewlineSuppressed = 1;
            memento.lastVerbosePtr = memblk;
            break;
        case 2:
            if (memento.verboseNewlineSuppressed)
                fprintf(stderr, "\n");
            fprintf(stderr, "%s failed (size="FMTZ"",
                    eventType[et], (FMTZ_CAST)s);
#ifdef MEMENTO_DETAILS
            fprintf(stderr, ",st=%x", st->hash);
#endif
            fprintf(stderr, ")");
            memento.verboseNewlineSuppressed = 1;
            memento.lastVerbosePtr = memblk;
            break;
        case 0:
            break;
        }
        return NULL;
    }

    memento.alloc      += s;
    memento.totalAlloc += s;
    if (memento.peakAlloc < memento.alloc)
        memento.peakAlloc = memento.alloc;
#ifndef MEMENTO_LEAKONLY
    memset(MEMBLK_TOBLK(memblk), MEMENTO_ALLOCFILL, s);
#endif
    memblk->rawsize       = s;
    memblk->sequence      = memento.sequence;
    memblk->lastCheckedOK = memblk->sequence;
    memblk->flags         = 0;
    memblk->label         = 0;
    memblk->child         = MEMENTO_CHILD_MAGIC;
    memblk->sibling       = MEMENTO_SIBLING_MAGIC;
#ifdef MEMENTO_DETAILS
    memblk->details       = NULL;
    memblk->details_tail  = &memblk->details;
    Memento_storeDetails(memblk, et, st);
#endif /* MEMENTO_DETAILS */
    Memento_addBlockHead(&memento.used, memblk, 0);

    if (memento.leaking > 0)
        memblk->flags |= Memento_Flag_KnownLeak;

    switch (memento.verbose) {
    default:
        if (memento.verboseNewlineSuppressed)
            fprintf(stderr, "\n");
        fprintf(stderr, "%s "FMTP":(size="FMTZ",num=%d",
                eventType[et],
                MEMBLK_TOBLK(memblk), (FMTZ_CAST)memblk->rawsize, memblk->sequence);
#ifdef MEMENTO_DETAILS
        fprintf(stderr, ",st=%x", st->hash);
#endif
        if (memblk->label)
            fprintf(stderr, ") (%s", memblk->label);
        fprintf(stderr, ")");
        memento.verboseNewlineSuppressed = 1;
        memento.lastVerbosePtr = memblk;
        break;
    case 2:
        if (memento.verboseNewlineSuppressed)
            fprintf(stderr, "\n");
        fprintf(stderr, "%s (size="FMTZ"",
                eventType[et],
                (FMTZ_CAST)memblk->rawsize);
#ifdef MEMENTO_DETAILS
        fprintf(stderr, ",st=%x", st->hash);
#endif
        if (memblk->label)
            fprintf(stderr, ") (%s", memblk->label);
        fprintf(stderr, ")");
        memento.verboseNewlineSuppressed = 1;
        memento.lastVerbosePtr = memblk;
        break;
    case 0:
        break;
    }

    return MEMBLK_TOBLK(memblk);
}

char *Memento_strdup(const char *text)
{
    size_t len = strlen(text) + 1;
    char *ret;

    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    ret = do_malloc(len, Memento_EventType_strdup);
    MEMENTO_UNLOCK();

    if (ret != NULL)
        memcpy(ret, text, len);

    return ret;
}

#if !defined(MEMENTO_GS_HACKS) && !defined(MEMENTO_MUPDF_HACKS)
int Memento_asprintf(char **ret, const char *format, ...)
{
    va_list va;
    int n;
    int n2;

    if (!memento.inited)
        Memento_init();

    va_start(va, format);
    n = vsnprintf(NULL, 0, format, va);
    va_end(va);
    if (n < 0)
        return n;

    MEMENTO_LOCK();
    *ret = do_malloc(n+1, Memento_EventType_asprintf);
    MEMENTO_UNLOCK();
    if (*ret == NULL)
        return -1;

    va_start(va, format);
    n2 = vsnprintf(*ret, n + 1, format, va);
    va_end(va);

    return n2;
}

int Memento_vasprintf(char **ret, const char *format, va_list ap)
{
    int n;
    va_list ap2;
    va_copy(ap2, ap);

    if (!memento.inited)
        Memento_init();

    n = vsnprintf(NULL, 0, format, ap);
    if (n < 0) {
        va_end(ap2);
        return n;
    }

    MEMENTO_LOCK();
    *ret = do_malloc(n+1, Memento_EventType_vasprintf);
    MEMENTO_UNLOCK();
    if (*ret == NULL) {
        va_end(ap2);
        return -1;
    }

    n = vsnprintf(*ret, n + 1, format, ap2);
    va_end(ap2);

    return n;
}
#endif

void *Memento_malloc(size_t s)
{
    void *ret;

    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    ret = do_malloc(s, Memento_EventType_malloc);
    MEMENTO_UNLOCK();

    return ret;
}

void *Memento_calloc(size_t n, size_t s)
{
    void *block;

    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    block = do_malloc(n*s, Memento_EventType_calloc);
    MEMENTO_UNLOCK();
    if (block)
        memset(block, 0, n*s);

    return block;
}

#ifdef MEMENTO_TRACKREFS
static void do_reference(Memento_BlkHeader *blk, int event)
{
#ifdef MEMENTO_DETAILS
    Memento_hashedST *st = Memento_getHashedStacktrace();
    Memento_storeDetails(blk, event, st);
#endif /* MEMENTO_DETAILS */
}
#endif

static int checkPointerOrNullLocked(void *blk)
{
    if (blk == NULL)
        return 0;
    if (blk == MEMENTO_PREFILL_PTR)
        fprintf(stderr, "Prefill value found as pointer - buffer underrun?\n");
    else if (blk == MEMENTO_POSTFILL_PTR)
        fprintf(stderr, "Postfill value found as pointer - buffer overrun?\n");
    else if (blk == MEMENTO_ALLOCFILL_PTR)
        fprintf(stderr, "Allocfill value found as pointer - use of uninitialised value?\n");
    else if (blk == MEMENTO_FREEFILL_PTR)
        fprintf(stderr, "Allocfill value found as pointer - use after free?\n");
    else
        return 0;
#ifdef MEMENTO_DETAILS
    fprintf(stderr, "Current backtrace:\n");
    Memento_bt();
    fprintf(stderr, "History:\n");
    Memento_infoLocked(blk);
#endif
    Memento_breakpointLocked();
    return 1;
}

int Memento_checkPointerOrNull(void *blk)
{
    int ret;
    MEMENTO_LOCK();
    ret = checkPointerOrNullLocked(blk);
    MEMENTO_UNLOCK();
    return ret;
}

static int checkBytePointerOrNullLocked(void *blk)
{
    unsigned char i;
    if (blk == NULL)
        return 0;
    checkPointerOrNullLocked(blk);

    i = *(unsigned char *)blk;

    if (i == MEMENTO_PREFILL_UBYTE)
        fprintf(stderr, "Prefill value found - buffer underrun?\n");
    else if (i == MEMENTO_POSTFILL_UBYTE)
        fprintf(stderr, "Postfill value found - buffer overrun?\n");
    else if (i == MEMENTO_ALLOCFILL_UBYTE)
        fprintf(stderr, "Allocfill value found - use of uninitialised value?\n");
    else if (i == MEMENTO_FREEFILL_UBYTE)
        fprintf(stderr, "Allocfill value found - use after free?\n");
    else
        return 0;
#ifdef MEMENTO_DETAILS
    fprintf(stderr, "Current backtrace:\n");
    Memento_bt();
    fprintf(stderr, "History:\n");
    Memento_infoLocked(blk);
#endif
    Memento_breakpointLocked();
    return 1;
}

int Memento_checkBytePointerOrNull(void *blk)
{
    int ret;
    MEMENTO_LOCK();
    ret = checkBytePointerOrNullLocked(blk);
    MEMENTO_UNLOCK();
    return ret;
}

static int checkShortPointerOrNullLocked(void *blk)
{
    unsigned short i;
    if (blk == NULL)
        return 0;
    checkPointerOrNullLocked(blk);

    i = *(unsigned short *)blk;

    if (i == MEMENTO_PREFILL_USHORT)
        fprintf(stderr, "Prefill value found - buffer underrun?\n");
    else if (i == MEMENTO_POSTFILL_USHORT)
        fprintf(stderr, "Postfill value found - buffer overrun?\n");
    else if (i == MEMENTO_ALLOCFILL_USHORT)
        fprintf(stderr, "Allocfill value found - use of uninitialised value?\n");
    else if (i == MEMENTO_FREEFILL_USHORT)
        fprintf(stderr, "Allocfill value found - use after free?\n");
    else
        return 0;
#ifdef MEMENTO_DETAILS
    fprintf(stderr, "Current backtrace:\n");
    Memento_bt();
    fprintf(stderr, "History:\n");
    Memento_infoLocked(blk);
#endif
    Memento_breakpointLocked();
    return 1;
}

int Memento_checkShortPointerOrNull(void *blk)
{
    int ret;
    MEMENTO_LOCK();
    ret = checkShortPointerOrNullLocked(blk);
    MEMENTO_UNLOCK();
    return ret;
}

static int checkIntPointerOrNullLocked(void *blk)
{
    unsigned int i;
    if (blk == NULL)
        return 0;
    checkPointerOrNullLocked(blk);

    i = *(unsigned int *)blk;

    if (i == MEMENTO_PREFILL_UINT)
        fprintf(stderr, "Prefill value found - buffer underrun?\n");
    else if (i == MEMENTO_POSTFILL_UINT)
        fprintf(stderr, "Postfill value found - buffer overrun?\n");
    else if (i == MEMENTO_ALLOCFILL_UINT)
        fprintf(stderr, "Allocfill value found - use of uninitialised value?\n");
    else if (i == MEMENTO_FREEFILL_UINT)
        fprintf(stderr, "Allocfill value found - use after free?\n");
    else
        return 0;
#ifdef MEMENTO_DETAILS
    fprintf(stderr, "Current backtrace:\n");
    Memento_bt();
    fprintf(stderr, "History:\n");
    Memento_infoLocked(blk);
#endif
    Memento_breakpointLocked();
    return 1;
}

int Memento_checkIntPointerOrNull(void *blk)
{
    int ret;
    MEMENTO_LOCK();
    ret = checkIntPointerOrNullLocked(blk);
    MEMENTO_UNLOCK();
    return ret;
}

#ifdef MEMENTO_TRACKREFS
static void *do_takeRef(void *blk)
{
    do_reference(safe_find_block(blk), Memento_EventType_takeRef);
    return blk;
}

static void *do_takeRefAndUnlock(void *blk)
{
    do_reference(safe_find_block(blk), Memento_EventType_takeRef);
    MEMENTO_UNLOCK();
    return blk;
}

static void *do_dropRef(void *blk)
{
    do_reference(safe_find_block(blk), Memento_EventType_dropRef);
    return blk;
}

static void *do_dropRefAndUnlock(void *blk)
{
    do_reference(safe_find_block(blk), Memento_EventType_dropRef);
    MEMENTO_UNLOCK();
    return blk;
}
#endif

void *Memento_takeByteRef(void *blk)
{
#ifdef MEMENTO_TRACKREFS
    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    if (Memento_event()) Memento_breakpointLocked();

    if (!blk) {
        MEMENTO_UNLOCK();
        return NULL;
    }

    (void)checkBytePointerOrNullLocked(blk);

    return do_takeRefAndUnlock(blk);
#else
    return blk;
#endif
}

void *Memento_takeShortRef(void *blk)
{
#ifdef MEMENTO_TRACKREFS
    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    if (Memento_event()) Memento_breakpointLocked();

    if (!blk) {
        MEMENTO_UNLOCK();
        return NULL;
    }

    (void)checkShortPointerOrNullLocked(blk);

    return do_takeRefAndUnlock(blk);
#else
    return blk;
#endif
}

void *Memento_takeIntRef(void *blk)
{
#ifdef MEMENTO_TRACKREFS
    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    if (Memento_event()) Memento_breakpointLocked();

    if (!blk) {
        MEMENTO_UNLOCK();
        return NULL;
    }

    (void)checkIntPointerOrNullLocked(blk);

    return do_takeRefAndUnlock(blk);
#else
    return blk;
#endif
}

void *Memento_takeRef(void *blk)
{
#ifdef MEMENTO_TRACKREFS
    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    if (Memento_event()) Memento_breakpointLocked();

    if (!blk) {
        MEMENTO_UNLOCK();
        return NULL;
    }

    return do_takeRefAndUnlock(blk);
#else
    return blk;
#endif
}

void *Memento_dropByteRef(void *blk)
{
#ifdef MEMENTO_TRACKREFS
    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    if (Memento_event()) Memento_breakpointLocked();

    if (!blk) {
        MEMENTO_UNLOCK();
        return NULL;
    }

    checkBytePointerOrNullLocked(blk);

    return do_dropRefAndUnlock(blk);
#else
    return blk;
#endif
}

void *Memento_dropShortRef(void *blk)
{
#ifdef MEMENTO_TRACKREFS
    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    if (Memento_event()) Memento_breakpointLocked();

    if (!blk) {
        MEMENTO_UNLOCK();
        return NULL;
    }

    checkShortPointerOrNullLocked(blk);

    return do_dropRefAndUnlock(blk);
#else
    return blk;
#endif
}

void *Memento_dropIntRef(void *blk)
{
#ifdef MEMENTO_TRACKREFS
    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    if (Memento_event()) Memento_breakpointLocked();

    if (!blk) {
        MEMENTO_UNLOCK();
        return NULL;
    }

    checkIntPointerOrNullLocked(blk);

    return do_dropRefAndUnlock(blk);
#else
    return blk;
#endif
}

void *Memento_dropRef(void *blk)
{
#ifdef MEMENTO_TRACKREFS
    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    if (Memento_event()) Memento_breakpointLocked();

    if (!blk) {
        MEMENTO_UNLOCK();
        return NULL;
    }

    return do_dropRefAndUnlock(blk);
#else
    return blk;
#endif
}

void *Memento_adjustRef(void *blk, int adjust)
{
#ifdef MEMENTO_TRACKREFS
    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    if (Memento_event()) Memento_breakpointLocked();

    if (blk == NULL) {
        MEMENTO_UNLOCK();
        return NULL;
    }

    while (adjust > 0)
    {
        do_takeRef(blk);
        adjust--;
    }
    while (adjust < 0)
    {
        do_dropRef(blk);
        adjust++;
    }

    MEMENTO_UNLOCK();
#endif
    return blk;
}

void *Memento_reference(void *blk)
{
#ifdef MEMENTO_TRACKREFS
    if (!blk)
        return NULL;

    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    do_reference(safe_find_block(blk), Memento_EventType_reference);
    MEMENTO_UNLOCK();
#endif
    return blk;
}

/* Treat blocks from the user with suspicion, and check them the slow
 * but safe way. */
static int checkBlockUser(Memento_BlkHeader *memblk, const char *action)
{
#ifndef MEMENTO_LEAKONLY
    BlkCheckData data;

    memset(&data, 0, sizeof(data));
    Memento_appBlockUser(&memento.used, Memento_Internal_checkAllocedBlock,
                         &data, memblk);
    if (!data.found) {
        /* Failure! */
        fprintf(stderr, "Attempt to %s block ", action);
        showBlock(memblk, 32);
        fprintf(stderr, "\n");
        Memento_breakpointLocked();
        return 1;
    } else if (data.preCorrupt || data.postCorrupt) {
        fprintf(stderr, "Block ");
        showBlock(memblk, ' ');
        fprintf(stderr, " found to be corrupted on %s!\n", action);
        if (data.preCorrupt) {
            fprintf(stderr, "Preguard corrupted\n");
        }
        if (data.postCorrupt) {
            fprintf(stderr, "Postguard corrupted\n");
        }
        fprintf(stderr, "Block last checked OK at allocation %d. Now %d.\n",
                memblk->lastCheckedOK, memento.sequence);
        if ((memblk->flags & Memento_Flag_Reported) == 0)
        {
            memblk->flags |= Memento_Flag_Reported;
            Memento_breakpointLocked();
        }
        return 1;
    }
#endif
    return 0;
}

static int checkBlock(Memento_BlkHeader *memblk, const char *action)
{
#ifndef MEMENTO_LEAKONLY
    BlkCheckData data;
#endif

    if (memblk->child != MEMENTO_CHILD_MAGIC ||
        memblk->sibling != MEMENTO_SIBLING_MAGIC)
    {
        /* Failure! */
        fprintf(stderr, "Attempt to %s invalid block ", action);
        showBlock(memblk, 32);
        fprintf(stderr, "\n");
        return 2;
    }

#ifndef MEMENTO_LEAKONLY
    memset(&data, 0, sizeof(data));
    Memento_appBlock(&memento.used, Memento_Internal_checkAllocedBlock,
                     &data, memblk);
    if (!data.found) {
        /* Failure! */
        fprintf(stderr, "Attempt to %s block ", action);
        showBlock(memblk, 32);
        fprintf(stderr, "\n");
        return 2;
    } else if (data.preCorrupt || data.postCorrupt) {
        fprintf(stderr, "Block ");
        showBlock(memblk, ' ');
        fprintf(stderr, " found to be corrupted on %s!\n", action);
        if (data.preCorrupt) {
            fprintf(stderr, "Preguard corrupted\n");
        }
        if (data.postCorrupt) {
            fprintf(stderr, "Postguard corrupted\n");
        }
        fprintf(stderr, "Block last checked OK at allocation %d. Now %d.\n",
                memblk->lastCheckedOK, memento.sequence);
        if ((memblk->flags & Memento_Flag_Reported) == 0)
        {
            memblk->flags |= Memento_Flag_Reported;
            return 2;
        }
        return 1;
    }
#endif
    return 0;
}

static void do_free(void *blk, int et)
{
    Memento_BlkHeader *memblk;
    int ret;
#ifdef MEMENTO_DETAILS
    Memento_hashedST *st;
#endif

    if (Memento_event()) Memento_breakpointLocked();

    if (blk == NULL)
        return;

    memblk = MEMBLK_FROMBLK(blk);
    VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
    ret = checkBlock(memblk, "free");
    if (ret)
    {
        if (ret & 2)
            Memento_breakpoint();
        if (memento.abortOnCorruption) {
            fprintf(stderr, "*** memblk corrupted, calling abort()\n");
            abort();
        }
        return;
    }

#ifdef MEMENTO_DETAILS
    st = Memento_getHashedStacktrace();
#endif

    switch (memento.verbose) {
    default:
        if (memento.verboseNewlineSuppressed) {
            fprintf(stderr, "\n");
            memento.verboseNewlineSuppressed = 0;
        }
        fprintf(stderr, "%s "FMTP":(size="FMTZ",num=%d",
                eventType[et],
                MEMBLK_TOBLK(memblk), (FMTZ_CAST)memblk->rawsize, memblk->sequence);
#ifdef MEMENTO_DETAILS
        fprintf(stderr, ",hash=%x", st->hash);
#endif
        if (memblk->label)
            fprintf(stderr, ") (%s", memblk->label);
        fprintf(stderr, ")\n");
        break;
    case 2:
        if (memento.verboseNewlineSuppressed) {
            fprintf(stderr, "\n");
            memento.verboseNewlineSuppressed = 0;
        }
        fprintf(stderr, "%s (size="FMTZ,
                eventType[et],
                (FMTZ_CAST)memblk->rawsize);
#ifdef MEMENTO_DETAILS
        fprintf(stderr, ",hash=%x", st->hash);
#endif
        if (memblk->label)
            fprintf(stderr, ") (%s", memblk->label);
        fprintf(stderr, ")\n");
        break;
    case 0:
        break;
    }

#ifdef MEMENTO_DETAILS
    Memento_storeDetails(memblk, et, st);
#endif

    VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
    if (memblk->flags & Memento_Flag_BreakOnFree)
        Memento_breakpointLocked();

    memento.alloc -= memblk->rawsize;
    memento.numFrees++;

    Memento_removeBlock(&memento.used, memblk);

    VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
    if (Memento_Internal_makeSpace(MEMBLK_SIZE(memblk->rawsize))) {
        VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
        VALGRIND_MAKE_MEM_DEFINED(MEMBLK_TOBLK(memblk),
                                  memblk->rawsize + Memento_PostSize);
#ifndef MEMENTO_LEAKONLY
        memset(MEMBLK_TOBLK(memblk), MEMENTO_FREEFILL, memblk->rawsize);
#endif
        memblk->flags |= Memento_Flag_Freed;
        Memento_addBlockTail(&memento.free, memblk, 1);
    } else {
        free_block(memblk);
    }
}

void Memento_free(void *blk)
{
    if (!memento.inited)
        Memento_init();

    MEMENTO_LOCK();
    do_free(blk, Memento_EventType_free);
    MEMENTO_UNLOCK();
}

static void *do_realloc(void *blk, size_t newsize, int type)
{
    Memento_BlkHeader *memblk, *newmemblk;
    size_t             newsizemem;
    int                flags, ret;
    size_t             oldsize;
#ifdef MEMENTO_DETAILS
    Memento_hashedST *st;
#endif

    if (Memento_failThisEventLocked()) {
        errno = ENOMEM;
        return NULL;
    }

#ifdef MEMENTO_DETAILS
    st = Memento_getHashedStacktrace();
#endif

    memblk     = MEMBLK_FROMBLK(blk);
    VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
    ret = checkBlock(memblk, "realloc");
    if (ret) {
        switch (memento.verbose) {
        default:
            if (memento.verboseNewlineSuppressed) {
                fprintf(stderr, "\n");
                memento.verboseNewlineSuppressed = 0;
            }
            fprintf(stderr, "%s bad block "FMTP":(size=?=>"FMTZ", num=?, now=%d",
                eventType[type],
                MEMBLK_TOBLK(memblk),
                (FMTZ_CAST)newsize, memento.sequence);
#ifdef MEMENTO_DETAILS
            fprintf(stderr, ",hash=%x", st->hash);
#endif
            fprintf(stderr, ")\n");
            break;
        case 2:
            if (memento.verboseNewlineSuppressed) {
                fprintf(stderr, "\n");
                memento.verboseNewlineSuppressed = 0;
            }
            fprintf(stderr, "%s bad block (size=?=>"FMTZ,
                eventType[type],
                (FMTZ_CAST)newsize);
#ifdef MEMENTO_DETAILS
            fprintf(stderr, ",hash=%x", st->hash);
#endif
            fprintf(stderr, ")\n");
            break;
        case 0:
            break;
        }
        if (ret == 2)
            Memento_breakpoint();
        errno = ENOMEM;
        return NULL;
    }

#ifdef MEMENTO_DETAILS
    Memento_storeDetails(memblk, type, st);
#endif

    VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
    if (memblk->flags & Memento_Flag_BreakOnRealloc)
        Memento_breakpointLocked();

    VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
    oldsize = memblk->rawsize;
    if (memento.maxMemory != 0 && memento.alloc - oldsize + newsize > memento.maxMemory) {
        switch (memento.verbose) {
        default:
            if (memento.verboseNewlineSuppressed) {
                fprintf(stderr, "\n");
                memento.verboseNewlineSuppressed = 0;
            }
            fprintf(stderr, "%s failing (memory limit exceeded) "FMTP":(size="FMTZ"=>"FMTZ", num=%d, now=%d",
                    eventType[type], MEMBLK_TOBLK(memblk),
                    (FMTZ_CAST)oldsize, (FMTZ_CAST)newsize,
                    memblk->sequence, memento.sequence);
#ifdef MEMENTO_DETAILS
            fprintf(stderr, ",hash=%x", st->hash);
#endif
            if (memblk->label)
                fprintf(stderr, ") (%s", memblk->label);
            fprintf(stderr, ")\n");
            break;
        case 2:
            if (memento.verboseNewlineSuppressed) {
                fprintf(stderr, "\n");
                memento.verboseNewlineSuppressed = 0;
            }
            fprintf(stderr, "%s failing (memory limit exceeded) (size="FMTZ"=>"FMTZ,
                    eventType[type], (FMTZ_CAST)oldsize, (FMTZ_CAST)newsize);
#ifdef MEMENTO_DETAILS
            fprintf(stderr, ",hash=%x", st->hash);
#endif
            if (memblk->label)
                fprintf(stderr, ") (%s", memblk->label);
            fprintf(stderr, ")\n");
            break;
        case 0:
            break;
        }
        errno = ENOMEM;
        return NULL;
    }

    newsizemem = MEMBLK_SIZE(newsize);
    Memento_removeBlock(&memento.used, memblk);
    VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
    flags = memblk->flags;
    newmemblk  = MEMENTO_UNDERLYING_REALLOC(memblk, newsizemem);
    if (newmemblk == NULL)
    {
        switch (memento.verbose) {
        default:
            if (memento.verboseNewlineSuppressed) {
                fprintf(stderr, "\n");
                memento.verboseNewlineSuppressed = 0;
            }
            fprintf(stderr, "%s failed "FMTP":(size="FMTZ"=>"FMTZ", num=%d, now=%d",
                    eventType[type], MEMBLK_TOBLK(memblk),
                    (FMTZ_CAST)oldsize, (FMTZ_CAST)newsize,
                    memblk->sequence, memento.sequence);
#ifdef MEMENTO_DETAILS
            fprintf(stderr, ",hash=%x", st->hash);
#endif
            if (memblk->label)
                fprintf(stderr, ") (%s", newmemblk->label);
            fprintf(stderr, ")\n");
            break;
        case 2:
            if (memento.verboseNewlineSuppressed) {
                fprintf(stderr, "\n");
                memento.verboseNewlineSuppressed = 0;
            }
            fprintf(stderr, "%s failed (size="FMTZ"=>"FMTZ,
                    eventType[type],
                    (FMTZ_CAST)oldsize, (FMTZ_CAST)newsize);
#ifdef MEMENTO_DETAILS
            fprintf(stderr, ",hash=%x", st->hash);
#endif
            if (memblk->label)
                fprintf(stderr, ") (%s", newmemblk->label);
            fprintf(stderr, ")\n");
            break;
        case 0:
            break;
        }
        Memento_addBlockHead(&memento.used, memblk, 2);
        return NULL;
    }
    memento.numReallocs++;
    memento.totalAlloc += newsize;
    memento.alloc      -= newmemblk->rawsize;
    memento.alloc      += newsize;
    if (memento.peakAlloc < memento.alloc)
        memento.peakAlloc = memento.alloc;
    newmemblk->flags = flags;
#ifndef MEMENTO_LEAKONLY
    if (newmemblk->rawsize < newsize) {
        char *newbytes = ((char *)MEMBLK_TOBLK(newmemblk))+newmemblk->rawsize;
        VALGRIND_MAKE_MEM_DEFINED(newbytes, newsize - newmemblk->rawsize);
        memset(newbytes, MEMENTO_ALLOCFILL, newsize - newmemblk->rawsize);
        VALGRIND_MAKE_MEM_UNDEFINED(newbytes, newsize - newmemblk->rawsize);
    }
#endif
    newmemblk->rawsize = newsize;
#ifndef MEMENTO_LEAKONLY
    VALGRIND_MAKE_MEM_DEFINED(newmemblk->preblk, Memento_PreSize);
    memset(newmemblk->preblk, MEMENTO_PREFILL, Memento_PreSize);
    VALGRIND_MAKE_MEM_UNDEFINED(newmemblk->preblk, Memento_PreSize);
    VALGRIND_MAKE_MEM_DEFINED(MEMBLK_POSTPTR(newmemblk), Memento_PostSize);
    memset(MEMBLK_POSTPTR(newmemblk), MEMENTO_POSTFILL, Memento_PostSize);
    VALGRIND_MAKE_MEM_UNDEFINED(MEMBLK_POSTPTR(newmemblk), Memento_PostSize);
#endif

    switch (memento.verbose) {
    default:
        if (memento.verboseNewlineSuppressed) {
            fprintf(stderr, "\n");
            memento.verboseNewlineSuppressed = 0;
        }
        fprintf(stderr, "%s "FMTP"=>"FMTP":(size="FMTZ"=>"FMTZ", num=%d, now=%d",
                eventType[type],
                MEMBLK_TOBLK(memblk), MEMBLK_TOBLK(newmemblk),
                (FMTZ_CAST)oldsize, (FMTZ_CAST)newsize,
                newmemblk->sequence, memento.sequence);
#ifdef MEMENTO_DETAILS
        fprintf(stderr, ",hash=%x", st->hash);
#endif
        if (memblk->label)
            fprintf(stderr, ") (%s", newmemblk->label);
        fprintf(stderr, ")\n");
        break;
    case 2:
        if (memento.verboseNewlineSuppressed) {
            fprintf(stderr, "\n");
            memento.verboseNewlineSuppressed = 0;
        }
        fprintf(stderr, "%s (size="FMTZ"=>"FMTZ,
                eventType[type],
                (FMTZ_CAST)oldsize, (FMTZ_CAST)newsize);
#ifdef MEMENTO_DETAILS
        fprintf(stderr, ",hash=%x", st->hash);
#endif
        if (memblk->label)
            fprintf(stderr, ") (%s", newmemblk->label);
        fprintf(stderr, ")\n");
        break;
    case 0:
        break;
    }

    Memento_addBlockHead(&memento.used, newmemblk, 2);
    return MEMBLK_TOBLK(newmemblk);
}

void *Memento_realloc(void *blk, size_t newsize)
{
    void *ret;

    if (!memento.inited)
        Memento_init();

    if (blk == NULL)
    {
        MEMENTO_LOCK();
        ret = do_malloc(newsize, Memento_EventType_realloc);
        MEMENTO_UNLOCK();
        if (!ret) errno = ENOMEM;
        return ret;
    }
    if (newsize == 0) {
        MEMENTO_LOCK();
        do_free(blk, Memento_EventType_realloc);
        MEMENTO_UNLOCK();
        return NULL;
    }

    MEMENTO_LOCK();
    ret = do_realloc(blk, newsize, Memento_EventType_realloc);
    MEMENTO_UNLOCK();
    if (!ret) errno = ENOMEM;
    return ret;
}

int Memento_checkBlock(void *blk)
{
    Memento_BlkHeader *memblk;
    int ret;

    if (blk == NULL)
        return 0;

    MEMENTO_LOCK();
    memblk = MEMBLK_FROMBLK(blk);
    ret = checkBlockUser(memblk, "check");
    MEMENTO_UNLOCK();
    return ret;
}

#ifndef MEMENTO_LEAKONLY
static int Memento_Internal_checkAllAlloced(Memento_BlkHeader *memblk, void *arg)
{
    BlkCheckData *data = (BlkCheckData *)arg;

    Memento_Internal_checkAllocedBlock(memblk, data);
    if (data->preCorrupt || data->postCorrupt) {
        if ((data->found & 2) == 0) {
            fprintf(stderr, "Allocated blocks:\n");
            data->found |= 2;
        }
        fprintf(stderr, "  Block ");
        showBlock(memblk, ' ');
        if (data->preCorrupt) {
            fprintf(stderr, " Preguard ");
        }
        if (data->postCorrupt) {
            fprintf(stderr, "%s Postguard ",
                    (data->preCorrupt ? "&" : ""));
        }
        fprintf(stderr, "corrupted.\n    "
                "Block last checked OK at allocation %d. Now %d.\n",
                memblk->lastCheckedOK, memento.sequence);
        if (memento.abortOnCorruption) {
            fprintf(stderr, "*** memblk corrupted, calling abort()\n");
            abort();
        }
        data->preCorrupt  = 0;
        data->postCorrupt = 0;
        data->freeCorrupt = 0;
        if ((memblk->flags & Memento_Flag_Reported) == 0)
        {
            memblk->flags |= Memento_Flag_Reported;
            data->found |= 8;
        }
    }
    else
        memblk->lastCheckedOK = memento.sequence;
    return 0;
}

static int Memento_Internal_checkAllFreed(Memento_BlkHeader *memblk, void *arg)
{
    BlkCheckData *data = (BlkCheckData *)arg;

    Memento_Internal_checkFreedBlock(memblk, data);
    if (data->preCorrupt || data->postCorrupt || data->freeCorrupt) {
        if ((data->found & 4) == 0) {
            fprintf(stderr, "Freed blocks:\n");
            data->found |= 4;
        }
        fprintf(stderr, "  ");
        showBlock(memblk, ' ');
        if (data->freeCorrupt) {
            fprintf(stderr, " index %d (address "FMTP") onwards", (int)data->index,
                    &((char *)MEMBLK_TOBLK(memblk))[data->index]);
            if (data->preCorrupt) {
                fprintf(stderr, "+ preguard");
            }
            if (data->postCorrupt) {
                fprintf(stderr, "+ postguard");
            }
        } else {
            if (data->preCorrupt) {
                fprintf(stderr, " preguard");
            }
            if (data->postCorrupt) {
                fprintf(stderr, "%s Postguard",
                        (data->preCorrupt ? "+" : ""));
            }
        }
        VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(Memento_BlkHeader));
        fprintf(stderr, " corrupted.\n"
                "    Block last checked OK at allocation %d. Now %d.\n",
                memblk->lastCheckedOK, memento.sequence);
        if ((memblk->flags & Memento_Flag_Reported) == 0)
        {
            memblk->flags |= Memento_Flag_Reported;
            data->found |= 8;
        }
        VALGRIND_MAKE_MEM_NOACCESS(memblk, sizeof(Memento_BlkHeader));
        data->preCorrupt  = 0;
        data->postCorrupt = 0;
        data->freeCorrupt = 0;
    }
    else
        memblk->lastCheckedOK = memento.sequence;
    return 0;
}
#endif /* MEMENTO_LEAKONLY */

static int Memento_checkAllMemoryLocked(void)
{
#ifndef MEMENTO_LEAKONLY
    BlkCheckData data;

    memset(&data, 0, sizeof(data));
    Memento_appBlocks(&memento.used, Memento_Internal_checkAllAlloced, &data);
    Memento_appBlocks(&memento.free, Memento_Internal_checkAllFreed, &data);
    return data.found;
#else
    return 0;
#endif
}

int Memento_checkAllMemory(void)
{
#ifndef MEMENTO_LEAKONLY
    int ret;

    MEMENTO_LOCK();
    ret = Memento_checkAllMemoryLocked();
    MEMENTO_UNLOCK();
    if (ret & 8) {
        Memento_breakpoint();
        return 1;
    }
#endif
    return 0;
}

int Memento_setParanoia(int i)
{
    memento.paranoia = i;
    if (memento.paranoia > 0)
        memento.countdown = memento.paranoia;
    else
        memento.countdown = -memento.paranoia;
    return i;
}

int Memento_setIgnoreNewDelete(int ignore)
{
    int ret = memento.ignoreNewDelete;
    memento.ignoreNewDelete = ignore;
    return ret;
}

int Memento_paranoidAt(int i)
{
    memento.paranoidAt = i;
    return i;
}

int Memento_getBlockNum(void *b)
{
    Memento_BlkHeader *memblk;
    if (b == NULL)
        return 0;
    memblk = MEMBLK_FROMBLK(b);
    return (memblk->sequence);
}

int Memento_check(void)
{
    int result;

    fprintf(stderr, "Checking memory\n");
    result = Memento_checkAllMemory();
    fprintf(stderr, "Memory checked!\n");
    return result;
}

int Memento_find(void *a)
{
    Memento_BlkHeader *blk;
    int s;
    int flags;

    MEMENTO_LOCK();
    blk = find_enclosing_block(&memento.used, a, &flags);
    if (blk != NULL) {
        fprintf(stderr, "Address "FMTP" is in %sallocated block ",
                a,
                (flags == 1 ? "" : (flags == 2 ? "preguard of " : "postguard of ")));
        s = showBlock(blk, ' ');
        fprintf(stderr, "\n");
        MEMENTO_UNLOCK();
        return s;
    }
    blk = find_enclosing_block(&memento.free, a, &flags);
    if (blk != NULL) {
        fprintf(stderr, "Address "FMTP" is in %sfreed block ",
                a,
                (flags == 1 ? "" : (flags == 2 ? "preguard of " : "postguard of ")));
        s = showBlock(blk, ' ');
        fprintf(stderr, "\n");
        MEMENTO_UNLOCK();
        return s;
    }
    MEMENTO_UNLOCK();
    return 0;
}

void Memento_breakOnFree(void *a)
{
    Memento_BlkHeader *blk;
    int flags;

    MEMENTO_LOCK();
    blk = find_enclosing_block(&memento.used, a, &flags);
    if (blk != NULL) {
        fprintf(stderr, "Will stop when address "FMTP" (in %sallocated block ",
                a,
                (flags == 1 ? "" : (flags == 2 ? "preguard of " : "postguard of ")));
        showBlock(blk, ' ');
        fprintf(stderr, ") is freed\n");
        VALGRIND_MAKE_MEM_DEFINED(blk, sizeof(Memento_BlkHeader));
        blk->flags |= Memento_Flag_BreakOnFree;
        VALGRIND_MAKE_MEM_NOACCESS(blk, sizeof(Memento_BlkHeader));
        MEMENTO_UNLOCK();
        return;
    }
    blk = find_enclosing_block(&memento.free, a, &flags);
    if (blk != NULL) {
        fprintf(stderr, "Can't stop on free; address "FMTP" is in %sfreed block ",
                a,
                (flags == 1 ? "" : (flags == 2 ? "preguard of " : "postguard of ")));
        showBlock(blk, ' ');
        fprintf(stderr, "\n");
        MEMENTO_UNLOCK();
        return;
    }
    fprintf(stderr, "Can't stop on free; address "FMTP" is not in a known block.\n", a);
    MEMENTO_UNLOCK();
}

void Memento_breakOnRealloc(void *a)
{
    Memento_BlkHeader *blk;
    int flags;

    MEMENTO_LOCK();
    blk = find_enclosing_block(&memento.used, a, &flags);
    if (blk != NULL) {
        fprintf(stderr, "Will stop when address "FMTP" (in %sallocated block ",
                a,
                (flags == 1 ? "" : (flags == 2 ? "preguard of " : "postguard of ")));
        showBlock(blk, ' ');
        fprintf(stderr, ") is freed (or realloced)\n");
        VALGRIND_MAKE_MEM_DEFINED(blk, sizeof(Memento_BlkHeader));
        blk->flags |= Memento_Flag_BreakOnFree | Memento_Flag_BreakOnRealloc;
        VALGRIND_MAKE_MEM_NOACCESS(blk, sizeof(Memento_BlkHeader));
        MEMENTO_UNLOCK();
        return;
    }
    blk = find_enclosing_block(&memento.free, a, &flags);
    if (blk != NULL) {
        fprintf(stderr, "Can't stop on free/realloc; address "FMTP" is in %sfreed block ",
                a,
                (flags == 1 ? "" : (flags == 2 ? "preguard of " : "postguard of ")));
        showBlock(blk, ' ');
        fprintf(stderr, "\n");
        MEMENTO_UNLOCK();
        return;
    }
    fprintf(stderr, "Can't stop on free/realloc; address "FMTP" is not in a known block.\n", a);
    MEMENTO_UNLOCK();
}

int Memento_failAt(int i)
{
    memento.failAt = i;
    if ((memento.sequence > memento.failAt) &&
        (memento.failing != 0))
        Memento_startFailing();
    return i;
}

size_t Memento_setMax(size_t max)
{
    memento.maxMemory = max;
    return max;
}

void Memento_startLeaking(void)
{
    if (!memento.inited)
        Memento_init();
    memento.leaking++;
}

void Memento_stopLeaking(void)
{
    memento.leaking--;
}

int Memento_squeezing(void)
{
    return memento.squeezing;
}

int Memento_setVerbose(int x)
{
    memento.verbose = x;
    return x;
}

int Memento_addBacktraceLimitFnname(const char *fnname)
{
    char **ss;
    char *s;
    if (!memento.inited)
        Memento_init();
    ss = MEMENTO_UNDERLYING_REALLOC(
            memento.backtraceLimitFnnames,
            sizeof(*memento.backtraceLimitFnnames) * (memento.backtraceLimitFnnamesNum + 1)
            );
    if (!ss) {
        fprintf(stderr, "Memento_addBacktraceLimitFnname(): out of memory\n");
        return -1;
    }
    memento.backtraceLimitFnnames = ss;
    s = MEMENTO_UNDERLYING_MALLOC(strlen(fnname) + 1);
    if (!s) {
        fprintf(stderr, "Memento_addBacktraceLimitFnname(): out of memory\n");
        return -1;
    }
    memento.backtraceLimitFnnames[memento.backtraceLimitFnnamesNum] = s;
    strcpy(s, fnname);
    memento.backtraceLimitFnnamesNum += 1;
    return 0;
}

int Memento_setAtexitFin(int atexitfin)
{
    if (!memento.inited) {
        Memento_init();
    }
    memento.atexitFin = atexitfin;
    return 0;
}

void *Memento_cpp_new(size_t size)
{
    void *ret;

    if (!memento.inited)
        Memento_init();

    if (memento.ignoreNewDelete)
        return MEMENTO_UNDERLYING_MALLOC(size);

    if (size == 0)
        size = 1;
    MEMENTO_LOCK();
    ret = do_malloc(size, Memento_EventType_new);
    MEMENTO_UNLOCK();
    return ret;
}

void Memento_cpp_delete(void *pointer)
{
    if (!pointer)
        return;

    if (!memento.inited)
        Memento_init();
    if (memento.ignoreNewDelete)
    {
        MEMENTO_UNDERLYING_FREE(pointer);
        return;
    }

    MEMENTO_LOCK();
    do_free(pointer, Memento_EventType_delete);
    MEMENTO_UNLOCK();
}

/* Some C++ systems (apparently) don't provide new[] or delete[]
 * operators. Provide a way to cope with this */
void *Memento_cpp_new_array(size_t size)
{
    void *ret;
    if (!memento.inited)
        Memento_init();

    if (size == 0)
        size = 1;

    if (memento.ignoreNewDelete)
        return MEMENTO_UNDERLYING_MALLOC(size);

    MEMENTO_LOCK();
    ret = do_malloc(size, Memento_EventType_newArray);
    MEMENTO_UNLOCK();
    return ret;
}

void  Memento_cpp_delete_array(void *pointer)
{
    if (memento.ignoreNewDelete)
    {
        MEMENTO_UNDERLYING_FREE(pointer);
        return;
    }

    MEMENTO_LOCK();
    do_free(pointer, Memento_EventType_deleteArray);
    MEMENTO_UNLOCK();
}

#else /* MEMENTO */

/* Just in case anyone has left some debugging code in... */
void (Memento_breakpoint)(void)
{
}

int (Memento_checkBlock)(void *b)
{
    return 0;
}

int (Memento_checkAllMemory)(void)
{
    return 0;
}

int (Memento_check)(void)
{
    return 0;
}

int (Memento_setParanoia)(int i)
{
    return 0;
}

int (Memento_paranoidAt)(int i)
{
    return 0;
}

int (Memento_breakAt)(int i)
{
    return 0;
}

int  (Memento_getBlockNum)(void *i)
{
    return 0;
}

int (Memento_find)(void *a)
{
    return 0;
}

int (Memento_failAt)(int i)
{
    return 0;
}

void (Memento_breakOnFree)(void *a)
{
}

void (Memento_breakOnRealloc)(void *a)
{
}

void *(Memento_takeRef)(void *a)
{
    return a;
}

void *(Memento_dropRef)(void *a)
{
    return a;
}

void *(Memento_adjustRef)(void *a, int adjust)
{
    return a;
}

void *(Memento_reference)(void *a)
{
    return a;
}

#undef Memento_malloc
#undef Memento_free
#undef Memento_realloc
#undef Memento_calloc
#undef Memento_strdup
#undef Memento_asprintf
#undef Memento_vasprintf

void *Memento_malloc(size_t size)
{
    return MEMENTO_UNDERLYING_MALLOC(size);
}

void Memento_free(void *b)
{
    MEMENTO_UNDERLYING_FREE(b);
}

void *Memento_realloc(void *b, size_t s)
{
    return MEMENTO_UNDERLYING_REALLOC(b, s);
}

void *Memento_calloc(size_t n, size_t s)
{
    return MEMENTO_UNDERLYING_CALLOC(n, s);
}

#if !defined(MEMENTO_GS_HACKS) && !defined(MEMENTO_MUPDF_HACKS)
/* Avoid calling strdup, in case our compiler doesn't support it.
 * Yes, I'm looking at you, early Visual Studios. */
char *Memento_strdup(const char *s)
{
    size_t len = strlen(s)+1;
    char *ret = MEMENTO_UNDERLYING_MALLOC(len);
    if (ret != NULL)
        memcpy(ret, s, len);
    return ret;
}

/* Avoid calling asprintf, in case our compiler doesn't support it.
 * Vaguely unhappy about relying on vsnprintf, but... */
int Memento_asprintf(char **ret, const char *format, ...)
{
    va_list va;
    int n;
    int n2;

    va_start(va, format);
    n = vsnprintf(NULL, 0, format, va);
    va_end(va);
    if (n < 0)
        return n;

    *ret = MEMENTO_UNDERLYING_MALLOC(n+1);
    if (*ret == NULL)
        return -1;

    va_start(va, format);
    n2 = vsnprintf(*ret, n + 1, format, va);
    va_end(va);

    return n2;
}

/* Avoid calling vasprintf, in case our compiler doesn't support it.
 * Vaguely unhappy about relying on vsnprintf, but... */
int Memento_vasprintf(char **ret, const char *format, va_list ap)
{
    int n;
    va_list ap2;
    va_copy(ap2, ap);

    n = vsnprintf(NULL, 0, format, ap);
    if (n < 0) {
        va_end(ap2);
        return n;
    }

    *ret = MEMENTO_UNDERLYING_MALLOC(n+1);
    if (*ret == NULL) {
        va_end(ap2);
        return -1;
    }

    n = vsnprintf(*ret, n + 1, format, ap2);
    va_end(ap2);

    return n;
}
#endif

void (Memento_listBlocks)(void)
{
}

void (Memento_listNewBlocks)(void)
{
}

void (Memento_listPhasedBlocks)(void)
{
}

int (Memento_setIgnoreNewDelete)(int ignore)
{
    return 0;
}

size_t (Memento_setMax)(size_t max)
{
    return 0;
}

void (Memento_stats)(void)
{
}

void *(Memento_label)(void *ptr, const char *label)
{
    return ptr;
}

void (Memento_info)(void *addr)
{
}

void (Memento_listBlockInfo)(void)
{
}

void (Memento_blockInfo)(void *ptr)
{
}

void (Memento_startLeaking)(void)
{
}

void (Memento_stopLeaking)(void)
{
}

int (Memento_squeezing)(void)
{
    return 0;
}

int (Memento_setVerbose)(int x)
{
    return x;
}

void Memento_showHash(unsigned int hash)
{
}

#endif /* MEMENTO */

#endif /* MEMENTO_CPP_EXTRAS_ONLY */

/* Everything here is only for C++, and then only if we haven't
 * disabled it. */

#ifndef MEMENTO_NO_CPLUSPLUS
#ifdef __cplusplus

// C++ Operator Veneers - START
void *operator new(size_t size)
{
    return Memento_cpp_new(size);
}
void operator delete(void *pointer)
{
    Memento_cpp_delete(pointer);
}
void *operator new[](size_t size)
{
    return Memento_cpp_new_array(size);
}
void operator delete[](void *pointer)
{
   Memento_cpp_delete_array(pointer);
}

/* Some C++ systems (apparently) don't provide new[] or delete[]
 * operators. Provide a way to cope with this */
#ifndef MEMENTO_CPP_NO_ARRAY_CONSTRUCTORS
void *operator new[](size_t size)
{
    return Memento_cpp_new_array(size);
}

void operator delete[](void *pointer)
{
    Memento_cpp_delete_array(pointer);
}
#endif /* MEMENTO_CPP_NO_ARRAY_CONSTRUCTORS */
// C++ Operator Veneers - END

#endif /* __cplusplus */
#endif /* MEMENTO_NO_CPLUSPLUS */
