/* Copyright (C) 2011 Artifex Software, Inc.
   All Rights Reserved.

   This software is provided AS-IS with no warranty, either express or
   implied.

   This software is distributed under license and may not be copied, modified
   or distributed except as expressly authorized under the terms of that
   license.  Refer to licensing information at http://www.artifex.com/
   or contact Artifex Software, Inc.,  7 Mt. Lassen Drive - Suite A-134,
   San Rafael, CA  94903, U.S.A., +1(415)492-9861, for further information.
*/

/* Inspired by Fortify by Simon P Bullen. */

/* Set the following if you're only looking for leaks, not memory overwrites
 * to speed the operation */
#undef MEMENTO_LEAKONLY

#ifndef MEMENTO_STACKTRACE_METHOD
#ifdef __GNUC__
#define MEMENTO_STACKTRACE_METHOD 1
#endif
#endif

/* Don't keep blocks around if they'd mean losing more than a quarter of
 * the freelist. */
#define MEMENTO_FREELIST_MAX_SINGLE_BLOCK (MEMENTO_FREELIST_MAX/4)

#define COMPILING_MEMENTO_C
#include "memento.h"
#include <stdio.h>
#include <stdlib.h>

#if defined(__linux__)
#define MEMENTO_HAS_FORK
#elif defined(__APPLE__) && defined(__MACH__)
#define MEMENTO_HAS_FORK
#endif

/* Define the underlying allocators, just in case */
void *MEMENTO_UNDERLYING_MALLOC(size_t);
void MEMENTO_UNDERLYING_FREE(void *);
void *MEMENTO_UNDERLYING_REALLOC(void *,size_t);
void *MEMENTO_UNDERLYING_CALLOC(size_t,size_t);

/* And some other standard functions we use. We don't include the header
 * files, just in case they pull in unexpected others. */
int atoi(const char *);
char *getenv(const char *);
//void *memset(void *,int,size_t);
//int atexit(void (*)(void));

#ifdef MEMENTO

#ifdef HAVE_VALGRIND
#include "valgrind/memcheck.h"
#else
#define VALGRIND_MAKE_MEM_NOACCESS(p,s)  do { } while (0==1)
#define VALGRIND_MAKE_MEM_UNDEFINED(p,s)  do { } while (0==1)
#define VALGRIND_MAKE_MEM_DEFINED(p,s)  do { } while (0==1)
#endif

enum {
    Memento_PreSize  = 16,
    Memento_PostSize = 16
};

typedef struct Memento_BlkHeader Memento_BlkHeader;

struct Memento_BlkHeader
{
    size_t             rawsize;
    int                sequence;
    int                lastCheckedOK;
    Memento_BlkHeader *next;
    char               preblk[Memento_PreSize];
};

/* In future this could (should) be a smarter data structure, like, say,
 * splay trees. For now, we use a list.
 */
typedef struct Memento_Blocks
{
    Memento_BlkHeader  *head;
    Memento_BlkHeader **tail;
} Memento_Blocks;

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
    int            squeezeAt;
    int            squeezing;
    int            squeezed;
    size_t         alloc;
    size_t         peakAlloc;
    size_t         totalAlloc;
    size_t         numMallocs;
    size_t         numFrees;
    size_t         numReallocs;
} globals;


#define MEMENTO_EXTRASIZE (sizeof(Memento_BlkHeader) + Memento_PostSize)

/* Round up size S to the next multiple of N (where N is a power of 2) */
#define MEMENTO_ROUNDUP(S,N) ((S + N-1)&~(N-1))

#define MEMBLK_SIZE(s) MEMENTO_ROUNDUP(s + MEMENTO_EXTRASIZE, MEMENTO_MAXALIGN)

#define MEMBLK_FROMBLK(B)   (&((Memento_BlkHeader*)(void *)(B))[-1])
#define MEMBLK_TOBLK(B)     ((void*)(&((Memento_BlkHeader*)(void*)(B))[1]))
#define MEMBLK_POSTPTR(B) \
          (&((char *)(void *)(B))[(B)->rawsize + sizeof(Memento_BlkHeader)])

void Memento_breakpoint(void)
{
    /* A handy externally visible function for breakpointing */
#if 0 /* Enable this to force automatic breakpointing */
#ifdef DEBUG
#ifdef _MSC_VER
    __asm int 3;
#endif
#endif
#endif
}

static void Memento_addBlockHead(Memento_Blocks    *blks,
                                 Memento_BlkHeader *b,
                                 int                type)
{
    if (blks->tail == &blks->head) {
        /* Adding into an empty list, means the tail changes too */
        blks->tail = &b->next;
    }
    b->next    = blks->head;
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
    VALGRIND_MAKE_MEM_DEFINED(blks->tail, sizeof(Memento_BlkHeader *));
    *blks->tail = b;
    blks->tail  = &b->next;
    b->next = NULL;
    VALGRIND_MAKE_MEM_NOACCESS(blks->tail, sizeof(Memento_BlkHeader *));
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

typedef struct BlkCheckData {
    int found;
    int preCorrupt;
    int postCorrupt;
    int freeCorrupt;
    int index;
} BlkCheckData;

static int Memento_Internal_checkAllocedBlock(Memento_BlkHeader *b, void *arg)
{
#ifndef MEMENTO_LEAKONLY
    int           i;
    char         *p;
    int           corrupt = 0;
    BlkCheckData *data = (BlkCheckData *)arg;

    p = b->preblk;
    i = Memento_PreSize;
    do {
        corrupt |= (*p++ ^ (char)MEMENTO_PREFILL);
    } while (--i);
    if (corrupt) {
        data->preCorrupt = 1;
    }
    p = MEMBLK_POSTPTR(b);
    i = Memento_PreSize;
    do {
        corrupt |= (*p++ ^ (char)MEMENTO_POSTFILL);
    } while (--i);
    if (corrupt) {
        data->postCorrupt = 1;
    }
    if ((data->freeCorrupt | data->preCorrupt | data->postCorrupt) == 0) {
        b->lastCheckedOK = globals.sequence;
    }
    data->found |= 1;
#endif
    return 0;
}

static int Memento_Internal_checkFreedBlock(Memento_BlkHeader *b, void *arg)
{
#ifndef MEMENTO_LEAKONLY
    int           i;
    char         *p;
    BlkCheckData *data = (BlkCheckData *)arg;

    p = MEMBLK_TOBLK(b);
    i = b->rawsize;
    /* Attempt to speed this up by checking an (aligned) int at a time */
    do {
        if (((size_t)p) & 1) {
            if (*p++ != (char)MEMENTO_FREEFILL)
                break;
            i--;
            if (i == 0)
                break;
        }
        if ((i >= 2) && (((size_t)p) & 2)) {
            if (*(short *)p != (short)(MEMENTO_FREEFILL | (MEMENTO_FREEFILL<<8)))
                goto mismatch;
            p += 2;
            i -= 2;
            if (i == 0)
                break;
        }
        i -= 4;
        while (i >= 0) {
            if (*(int *)p != (MEMENTO_FREEFILL |
                              (MEMENTO_FREEFILL<<8) |
                              (MEMENTO_FREEFILL<<16) |
                              (MEMENTO_FREEFILL<<24)))
                goto mismatch;
            p += 4;
            i -= 4;
        }
        i += 4;
        if ((i >= 2) && (((size_t)p) & 2)) {
            if (*(short *)p != (short)(MEMENTO_FREEFILL | (MEMENTO_FREEFILL<<8)))
                goto mismatch;
            p += 2;
            i -= 2;
        }
mismatch:
        while (i) {
            if (*p++ != (char)MEMENTO_FREEFILL)
                break;
            i--;
        }
    } while (0);
    if (i) {
        data->freeCorrupt = 1;
        data->index       = b->rawsize-i;
    }
    return Memento_Internal_checkAllocedBlock(b, arg);
#else
    return 0;
#endif
}

static void Memento_removeBlock(Memento_Blocks    *blks,
                                Memento_BlkHeader *b)
{
    Memento_BlkHeader *head = blks->head;
    Memento_BlkHeader *prev = NULL;
    while ((head) && (head != b)) {
        VALGRIND_MAKE_MEM_DEFINED(head, sizeof(*head));
        prev = head;
        head = head->next;
        VALGRIND_MAKE_MEM_NOACCESS(prev, sizeof(*prev));
    }
    if (head == NULL) {
        /* FAIL! Will have been reported to user earlier, so just exit. */
        return;
    }
    if (*blks->tail == head) {
        /* Removing the tail of the list */
        if (prev == NULL) {
            /* Which is also the head */
            blks->tail = &blks->head;
        } else {
            /* Which isn't the head */
            blks->tail = &prev->next;
        }
    }
    if (prev == NULL) {
        /* Removing from the head of the list */
        VALGRIND_MAKE_MEM_DEFINED(head, sizeof(*head));
        blks->head = head->next;
        VALGRIND_MAKE_MEM_NOACCESS(head, sizeof(*head));
    } else {
        /* Removing from not-the-head */
        VALGRIND_MAKE_MEM_DEFINED(head, sizeof(*head));
        VALGRIND_MAKE_MEM_DEFINED(prev, sizeof(*prev));
        prev->next = head->next;
        VALGRIND_MAKE_MEM_NOACCESS(head, sizeof(*head));
        VALGRIND_MAKE_MEM_NOACCESS(prev, sizeof(*prev));
    }
}

static int Memento_Internal_makeSpace(size_t space)
{
    /* If too big, it can never go on the freelist */
    if (space > MEMENTO_FREELIST_MAX_SINGLE_BLOCK)
        return 0;
    /* Pretend we added it on. */
    globals.freeListSize += space;
    /* Ditch blocks until it fits within our limit */
    while (globals.freeListSize > MEMENTO_FREELIST_MAX) {
        Memento_BlkHeader *head = globals.free.head;
        VALGRIND_MAKE_MEM_DEFINED(head, sizeof(*head));
        globals.free.head = head->next;
        globals.freeListSize -= MEMBLK_SIZE(head->rawsize);
        MEMENTO_UNDERLYING_FREE(head);
    }
    /* Make sure we haven't just completely emptied the free list */
    /* (This should never happen, but belt and braces... */
    if (globals.free.head == NULL)
        globals.free.tail = &globals.free.head;
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

static int Memento_appBlock(Memento_Blocks    *blks,
                            int                (*app)(Memento_BlkHeader *,
                                                      void *),
                            void              *arg,
                            Memento_BlkHeader *b)
{
    Memento_BlkHeader *head = blks->head;
    Memento_BlkHeader *next;
    int                result;
    while (head && head != b) {
        VALGRIND_MAKE_MEM_DEFINED(head, sizeof(Memento_BlkHeader));
        next = head->next;
        VALGRIND_MAKE_MEM_NOACCESS(MEMBLK_POSTPTR(head), Memento_PostSize);
        head = next;
    }
    if (head == b) {
        VALGRIND_MAKE_MEM_DEFINED(head, sizeof(Memento_BlkHeader));
        VALGRIND_MAKE_MEM_DEFINED(MEMBLK_TOBLK(head),
                                  head->rawsize + Memento_PostSize);
        result = app(head, arg);
        VALGRIND_MAKE_MEM_NOACCESS(MEMBLK_POSTPTR(head), Memento_PostSize);
        VALGRIND_MAKE_MEM_NOACCESS(head, sizeof(Memento_BlkHeader));
        return result;
    }
    return 0;
}

static int Memento_listBlock(Memento_BlkHeader *b,
                             void              *arg)
{
    int *counts = (int *)arg;
    fprintf(stderr, "    0x%p:(size=%d,num=%d)\n",
            MEMBLK_TOBLK(b), (int)b->rawsize, b->sequence);
    counts[0]++;
    counts[1]+= b->rawsize;
    return 0;
}

static void Memento_listBlocks(void) {
    int counts[2];
    counts[0] = 0;
    counts[1] = 0;
    fprintf(stderr, "Allocated blocks:\n");
    Memento_appBlocks(&globals.used, Memento_listBlock, &counts[0]);
    fprintf(stderr, "  Total number of blocks = %d\n", counts[0]);
    fprintf(stderr, "  Total size of blocks = %d\n", counts[1]);
}

static void Memento_fin(void)
{
    Memento_checkAllMemory();
    fprintf(stderr, "Total memory malloced = %d bytes\n", globals.totalAlloc);
    fprintf(stderr, "Peak memory malloced = %d bytes\n", globals.peakAlloc);
    fprintf(stderr, "%d mallocs, %d frees, %d reallocs\n", globals.numMallocs,
            globals.numFrees, globals.numReallocs);
    fprintf(stderr, "Average allocation size %d bytes\n",
            globals.totalAlloc/globals.numMallocs);
    if (globals.used.head) {
        Memento_listBlocks();
        Memento_breakpoint();
    }
    if (globals.squeezed) {
        fprintf(stderr, "Memory squeezing @ %d complete\n", globals.squeezed);
    }
}

static void Memento_inited(void)
{
    /* A good place for a breakpoint */
}

static void Memento_init(void)
{
    char *env;
    memset(&globals, 0, sizeof(globals));
    globals.inited    = 1;
    globals.used.head = NULL;
    globals.used.tail = &globals.used.head;
    globals.free.head = NULL;
    globals.free.tail = &globals.free.head;
    globals.sequence  = 0;
    globals.countdown = 1024;

    env = getenv("MEMENTO_FAILAT");
    globals.failAt = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_PARANOIA");
    globals.paranoia = (env ? atoi(env) : 0);
    if (globals.paranoia == 0)
        globals.paranoia = 1024;

    env = getenv("MEMENTO_PARANOIDAT");
    globals.paranoidAt = (env ? atoi(env) : 0);

    env = getenv("MEMENTO_SQUEEZEAT");
    globals.squeezeAt = (env ? atoi(env) : 0);

    atexit(Memento_fin);

    Memento_inited();
}

static void Memento_event(void)
{
    globals.sequence++;
    if ((globals.sequence >= globals.paranoidAt) && (globals.paranoidAt != 0)) {
        globals.paranoia = 1;
        globals.countdown = 1;
    }
    if ((globals.sequence >= globals.failAt) && (globals.failAt != 0)) {
        globals.failing = 1;
    }
    if ((globals.sequence >= globals.squeezeAt) && (globals.squeezeAt != 0)) {
        globals.squeezing = 1;
    }

    if (--globals.countdown == 0) {
        Memento_checkAllMemory();
        globals.countdown = globals.paranoia;
    }

    if (globals.sequence == globals.breakAt) {
        fprintf(stderr, "Breaking at event %d\n", globals.breakAt);
        Memento_breakpoint();
    }
}

int Memento_breakAt(int event)
{
    globals.breakAt = event;
    return event;
}

#ifdef MEMENTO_HAS_FORK
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#ifdef MEMENTO_STACKTRACE_METHOD
#if MEMENTO_STACKTRACE_METHOD == 1
#include <signal.h>
#endif
#endif

/* FIXME: Find some portable way of getting this */
/* MacOSX has 10240, Ubuntu seems to have 256 */
#define OPEN_MAX 10240

/* stashed_map[j] = i means that filedescriptor i-1 was duplicated to j */
int stashed_map[OPEN_MAX];

static void Memento_signal(void)
{
    fprintf(stderr, "SEGV after Memory squeezing @ %d\n", globals.squeezed);

#ifdef MEMENTO_STACKTRACE_METHOD
#if MEMENTO_STACKTRACE_METHOD == 1
    {
      void *array[100];
      size_t size;

      size = backtrace(array, 100);
      fprintf(stderr, "------------------------------------------------------------------------\n");
      fprintf(stderr, "Backtrace:\n");
      backtrace_symbols_fd(array, size, 2);
      fprintf(stderr, "------------------------------------------------------------------------\n");
    }
#endif
#endif

    exit(1);
}

static void squeeze(void)
{
    pid_t pid;
    int i, status;

    fprintf(stderr, "Memory squeezing @ %d\n", globals.sequence);

    /* When we fork below, the child is going to snaffle all our file pointers
     * and potentially corrupt them. Let's make copies of all of them before
     * we fork, so we can restore them when we restart. */
    for (i = 0; i < OPEN_MAX; i++) {
        if (stashed_map[i] == 0) {
            int j = dup(i);
            stashed_map[j] = i+1;
        }
    }

    pid = fork();
    if (pid == 0) {
        /* Child */
        signal(SIGSEGV, Memento_signal);
        /* We must fail all new allocations from here */
        globals.failing  = 1;
        globals.squeezed = globals.sequence;
        return;
    }

    /* Wait for pid to finish */
    waitpid(pid, &status, 0);

    /* Put the files back */
    for (i = 0; i < OPEN_MAX; i++) {
        if (stashed_map[i] != 0) {
            dup2(i, stashed_map[i]-1);
            close(i);
            stashed_map[i] = 0;
        }
    }
}
#else
void squeeze(void)
{
    fprintf(stderr, "Memento memory squeezing disabled as no fork!\n");
}
#endif

int Memento_failThisEvent(void)
{
    if (!globals.inited)
        Memento_init();

    Memento_event();

    if ((globals.squeezing) && (!globals.squeezed))
        squeeze();

    return globals.failing;
}

void *Memento_malloc(size_t s)
{
    Memento_BlkHeader *memblk;
    size_t             smem = MEMBLK_SIZE(s);

    if (!globals.inited)
        Memento_init();

    Memento_event();

    if ((globals.squeezing) && (!globals.squeezed))
        squeeze();

    if (globals.failing)
        return NULL;

    if (s == 0)
        return NULL;

    globals.numMallocs++;

    memblk = MEMENTO_UNDERLYING_MALLOC(smem);
    if (memblk == NULL)
        return NULL;

    globals.alloc      += s;
    globals.totalAlloc += s;
    if (globals.peakAlloc < globals.alloc)
        globals.peakAlloc = globals.alloc;
#ifndef MEMENTO_LEAKONLY
    memset(MEMBLK_TOBLK(memblk), MEMENTO_ALLOCFILL, s);
#endif
    memblk->rawsize       = s;
    memblk->sequence      = globals.sequence;
    memblk->lastCheckedOK = memblk->sequence;
    Memento_addBlockHead(&globals.used, memblk, 0);
    return MEMBLK_TOBLK(memblk);
}

void *Memento_calloc(size_t n, size_t s)
{
    void *block = Memento_malloc(n*s);

    if (block)
        memset(block, 0, n*s);
    return block;
}

static int checkBlock(Memento_BlkHeader *memblk, const char *action)
{
#ifndef MEMENTO_LEAKONLY
    BlkCheckData data;

    memset(&data, 0, sizeof(data));
    Memento_appBlock(&globals.used, Memento_Internal_checkAllocedBlock,
                     &data, memblk);
    if (!data.found) {
        /* Failure! */
        fprintf(stderr, "Attempt to %s block 0x%p(size=%d,num=%d) not on allocated list!\n",
                action, memblk, memblk->rawsize, memblk->sequence);
        Memento_breakpoint();
        return 1;
    } else if (data.preCorrupt || data.postCorrupt) {
        fprintf(stderr, "Block 0x%p(size=%d,num=%d) found to be corrupted on %s!\n",
                action, memblk->rawsize, memblk->sequence, action);
        if (data.preCorrupt) {
            fprintf(stderr, "Preguard corrupted\n");
        }
        if (data.postCorrupt) {
            fprintf(stderr, "Postguard corrupted\n");
        }
        fprintf(stderr, "Block last checked OK at allocation %d. Now %d.\n",
                memblk->lastCheckedOK, globals.sequence);
        Memento_breakpoint();
        return 1;
    }
#endif
    return 0;
}

void Memento_free(void *blk)
{
    Memento_BlkHeader *memblk;

    if (!globals.inited)
        Memento_init();

    Memento_event();

    if (blk == NULL)
        return;

    memblk = MEMBLK_FROMBLK(blk);
    VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
    if (checkBlock(memblk, "free"))
        return;

    VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
    globals.alloc -= memblk->rawsize;
    globals.numFrees++;

    Memento_removeBlock(&globals.used, memblk);

    VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
    if (Memento_Internal_makeSpace(MEMBLK_SIZE(memblk->rawsize))) {
        VALGRIND_MAKE_MEM_DEFINED(memblk, sizeof(*memblk));
        VALGRIND_MAKE_MEM_DEFINED(MEMBLK_TOBLK(memblk),
                                  memblk->rawsize + Memento_PostSize);
#ifndef MEMENTO_LEAKONLY
        memset(MEMBLK_TOBLK(memblk), MEMENTO_FREEFILL, memblk->rawsize);
#endif
        Memento_addBlockTail(&globals.free, memblk, 1);
    } else {
        MEMENTO_UNDERLYING_FREE(memblk);
    }
}

void *Memento_realloc(void *blk, size_t newsize)
{
    Memento_BlkHeader *memblk, *newmemblk;
    size_t             newsizemem;

    if (!globals.inited)
        Memento_init();

    if (blk == NULL)
        return Memento_malloc(newsize);
    if (newsize == 0) {
        Memento_free(blk);
        return NULL;
    }
    if ((globals.squeezing) && (!globals.squeezed))
        squeeze();
    if (globals.failing)
        return NULL;

    memblk     = MEMBLK_FROMBLK(blk);

    Memento_event();

    if (checkBlock(memblk, "realloc"))
        return NULL;

    newsizemem = MEMBLK_SIZE(newsize);
    Memento_removeBlock(&globals.used, memblk);
    newmemblk  = MEMENTO_UNDERLYING_REALLOC(memblk, newsizemem);
    if (newmemblk == NULL)
    {
        Memento_addBlockHead(&globals.used, memblk, 2);
        return NULL;
    }
    globals.numReallocs++;
    globals.totalAlloc += newsize;
    globals.alloc      -= newmemblk->rawsize;
    globals.alloc      += newsize;
    if (globals.peakAlloc < globals.alloc)
        globals.peakAlloc = globals.alloc;
    if (newmemblk->rawsize < newsize) {
        char *newbytes = ((char *)MEMBLK_TOBLK(newmemblk))+newmemblk->rawsize;
#ifndef MEMENTO_LEAKONLY
        memset(newbytes, MEMENTO_ALLOCFILL, newsize - newmemblk->rawsize);
#endif
        VALGRIND_MAKE_MEM_UNDEFINED(newbytes, newsize - newmemblk->rawsize);
    }
    newmemblk->rawsize = newsize;
#ifndef MEMENTO_LEAKONLY
    memset(newmemblk->preblk, MEMENTO_PREFILL, Memento_PreSize);
    memset(MEMBLK_POSTPTR(newmemblk), MEMENTO_POSTFILL, Memento_PostSize);
#endif
    Memento_addBlockHead(&globals.used, newmemblk, 2);
    return MEMBLK_TOBLK(newmemblk);
}

int Memento_checkBlock(void *blk)
{
    Memento_BlkHeader *memblk;

    if (blk == NULL)
        return 0;
    memblk = MEMBLK_FROMBLK(blk);
    return checkBlock(memblk, "check");
}

static int Memento_Internal_checkAllAlloced(Memento_BlkHeader *memblk, void *arg)
{
    BlkCheckData *data = (BlkCheckData *)arg;

    Memento_Internal_checkAllocedBlock(memblk, data);
    if (data->preCorrupt || data->postCorrupt) {
        if ((data->found & 2) == 0) {
            fprintf(stderr, "Allocated blocks:\n");
            data->found |= 2;
        }
        fprintf(stderr, "  Block 0x%p(size=%d,num=%d)",
                memblk, memblk->rawsize, memblk->sequence);
        if (data->preCorrupt) {
            fprintf(stderr, " Preguard ");
        }
        if (data->postCorrupt) {
            fprintf(stderr, "%s Postguard ",
                    (data->preCorrupt ? "&" : ""));
        }
        fprintf(stderr, "corrupted.\n    "
                "Block last checked OK at allocation %d. Now %d.\n",
                memblk->lastCheckedOK, globals.sequence);
        data->preCorrupt  = 0;
        data->postCorrupt = 0;
        data->freeCorrupt = 0;
    }
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
        fprintf(stderr, "  0x%p(size=%d,num=%d) ",
                MEMBLK_TOBLK(memblk), memblk->rawsize, memblk->sequence);
        if (data->freeCorrupt) {
            fprintf(stderr, "index %d (address 0x%p) onwards ", data->index,
                    &((char *)MEMBLK_TOBLK(memblk))[data->index]);
            if (data->preCorrupt) {
                fprintf(stderr, "+ preguard ");
            }
            if (data->postCorrupt) {
                fprintf(stderr, "+ postguard ");
            }
        } else {
            if (data->preCorrupt) {
                fprintf(stderr, " preguard ");
            }
            if (data->postCorrupt) {
                fprintf(stderr, "%s Postguard ",
                        (data->preCorrupt ? "+" : ""));
            }
        }
        fprintf(stderr, "corrupted.\n    "
                "Block last checked OK at allocation %d. Now %d.\n",
                memblk->lastCheckedOK, globals.sequence);
        data->preCorrupt  = 0;
        data->postCorrupt = 0;
        data->freeCorrupt = 0;
    }
    return 0;
}

int Memento_checkAllMemory(void)
{
#ifndef MEMENTO_LEAKONLY
    BlkCheckData data;

    memset(&data, 0, sizeof(data));
    Memento_appBlocks(&globals.used, Memento_Internal_checkAllAlloced, &data);
    Memento_appBlocks(&globals.free, Memento_Internal_checkAllFreed, &data);
    if (data.found & 6) {
        Memento_breakpoint();
        return 1;
    }
#endif
    return 0;
}

int Memento_setParanoia(int i)
{
    globals.paranoia = i;
    globals.countdown = globals.paranoia;
    return i;
}

int Memento_paranoidAt(int i)
{
    globals.paranoidAt = i;
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

typedef struct findBlkData {
    void              *addr;
    Memento_BlkHeader *blk;
    int                flags;
} findBlkData;

static int Memento_containsAddr(Memento_BlkHeader *b,
                                void *arg)
{
    findBlkData *data = (findBlkData *)arg;
    char *blkend = &((char *)MEMBLK_TOBLK(b))[b->rawsize];
    if ((MEMBLK_TOBLK(b) <= data->addr) &&
        ((void *)blkend > data->addr)) {
        data->blk = b;
        data->flags = 1;
        return 1;
    }
    if (((void *)b <= data->addr) &&
        (MEMBLK_TOBLK(b) > data->addr)) {
        data->blk = b;
        data->flags = 2;
        return 1;
    }
    if (((void *)blkend <= data->addr) &&
        ((void *)(blkend + Memento_PostSize) > data->addr)) {
        data->blk = b;
        data->flags = 3;
        return 1;
    }
    return 0;
}

int Memento_find(void *a)
{
    findBlkData data;

    data.addr  = a;
    data.blk   = NULL;
    data.flags = 0;
    Memento_appBlocks(&globals.used, Memento_containsAddr, &data);
    if (data.blk) {
        fprintf(stderr, "Address 0x%p is in %sallocated block 0x%p(size=%d,num=%d)\n",
                data.addr,
                (data.flags == 1 ? "" : (data.flags == 2 ?
                                         "preguard of " : "postguard of ")),
                MEMBLK_TOBLK(data.blk), data.blk->rawsize, data.blk->sequence);
        return data.blk->sequence;
    }
    data.blk   = NULL;
    data.flags = 0;
    Memento_appBlocks(&globals.free, Memento_containsAddr, &data);
    if (data.blk) {
        fprintf(stderr, "Address 0x%p is in %sfreed block 0x%p(size=%d,num=%d)\n",
                data.addr,
                (data.flags == 1 ? "" : (data.flags == 2 ?
                                         "preguard of " : "postguard of ")),
                MEMBLK_TOBLK(data.blk), data.blk->rawsize, data.blk->sequence);
        return data.blk->sequence;
    }
    return 0;
}

int Memento_failAt(int i)
{
    globals.failAt = i;
    if ((globals.sequence > globals.failAt) &&
        (globals.failing != 0))
        globals.failing = 1;
    return i;
}

#else

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

#undef Memento_malloc
#undef Memento_free
#undef Memento_realloc
#undef Memento_calloc

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


#endif
