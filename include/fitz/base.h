#undef nil
#define nil ((void*)0)

#undef offsetof
#define offsetof(s, m) (unsigned long)(&(((s*)0)->m))

#undef ABS
#define ABS(x) ( (x) < 0 ? -(x) : (x) )

#undef MAX
#define MAX(a,b) ( (a) > (b) ? (a) : (b) )

#undef MIN
#define MIN(a,b) ( (a) < (b) ? (a) : (b) )

#undef CLAMP
#define CLAMP(x,a,b) ( (x) > (b) ? (b) : ( (x) < (a) ? (a) : (x) ) )

#define MAX4(a,b,c,d) MAX(MAX(a,b), MAX(c,d))
#define MIN4(a,b,c,d) MIN(MIN(a,b), MIN(c,d))

#define STRIDE(n, bcp) (((bpc) * (n) + 7) / 8)

typedef struct fz_error_s fz_error;

struct fz_error_s
{
	int nrefs;
	char msg[184];
	char file[32];
	char func[32];
	int line;
};

#define fz_outofmem (&fz_koutofmem)
extern fz_error fz_koutofmem;

#ifdef WIN32
#define fz_throw(...) fz_throw0(__FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#else
#define fz_throw(fmt, ...) fz_throw0(__func__, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#endif
fz_error *fz_throw0(const char *func, const char *file, int line, char *fmt, ...);

void fz_warn(char *fmt, ...);
void fz_abort(fz_error *eo);
void fz_droperror(fz_error *eo);

typedef struct fz_memorycontext_s fz_memorycontext;

struct fz_memorycontext_s
{
	void * (*malloc)(fz_memorycontext *, int);
	void * (*realloc)(fz_memorycontext *, void *, int);
	void (*free)(fz_memorycontext *, void *);
};

fz_memorycontext *fz_currentmemorycontext(void);
void fz_setmemorycontext(fz_memorycontext *memorycontext);

void *fz_malloc(int n);
void *fz_realloc(void *p, int n);
void fz_free(void *p);

