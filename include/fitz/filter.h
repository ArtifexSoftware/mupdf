typedef struct fz_filter_s fz_filter;
typedef struct fz_buffer_s fz_buffer;

#define FZ_BUFSIZE (32 * 1024)

#define fz_ioneedin (&fz_kioneedin)
#define fz_ioneedout (&fz_kioneedout)
#define fz_iodone (&fz_kiodone)

extern fz_error fz_kioneedin;
extern fz_error fz_kioneedout;
extern fz_error fz_kiodone;

#define FZ_NEWFILTER(TYPE,VAR,NAME)                                     \
	fz_error * fz_process ## NAME (fz_filter*,fz_buffer*,fz_buffer*);   \
	void fz_drop ## NAME (fz_filter*);                                  \
	TYPE *VAR;                                                          \
	*fp = fz_malloc(sizeof(TYPE));                                      \
	if (!*fp) return fz_outofmem;                                       \
	(*fp)->refs = 1;                                                    \
	(*fp)->process = fz_process ## NAME ;                               \
	(*fp)->drop = fz_drop ## NAME ;                                     \
	(*fp)->consumed = 0;                                                \
	(*fp)->produced = 0;                                                \
	(*fp)->count = 0;                                                   \
	VAR = (TYPE*) *fp

struct fz_filter_s
{
	int refs;
	fz_error* (*process)(fz_filter *filter, fz_buffer *in, fz_buffer *out);
	void (*drop)(fz_filter *filter);
	int consumed;
	int produced;
	int count;
};

struct fz_buffer_s
{
	int refs;
	int ownsdata;
	unsigned char *bp;
	unsigned char *rp;
	unsigned char *wp;
	unsigned char *ep;
	int eof;
};

fz_error *fz_process(fz_filter *f, fz_buffer *in, fz_buffer *out);
fz_filter *fz_keepfilter(fz_filter *f);
void fz_dropfilter(fz_filter *f);

fz_error *fz_newnullfilter(fz_filter **fp, int len);
fz_error *fz_newarc4filter(fz_filter **fp, unsigned char *key, unsigned keylen);
fz_error *fz_newpipeline(fz_filter **fp, fz_filter *head, fz_filter *tail);

fz_error *fz_chainpipeline(fz_filter **fp, fz_filter *head, fz_filter *tail, fz_buffer *buf);
void fz_unchainpipeline(fz_filter *pipe, fz_filter **oldfp, fz_buffer **oldbp);

fz_error *fz_newbuffer(fz_buffer **bufp, int size);
fz_error *fz_newbufferwithdata(fz_buffer **bufp, unsigned char *data, int size);
fz_error *fz_rewindbuffer(fz_buffer *buf);
fz_error *fz_growbuffer(fz_buffer *buf);
fz_buffer *fz_keepbuffer(fz_buffer *buf);
void fz_dropbuffer(fz_buffer *buf);

fz_error *fz_newa85d(fz_filter **filterp, fz_obj *param);
fz_error *fz_newa85e(fz_filter **filterp, fz_obj *param);
fz_error *fz_newahxd(fz_filter **filterp, fz_obj *param);
fz_error *fz_newahxe(fz_filter **filterp, fz_obj *param);
fz_error *fz_newrld(fz_filter **filterp, fz_obj *param);
fz_error *fz_newrle(fz_filter **filterp, fz_obj *param);
fz_error *fz_newdctd(fz_filter **filterp, fz_obj *param);
fz_error *fz_newdcte(fz_filter **filterp, fz_obj *param);
fz_error *fz_newfaxd(fz_filter **filterp, fz_obj *param);
fz_error *fz_newfaxe(fz_filter **filterp, fz_obj *param);
fz_error *fz_newflated(fz_filter **filterp, fz_obj *param);
fz_error *fz_newflatee(fz_filter **filterp, fz_obj *param);
fz_error *fz_newlzwd(fz_filter **filterp, fz_obj *param);
fz_error *fz_newlzwe(fz_filter **filterp, fz_obj *param);
fz_error *fz_newpredictd(fz_filter **filterp, fz_obj *param);
fz_error *fz_newpredicte(fz_filter **filterp, fz_obj *param);
fz_error *fz_newjbig2d(fz_filter **filterp, fz_obj *param);
fz_error *fz_newjpxd(fz_filter **filterp, fz_obj *param);

void fz_pushbackahxd(fz_filter *filter, fz_buffer *in, fz_buffer *out, int n);

