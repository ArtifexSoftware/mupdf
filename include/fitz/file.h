typedef struct fz_file_s fz_file;

enum { FZ_READ, FZ_WRITE, FZ_APPEND };

struct fz_file_s
{
	int mode;	/* FZ_READ or FZ_WRITE */
	int fd;
	int depth;
	fz_filter *filter;
	fz_buffer *in;
	fz_buffer *out;
	fz_error *error;
};

fz_error *fz_openfile(fz_file **filep, char *path, int mode);
fz_error *fz_openbuffer(fz_file **filep, fz_buffer *buf, int mode);
fz_error *fz_pushfilter(fz_file *file, fz_filter *filter);
void fz_popfilter(fz_file *file);
void fz_closefile(fz_file *file);
fz_error *fz_ferror(fz_file *f);

int fz_seek(fz_file *f, int ofs, int whence);
int fz_tell(fz_file *f);

int fz_readbyte(fz_file *f);
int fz_peekbyte(fz_file *f);
int fz_readline(fz_file *f, char *buf, int n);
int fz_read(fz_file *f, char *buf, int n);

fz_error *fz_readfile(fz_buffer **bufp, fz_file *file);

int fz_printstring(fz_file *f, char *s);
int fz_printobj(fz_file *f, fz_obj *o, int tight);
int fz_print(fz_file *f, char *fmt, ...);
int fz_write(fz_file *f, char *buf, int n);
int fz_flush(fz_file *f);

