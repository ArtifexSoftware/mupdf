typedef struct fz_file_s fz_file;

struct fz_file_s
{
	int mode;	/* O_RDONLY or O_WRONLY */
	int fd;
	int depth;
	fz_filter *filter;
	fz_buffer *in;
	fz_buffer *out;
	fz_error *error;
};

fz_error *fz_openfile(fz_file **filep, char *path, int mode);
fz_error *fz_pushfilter(fz_file *file, fz_filter *filter);
void fz_popfilter(fz_file *file);
void fz_closefile(fz_file *file);

int fz_seek(fz_file *f, int ofs);
int fz_tell(fz_file *f);

int fz_readbyte(fz_file *f);
int fz_peekbyte(fz_file *f);
int fz_readline(fz_file *f, char *buf, int n);
int fz_read(fz_file *f, char *buf, int n);

int fz_write(fz_file *f, char *buf, int n);
int fz_flush(fz_file *f);

fz_error *fz_readfile(unsigned char **bufp, int *lenp, fz_file *file);

fz_error *fz_ferror(fz_file *f);

