#include <fitz.h>

/* TODO: nil filter on write */

fz_error *
fz_ferror(fz_file *f)
{
	fz_error *e = f->error;
	f->error = nil;
	return e;
}

fz_error *
fz_openfile(fz_file **filep, char *path, int mode)
{
	fz_error *error;
	fz_file *file;
	int fd;

	assert(mode == O_RDONLY || mode == O_WRONLY);

	file = *filep = fz_malloc(sizeof(fz_file));
	if (!file)
		return fz_outofmem;

	fd = open(path, mode, 0);
	if (fd == -1)
		return fz_throw("ioerror: open '%s': %s", path, strerror(errno));

	file->mode = mode;
	file->fd = fd;
	file->depth = 0;
	file->error = nil;
	file->filter = nil;
	file->in = nil;
	file->out = nil;

	error = fz_newbuffer(&file->in, FZ_BUFSIZE);
	if (error)
		goto cleanup;

	error = fz_newbuffer(&file->out, FZ_BUFSIZE);
	if (error)
		goto cleanup;

	return nil;

cleanup:
	close(fd);
	fz_free(file->out);
	fz_free(file->in);
	fz_free(file);
	*filep = nil;
	return error;
}

void
fz_closefile(fz_file *file)
{
	assert(file->depth == 0);

	if (file->mode == O_WRONLY)
		fz_flush(file);

	if (file->error)
	{
		fz_warn("%s", file->error->msg);
		fz_freeerror(file->error);
		file->error = nil;
	}

	close(file->fd);

	if (file->filter) fz_freefilter(file->filter);
	fz_freebuffer(file->in);
	fz_freebuffer(file->out);
	fz_free(file);
}

fz_error *
fz_pushfilter(fz_file *file, fz_filter *filter)
{
	fz_error *error;
	fz_buffer *buf;

	if (file->depth == 0)
	{
		buf = file->out;
		file->out = file->in;
		file->in = buf;

		file->out->rp = file->out->bp;
		file->out->wp = file->out->bp;
		file->out->eof = 0;

		file->filter = filter;
	}
	else
	{
		error = fz_chainpipeline(&file->filter, file->filter, filter, file->out);
		if (error)
			return error;

		error = fz_newbuffer(&file->out, FZ_BUFSIZE);
		if (error)
		{
			fz_unchainpipeline(file->filter, &file->filter, &file->out);
			return error;
		}
	}

	file->depth ++;

	return nil;
}

void
fz_popfilter(fz_file *file)
{
	fz_buffer *buf;

	assert(file->depth > 0);

	if (file->mode == O_WRONLY)
		fz_flush(file);

	if (file->error)
	{
		fz_warn("%s", file->error->msg);
		fz_freeerror(file->error);
		file->error = nil;
	}

	if (file->depth == 1)
	{
		fz_freefilter(file->filter);
		file->filter = nil;

		buf = file->out;
		file->out = file->in;
		file->in = buf;

		file->in->rp = file->in->bp;
		file->in->wp = file->in->bp;
		file->in->eof = 0;
	}
	else
	{
		fz_freebuffer(file->out);
		fz_unchainpipeline(file->filter, &file->filter, &file->out);
	}

	file->depth --;
}

int
fz_seek(fz_file *f, int ofs)
{
	int t;
	int c;

	assert(f->mode == O_RDONLY);

	if (f->filter)
	{
		if (ofs < fz_tell(f))
		{
			f->error = fz_throw("ioerror: cannot seek backwards in filter");
			return -1;
		}
		while (fz_tell(f) < ofs)
		{
			c = fz_readbyte(f);
			if (c == EOF)
				return -1;
		}
		return 0;
	}

	t = lseek(f->fd, ofs, 0);
	if (t == -1)
	{
		f->error = fz_throw("ioerror: lseek: %s", strerror(errno));
		return -1;
	}

	f->out->rp = f->out->bp;
	f->out->wp = f->out->bp;
	f->out->eof = 0;

	return 0;
}

int
fz_tell(fz_file *f)
{
	int t;

	if (f->filter)
	{
		return f->filter->count - (f->out->wp - f->out->rp);
	}

	t = lseek(f->fd, 0, 1);
	if (t == -1)
	{
		f->error = fz_throw("ioerror: lseek: %s", strerror(errno));
		return -1;
	}

	return t - (f->out->wp - f->out->rp);
}

/*
 * Read mode
 */

static int doread(fz_buffer *b, int fd)
{
	int n = read(fd, b->wp, b->ep - b->wp);
	if (n == -1)
		return -1;
	if (n == 0)
		b->eof = 1;
	b->wp += n;
	return n;
}

static int producedata(fz_file *f)
{
	fz_error *reason;
	int produced;
	int n;

	assert(f->mode == O_RDONLY);
	assert(f->error == nil);

	if (!f->filter)
	{
		fz_rewindbuffer(f->out);
		n = doread(f->out, f->fd);
		if (n < 0) {
			f->error = fz_throw("ioerror in read: %s", strerror(errno));
			return -1;
		}
		return 0;
	}

	produced = 0;

	while (1)
	{
		reason = fz_process(f->filter, f->in, f->out);

		if (f->filter->produced)
			produced = 1;

		if (reason == fz_ioneedin)
		{
			if (f->in->eof) {
				f->error = fz_throw("ioerror: premature eof in filter");
				return -1;
			}

			/* no space to produce, rewind or grow */
			if (f->in->wp == f->in->ep)
			{
				if (f->in->rp > f->in->bp)
					f->error = fz_rewindbuffer(f->in);
				else
					f->error = fz_growbuffer(f->in);
				if (f->error)
					return -1;
			}

			/* then fill with more input */
			n = doread(f->in, f->fd);
			if (n < 0) {
				f->error = fz_throw("ioerror in read: %s", strerror(errno));
				return -1;
			}

			if (produced)
				return 0;
		}

		else if (reason == fz_ioneedout)
		{
			if (produced)
				return 0;

			/* need more outspace, and produced no data */
			if (f->out->rp > f->out->bp)
				f->error = fz_rewindbuffer(f->out);
			else
				f->error = fz_growbuffer(f->out);
			if (f->error)
				return -1;
		}

		else if (reason == fz_iodone)
			return 0;

		else {
			f->error = reason;
			return -1;
		}
	}
}

int
fz_peekbyte(fz_file *f)
{
	if (f->out->rp == f->out->wp)
	{
		if (f->out->eof) return EOF;
		if (producedata(f)) return EOF;
	}

	if (f->out->rp < f->out->wp)
		return *f->out->rp;

	return EOF;
}

int
fz_readbyte(fz_file *f)
{
	if (f->out->rp == f->out->wp)
	{
		if (f->out->eof) return EOF;
		if (producedata(f)) return EOF;
	}

	if (f->out->rp < f->out->wp)
		return *f->out->rp++;

	return EOF;
}

int
fz_read(fz_file *f, char *buf, int n)
{
	int i = 0;

	while (i < n)
	{
		while (f->out->rp < f->out->wp && i < n)
			buf[i++] = *f->out->rp ++;

		if (f->out->rp == f->out->wp)
		{
			if (f->out->eof) return i;
			if (producedata(f) < 0) return -1;
		}
	}

	return i;
}

int
fz_readline(fz_file *f, char *buf, int n)
{
	int c = EOF;
	char *s = buf;

	while (n > 1)
	{
		c = fz_readbyte(f);
		if (c == EOF)
			break;
		if (c == '\r') {
			c = fz_peekbyte(f);
			if (c == '\n')
				c = fz_readbyte(f);
			break;
		}
		if (c == '\n')
			break;
		*s++ = c;
		n--;
	}
	if (n)
		*s = '\0';
	return s - buf;
}

/*
 * Write mode
 */

static int dowrite(fz_buffer *b, int fd)
{
	int n = write(fd, b->rp, b->wp - b->rp);
	if (n == -1)
		return -1;
	b->rp += n;
	return n;
}

int
fz_write(fz_file *f, char *buf, int n)
{
	fz_error *reason;
	int i = 0;
	int x;

	assert(f->mode == O_WRONLY);
	assert(f->error == nil);

	while (i < n)
	{
		while (f->in->rp < f->in->wp && i < n)
		{
			*f->in->rp++ = buf[i++];
		}

		if (f->in->rp == f->in->wp)
		{
			reason = fz_process(f->filter, f->in, f->out);

			if (reason == fz_ioneedin)
			{
				if (f->in->wp == f->in->ep) {
					if (f->in->rp > f->in->bp)
						f->error = fz_rewindbuffer(f->in);
					else
						f->error = fz_growbuffer(f->in);
					if (f->error)
						return -1;
				}
			}

			else if (reason == fz_ioneedout)
			{
				x = dowrite(f->out, f->fd);
				if (x < 0) {
					f->error = fz_throw("ioerror in write: %s", strerror(errno));
					return -1;
				}

				if (f->out->rp > f->out->bp)
					f->error = fz_rewindbuffer(f->out);
				else
					f->error = fz_growbuffer(f->out);
				if (f->error)
					return -1;
			}

			else if (reason == fz_iodone)
			{
				x = dowrite(f->out, f->fd);
				if (x < 0) {
					f->error = fz_throw("ioerror in write: %s", strerror(errno));
					return -1;
				}
				break;
			}

			else {
				f->error = reason;
				return -1;
			}
		}
	}

	return i;
}

int
fz_flush(fz_file *f)
{
	fz_error *reason;
	int n;

	assert(f->mode == O_WRONLY);
	assert(f->error == nil);

	f->in->eof = 1;

	while (!f->out->eof)
	{
		reason = fz_process(f->filter, f->in, f->out);

		if (reason == fz_ioneedin) {
			f->error = fz_throw("ioerror: premature eof in filter");
			return -1;
		}

		else if (reason == fz_ioneedout)
		{
			n = dowrite(f->out, f->fd);
			if (n < 0) {
				f->error = fz_throw("ioerror in write: %s", strerror(errno));
				return -1;
			}

			if (f->out->rp > f->out->bp)
				f->error = fz_rewindbuffer(f->out);
			else
				f->error = fz_growbuffer(f->out);
			if (f->error)
				return -1;
		}

		else if (reason == fz_iodone)
		{
			n = dowrite(f->out, f->fd);
			if (n < 0) {
				f->error = fz_throw("ioerror in write: %s", strerror(errno));
				return -1;
			}
			break;
		}

		else {
			f->error = reason;
			return -1;
		}
	}

	return 0;
}

/*
 * Utility function to consume contents of file stream into
 * a freshly allocated buffer; realloced and trimmed to size.
 */

enum { CHUNKSIZE = 4096 };

fz_error *
fz_readfile(unsigned char **bufp, int *lenp, fz_file *file)
{
	unsigned char *newbuf;
	unsigned char *buf;
	int len;
	int pos;
	int n;

	*bufp = nil;
	*lenp = 0;

	len = 0;
	pos = 0;
	buf = nil;

	while (1)
	{
		if (len - pos == 0)
		{
			len += CHUNKSIZE;
			newbuf = fz_realloc(buf, len);
			if (!newbuf)
			{
				fz_free(buf);
				return fz_outofmem;
			}
			buf = newbuf;
		}

		n = fz_read(file, buf + pos, len - pos);

printf("fz_read %d bytes\n", n);

		if (n < 0)
		{
			fz_free(buf);
			return fz_ferror(file);
		}

		pos += n;

		if (n < CHUNKSIZE)
		{
			newbuf = fz_realloc(buf, pos);
			if (!newbuf)
			{
				fz_free(buf);
				return fz_outofmem;
			}

			*bufp = newbuf;
			*lenp = pos;
			return nil;
		}
	}
}

