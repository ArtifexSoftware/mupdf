#include <fitz.h>

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

int fz_producedata(fz_file *f)
{
	fz_error *reason;
	int produced;
	int n;

	assert(f->mode == FZ_READ);
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
		if (fz_producedata(f)) return EOF;
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
		if (fz_producedata(f)) return EOF;
	}

	if (f->out->rp < f->out->wp)
		return *f->out->rp++;

	return EOF;
}

int
fz_read(fz_file *f, unsigned char *buf, int n)
{
	int i = 0;

	while (i < n)
	{
		while (f->out->rp < f->out->wp && i < n)
			buf[i++] = *f->out->rp ++;

		if (f->out->rp == f->out->wp)
		{
			if (f->out->eof) return i;
			if (fz_producedata(f) < 0) return -1;
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
 * Utility function to consume contents of file stream into
 * a freshly allocated buffer; realloced and trimmed to size.
 */

enum { CHUNKSIZE = 1024 * 32 };

fz_error *
fz_readfile(fz_buffer **bufp, fz_file *file)
{
	fz_buffer *real;
	unsigned char *newbuf;
	unsigned char *buf;
	int len;
	int pos;
	int n;

	*bufp = nil;

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

		if (n < 0)
		{
			fz_free(buf);
			return fz_ferror(file);
		}

		pos += n;

		if (n < CHUNKSIZE)
		{
			if (pos > 0)
			{
				newbuf = fz_realloc(buf, pos);
				if (!newbuf)
				{
					fz_free(buf);
					return fz_outofmem;
				}
			}
			else newbuf = buf;

			real = *bufp = fz_malloc(sizeof(fz_buffer));
			if (!real)
			{
				fz_free(newbuf);
				return fz_outofmem;
			}

			real->refs = 1;
			real->ownsdata = 1;
			real->bp = buf;
			real->rp = buf;
			real->wp = buf + pos;
			real->ep = buf + pos;
			real->eof = 1;

			return nil;
		}
	}
}

