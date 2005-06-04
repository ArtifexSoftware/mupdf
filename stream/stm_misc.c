/*
 * Miscellaneous I/O functions
 */

#include "fitz-base.h"
#include "fitz-stream.h"

int fz_tell(fz_stream *stm)
{
	if (stm->mode == FZ_SREAD)
		return fz_rtell(stm);
	return fz_wtell(stm);
}

int fz_seek(fz_stream *stm, int offset, int whence)
{
	if (stm->mode == FZ_SREAD)
		return fz_rseek(stm, offset, whence);
	return fz_wseek(stm, offset, whence);
}

/*
 * Read a line terminated by LF or CR or CRLF.
 */

int fz_readline(fz_stream *stm, char *mem, int n)
{
	char *s = mem;
	int c = EOF;
	while (n > 1)
	{
		c = fz_readbyte(stm);
		if (c == EOF)
			break;
		if (c == '\r') {
			c = fz_peekbyte(stm);
			if (c == '\n')
				c = fz_readbyte(stm);
			break;
		}
		if (c == '\n')
			break;
		*s++ = c;
		n--;
	}
	if (n)
		*s = '\0';
	return s - mem;
}

/*
 * Utility function to consume all the contents of an input stream into
 * a freshly allocated buffer; realloced and trimmed to size.
 */

enum { CHUNKSIZE = 1024 * 4 };

int fz_readall(fz_buffer **bufp, fz_stream *stm)
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
				return -1;
			}
			buf = newbuf;
		}

		n = fz_read(stm, buf + pos, len - pos);

		if (n < 0)
		{
			fz_free(buf);
			return -1;
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
					return -1;
				}
			}
			else newbuf = buf;

			real = *bufp = fz_malloc(sizeof(fz_buffer));
			if (!real)
			{
				fz_free(newbuf);
				return -1;
			}

			real->refs = 1;
			real->ownsdata = 1;
			real->bp = buf;
			real->rp = buf;
			real->wp = buf + pos;
			real->ep = buf + pos;
			real->eof = 1;

			return real->wp - real->rp;
		}
	}
}

