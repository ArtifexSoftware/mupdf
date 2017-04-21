#include "fitz-imp.h"

#include <string.h>

#define MIN_BOMB (100 << 20)

size_t
fz_read(fz_context *ctx, fz_stream *stm, unsigned char *buf, size_t len)
{
	size_t count, n;

	count = 0;
	do
	{
		n = fz_available(ctx, stm, len);
		if (n > len)
			n = len;
		if (n == 0)
			break;

		memcpy(buf, stm->rp, n);
		stm->rp += n;
		buf += n;
		count += n;
		len -= n;
	}
	while (len > 0);

	return count;
}

static unsigned char skip_buf[4096];

size_t fz_skip(fz_context *ctx, fz_stream *stm, size_t len)
{
	size_t count, l, total = 0;

	while (len)
	{
		l = len;
		if (l > sizeof(skip_buf))
			l = sizeof(skip_buf);
		count = fz_read(ctx, stm, skip_buf, l);
		total += count;
		if (count < l)
			break;
		len -= count;
	}
	return total;
}

fz_buffer *
fz_read_all(fz_context *ctx, fz_stream *stm, size_t initial)
{
	return fz_read_best(ctx, stm, initial, NULL);
}

fz_buffer *
fz_read_best(fz_context *ctx, fz_stream *stm, size_t initial, int *truncated)
{
	fz_buffer *buf = NULL;
	size_t n;

	fz_var(buf);

	if (truncated)
		*truncated = 0;

	fz_try(ctx)
	{
		if (initial < 1024)
			initial = 1024;

		buf = fz_new_buffer(ctx, initial+1);

		while (1)
		{
			if (buf->len == buf->cap)
				fz_grow_buffer(ctx, buf);

			if (buf->len >= MIN_BOMB && buf->len / 200 > initial)
			{
				fz_throw(ctx, FZ_ERROR_GENERIC, "compression bomb detected");
			}

			n = fz_read(ctx, stm, buf->data + buf->len, buf->cap - buf->len);
			if (n == 0)
				break;

			buf->len += n;
		}
	}
	fz_catch(ctx)
	{
		if (fz_caught(ctx) == FZ_ERROR_TRYLATER)
		{
			fz_drop_buffer(ctx, buf);
			fz_rethrow(ctx);
		}
		if (truncated)
		{
			*truncated = 1;
		}
		else
		{
			fz_drop_buffer(ctx, buf);
			fz_rethrow(ctx);
		}
	}

	return buf;
}

char *
fz_read_line(fz_context *ctx, fz_stream *stm, char *mem, size_t n)
{
	char *s = mem;
	int c = EOF;
	while (n > 1)
	{
		c = fz_read_byte(ctx, stm);
		if (c == EOF)
			break;
		if (c == '\r') {
			c = fz_peek_byte(ctx, stm);
			if (c == '\n')
				fz_read_byte(ctx, stm);
			break;
		}
		if (c == '\n')
			break;
		*s++ = c;
		n--;
	}
	if (n)
		*s = '\0';
	return (s == mem && c == EOF) ? NULL : mem;
}

fz_off_t
fz_tell(fz_context *ctx, fz_stream *stm)
{
	return stm->pos - (stm->wp - stm->rp);
}

void
fz_seek(fz_context *ctx, fz_stream *stm, fz_off_t offset, int whence)
{
	stm->avail = 0; /* Reset bit reading */
	if (stm->seek)
	{
		if (whence == 1)
		{
			offset += fz_tell(ctx, stm);
			whence = 0;
		}
		stm->seek(ctx, stm, offset, whence);
		stm->eof = 0;
	}
	else if (whence != 2)
	{
		if (whence == 0)
			offset -= fz_tell(ctx, stm);
		if (offset < 0)
			fz_warn(ctx, "cannot seek backwards");
		/* dog slow, but rare enough */
		while (offset-- > 0)
		{
			if (fz_read_byte(ctx, stm) == EOF)
			{
				fz_warn(ctx, "seek failed");
				break;
			}
		}
	}
	else
		fz_warn(ctx, "cannot seek");
}

int fz_stream_meta(fz_context *ctx, fz_stream *stm, int key, int size, void *ptr)
{
	if (!stm || !stm->meta)
		return -1;
	return stm->meta(ctx, stm, key, size, ptr);
}

fz_buffer *
fz_read_file(fz_context *ctx, const char *filename)
{
	fz_stream *stm;
	fz_buffer *buf = NULL;

	fz_var(buf);

	stm = fz_open_file(ctx, filename);
	fz_try(ctx)
	{
		buf = fz_read_all(ctx, stm, 0);
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, stm);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return buf;
}

uint16_t fz_read_uint16(fz_context *ctx, fz_stream *stm)
{
	uint32_t a = fz_read_byte(ctx, stm);
	uint32_t b = fz_read_byte(ctx, stm);
	uint32_t x = (a<<8) | (b);
	if (a == EOF || b == EOF)
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of file in int16");
	return x;
}

uint32_t fz_read_uint24(fz_context *ctx, fz_stream *stm)
{
	uint32_t a = fz_read_byte(ctx, stm);
	uint32_t b = fz_read_byte(ctx, stm);
	uint32_t c = fz_read_byte(ctx, stm);
	uint32_t x = (a<<16) | (b<<8) | (c);
	if (a == EOF || b == EOF || c == EOF)
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of file in int24");
	return x;
}

uint32_t fz_read_uint32(fz_context *ctx, fz_stream *stm)
{
	uint32_t a = fz_read_byte(ctx, stm);
	uint32_t b = fz_read_byte(ctx, stm);
	uint32_t c = fz_read_byte(ctx, stm);
	uint32_t d = fz_read_byte(ctx, stm);
	uint32_t x = (a<<24) | (b<<16) | (c<<8) | (d);
	if (a == EOF || b == EOF || c == EOF || d == EOF)
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of file in int32");
	return x;
}

uint64_t fz_read_uint64(fz_context *ctx, fz_stream *stm)
{
	uint64_t a = fz_read_byte(ctx, stm);
	uint64_t b = fz_read_byte(ctx, stm);
	uint64_t c = fz_read_byte(ctx, stm);
	uint64_t d = fz_read_byte(ctx, stm);
	uint64_t e = fz_read_byte(ctx, stm);
	uint64_t f = fz_read_byte(ctx, stm);
	uint64_t g = fz_read_byte(ctx, stm);
	uint64_t h = fz_read_byte(ctx, stm);
	uint64_t x = (a<<56) | (b<<48) | (c<<40) | (d<<32) | (e<<24) | (f<<16) | (g<<8) | (h);
	if (a == EOF || b == EOF || c == EOF || d == EOF || e == EOF || f == EOF || g == EOF || h == EOF)
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of file in int64");
	return x;
}

uint16_t fz_read_uint16_le(fz_context *ctx, fz_stream *stm)
{
	uint32_t a = fz_read_byte(ctx, stm);
	uint32_t b = fz_read_byte(ctx, stm);
	uint32_t x = (a) | (b<<8);
	if (a == EOF || b == EOF)
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of file in int16");
	return x;
}

uint32_t fz_read_uint24_le(fz_context *ctx, fz_stream *stm)
{
	uint32_t a = fz_read_byte(ctx, stm);
	uint32_t b = fz_read_byte(ctx, stm);
	uint32_t c = fz_read_byte(ctx, stm);
	uint32_t x = (a) | (b<<8) | (c<<16);
	if (a == EOF || b == EOF || c == EOF)
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of file in int24");
	return x;
}

uint32_t fz_read_uint32_le(fz_context *ctx, fz_stream *stm)
{
	uint32_t a = fz_read_byte(ctx, stm);
	uint32_t b = fz_read_byte(ctx, stm);
	uint32_t c = fz_read_byte(ctx, stm);
	uint32_t d = fz_read_byte(ctx, stm);
	uint32_t x = (a) | (b<<8) | (c<<16) | (d<<24);
	if (a == EOF || b == EOF || c == EOF || d == EOF)
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of file in int32");
	return x;
}

uint64_t fz_read_uint64_le(fz_context *ctx, fz_stream *stm)
{
	uint64_t a = fz_read_byte(ctx, stm);
	uint64_t b = fz_read_byte(ctx, stm);
	uint64_t c = fz_read_byte(ctx, stm);
	uint64_t d = fz_read_byte(ctx, stm);
	uint64_t e = fz_read_byte(ctx, stm);
	uint64_t f = fz_read_byte(ctx, stm);
	uint64_t g = fz_read_byte(ctx, stm);
	uint64_t h = fz_read_byte(ctx, stm);
	uint64_t x = (a) | (b<<8) | (c<<16) | (d<<24) | (e<<32) | (f<<40) | (g<<48) | (h<<56);
	if (a == EOF || b == EOF || c == EOF || d == EOF || e == EOF || f == EOF || g == EOF || h == EOF)
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of file in int64");
	return x;
}

int16_t fz_read_int16(fz_context *ctx, fz_stream *stm) { return (int16_t)fz_read_uint16(ctx, stm); }
int32_t fz_read_int32(fz_context *ctx, fz_stream *stm) { return (int32_t)fz_read_uint32(ctx, stm); }
int64_t fz_read_int64(fz_context *ctx, fz_stream *stm) { return (int64_t)fz_read_uint64(ctx, stm); }

int16_t fz_read_int16_le(fz_context *ctx, fz_stream *stm) { return (int16_t)fz_read_uint16_le(ctx, stm); }
int32_t fz_read_int32_le(fz_context *ctx, fz_stream *stm) { return (int32_t)fz_read_uint32_le(ctx, stm); }
int64_t fz_read_int64_le(fz_context *ctx, fz_stream *stm) { return (int64_t)fz_read_uint64_le(ctx, stm); }

void fz_read_string(fz_context *ctx, fz_stream *stm, char *buffer, int len)
{
	int c;
	do
	{
		if (len <= 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Buffer overrun reading null terminated string");

		c = fz_read_byte(ctx, stm);
		if (c == EOF)
			fz_throw(ctx, FZ_ERROR_GENERIC, "EOF reading null terminated string");
		*buffer++ = c;
		len--;
	}
	while (c != 0);
}
