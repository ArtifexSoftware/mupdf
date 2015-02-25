#include "mupdf/fitz.h"

fz_stream *
fz_new_stream(fz_context *ctx, void *state, fz_stream_next_fn *next, fz_stream_close_fn *close)
{
	fz_stream *stm;

	fz_try(ctx)
	{
		stm = fz_malloc_struct(ctx, fz_stream);
	}
	fz_catch(ctx)
	{
		close(ctx, state);
		fz_rethrow(ctx);
	}

	stm->refs = 1;
	stm->error = 0;
	stm->eof = 0;
	stm->pos = 0;

	stm->bits = 0;
	stm->avail = 0;

	stm->rp = NULL;
	stm->wp = NULL;

	stm->state = state;
	stm->next = next;
	stm->close = close;
	stm->seek = NULL;

	return stm;
}

fz_stream *
fz_keep_stream(fz_context *ctx, fz_stream *stm)
{
	if (stm)
		stm->refs ++;
	return stm;
}

void
fz_drop_stream(fz_context *ctx, fz_stream *stm)
{
	if (!stm)
		return;
	stm->refs --;
	if (stm->refs == 0)
	{
		if (stm->close)
			stm->close(ctx, stm->state);
		fz_free(ctx, stm);
	}
}

/* File stream */

typedef struct fz_file_stream_s
{
	int file;
	unsigned char buffer[4096];
} fz_file_stream;

static int next_file(fz_context *ctx, fz_stream *stm, int n)
{
	fz_file_stream *state = stm->state;

	/* n is only a hint, that we can safely ignore */
	n = read(state->file, state->buffer, sizeof(state->buffer));
	if (n < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "read error: %s", strerror(errno));
	stm->rp = state->buffer;
	stm->wp = state->buffer + n;
	stm->pos += n;

	if (n == 0)
		return EOF;
	return *stm->rp++;
}

static void seek_file(fz_context *ctx, fz_stream *stm, int offset, int whence)
{
	fz_file_stream *state = stm->state;
	int n = lseek(state->file, offset, whence);
	if (n < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot lseek: %s", strerror(errno));
	stm->pos = n;
	stm->rp = state->buffer;
	stm->wp = state->buffer;
}

static void close_file(fz_context *ctx, void *state_)
{
	fz_file_stream *state = state_;
	int n = close(state->file);
	if (n < 0)
		fz_warn(ctx, "close error: %s", strerror(errno));
	fz_free(ctx, state);
}

fz_stream *
fz_open_fd(fz_context *ctx, int fd)
{
	fz_stream *stm;
	fz_file_stream *state = fz_malloc_struct(ctx, fz_file_stream);
	state->file = fd;

	fz_try(ctx)
	{
		stm = fz_new_stream(ctx, state, next_file, close_file);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, state);
		fz_rethrow(ctx);
	}
	stm->seek = seek_file;

	return stm;
}

fz_stream *
fz_open_file(fz_context *ctx, const char *name)
{
#if defined(_WIN32) || defined(_WIN64)
	char *s = (char*)name;
	wchar_t *wname, *d;
	int c, fd;
	d = wname = fz_malloc(ctx, (strlen(name)+1) * sizeof(wchar_t));
	while (*s) {
		s += fz_chartorune(&c, s);
		*d++ = c;
	}
	*d = 0;
	fd = _wopen(wname, O_BINARY | O_RDONLY, 0);
	fz_free(ctx, wname);
#else
	int fd = open(name, O_BINARY | O_RDONLY, 0);
#endif
	if (fd == -1)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open %s", name);
	return fz_open_fd(ctx, fd);
}

#if defined(_WIN32) || defined(_WIN64)
fz_stream *
fz_open_file_w(fz_context *ctx, const wchar_t *name)
{
	int fd = _wopen(name, O_BINARY | O_RDONLY, 0);
	if (fd == -1)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open file %ls", name);
	return fz_open_fd(ctx, fd);
}
#endif

/* Memory stream */

static int next_buffer(fz_context *ctx, fz_stream *stm, int max)
{
	return EOF;
}

static void seek_buffer(fz_context *ctx, fz_stream *stm, int offset, int whence)
{
	int pos = stm->pos - (stm->wp - stm->rp);
	/* Convert to absolute pos */
	if (whence == 1)
	{
		offset += pos; /* Was relative to current pos */
	}
	else if (whence == 2)
	{
		offset += stm->pos; /* Was relative to end */
	}

	if (offset < 0)
		offset = 0;
	if (offset > stm->pos)
		offset = stm->pos;
	stm->rp += offset - pos;
}

static void close_buffer(fz_context *ctx, void *state_)
{
	fz_buffer *state = (fz_buffer *)state_;
	if (state)
		fz_drop_buffer(ctx, state);
}

fz_stream *
fz_open_buffer(fz_context *ctx, fz_buffer *buf)
{
	fz_stream *stm;

	fz_keep_buffer(ctx, buf);
	stm = fz_new_stream(ctx, buf, next_buffer, close_buffer);
	stm->seek = seek_buffer;

	stm->rp = buf->data;
	stm->wp = buf->data + buf->len;

	stm->pos = buf->len;

	return stm;
}

fz_stream *
fz_open_memory(fz_context *ctx, unsigned char *data, int len)
{
	fz_stream *stm;

	stm = fz_new_stream(ctx, NULL, next_buffer, close_buffer);
	stm->seek = seek_buffer;

	stm->rp = data;
	stm->wp = data + len;

	stm->pos = len;

	return stm;
}
