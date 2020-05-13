#define _LARGEFILE_SOURCE
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include "mupdf/fitz.h"

#include <string.h>
#include <errno.h>
#include <stdio.h>

int
fz_file_exists(fz_context *ctx, const char *path)
{
	FILE *file;
#ifdef _WIN32
	file = fz_fopen_utf8(path, "rb");
#else
	file = fopen(path, "rb");
#endif
	if (file)
		fclose(file);
	return !!file;
}

fz_stream *
fz_new_stream(fz_context *ctx, void *state, fz_stream_next_fn *next, fz_stream_drop_fn *drop)
{
	fz_stream *stm = NULL;

	fz_try(ctx)
	{
		stm = fz_malloc_struct(ctx, fz_stream);
	}
	fz_catch(ctx)
	{
		if (drop)
			drop(ctx, state);
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
	stm->drop = drop;
	stm->seek = NULL;

	return stm;
}

fz_stream *
fz_keep_stream(fz_context *ctx, fz_stream *stm)
{
	return fz_keep_imp(ctx, stm, &stm->refs);
}

void
fz_drop_stream(fz_context *ctx, fz_stream *stm)
{
	if (fz_drop_imp(ctx, stm, &stm->refs))
	{
		if (stm->drop)
			stm->drop(ctx, stm->state);
		fz_free(ctx, stm);
	}
}

/* File stream */

// TODO: WIN32: HANDLE CreateFileW(), etc.
// TODO: POSIX: int creat(), read(), write(), lseeko, etc.

typedef struct
{
	FILE *file;
	unsigned char buffer[4096];
} fz_file_stream;

static int next_file(fz_context *ctx, fz_stream *stm, size_t n)
{
	fz_file_stream *state = stm->state;

	/* n is only a hint, that we can safely ignore */
	n = fread(state->buffer, 1, sizeof(state->buffer), state->file);
	if (n < sizeof(state->buffer) && ferror(state->file))
		fz_throw(ctx, FZ_ERROR_GENERIC, "read error: %s", strerror(errno));
	stm->rp = state->buffer;
	stm->wp = state->buffer + n;
	stm->pos += (int64_t)n;

	if (n == 0)
		return EOF;
	return *stm->rp++;
}

static void seek_file(fz_context *ctx, fz_stream *stm, int64_t offset, int whence)
{
	fz_file_stream *state = stm->state;
#ifdef _WIN32
	int64_t n = _fseeki64(state->file, offset, whence);
#else
	int64_t n = fseeko(state->file, offset, whence);
#endif
	if (n < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot seek: %s", strerror(errno));
#ifdef _WIN32
	stm->pos = _ftelli64(state->file);
#else
	stm->pos = ftello(state->file);
#endif
	stm->rp = state->buffer;
	stm->wp = state->buffer;
}

static void drop_file(fz_context *ctx, void *state_)
{
	fz_file_stream *state = state_;
	int n = fclose(state->file);
	if (n < 0)
		fz_warn(ctx, "close error: %s", strerror(errno));
	fz_free(ctx, state);
}

static fz_stream *
fz_open_file_ptr(fz_context *ctx, FILE *file)
{
	fz_stream *stm;
	fz_file_stream *state = fz_malloc_struct(ctx, fz_file_stream);
	state->file = file;

	stm = fz_new_stream(ctx, state, next_file, drop_file);
	stm->seek = seek_file;

	return stm;
}

fz_stream *fz_open_file_ptr_no_close(fz_context *ctx, FILE *file)
{
	fz_stream *stm = fz_open_file_ptr(ctx, file);
	/* We don't own the file ptr. Ensure we don't close it */
	stm->drop = fz_free;
	return stm;
}

fz_stream *
fz_open_file(fz_context *ctx, const char *name)
{
	FILE *file;
#ifdef _WIN32
	file = fz_fopen_utf8(name, "rb");
#else
	file = fopen(name, "rb");
#endif
	if (file == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open %s: %s", name, strerror(errno));
	return fz_open_file_ptr(ctx, file);
}

#ifdef _WIN32
fz_stream *
fz_open_file_w(fz_context *ctx, const wchar_t *name)
{
	FILE *file = _wfopen(name, L"rb");
	if (file == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open file %ls: %s", name, strerror(errno));
	return fz_open_file_ptr(ctx, file);
}
#endif

/* Memory stream */

static int next_buffer(fz_context *ctx, fz_stream *stm, size_t max)
{
	return EOF;
}

static void seek_buffer(fz_context *ctx, fz_stream *stm, int64_t offset, int whence)
{
	int64_t pos = stm->pos - (stm->wp - stm->rp);
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
	stm->rp += (int)(offset - pos);
}

static void drop_buffer(fz_context *ctx, void *state_)
{
	fz_buffer *state = (fz_buffer *)state_;
	fz_drop_buffer(ctx, state);
}

fz_stream *
fz_open_buffer(fz_context *ctx, fz_buffer *buf)
{
	fz_stream *stm;

	fz_keep_buffer(ctx, buf);
	stm = fz_new_stream(ctx, buf, next_buffer, drop_buffer);
	stm->seek = seek_buffer;

	stm->rp = buf->data;
	stm->wp = buf->data + buf->len;

	stm->pos = (int64_t)buf->len;

	return stm;
}

fz_stream *
fz_open_memory(fz_context *ctx, const unsigned char *data, size_t len)
{
	fz_stream *stm;

	stm = fz_new_stream(ctx, NULL, next_buffer, NULL);
	stm->seek = seek_buffer;

	stm->rp = (unsigned char *)data;
	stm->wp = (unsigned char *)data + len;

	stm->pos = (int64_t)len;

	return stm;
}
