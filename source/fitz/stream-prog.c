#include "mupdf/fitz.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* File stream - progressive reading to simulate http download */

typedef struct prog_state
{
	FILE *file;
	int64_t length;
	int64_t available;
	int bps;
	clock_t start_time;
	unsigned char buffer[4096];
} prog_state;

static int next_prog(fz_context *ctx, fz_stream *stm, size_t len)
{
	prog_state *ps = (prog_state *)stm->state;
	size_t n;
	unsigned char *buf = ps->buffer;

	if (len > sizeof(ps->buffer))
		len = sizeof(ps->buffer);

	/* Simulate more data having arrived */
	if (ps->available < ps->length)
	{
		int64_t av = (int64_t)((float)(clock() - ps->start_time) * ps->bps / (CLOCKS_PER_SEC*8));
		if (av > ps->length)
			av = ps->length;
		ps->available = av;
		/* Limit any fetches to be within the data we have */
		if (av < ps->length && len + stm->pos > (size_t)av)
		{
			len = av - stm->pos;
			if (len <= 0)
				fz_throw(ctx, FZ_ERROR_TRYLATER, "Not enough data yet");
		}
	}

	n = (len > 0 ? fread(buf, 1, len, ps->file) : 0);
	if (n < len && ferror(ps->file))
		fz_throw(ctx, FZ_ERROR_GENERIC, "read error: %s", strerror(errno));
	stm->rp = ps->buffer + stm->pos;
	stm->wp = ps->buffer + stm->pos + n;
	stm->pos += (int64_t)n;
	if (n == 0)
		return EOF;
	return *stm->rp++;
}

static void seek_prog(fz_context *ctx, fz_stream *stm, int64_t offset, int whence)
{
	prog_state *ps = (prog_state *)stm->state;

	/* Simulate more data having arrived */
	if (ps->available < ps->length)
	{
		int av = (int)((float)(clock() - ps->start_time) * ps->bps / (CLOCKS_PER_SEC*8));
		if (av > ps->length)
			av = ps->length;
		ps->available = av;
	}
	if (ps->available < ps->length)
	{
		if (whence == SEEK_END)
			fz_throw(ctx, FZ_ERROR_TRYLATER, "Not enough data to seek to end yet");
	}
	if (whence == SEEK_CUR)
	{
		whence = SEEK_SET;
		offset += stm->pos;
		if (offset > ps->available)
			fz_throw(ctx, FZ_ERROR_TRYLATER, "Not enough data to seek (relatively) to offset yet");
	}
	if (whence == SEEK_SET)
	{
		if (offset > ps->available)
			fz_throw(ctx, FZ_ERROR_TRYLATER, "Not enough data to seek to offset yet");
	}

	if (fseek(ps->file, offset, whence) != 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot seek: %s", strerror(errno));
	stm->pos = offset;
	stm->wp = stm->rp;
}

static void close_prog(fz_context *ctx, void *state)
{
	prog_state *ps = (prog_state *)state;
	fclose(ps->file);
	fz_free(ctx, state);
}

static int meta_prog(fz_context *ctx, fz_stream *stm, int key, int size, void *ptr)
{
	prog_state *ps = (prog_state *)stm->state;
	switch(key)
	{
	case FZ_STREAM_META_PROGRESSIVE:
		return 1;
		break;
	case FZ_STREAM_META_LENGTH:
		return ps->length;
	}
	return -1;
}

static fz_stream *
fz_open_file_ptr_progressive(fz_context *ctx, FILE *file, int bps)
{
	fz_stream *stm;
	prog_state *state;

	state = fz_malloc_struct(ctx, prog_state);
	state->file = file;
	state->bps = bps;
	state->start_time = clock();
	state->available = 0;

	fseek(state->file, 0, SEEK_END);
	state->length = ftell(state->file);
	fseek(state->file, 0, SEEK_SET);

	stm = fz_new_stream(ctx, state, next_prog, close_prog);
	stm->seek = seek_prog;
	stm->meta = meta_prog;

	return stm;
}

fz_stream *
fz_open_file_progressive(fz_context *ctx, const char *name, int bps)
{
	FILE *f;
#ifdef _WIN32
	f = fz_fopen_utf8(name, "rb");
#else
	f = fopen(name, "rb");
#endif
	if (f == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open %s", name);
	return fz_open_file_ptr_progressive(ctx, f, bps);
}
