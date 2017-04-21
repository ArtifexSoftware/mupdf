/* Simple example fz_stream implementation using curl */

#include "mupdf/fitz.h"

#include <string.h>
#include <stdlib.h>

#include "curl_stream.h"

#define CURL_STATICLIB
#include <curl/curl.h>

#undef DEBUG_BLOCK_FETCHING

#ifdef DEBUG_BLOCK_FETCHING
#define DEBUG_MESSAGE(A) do { fz_warn A; } while(0)
#else
#define DEBUG_MESSAGE(A) do { } while(0)
#endif

#define BLOCK_SHIFT 20
#define BLOCK_SIZE (1<<BLOCK_SHIFT)

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include "pthread.h"
#include <ctype.h>
#endif

typedef struct curl_stream_state_s curl_stream_state;

struct curl_stream_state_s
{
	fz_context *ctx;
	CURL *handle;
	char *filename;
	int data_arrived;
	int content_length; /* As returned by curl. -1 for unknown. */
	int total_length; /* As obtained from the Content-Range header. */
	int buffer_max;
	int buffer_fill;
	unsigned char *buffer;
	int map_length;
	unsigned char *map;
	int fill_point; /* The next file offset we will fetch to */
	int current_fill_point; /* The current file offset we are fetching to */
	int complete;
	int kill_thread;
	void (*more_data)(void *, int);
	void *more_data_arg;
	const char *error;

	unsigned char public_buffer[4096];

#if defined(_WIN32) || defined(_WIN64)
	void *thread;
	DWORD thread_id;
	HANDLE mutex;
#else
	pthread_t thread;
	pthread_mutex_t mutex;
#endif
};

static void fetcher_thread(curl_stream_state *state);

#if defined(_WIN32) || defined(_WIN64)
static void
lock(curl_stream_state *state)
{
	WaitForSingleObject(state->mutex, INFINITE);
}

static void
unlock(curl_stream_state *state)
{
	ReleaseMutex(state->mutex);
}

static DWORD WINAPI
win_thread(void *lparam)
{
	fetcher_thread((curl_stream_state *)lparam);

	return 0;
}

#else /* Anything else assumed to be pthreads */

static void
lock(curl_stream_state *state)
{
	pthread_mutex_lock(&state->mutex);
}

static void
unlock(curl_stream_state *state)
{
	pthread_mutex_unlock(&state->mutex);
}

static void *
pthread_thread(void *arg)
{
	fetcher_thread((curl_stream_state *)arg);

	return NULL;
}
#endif

static size_t header_arrived(void *ptr, size_t size, size_t nmemb, void *state_)
{
	curl_stream_state *state = (curl_stream_state *)state_;

	if (strncmp(ptr, "Content-Range:", 14) == 0)
	{
		char *p = (char *)ptr;
		int len = (int)(nmemb * size);
		int start, end, total;
		while (len && !isdigit(*p))
			p++, len--;
		start = 0;
		while (len && isdigit(*p))
		{
			start = start*10 + *p-'0';
			p++, len--;
		}
		while (len && !isdigit(*p))
			p++, len--;
		end = 0;
		while (len && isdigit(*p))
		{
			end = end*10 + *p-'0';
			p++, len--;
		}
		while (len && !isdigit(*p))
			p++, len--;
		total = 0;
		while (len && isdigit(*p))
		{
			total = total*10 + *p-'0';
			p++, len--;
		}
		state->total_length = total;
	}

	return nmemb * size;
}

static size_t data_arrived(void *ptr, size_t size, size_t nmemb, void *state_)
{
	curl_stream_state *state = (curl_stream_state *)state_;
	int old_start;

	size *= nmemb;

	if (state->data_arrived == 0)
	{
		double d;
		long response;
		int len;
		/* This is the first time data has arrived. If the response
		 * code is 206, then we can do byte requests, and we will
		 * known the total_length from having processed the header
		 * already. */
		curl_easy_getinfo(state->handle, CURLINFO_RESPONSE_CODE, &response);
		if (state->total_length && response == 206)
		{
			/* We got a range header, and the correct http response
			 * code. We can assume that byte fetches are accepted
			 * and we'll run without progressive mode. */
			state->content_length = len = state->total_length;
			state->map_length = (len+BLOCK_SIZE-1)>>BLOCK_SHIFT;
			state->map = fz_malloc_no_throw(state->ctx, (state->map_length+7)>>3);
			state->buffer = fz_malloc_no_throw(state->ctx, len);
			state->buffer_max = len;
			if (state->map == NULL || state->buffer == NULL)
			{
				/* FIXME: Crap error handling! */
				exit(1);
			}
			memset(state->map, 0, (state->map_length+7)>>3);
		}
		else
		{
			/* So we can't use ByteRanges. Do we at least know the
			 * complete length of the file? */
			curl_easy_getinfo(state->handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &d);
			state->content_length = len = (int)d;
			if (len > 0 && response == 200)
			{
				/* Yes. We can run as a progressive file */
				state->buffer = fz_malloc_no_throw(state->ctx, len);
				state->buffer_max = len;
				if (state->buffer == NULL)
				{
					/* FIXME: Crap error handling! */
					exit(1);
				}
			}
			else
			{
				/* What a crap server. Won't tell us how big
				 * the file is. We'll have to expand as data
				 * as arrives. */
				state->content_length = -1;
			}
		}
		state->data_arrived = 1;
	}
	if (state->content_length < 0)
	{
		int newsize = (int)(state->current_fill_point + size);
		if (newsize > state->buffer_max)
		{
			/* Expand the buffer */
			int new_max = state->buffer_max * 2;
			if (new_max == 0)
				new_max = 4096;
			state->buffer = fz_resize_array_no_throw(state->ctx, state->buffer, new_max, 1);
			if (state->buffer == NULL)
			{
				/* FIXME: Crap error handling! */
				exit(1);
			}
			state->buffer_max = new_max;
		}
	}

	DEBUG_MESSAGE((state->ctx, "data arrived: offset=%d len=%d", state->current_fill_point, (int) size));
	old_start = state->current_fill_point;
	memcpy(state->buffer + state->current_fill_point, ptr, size);
	state->current_fill_point += (int)size;
	if (state->current_fill_point == state->content_length ||
		(((state->current_fill_point ^ old_start) & ~(BLOCK_SIZE-1)) != 0))
	{
		if (state->map)
		{
			old_start >>= BLOCK_SHIFT;
			state->map[old_start>>3] |= 1<<(old_start & 7);
		}
	}

	if (state->more_data)
		state->more_data(state->more_data_arg, 0);

	return size;
}

#define HAVE_BLOCK(map, num) \
	(((map)[(num)>>3] & (1<<((num) & 7))) != 0)

static void
fetch_chunk(curl_stream_state *state)
{
	char text[32];
	int fill, start, end;
	CURLcode ret;

	lock(state);

	if (state->kill_thread)
	{
		state->complete = 1;
		unlock(state);
		return;
	}

	fill = state->fill_point;
	if (state->content_length > 0)
	{
		/* Find the next block that we haven't got */
		int map_length = state->map_length;
		unsigned char *map = state->map;
		for ( ; (fill < map_length && HAVE_BLOCK(map, fill)); fill++);
		if (fill == map_length)
		{
			for (fill = 0;
				(fill < map_length && HAVE_BLOCK(map, fill));
				fill++);
			if (fill == map_length)
			{
				/* We've got it all! */
				state->complete = 1;
				state->kill_thread = 1;
				unlock(state);
				if (state->more_data)
					state->more_data(state->more_data_arg, 1);
				fz_warn(state->ctx, "Background fetch complete!");
				return;
			}
		}
		DEBUG_MESSAGE((state->ctx, "block requested was %d, fetching %d", state->fill_point, fill));
		state->fill_point = fill;
	}

	unlock(state);

	/* Fetch that block */
	start = fill * BLOCK_SIZE;
	end = start + BLOCK_SIZE-1;
	state->current_fill_point = start;
	if (state->content_length > 0 && start >= state->content_length)
		state->complete = 1;
	if (state->content_length > 0 && end >= state->content_length)
		end = state->content_length-1;
	snprintf(text, 32, "%d-%d", start, end);
	curl_easy_setopt(state->handle, CURLOPT_RANGE, text);
	ret = curl_easy_perform(state->handle);
	if (ret != CURLE_OK)
		state->error = curl_easy_strerror(ret);
}

static void
fetcher_thread(curl_stream_state *state)
{
	while (!state->complete)
		fetch_chunk(state);
}

static int
stream_next(fz_context *ctx, fz_stream *stream, size_t len)
{
	curl_stream_state *state = (curl_stream_state *)stream->state;
	size_t len_read = 0;
	fz_off_t read_point = stream->pos;
	int block = read_point>>BLOCK_SHIFT;
	size_t left_over = (-read_point) & (BLOCK_SIZE-1);
	unsigned char *buf = state->public_buffer;

	if (state->error != NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot fetch data: %s", state->error);

	if (len > sizeof(state->public_buffer))
		len = sizeof(state->public_buffer);

	if (state->content_length == 0)
		fz_throw(ctx, FZ_ERROR_TRYLATER, "read of a block we don't have (A) (offset=%d)", read_point);

	if (state->map == NULL)
	{
		/* We are doing a simple linear fetch as we don't know the
		 * content length. */
		if (read_point + len > state->current_fill_point)
		{
			stream->rp = stream->wp;
			fz_throw(ctx, FZ_ERROR_TRYLATER, "read of a block we don't have (B) (offset=%d)", read_point);
		}
		memcpy(buf, state->buffer + read_point, len);
		stream->rp = buf;
		stream->wp = buf + len;
		stream->pos += len;
		if (len == 0)
			return EOF;
		return *stream->rp++;
	}

	if (read_point + len > state->content_length)
		len = state->content_length - read_point;
	if (left_over > len)
		left_over = len;

	if (left_over)
	{
		/* We are starting midway through a block */
		if (!HAVE_BLOCK(state->map, block))
		{
			lock(state);
			state->fill_point = block;
			unlock(state);
			stream->rp = stream->wp;
			fz_throw(ctx, FZ_ERROR_TRYLATER, "read of a block we don't have (C) (offset=%d)", read_point);
		}
		block++;
		if (left_over > len)
			left_over = len;
		memcpy(buf, state->buffer + read_point, left_over);
		buf += left_over;
		read_point += left_over;
		len -= left_over;
		len_read += left_over;
	}

	/* Copy any complete blocks */
	while (len > BLOCK_SIZE)
	{
		if (!HAVE_BLOCK(state->map, block))
		{
			lock(state);
			state->fill_point = block;
			unlock(state);
			stream->rp = stream->wp;
			fz_throw(ctx, FZ_ERROR_TRYLATER, "read of a block we don't have (D) (offset=%d)", read_point);
		}
		block++;
		memcpy(buf, state->buffer + read_point, BLOCK_SIZE);
		buf += BLOCK_SIZE;
		read_point += BLOCK_SIZE;
		len -= BLOCK_SIZE;
		len_read += BLOCK_SIZE;
	}

	/* Copy any trailing bytes */
	if (len > 0)
	{
		if (!HAVE_BLOCK(state->map, block))
		{
			lock(state);
			state->fill_point = block;
			unlock(state);
			stream->rp = stream->wp;
			fz_throw(ctx, FZ_ERROR_TRYLATER, "read of a block we don't have (E) (offset=%d)", read_point);
		}
		memcpy(buf, state->buffer + read_point, len);
		len_read += len;
	}
	stream->rp = state->public_buffer;
	stream->wp = stream->rp + len_read;
	stream->pos += len_read;
	if (len_read == 0)
		return EOF;
	return *stream->rp++;
}

static void
stream_close(fz_context *ctx, void *state_)
{
	curl_stream_state *state = (curl_stream_state *)state_;

	if (!state || state->kill_thread)
		return;

	lock(state);
	state->kill_thread = 1;
	unlock(state);

#if defined(_WIN32) || defined(_WIN64)
	WaitForSingleObject(state->thread, INFINITE);
	CloseHandle(state->thread);
	CloseHandle(state->mutex);
#else
	pthread_join(state->thread, NULL);
	pthread_mutex_destroy(&state->mutex);
#endif

	curl_easy_cleanup(state->handle);

	fz_free(ctx, state->buffer);
	fz_free(ctx, state->map);
	fz_free(ctx, state);
}

static fz_stream hack_stream;
static curl_stream_state hack;
static int hack_pos;

static void
stream_seek(fz_context *ctx, fz_stream *stream, fz_off_t offset, int whence)
{
	curl_stream_state *state = (curl_stream_state *)stream->state;

	switch(whence)
	{
	case SEEK_CUR:
		offset += stream->pos;
		break;
	case SEEK_END:
		offset += state->content_length;
		break;
	default:
	case SEEK_SET:
		break;
	}
	if (offset < 0)
		offset = 0;
	else if (state->content_length > 0 && offset > state->content_length)
		offset = state->content_length;
	stream->wp = stream->rp;
	stream->pos = offset;
	hack = *state;
	hack_pos = offset;
	hack_stream = *stream;
}

static int
stream_meta(fz_context *ctx, fz_stream *stream, int key, int size, void *ptr)
{
	curl_stream_state *state = (curl_stream_state *)stream->state;

	switch(key)
	{
	case FZ_STREAM_META_LENGTH:
		if (!state->data_arrived)
			fz_throw(ctx, FZ_ERROR_TRYLATER, "still awaiting file length");
		return state->content_length;
	case FZ_STREAM_META_PROGRESSIVE:
		return 1;
	}
	return -1;
}

fz_stream *fz_stream_from_curl(fz_context *ctx, char *filename, void (*more_data)(void *,int), void *more_data_arg)
{
	CURLcode ret;
	CURL *handle;
	curl_stream_state *state = fz_malloc_struct(ctx, curl_stream_state);
	fz_stream *stream;

	ret = curl_global_init(CURL_GLOBAL_ALL);
	if (ret != 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "curl init failed (code %d)", ret);

	state->ctx = ctx;
	state->handle = handle = curl_easy_init();
	state->more_data = more_data;
	state->more_data_arg = more_data_arg;

	curl_easy_setopt(handle, CURLOPT_URL, filename);

	curl_easy_setopt(handle, CURLOPT_NOPROGRESS, 1);

	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, data_arrived);

	curl_easy_setopt(handle, CURLOPT_WRITEDATA, state);

	curl_easy_setopt(handle, CURLOPT_WRITEHEADER, state);

	curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_arrived);

#if defined(_WIN32) || defined(_WIN64)
	state->mutex = CreateMutex(NULL, FALSE, NULL);
	if (state->mutex == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "mutex creation failed");

	state->thread = CreateThread(NULL, 0, win_thread, state, 0, &state->thread_id);
	if (state->thread == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "thread creation failed");
#else
	if (pthread_mutex_init(&state->mutex, NULL))
		fz_throw(ctx, FZ_ERROR_GENERIC, "mutex creation failed");

	if (pthread_create(&state->thread, NULL, pthread_thread, state))
		fz_throw(ctx, FZ_ERROR_GENERIC, "thread creation failed");

#endif

	stream = fz_new_stream(ctx, state, stream_next, stream_close);
	stream->seek = stream_seek;
	stream->meta = stream_meta;
	return stream;
}
