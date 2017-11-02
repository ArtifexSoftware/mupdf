#define _LARGEFILE_SOURCE
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include "mupdf/fitz.h"
#include "fitz-imp.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct fz_output_context_s
{
	int refs;
	fz_output *out;
	fz_output *err;
};

static void std_write(fz_context *ctx, void *opaque, const void *buffer, size_t count);

static fz_output fz_stdout_global = {
	&fz_stdout_global,
	std_write,
	NULL,
	NULL,
	NULL,
};

static fz_output fz_stderr_global = {
	&fz_stderr_global,
	std_write,
	NULL,
	NULL,
	NULL,
};

void
fz_new_output_context(fz_context *ctx)
{
	ctx->output = fz_malloc_struct(ctx, fz_output_context);
	ctx->output->refs = 1;
	ctx->output->out = &fz_stdout_global;
	ctx->output->err = &fz_stderr_global;
}

fz_output_context *
fz_keep_output_context(fz_context *ctx)
{
	if (!ctx)
		return NULL;
	return fz_keep_imp(ctx, ctx->output, &ctx->output->refs);
}

void
fz_drop_output_context(fz_context *ctx)
{
	if (!ctx)
		return;

	if (fz_drop_imp(ctx, ctx->output, &ctx->output->refs))
	{
		/* FIXME: should we flush here? closing the streams seems wrong */
		fz_free(ctx, ctx->output);
		ctx->output = NULL;
	}
}

void
fz_set_stdout(fz_context *ctx, fz_output *out)
{
	fz_drop_output(ctx, ctx->output->out);
	ctx->output->out = out ? out : &fz_stdout_global;
}

void
fz_set_stderr(fz_context *ctx, fz_output *err)
{
	fz_drop_output(ctx, ctx->output->err);
	ctx->output->err = err ? err : &fz_stderr_global;
}

fz_output *
fz_stdout(fz_context *ctx)
{
	return ctx->output->out;
}

fz_output *
fz_stderr(fz_context *ctx)
{
	return ctx->output->err;
}

static void
file_write(fz_context *ctx, void *opaque, const void *buffer, size_t count)
{
	FILE *file = opaque;
	size_t n;

	if (count == 0)
		return;

	if (count == 1)
	{
		int x = putc(((unsigned char*)buffer)[0], file);
		if (x == EOF && ferror(file))
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot fwrite: %s", strerror(errno));
		return;
	}

	n = fwrite(buffer, 1, count, file);
	if (n < count && ferror(file))
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot fwrite: %s", strerror(errno));
}

static void
std_write(fz_context *ctx, void *opaque, const void *buffer, size_t count)
{
	FILE *f = opaque == &fz_stdout_global ? stdout : opaque == &fz_stderr_global ? stderr : NULL;
	file_write(ctx, f, buffer, count);
}

static void
file_seek(fz_context *ctx, void *opaque, int64_t off, int whence)
{
	FILE *file = opaque;
#if defined(_WIN32) || defined(_WIN64)
	int n = _fseeki64(file, off, whence);
#else
	int n = fseeko(file, off, whence);
#endif
	if (n < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot fseek: %s", strerror(errno));
}

static int64_t
file_tell(fz_context *ctx, void *opaque)
{
	FILE *file = opaque;
#if defined(_WIN32) || defined(_WIN64)
	int64_t off = _ftelli64(file);
#else
	int64_t off = ftello(file);
#endif
	if (off == -1)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot ftell: %s", strerror(errno));
	return off;
}

static void
file_drop(fz_context *ctx, void *opaque)
{
	FILE *file = opaque;
	int n = fclose(file);
	if (n < 0)
		fz_warn(ctx, "cannot fclose: %s", strerror(errno));
}

fz_output *
fz_new_output(fz_context *ctx, void *state, fz_output_write_fn *write, fz_output_close_fn *close, fz_output_drop_fn *drop)
{
	fz_output *out = NULL;

	fz_try(ctx)
	{
		out = fz_malloc_struct(ctx, fz_output);
		out->state = state;
		out->write = write;
		out->close = close;
		out->drop = drop;
	}
	fz_catch(ctx)
	{
		if (drop)
			drop(ctx, state);
		fz_rethrow(ctx);
	}
	return out;
}

fz_output *
fz_new_output_with_path(fz_context *ctx, const char *filename, int append)
{
	FILE *file;
	fz_output *out;

	if (!strcmp(filename, "/dev/null") || !fz_strcasecmp(filename, "nul:"))
		return NULL;

#if defined(_WIN32) || defined(_WIN64)
	/* Ensure we create a brand new file. We don't want to clobber our old file. */
	if (!append)
	{
		if (fz_remove_utf8(filename) < 0)
			if (errno != ENOENT)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot remove file '%s': %s", filename, strerror(errno));
	}
	file = fz_fopen_utf8(filename, append ? "ab" : "wb");
#else
	/* Ensure we create a brand new file. We don't want to clobber our old file. */
	if (!append)
	{
		if (remove(filename) < 0)
			if (errno != ENOENT)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot remove file '%s': %s", filename, strerror(errno));
	}
	file = fopen(filename, append ? "ab" : "wb");
#endif
	if (!file)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open file '%s': %s", filename, strerror(errno));

	out = fz_new_output(ctx, file, file_write, NULL, file_drop);
	out->seek = file_seek;
	out->tell = file_tell;

	return out;
}

static void
buffer_write(fz_context *ctx, void *opaque, const void *data, size_t len)
{
	fz_buffer *buffer = opaque;
	fz_append_data(ctx, buffer, data, len);
}

static void
buffer_seek(fz_context *ctx, void *opaque, int64_t off, int whence)
{
	fz_throw(ctx, FZ_ERROR_GENERIC, "cannot seek in buffer: %s", strerror(errno));
}

static int64_t
buffer_tell(fz_context *ctx, void *opaque)
{
	fz_buffer *buffer = opaque;
	return (int64_t)buffer->len;
}

static void
buffer_drop(fz_context *ctx, void *opaque)
{
	fz_buffer *buffer = opaque;
	fz_drop_buffer(ctx, buffer);
}

fz_output *
fz_new_output_with_buffer(fz_context *ctx, fz_buffer *buf)
{
	fz_output *out = fz_new_output(ctx, fz_keep_buffer(ctx, buf), buffer_write, NULL, buffer_drop);
	out->seek = buffer_seek;
	out->tell = buffer_tell;
	return out;
}

void
fz_close_output(fz_context *ctx, fz_output *out)
{
	if (!out) return;
	if (out->close)
		out->close(ctx, out->state);
	out->close = NULL;
}

void
fz_drop_output(fz_context *ctx, fz_output *out)
{
	if (!out) return;
	if (out->close)
		fz_warn(ctx, "dropping unclosed output");
	if (out->drop)
		out->drop(ctx, out->state);
	if (out->state != &fz_stdout_global && out->state != &fz_stderr_global)
		fz_free(ctx, out);
}

void
fz_seek_output(fz_context *ctx, fz_output *out, int64_t off, int whence)
{
	if (!out) return;
	if (out->seek == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Cannot seek in unseekable output stream\n");
	out->seek(ctx, out->state, off, whence);
}

int64_t
fz_tell_output(fz_context *ctx, fz_output *out)
{
	if (!out) return 0;
	if (out->tell == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Cannot tell in untellable output stream\n");
	return out->tell(ctx, out->state);
}

static void
fz_write_emit(fz_context *ctx, void *out, int c)
{
	fz_write_byte(ctx, out, c);
}

void
fz_write_vprintf(fz_context *ctx, fz_output *out, const char *fmt, va_list args)
{
	if (!out) return;
	fz_format_string(ctx, out, fz_write_emit, fmt, args);
}

void
fz_write_printf(fz_context *ctx, fz_output *out, const char *fmt, ...)
{
	va_list args;
	if (!out) return;
	va_start(args, fmt);
	fz_format_string(ctx, out, fz_write_emit, fmt, args);
	va_end(args);
}

void
fz_write_data(fz_context *ctx, fz_output *out, const void *data, size_t size)
{
	if (out)
		out->write(ctx, out->state, data, size);
}

void
fz_write_string(fz_context *ctx, fz_output *out, const char *s)
{
	if (out)
		out->write(ctx, out->state, s, strlen(s));
}

void
fz_write_int32_be(fz_context *ctx, fz_output *out, int x)
{
	char data[4];

	data[0] = x>>24;
	data[1] = x>>16;
	data[2] = x>>8;
	data[3] = x;

	if (out)
		out->write(ctx, out->state, data, 4);
}

void
fz_write_int32_le(fz_context *ctx, fz_output *out, int x)
{
	char data[4];

	data[0] = x;
	data[1] = x>>8;
	data[2] = x>>16;
	data[3] = x>>24;

	if (out)
		out->write(ctx, out->state, data, 4);
}

void
fz_write_int16_be(fz_context *ctx, fz_output *out, int x)
{
	char data[2];

	data[0] = x>>8;
	data[1] = x;

	if (out)
		out->write(ctx, out->state, data, 2);
}

void
fz_write_int16_le(fz_context *ctx, fz_output *out, int x)
{
	char data[2];

	data[0] = x;
	data[1] = x>>8;

	if (out)
		out->write(ctx, out->state, data, 2);
}

void
fz_write_byte(fz_context *ctx, fz_output *out, unsigned char x)
{
	if (out)
		out->write(ctx, out->state, &x, 1);
}

void
fz_write_rune(fz_context *ctx, fz_output *out, int rune)
{
	char data[10];
	if (out)
		out->write(ctx, out->state, data, fz_runetochar(data, rune));
}

void
fz_write_base64(fz_context *ctx, fz_output *out, const unsigned char *data, int size, int newline)
{
	static const char set[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i;
	for (i = 0; i + 3 < size; i += 3)
	{
		int c = data[i];
		int d = data[i+1];
		int e = data[i+2];
		if (newline && (i & 15) == 0)
			fz_write_byte(ctx, out, '\n');
		fz_write_byte(ctx, out, set[c>>2]);
		fz_write_byte(ctx, out, set[((c&3)<<4)|(d>>4)]);
		fz_write_byte(ctx, out, set[((d&15)<<2)|(e>>6)]);
		fz_write_byte(ctx, out, set[e&63]);
	}
	if (size - i == 2)
	{
		int c = data[i];
		int d = data[i+1];
		fz_write_byte(ctx, out, set[c>>2]);
		fz_write_byte(ctx, out, set[((c&3)<<4)|(d>>4)]);
		fz_write_byte(ctx, out, set[((d&15)<<2)]);
		fz_write_byte(ctx, out, '=');
	}
	else if (size - i == 1)
	{
		int c = data[i];
		fz_write_byte(ctx, out, set[c>>2]);
		fz_write_byte(ctx, out, set[((c&3)<<4)]);
		fz_write_byte(ctx, out, '=');
		fz_write_byte(ctx, out, '=');
	}
}

void
fz_write_base64_buffer(fz_context *ctx, fz_output *out, fz_buffer *buf, int newline)
{
	unsigned char *data;
	size_t size = fz_buffer_storage(ctx, buf, &data);
	fz_write_base64(ctx, out, data, size, newline);
}

void
fz_save_buffer(fz_context *ctx, fz_buffer *buf, const char *filename)
{
	fz_output *out = fz_new_output_with_path(ctx, filename, 0);
	fz_try(ctx)
	{
		fz_write_data(ctx, out, buf->data, buf->len);
		fz_close_output(ctx, out);
	}
	fz_always(ctx)
		fz_drop_output(ctx, out);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

fz_band_writer *fz_new_band_writer_of_size(fz_context *ctx, size_t size, fz_output *out)
{
	fz_band_writer *writer = fz_calloc(ctx, size, 1);
	writer->out = out;
	return writer;
}

void fz_write_header(fz_context *ctx, fz_band_writer *writer, int w, int h, int n, int alpha, int xres, int yres, int pagenum, const fz_colorspace *cs, fz_separations *seps)
{
	if (writer == NULL || writer->band == NULL)
		return;

	writer->w = w;
	writer->h = h;
	writer->s = fz_count_active_separations(ctx, seps);
	writer->n = n;
	writer->alpha = alpha;
	writer->xres = xres;
	writer->yres = yres;
	writer->pagenum = pagenum;
	writer->line = 0;
	writer->seps = fz_keep_separations(ctx, seps);
	writer->header(ctx, writer, cs);
}

void fz_write_band(fz_context *ctx, fz_band_writer *writer, int stride, int band_height, const unsigned char *samples)
{
	if (writer == NULL || writer->band == NULL)
		return;
	if (writer->line + band_height > writer->h)
		band_height = writer->h - writer->line;
	if (band_height < 0) {
		fz_throw(ctx, FZ_ERROR_GENERIC, "Too much band data!");
	}
	if (band_height > 0) {
		writer->band(ctx, writer, stride, writer->line, band_height, samples);
		writer->line += band_height;
	}
	if (writer->line == writer->h && writer->trailer) {
		writer->trailer(ctx, writer);
		/* Protect against more band_height == 0 calls */
		writer->line++;
	}
}

void fz_drop_band_writer(fz_context *ctx, fz_band_writer *writer)
{
	if (writer == NULL)
		return;
	if (writer->drop != NULL)
		writer->drop(ctx, writer);
	fz_drop_separations(ctx, writer->seps);
	fz_free(ctx, writer);
}
