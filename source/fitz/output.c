#include "mupdf/fitz.h"

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
	if (!ctx || !ctx->output)
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
file_seek(fz_context *ctx, void *opaque, fz_off_t off, int whence)
{
	FILE *file = opaque;
	int n = fz_fseek(file, off, whence);
	if (n < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot fseek: %s", strerror(errno));
}

static fz_off_t
file_tell(fz_context *ctx, void *opaque)
{
	FILE *file = opaque;
	fz_off_t off = fz_ftell(file);
	if (off == -1)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot ftell: %s", strerror(errno));
	return off;
}

static void
file_close(fz_context *ctx, void *opaque)
{
	FILE *file = opaque;
	int n = fclose(file);
	if (n < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot fclose: %s", strerror(errno));
}

fz_output *
fz_new_output_with_file_ptr(fz_context *ctx, FILE *file, int close)
{
	fz_output *out = fz_malloc_struct(ctx, fz_output);
	out->opaque = file;
	out->write = file_write;
	out->seek = file_seek;
	out->tell = file_tell;
	out->close = close ? file_close : NULL;
	return out;
}

fz_output *
fz_new_output_with_path(fz_context *ctx, const char *filename, int append)
{
	fz_output *out = NULL;
	FILE *file;

	if (!strcmp(filename, "/dev/null") || !fz_strcasecmp(filename, "nul:"))
		return NULL;

	file = fz_fopen(filename, append ? "ab" : "wb");
	if (!file)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open file '%s': %s", filename, strerror(errno));

	fz_try(ctx)
	{
		out = fz_new_output_with_file_ptr(ctx, file, 1);
	}
	fz_catch(ctx)
	{
		fclose(file);
		fz_rethrow(ctx);
	}
	return out;
}

static void
buffer_write(fz_context *ctx, void *opaque, const void *data, size_t len)
{
	fz_buffer *buffer = opaque;
	fz_write_buffer(ctx, buffer, data, len);
}

static void
buffer_seek(fz_context *ctx, void *opaque, fz_off_t off, int whence)
{
	fz_throw(ctx, FZ_ERROR_GENERIC, "cannot seek in buffer: %s", strerror(errno));
}

static fz_off_t
buffer_tell(fz_context *ctx, void *opaque)
{
	fz_buffer *buffer = opaque;
	return buffer->len;
}

static void
buffer_close(fz_context *ctx, void *opaque)
{
	fz_buffer *buffer = opaque;
	fz_drop_buffer(ctx, buffer);
}

fz_output *
fz_new_output_with_buffer(fz_context *ctx, fz_buffer *buf)
{
	fz_output *out = fz_malloc_struct(ctx, fz_output);
	out->opaque = fz_keep_buffer(ctx, buf);
	out->write = buffer_write;
	out->seek = buffer_seek;
	out->tell = buffer_tell;
	out->close = buffer_close;
	return out;
}

void
fz_drop_output(fz_context *ctx, fz_output *out)
{
	if (!out) return;
	if (out->close)
		out->close(ctx, out->opaque);
	if (out->opaque != &fz_stdout_global && out->opaque != &fz_stderr_global)
		fz_free(ctx, out);
}

void
fz_seek_output(fz_context *ctx, fz_output *out, fz_off_t off, int whence)
{
	if (!out) return;
	out->seek(ctx, out->opaque, off, whence);
}

fz_off_t
fz_tell_output(fz_context *ctx, fz_output *out)
{
	if (!out) return 0;
	return out->tell(ctx, out->opaque);
}

void
fz_vprintf(fz_context *ctx, fz_output *out, const char *fmt, va_list old_args)
{
	char buffer[256], *p = buffer;
	size_t len;
	va_list args;

	if (!out) return;

	/* First try using our fixed size buffer */
	va_copy(args, old_args);
	len = fz_vsnprintf(buffer, sizeof buffer, fmt, args);
	va_copy_end(args);

	/* If that failed, allocate a big enough buffer */
	if (len > sizeof buffer)
	{
		p = fz_malloc(ctx, len);
		va_copy(args, old_args);
		fz_vsnprintf(p, len, fmt, args);
		va_copy_end(args);
	}

	fz_try(ctx)
		out->write(ctx, out->opaque, p, len);
	fz_always(ctx)
		if (p != buffer)
			fz_free(ctx, p);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

void
fz_printf(fz_context *ctx, fz_output *out, const char *fmt, ...)
{
	va_list args;
	if (!out) return;
	va_start(args, fmt);
	fz_vprintf(ctx, out, fmt, args);
	va_end(args);
}

void
fz_save_buffer(fz_context *ctx, fz_buffer *buf, const char *filename)
{
	fz_output *out = fz_new_output_with_path(ctx, filename, 0);
	fz_try(ctx)
		fz_write(ctx, out, buf->data, buf->len);
	fz_always(ctx)
		fz_drop_output(ctx, out);
	fz_catch(ctx)
		fz_rethrow(ctx);
}
