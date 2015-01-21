#include "mupdf/fitz.h"

struct fz_output_s
{
	void *opaque;
	int (*printf)(fz_context *, void *opaque, const char *, va_list ap);
	int (*write)(fz_context *, void *opaque, const void *, int n);
	void (*close)(fz_context *, void *opaque);
};

static int
file_printf(fz_context *ctx, void *opaque, const char *fmt, va_list ap)
{
	FILE *file = opaque;
	return fz_vfprintf(ctx, file, fmt, ap);
}

static int
file_write(fz_context *ctx, void *opaque, const void *buffer, int count)
{
	FILE *file = opaque;
	return fwrite(buffer, 1, count, file);
}

static void
file_close(fz_context *ctx, void *opaque)
{
	FILE *file = opaque;
	fclose(file);
}

fz_output *
fz_new_output_with_file(fz_context *ctx, FILE *file, int close)
{
	fz_output *out = fz_malloc_struct(ctx, fz_output);
	out->opaque = file;
	out->printf = file_printf;
	out->write = file_write;
	out->close = close ? file_close : NULL;
	return out;
}

fz_output *
fz_new_output_to_filename(fz_context *ctx, const char *filename)
{
	fz_output *out = NULL;

	FILE *file = fopen(filename, "wb");
	if (!file)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open file '%s': %s", filename, strerror(errno));

	fz_var(ctx);

	fz_try(ctx)
	{
		out = fz_malloc_struct(ctx, fz_output);
		out->opaque = file;
		out->printf = file_printf;
		out->write = file_write;
		out->close = file_close;
	}
	fz_catch(ctx)
	{
		fclose(file);
		fz_rethrow(ctx);
	}
	return out;
}

void
fz_drop_output(fz_context *ctx, fz_output *out)
{
	if (!out)
		return;
	if (out->close)
		out->close(ctx, out->opaque);
	fz_free(ctx, out);
}

int
fz_printf(fz_context *ctx, fz_output *out, const char *fmt, ...)
{
	int ret;
	va_list ap;

	if (!out)
		return 0;

	va_start(ap, fmt);
	ret = out->printf(ctx, out->opaque, fmt, ap);
	va_end(ap);

	return ret;
}

int
fz_write(fz_context *ctx, fz_output *out, const void *data, int len)
{
	if (!out)
		return 0;
	return out->write(ctx, out->opaque, data, len);
}

void
fz_putc(fz_context *ctx, fz_output *out, char c)
{
	if (out)
		(void)out->write(ctx, out->opaque, &c, 1);
}

int
fz_puts(fz_context *ctx, fz_output *out, const char *str)
{
	if (!out)
		return 0;
	return out->write(ctx, out->opaque, str, strlen(str));
}

static int
buffer_printf(fz_context *ctx, void *opaque, const char *fmt, va_list list)
{
	fz_buffer *buffer = opaque;
	return fz_buffer_vprintf(ctx, buffer, fmt, list);
}

static int
buffer_write(fz_context *ctx, void *opaque, const void *data, int len)
{
	fz_buffer *buffer = opaque;
	fz_write_buffer(ctx, buffer, (unsigned char *)data, len);
	return len;
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
	out->printf = buffer_printf;
	out->write = buffer_write;
	out->close = buffer_close;
	return out;
}
