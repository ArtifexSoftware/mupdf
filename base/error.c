#include <fitz.h>

void
fz_warn(char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "warning: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

fz_error *
fz_throw0(const char *func, const char *file, int line, char *fmt, ...)
{
	va_list ap;
	fz_error *eo;

	eo = fz_malloc(sizeof(fz_error));
	if (!eo) return fz_outofmem;

	strlcpy(eo->func, func, sizeof eo->func);
	strlcpy(eo->file, file, sizeof eo->file);
	eo->line = line;

	va_start(ap, fmt);
	vsnprintf(eo->msg, sizeof eo->msg, fmt, ap);
	eo->msg[sizeof(eo->msg) - 1] = '\0';
	va_end(ap);

	return eo;
}

void
fz_freeerror(fz_error *eo)
{
	if (!eo->frozen)
		fz_free(eo);
}

void
fz_abort(fz_error *eo)
{
	fflush(stdout);
	fprintf(stderr, "%s:%d: %s(): %s\n", eo->file, eo->line, eo->func, eo->msg);
	fflush(stderr);
	abort();
}

