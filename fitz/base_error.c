#include "fitz.h"

enum { LINELEN = 160, LINECOUNT = 25 };

static char warnmessage[LINELEN] = "";
static int warncount = 0;

void fz_flushwarnings(void)
{
	if (warncount > 1)
		fprintf(stderr, "warning: ... repeated %d times ...\n", warncount);
	warnmessage[0] = 0;
	warncount = 0;
}

void fz_warn(char *fmt, ...)
{
	va_list ap;
	char buf[LINELEN];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	if (!strcmp(buf, warnmessage))
	{
		warncount++;
	}
	else
	{
		fz_flushwarnings();
		fprintf(stderr, "warning: %s\n", buf);
		fz_strlcpy(warnmessage, buf, sizeof warnmessage);
		warncount = 1;
	}
}

fz_error
fz_throwimp(const char *file, int line, const char *func, char *fmt, ...)
{
	va_list ap;
	fz_flushwarnings();
	fprintf(stderr, "+ %s:%d: %s(): ", file, line, func);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	return -1;
}

fz_error
fz_rethrowimp(const char *file, int line, const char *func, fz_error cause, char *fmt, ...)
{
	va_list ap;
	fz_flushwarnings();
	fprintf(stderr, "| %s:%d: %s(): ", file, line, func);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	return cause;
}

void
fz_catchimp(const char *file, int line, const char *func, fz_error cause, char *fmt, ...)
{
	va_list ap;
	fz_flushwarnings();
	fprintf(stderr, "\\ %s:%d: %s(): ", file, line, func);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

fz_error
fz_throwimpx(char *fmt, ...)
{
	va_list ap;
	fz_flushwarnings();
	fprintf(stderr, "+ ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	return -1;
}

fz_error
fz_rethrowimpx(fz_error cause, char *fmt, ...)
{
	va_list ap;
	fz_flushwarnings();
	fprintf(stderr, "| ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	return cause;
}

void
fz_catchimpx(fz_error cause, char *fmt, ...)
{
	va_list ap;
	fz_flushwarnings();
	fprintf(stderr, "\\ ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}
