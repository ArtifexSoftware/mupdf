#include "mupdf/fitz.h"

static const char *fz_hex_digits = "0123456789abcdef";

struct fmtbuf
{
	char *p;
	size_t s;
	size_t n;
};

static void fmtputc(struct fmtbuf *out, int c)
{
	if (out->n < out->s)
		out->p[out->n] = c;
	++(out->n);
}

/*
 * Convert float to shortest possible string that won't lose precision, except:
 * NaN to 0, +Inf to FLT_MAX, -Inf to -FLT_MAX.
 */
static void fmtfloat(struct fmtbuf *out, float f)
{
	char digits[40], *s = digits;
	int exp, ndigits, point;

	if (isnan(f)) f = 0;
	if (isinf(f)) f = f < 0 ? -FLT_MAX : FLT_MAX;

	if (signbit(f))
		fmtputc(out, '-');

	if (f == 0)
	{
		fmtputc(out, '0');
		return;
	}

	ndigits = fz_grisu(f, digits, &exp);
	point = exp + ndigits;

	if (point <= 0)
	{
		fmtputc(out, '.');
		while (point++ < 0)
			fmtputc(out, '0');
		while (ndigits-- > 0)
			fmtputc(out, *s++);
	}

	else
	{
		while (ndigits-- > 0)
		{
			fmtputc(out, *s++);
			if (--point == 0 && ndigits > 0)
				fmtputc(out, '.');
		}
		while (point-- > 0)
			fmtputc(out, '0');
	}
}

static void fmtuint(struct fmtbuf *out, unsigned int a, int z, int base)
{
	char buf[40];
	int i;

	i = 0;
	while (a) {
		buf[i++] = fz_hex_digits[a % base];
		a /= base;
	}
	while (i < z)
		buf[i++] = '0';
	while (i > 0)
		fmtputc(out, buf[--i]);
}

static void fmtuint64(struct fmtbuf *out, uint64_t a, int z, int base)
{
	char buf[80];
	int i;

	i = 0;
	while (a) {
		buf[i++] = fz_hex_digits[a % base];
		a /= base;
	}
	while (i < z)
		buf[i++] = '0';
	while (i > 0)
		fmtputc(out, buf[--i]);
}

static void fmtint(struct fmtbuf *out, int value, int z, int base)
{
	unsigned int a;

	if (value < 0)
	{
		fmtputc(out, '-');
		a = -value;
	}
	else
		a = value;
	fmtuint(out, a, z, base);
}

static void fmtint64(struct fmtbuf *out, int64_t value, int z, int base)
{
	unsigned int a;

	if (value < 0)
	{
		fmtputc(out, '-');
		a = -value;
	}
	else
		a = value;
	fmtuint64(out, a, z, base);
}

static void fmtquote(struct fmtbuf *out, const char *s, int sq, int eq)
{
	int c;
	fmtputc(out, sq);
	while ((c = *s++) != 0) {
		switch (c) {
		default:
			if (c < 32 || c > 127) {
				fmtputc(out, '\\');
				fmtputc(out, '0' + ((c >> 6) & 7));
				fmtputc(out, '0' + ((c >> 3) & 7));
				fmtputc(out, '0' + ((c) & 7));
			} else {
				if (c == sq || c == eq)
					fmtputc(out, '\\');
				fmtputc(out, c);
			}
			break;
		case '\\': fmtputc(out, '\\'); fmtputc(out, '\\'); break;
		case '\b': fmtputc(out, '\\'); fmtputc(out, 'b'); break;
		case '\f': fmtputc(out, '\\'); fmtputc(out, 'f'); break;
		case '\n': fmtputc(out, '\\'); fmtputc(out, 'n'); break;
		case '\r': fmtputc(out, '\\'); fmtputc(out, 'r'); break;
		case '\t': fmtputc(out, '\\'); fmtputc(out, 't'); break;
		}
	}
	fmtputc(out, eq);
}

size_t
fz_vsnprintf(char *buffer, size_t space, const char *fmt, va_list args)
{
	struct fmtbuf out;
	fz_matrix *m;
	fz_rect *r;
	fz_point *p;
	int c, i, n, z;
	int64_t i64;
	double f;
	char *s;
	size_t length;

	out.p = buffer;
	out.s = space;
	out.n = 0;

	while ((c = *fmt++) != 0)
	{
		if (c == '%') {
			c = *fmt++;
			if (c == 0)
				break;
			z = 1;
			if (c == '0' && fmt[0] && fmt[1]) {
				z = *fmt++ - '0';
				c = *fmt++;
				while (c >= '0' && c <= '9' && fmt[0])
				{
					z = z*10 + c - '0';
					c = *fmt++;
				}
			}
			/* Check for lengths */
			length = 0;
			switch (c) {
			case 'l':
				c = *fmt++;
				if (c == 'l')
					length = 64;
				else
					fmt--;
				break;
			case 'z':
				if (sizeof(size_t) >= 8)
					length = 64;
				break;
			case 'Z':
				if (sizeof(fz_off_t) >= 8)
					length = 64;
				else
					length = 32;
				break;
			}
			if (length != 0)
			{
				c = *fmt++;
				if (c == 0)
					break; /* Can't warn :( */
			}
			switch (c) {
			default:
				fmtputc(&out, '%');
				fmtputc(&out, c);
				break;
			case '%':
				fmtputc(&out, '%');
				break;
			case 'M': /* fz_matrix * */
				m = va_arg(args, fz_matrix*);
				fmtfloat(&out, m->a); fmtputc(&out, ' ');
				fmtfloat(&out, m->b); fmtputc(&out, ' ');
				fmtfloat(&out, m->c); fmtputc(&out, ' ');
				fmtfloat(&out, m->d); fmtputc(&out, ' ');
				fmtfloat(&out, m->e); fmtputc(&out, ' ');
				fmtfloat(&out, m->f);
				break;
			case 'R': /* fz_rect * */
				r = va_arg(args, fz_rect*);
				fmtfloat(&out, r->x0); fmtputc(&out, ' ');
				fmtfloat(&out, r->y0); fmtputc(&out, ' ');
				fmtfloat(&out, r->x1); fmtputc(&out, ' ');
				fmtfloat(&out, r->y1);
				break;
			case 'P': /* fz_point * */
				p = va_arg(args, fz_point*);
				fmtfloat(&out, p->x); fmtputc(&out, ' ');
				fmtfloat(&out, p->y);
				break;
			case 'C': /* unicode char */
				c = va_arg(args, int);
				if (c < 128)
					fmtputc(&out, c);
				else {
					char buf[10];
					n = fz_runetochar(buf, c);
					for (i=0; i < n; ++i)
						fmtputc(&out, buf[i]);
				}
				break;
			case 'c':
				c = va_arg(args, int);
				fmtputc(&out, c);
				break;
			case 'f':
			case 'g':
				f = va_arg(args, double);
				fmtfloat(&out, f);
				break;
			case 'x':
				if (length == 64)
				{
					i64 = va_arg(args, int64_t);
					fmtuint64(&out, i64, z, 16);
				}
				else
				{
					i = va_arg(args, int);
					fmtuint(&out, i, z, 16);
				}
				break;
			case 'd':
				if (length == 64)
				{
					i64 = va_arg(args, int64_t);
					fmtint64(&out, i64, z, 10);
				}
				else
				{
					i = va_arg(args, int);
					fmtint(&out, i, z, 10);
				}
				break;
			case 'u':
				if (length == 64)
				{
					i64 = va_arg(args, int64_t);
					fmtuint64(&out, i64, z, 10);
				}
				else
				{
					i = va_arg(args, int);
					fmtuint(&out, i, z, 10);
				}
				break;
			case 'o':
				i = va_arg(args, int);
				fmtint(&out, i, z, 8);
				break;
			case 's':
				s = va_arg(args, char*);
				if (!s)
					s = "(null)";
				while ((c = *s++) != 0)
					fmtputc(&out, c);
				break;
			case 'q':
				s = va_arg(args, char*);
				if (!s) s = "";
				fmtquote(&out, s, '"', '"');
				break;
			case '(':
				s = va_arg(args, char*);
				if (!s) s = "";
				fmtquote(&out, s, '(', ')');
				break;
			}
		} else {
			fmtputc(&out, c);
		}
	}

	fmtputc(&out, 0);
	return out.n - 1;
}

size_t
fz_snprintf(char *buffer, size_t space, const char *fmt, ...)
{
	size_t n;
	va_list ap;
	va_start(ap, fmt);
	n = fz_vsnprintf(buffer, space, fmt, ap);
	va_end(ap);
	return n;
}
