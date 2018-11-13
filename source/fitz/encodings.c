#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include "encodings.h"

#include <string.h>
#include <stdlib.h>

#define FROM_UNICODE(ENC) \
{ \
	int l = 0; \
	int r = nelem(ENC##_from_unicode) - 1; \
	if (u < 128) \
		return u; \
	while (l <= r) \
	{ \
		int m = (l + r) >> 1; \
		if (u < ENC##_from_unicode[m].u) \
			r = m - 1; \
		else if (u > ENC##_from_unicode[m].u) \
			l = m + 1; \
		else \
			return ENC##_from_unicode[m].c; \
	} \
	return -1; \
}

int fz_iso8859_1_from_unicode(int u) FROM_UNICODE(iso8859_1)
int fz_iso8859_7_from_unicode(int u) FROM_UNICODE(iso8859_7)
int fz_koi8u_from_unicode(int u) FROM_UNICODE(koi8u)
int fz_windows_1250_from_unicode(int u) FROM_UNICODE(windows_1250)
int fz_windows_1251_from_unicode(int u) FROM_UNICODE(windows_1251)
int fz_windows_1252_from_unicode(int u) FROM_UNICODE(windows_1252)
