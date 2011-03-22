#include "fitz.h"
#include "muxps.h"

/*
 * http://tools.ietf.org/html/rfc3629
 */

int
xps_utf8_to_ucs(int *p, const char *ss, int n)
{
	unsigned char *s = (unsigned char *)ss;

	if (s == NULL)
		goto bad;

	if ((s[0] & 0x80) == 0)
	{
		*p = (s[0] & 0x7f);
		return 1;
	}

	if ((s[0] & 0xe0) == 0xc0)
	{
		if (n < 2 || s[1] < 0x80)
			goto bad;
		*p = (s[0] & 0x1f) << 6;
		*p |= (s[1] & 0x3f);
		return 2;
	}

	if ((s[0] & 0xf0) == 0xe0)
	{
		if (n < 3 || s[1] < 0x80 || s[2] < 0x80)
			goto bad;
		*p = (s[0] & 0x0f) << 12;
		*p |= (s[1] & 0x3f) << 6;
		*p |= (s[2] & 0x3f);
		return 3;
	}

	if ((s[0] & 0xf8) == 0xf0)
	{
		if (n < 4 || s[1] < 0x80 || s[2] < 0x80 || s[3] < 0x80)
			goto bad;
		*p = (s[0] & 0x07) << 18;
		*p |= (s[1] & 0x3f) << 12;
		*p |= (s[2] & 0x3f) << 6;
		*p |= (s[3] & 0x3f);
		return 4;
	}

bad:
	*p = 0x80;
	return 1;
}
