#include "mupdf/fitz.h"

/*
 * compute decimal integer m, exp such that:
 *	f = m*10^exp
 *	m is as short as possible with losing exactness
 * assumes special cases (NaN, +Inf, -Inf) have been handled.
 */
void
fz_ftoa(float f, char *s, int *exp, int *neg, int *ns)
{
	char buf[40], *p = buf;
	int i;

	for (i = 0; i < 10; ++i)
	{
		sprintf(buf, "%.*e", i, f);
		if (fz_atof(buf) == f)
			break;
	}

	if (*p == '-')
	{
		*neg = 1;
		++p;
	}
	else
		*neg = 0;

	*ns = 0;
	while (*p && *p != 'e')
	{
		if (*p >= '0' && *p <= '9')
		{
			*ns += 1;
			*s++ = *p;
		}
		++p;
	}

	*exp = fz_atoi(p+1) - (*ns) + 1;
}
