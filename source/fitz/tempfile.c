#include "mupdf/fitz.h"

/* Produce a (hopefully) unique temporary filename based upon a given
 * 'base' name, with a 'hint' for where to create it.
 *
 * Isolated into a file that can be modified on a per-platform basis
 * if required.
 */

#include <stdio.h>

char *fz_tempfilename(fz_context *ctx, const char *base, const char *dir)
{
	char *p = tmpnam(NULL);
	if (!p)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot generate temporary file name");
	return fz_strdup(ctx, p);
}
