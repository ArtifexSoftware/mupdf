#include "mupdf/fitz.h"

/* Produce a (hopefully) unique temporary filename based upon a given
 * 'base' name.
 *
 * Isolated into a file that can be modified on a per-platform basis
 * if required.
 */

char *fz_tempfilename(fz_context *ctx, const char *base)
{
	char *tmp = tempnam(".", base);
	char *ret;

	if (tmp == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to construct temporary file name");
	ret = fz_strdup(ctx, tmp);

	/* The value returned from tempnam is allocated using malloc.
	 * We must therefore free it using free. Real, honest to God
	 * free, not Memento_free, or other wrapped versions.
	 */
#undef free
	(free)(tmp);
	return ret;
}
