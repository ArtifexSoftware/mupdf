#include "mupdf/fitz.h"

/* Produce a (hopefully) unique temporary filename based upon a given
 * 'base' name, with a 'hint' for where to create it.
 *
 * Isolated into a file that can be modified on a per-platform basis
 * if required.
 */

#include <stdio.h>

/*
	Get a temporary filename based upon 'base'.

	'hint' is the path of a file (normally the existing document file)
	supplied to give the function an idea of what directory to use. This
	may or may not be used depending on the implementation's whim.

	The returned path must be freed.
*/
char *fz_tempfilename(fz_context *ctx, const char *base, const char *dir)
{
	char *p = tmpnam(NULL);
	if (!p)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot generate temporary file name");
	return fz_strdup(ctx, p);
}
