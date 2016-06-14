#include "mupdf/fitz.h"

/* Produce a (hopefully) unique temporary filename based upon a given
 * 'base' name, with a 'hint' for where to create it.
 *
 * Isolated into a file that can be modified on a per-platform basis
 * if required.
 */

/* For now, put temporary files with the hint. */
#define USE_HINT_FOR_DIR

#if defined(_WIN32) || defined(_WIN64)
#define DIRSEP '\\'
#else
#define DIRSEP '/'
#endif

char *fz_tempfilename(fz_context *ctx, const char *base, const char *hint)
{
	char *tmp;
	char *ret;

#ifdef USE_HINT_FOR_DIR
	char *hintpath;
	size_t hintlen;

	hintlen = strlen(hint);
	hintpath = fz_malloc(ctx, 1 + hintlen);
	if (hint == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to construct temporary file name");

	while (hintlen > 0 && hint[hintlen-1] != DIRSEP)
		hintlen--;

	if (hintlen > 0)
		memcpy(hintpath, hint, hintlen);
	hintpath[hintlen] = 0;
	tmp = tempnam(hintlen > 0 ? hintpath : ".", base);
	fz_free(ctx, hintpath);
#else
	tmp = tempnam(".", base);
#endif

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
