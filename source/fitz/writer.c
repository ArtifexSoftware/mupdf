#include "mupdf/fitz.h"

/* Return non-null terminated pointers to key/value entries in comma separated
 * option string. A plain key has the default value 'yes'. Use strncmp to compare
 * key/value strings. */
static const char *
fz_get_option(fz_context *ctx, const char **key, const char **val, const char *opts)
{
	if (!opts || *opts == 0)
		return NULL;

	if (*opts == ',')
		++opts;

	*key = opts;
	while (*opts != 0 && *opts != ',' && *opts != '=')
		++opts;

	if (*opts == '=')
	{
		*val = ++opts;
		while (*opts != 0 && *opts != ',')
			++opts;
	}
	else
	{
		*val = "yes";
	}

	return opts;
}

int
fz_has_option(fz_context *ctx, const char *opts, const char *key, const char **val)
{
	const char *straw;
	int n = strlen(key);
	while ((opts = fz_get_option(ctx, &straw, val, opts)))
		if (!strncmp(straw, key, n) && (straw[n] == '=' || straw[n] == ',' || straw[n] == 0))
			return 1;
	return 0;
}

fz_document_writer *
fz_new_document_writer(fz_context *ctx, const char *path, const char *format, const char *options)
{
	if (!format)
	{
		format = strrchr(path, '.');
		if (!format)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot detect document format");
		format += 1; /* skip the '.' */
	}

	if (!fz_strcasecmp(format, "cbz"))
		return fz_new_cbz_writer(ctx, path, options);
	if (!fz_strcasecmp(format, "pdf"))
		return fz_new_pdf_writer(ctx, path, options);

	fz_throw(ctx, FZ_ERROR_GENERIC, "unknown document format: %s", format);
}

void
fz_close_document_writer(fz_context *ctx, fz_document_writer *wri)
{
	if (wri->close)
		wri->close(ctx, wri);
	wri->close = NULL;
}

void
fz_drop_document_writer(fz_context *ctx, fz_document_writer *wri)
{
	if (wri->close)
		wri->close(ctx, wri);
	fz_free(ctx, wri);
}

fz_device *
fz_begin_page(fz_context *ctx, fz_document_writer *wri, const fz_rect *mediabox, fz_matrix *ctm)
{
	return wri->begin_page(ctx, wri, mediabox, ctm);
}

void
fz_end_page(fz_context *ctx, fz_document_writer *wri, fz_device *dev)
{
	wri->end_page(ctx, wri, dev);
}
