#include "mupdf/xps.h"

static void xps_init_document(fz_context *ctx, xps_document *doc);

xps_part *
xps_new_part(fz_context *ctx, xps_document *doc, char *name, unsigned char *data, int size)
{
	xps_part *part;

	part = fz_malloc_struct(ctx, xps_part);
	fz_try(ctx)
	{
		part->name = fz_strdup(ctx, name);
		part->data = data;
		part->size = size;
	}
	fz_catch(ctx)
	{
		fz_free(ctx, part->name);
		fz_free(ctx, part->data);
		fz_free(ctx, part);
		fz_rethrow(ctx);
	}

	return part;
}

void
xps_drop_part(fz_context *ctx, xps_document *doc, xps_part *part)
{
	fz_free(ctx, part->name);
	fz_free(ctx, part->data);
	fz_free(ctx, part);
}

/*
 * Read and interleave split parts from a ZIP file.
 */
xps_part *
xps_read_part(fz_context *ctx, xps_document *doc, char *partname)
{
	fz_archive *zip = doc->zip;
	fz_buffer *buf, *tmp;
	char path[2048];
	unsigned char *data;
	int size;
	int count;
	char *name;
	int seen_last;

	name = partname;
	if (name[0] == '/')
		name ++;

	/* All in one piece */
	if (fz_has_archive_entry(ctx, zip, name))
	{
		buf = fz_read_archive_entry(ctx, zip, name);
	}

	/* Assemble all the pieces */
	else
	{
		buf = fz_new_buffer(ctx, 512);
		seen_last = 0;
		for (count = 0; !seen_last; ++count)
		{
			sprintf(path, "%s/[%d].piece", name, count);
			if (fz_has_archive_entry(ctx, zip, path))
			{
				tmp = fz_read_archive_entry(ctx, zip, path);
				fz_buffer_cat(ctx, buf, tmp);
				fz_drop_buffer(ctx, tmp);
			}
			else
			{
				sprintf(path, "%s/[%d].last.piece", name, count);
				if (fz_has_archive_entry(ctx, zip, path))
				{
					tmp = fz_read_archive_entry(ctx, zip, path);
					fz_buffer_cat(ctx, buf, tmp);
					fz_drop_buffer(ctx, tmp);
					seen_last = 1;
				}
				else
				{
					fz_drop_buffer(ctx, buf);
					fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find all pieces for part '%s'", partname);
				}
			}
		}
	}

	fz_write_buffer_byte(ctx, buf, 0); /* zero-terminate */

	/* take over the data */
	data = buf->data;
	/* size doesn't include the added zero-terminator */
	size = buf->len - 1;
	fz_free(ctx, buf);

	return xps_new_part(ctx, doc, partname, data, size);
}

int
xps_has_part(fz_context *ctx, xps_document *doc, char *name)
{
	char buf[2048];
	if (name[0] == '/')
		name++;
	if (fz_has_archive_entry(ctx, doc->zip, name))
		return 1;
	sprintf(buf, "%s/[0].piece", name);
	if (fz_has_archive_entry(ctx, doc->zip, buf))
		return 1;
	sprintf(buf, "%s/[0].last.piece", name);
	if (fz_has_archive_entry(ctx, doc->zip, buf))
		return 1;
	return 0;
}

static xps_document *
xps_open_document_with_directory(fz_context *ctx, const char *directory)
{
	xps_document *doc;

	doc = fz_malloc_struct(ctx, xps_document);
	xps_init_document(ctx, doc);
	doc->zip = fz_open_directory(ctx, directory);

	fz_try(ctx)
	{
		xps_read_page_list(ctx, doc);
	}
	fz_catch(ctx)
	{
		xps_close_document(ctx, doc);
		fz_rethrow(ctx);
	}

	return doc;
}

xps_document *
xps_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	xps_document *doc;

	doc = fz_malloc_struct(ctx, xps_document);
	xps_init_document(ctx, doc);

	fz_try(ctx)
	{
		doc->zip = fz_open_archive_with_stream(ctx, file);
		xps_read_page_list(ctx, doc);
	}
	fz_catch(ctx)
	{
		xps_close_document(ctx, doc);
		fz_rethrow(ctx);
	}

	return doc;
}

xps_document *
xps_open_document(fz_context *ctx, const char *filename)
{
	char buf[2048];
	fz_stream *file;
	char *p;
	xps_document *doc;

	if (strstr(filename, "/_rels/.rels") || strstr(filename, "\\_rels\\.rels"))
	{
		fz_strlcpy(buf, filename, sizeof buf);
		p = strstr(buf, "/_rels/.rels");
		if (!p)
			p = strstr(buf, "\\_rels\\.rels");
		*p = 0;
		return xps_open_document_with_directory(ctx, buf);
	}

	file = fz_open_file(ctx, filename);

	fz_try(ctx)
		doc = xps_open_document_with_stream(ctx, file);
	fz_always(ctx)
		fz_drop_stream(ctx, file);
	fz_catch(ctx)
		fz_rethrow_message(ctx, "cannot load document '%s'", filename);

	return doc;
}

void
xps_close_document(fz_context *ctx, xps_document *doc)
{
	xps_font_cache *font, *next;

	if (!doc)
		return;

	if (doc->zip)
		fz_drop_archive(ctx, doc->zip);

	font = doc->font_table;
	while (font)
	{
		next = font->next;
		fz_drop_font(ctx, font->font);
		fz_free(ctx, font->name);
		fz_free(ctx, font);
		font = next;
	}

	xps_drop_page_list(ctx, doc);

	fz_free(ctx, doc->start_part);
	fz_free(ctx, doc);
}

static int
xps_lookup_metadata(fz_context *ctx, xps_document *doc, const char *key, char *buf, int size)
{
	if (!strcmp(key, "format"))
		return fz_strlcpy(buf, "XPS", size);
	return -1;
}

static void
xps_init_document(fz_context *ctx, xps_document *doc)
{
	doc->super.refs = 1;
	doc->super.close = (fz_document_close_fn *)xps_close_document;
	doc->super.load_outline = (fz_document_load_outline_fn *)xps_load_outline;
	doc->super.count_pages = (fz_document_count_pages_fn *)xps_count_pages;
	doc->super.load_page = (fz_document_load_page_fn *)xps_load_page;
	doc->super.lookup_metadata = (fz_document_lookup_metadata_fn *)xps_lookup_metadata;
}
