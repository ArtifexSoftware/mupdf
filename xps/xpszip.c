#include "fitz.h"
#include "muxps.h"

#include <zlib.h>

static inline int getshort(FILE *file)
{
	int a = getc(file);
	int b = getc(file);
	return a | (b << 8);
}

static inline int getlong(FILE *file)
{
	int a = getc(file);
	int b = getc(file);
	int c = getc(file);
	int d = getc(file);
	return a | (b << 8) | (c << 16) | (d << 24);
}

static void *
xps_zip_alloc_items(xps_context_t *ctx, int items, int size)
{
	return xps_alloc(ctx, items * size);
}

static void
xps_zip_free(xps_context_t *ctx, void *ptr)
{
	xps_free(ctx, ptr);
}

static int
xps_compare_entries(const void *a0, const void *b0)
{
	xps_entry_t *a = (xps_entry_t*) a0;
	xps_entry_t *b = (xps_entry_t*) b0;
	return xps_strcasecmp(a->name, b->name);
}

static xps_entry_t *
xps_find_zip_entry(xps_context_t *ctx, char *name)
{
	int l = 0;
	int r = ctx->zip_count - 1;
	while (l <= r)
	{
		int m = (l + r) >> 1;
		int c = xps_strcasecmp(name, ctx->zip_table[m].name);
		if (c < 0)
			r = m - 1;
		else if (c > 0)
			l = m + 1;
		else
			return &ctx->zip_table[m];
	}
	return NULL;
}

/*
 * Inflate the data in a zip entry.
 */

static int
xps_read_zip_entry(xps_context_t *ctx, xps_entry_t *ent, unsigned char *outbuf)
{
	z_stream stream;
	unsigned char *inbuf;
	int sig;
	int version, general, method;
	int namelength, extralength;
	int code;

	fseek(ctx->file, ent->offset, 0);

	sig = getlong(ctx->file);
	if (sig != ZIP_LOCAL_FILE_SIG)
		return fz_throw("wrong zip local file signature (0x%x)", sig);

	version = getshort(ctx->file);
	general = getshort(ctx->file);
	method = getshort(ctx->file);
	(void) getshort(ctx->file); /* file time */
	(void) getshort(ctx->file); /* file date */
	(void) getlong(ctx->file); /* crc-32 */
	(void) getlong(ctx->file); /* csize */
	(void) getlong(ctx->file); /* usize */
	namelength = getshort(ctx->file);
	extralength = getshort(ctx->file);

	fseek(ctx->file, namelength + extralength, 1);

	if (method == 0)
	{
		fread(outbuf, 1, ent->usize, ctx->file);
	}
	else if (method == 8)
	{
		inbuf = xps_alloc(ctx, ent->csize);

		fread(inbuf, 1, ent->csize, ctx->file);

		memset(&stream, 0, sizeof(z_stream));
		stream.zalloc = (alloc_func) xps_zip_alloc_items;
		stream.zfree = (free_func) xps_zip_free;
		stream.opaque = ctx;
		stream.next_in = inbuf;
		stream.avail_in = ent->csize;
		stream.next_out = outbuf;
		stream.avail_out = ent->usize;

		code = inflateInit2(&stream, -15);
		if (code != Z_OK)
			return fz_throw("zlib inflateInit2 error: %s", stream.msg);
		code = inflate(&stream, Z_FINISH);
		if (code != Z_STREAM_END)
		{
			inflateEnd(&stream);
			return fz_throw("zlib inflate error: %s", stream.msg);
		}
		code = inflateEnd(&stream);
		if (code != Z_OK)
			return fz_throw("zlib inflateEnd error: %s", stream.msg);

		xps_free(ctx, inbuf);
	}
	else
	{
		return fz_throw("unknown compression method (%d)", method);
	}

	return fz_okay;
}

/*
 * Read the central directory in a zip file.
 */

static int
xps_read_zip_dir(xps_context_t *ctx, int start_offset)
{
	int sig;
	int offset, count;
	int namesize, metasize, commentsize;
	int i;

	fseek(ctx->file, start_offset, 0);

	sig = getlong(ctx->file);
	if (sig != ZIP_END_OF_CENTRAL_DIRECTORY_SIG)
		return fz_throw("wrong zip end of central directory signature (0x%x)", sig);

	(void) getshort(ctx->file); /* this disk */
	(void) getshort(ctx->file); /* start disk */
	(void) getshort(ctx->file); /* entries in this disk */
	count = getshort(ctx->file); /* entries in central directory disk */
	(void) getlong(ctx->file); /* size of central directory */
	offset = getlong(ctx->file); /* offset to central directory */

	ctx->zip_count = count;
	ctx->zip_table = xps_alloc(ctx, sizeof(xps_entry_t) * count);
	if (!ctx->zip_table)
		return fz_throw("cannot allocate zip entry table");

	memset(ctx->zip_table, 0, sizeof(xps_entry_t) * count);

	fseek(ctx->file, offset, 0);

	for (i = 0; i < count; i++)
	{
		sig = getlong(ctx->file);
		if (sig != ZIP_CENTRAL_DIRECTORY_SIG)
			return fz_throw("wrong zip central directory signature (0x%x)", sig);

		(void) getshort(ctx->file); /* version made by */
		(void) getshort(ctx->file); /* version to extract */
		(void) getshort(ctx->file); /* general */
		(void) getshort(ctx->file); /* method */
		(void) getshort(ctx->file); /* last mod file time */
		(void) getshort(ctx->file); /* last mod file date */
		(void) getlong(ctx->file); /* crc-32 */
		ctx->zip_table[i].csize = getlong(ctx->file);
		ctx->zip_table[i].usize = getlong(ctx->file);
		namesize = getshort(ctx->file);
		metasize = getshort(ctx->file);
		commentsize = getshort(ctx->file);
		(void) getshort(ctx->file); /* disk number start */
		(void) getshort(ctx->file); /* int file atts */
		(void) getlong(ctx->file); /* ext file atts */
		ctx->zip_table[i].offset = getlong(ctx->file);

		ctx->zip_table[i].name = xps_alloc(ctx, namesize + 1);
		if (!ctx->zip_table[i].name)
			return fz_throw("cannot allocate zip entry name");

		fread(ctx->zip_table[i].name, 1, namesize, ctx->file);
		ctx->zip_table[i].name[namesize] = 0;

		fseek(ctx->file, metasize, 1);
		fseek(ctx->file, commentsize, 1);
	}

	qsort(ctx->zip_table, count, sizeof(xps_entry_t), xps_compare_entries);

	return fz_okay;
}

static int
xps_find_and_read_zip_dir(xps_context_t *ctx)
{
	int filesize, back, maxback;
	int i, n;
	char buf[512];

	fseek(ctx->file, 0, SEEK_END);
	filesize = ftell(ctx->file);

	maxback = MIN(filesize, 0xFFFF + sizeof buf);
	back = MIN(maxback, sizeof buf);

	while (back < maxback)
	{
		fseek(ctx->file, filesize - back, 0);

		n = fread(buf, 1, sizeof buf, ctx->file);
		if (n < 0)
			return fz_throw("cannot read end of central directory");

		for (i = n - 4; i > 0; i--)
			if (!memcmp(buf + i, "PK\5\6", 4))
				return xps_read_zip_dir(ctx, filesize - back + i);

		back += sizeof buf - 4;
	}

	return fz_throw("cannot find end of central directory");
}

/*
 * Read and interleave split parts from a ZIP file.
 */

static xps_part_t *
xps_read_zip_part(xps_context_t *ctx, char *partname)
{
	char buf[2048];
	xps_entry_t *ent;
	xps_part_t *part;
	int count, size, offset, i;
	char *name;

	name = partname;
	if (name[0] == '/')
		name ++;

	/* All in one piece */
	ent = xps_find_zip_entry(ctx, name);
	if (ent)
	{
		part = xps_new_part(ctx, partname, ent->usize);
		xps_read_zip_entry(ctx, ent, part->data);
		return part;
	}

	/* Count the number of pieces and their total size */
	count = 0;
	size = 0;
	while (1)
	{
		sprintf(buf, "%s/[%d].piece", name, count);
		ent = xps_find_zip_entry(ctx, buf);
		if (!ent)
		{
			sprintf(buf, "%s/[%d].last.piece", name, count);
			ent = xps_find_zip_entry(ctx, buf);
		}
		if (!ent)
			break;
		count ++;
		size += ent->usize;
	}

	/* Inflate the pieces */
	if (count)
	{
		part = xps_new_part(ctx, partname, size);
		offset = 0;
		for (i = 0; i < count; i++)
		{
			if (i < count - 1)
				sprintf(buf, "%s/[%d].piece", name, i);
			else
				sprintf(buf, "%s/[%d].last.piece", name, i);
			ent = xps_find_zip_entry(ctx, buf);
			xps_read_zip_entry(ctx, ent, part->data + offset);
			offset += ent->usize;
		}
		return part;
	}

	return NULL;
}

/*
 * Read and interleave split parts from files in the directory.
 */

static xps_part_t *
xps_read_dir_part(xps_context_t *ctx, char *name)
{
	char buf[2048];
	xps_part_t *part;
	FILE *file;
	int count, size, offset, i, n;

	xps_strlcpy(buf, ctx->directory, sizeof buf);
	xps_strlcat(buf, name, sizeof buf);

	/* All in one piece */
	file = fopen(buf, "rb");
	if (file)
	{
		fseek(file, 0, SEEK_END);
		size = ftell(file);
		fseek(file, 0, SEEK_SET);
		part = xps_new_part(ctx, name, size);
		fread(part->data, 1, size, file);
		fclose(file);
		return part;
	}

	/* Count the number of pieces and their total size */
	count = 0;
	size = 0;
	while (1)
	{
		sprintf(buf, "%s%s/[%d].piece", ctx->directory, name, count);
		file = fopen(buf, "rb");
		if (!file)
		{
			sprintf(buf, "%s%s/[%d].last.piece", ctx->directory, name, count);
			file = fopen(buf, "rb");
		}
		if (!file)
			break;
		count ++;
		fseek(file, 0, SEEK_END);
		size += ftell(file);
		fclose(file);
	}

	/* Inflate the pieces */
	if (count)
	{
		part = xps_new_part(ctx, name, size);
		offset = 0;
		for (i = 0; i < count; i++)
		{
			if (i < count - 1)
				sprintf(buf, "%s%s/[%d].piece", ctx->directory, name, i);
			else
				sprintf(buf, "%s%s/[%d].last.piece", ctx->directory, name, i);
			file = fopen(buf, "rb");
			n = fread(part->data + offset, 1, size - offset, file);
			offset += n;
			fclose(file);
		}
		return part;
	}

	return NULL;
}

xps_part_t *
xps_read_part(xps_context_t *ctx, char *partname)
{
	if (ctx->directory)
		return xps_read_dir_part(ctx, partname);
	return xps_read_zip_part(ctx, partname);
}

/*
 * Read and process the XPS document.
 */

static int
xps_read_and_process_metadata_part(xps_context_t *ctx, char *name)
{
	xps_part_t *part;
	int code;

	part = xps_read_part(ctx, name);
	if (!part)
		return fz_rethrow(-1, "cannot read zip part '%s'", name);

	code = xps_parse_metadata(ctx, part);
	if (code)
		return fz_rethrow(code, "cannot process metadata part '%s'", name);

	xps_free_part(ctx, part);

	return fz_okay;
}

/*
 * Called by xpstop.c
 */

int
xps_open_file(xps_context_t *ctx, char *filename)
{
	char buf[2048];
	xps_document_t *doc;
	int code;
	char *p;

	ctx->file = fopen(filename, "rb");
	if (!ctx->file)
		return fz_throw("cannot open file: '%s'", filename);

	if (strstr(filename, "/_rels/.rels") || strstr(filename, "\\_rels\\.rels"))
	{
		xps_strlcpy(buf, filename, sizeof buf);
		p = strstr(buf, "/_rels/.rels");
		if (!p)
			p = strstr(buf, "\\_rels\\.rels");
		*p = 0;
		ctx->directory = xps_strdup(ctx, buf);
	}
	else
	{
		code = xps_find_and_read_zip_dir(ctx);
		if (code < 0)
			return fz_rethrow(code, "cannot read zip central directory");
	}

	code = xps_read_and_process_metadata_part(ctx, "/_rels/.rels");
	if (code)
		return fz_rethrow(code, "cannot process root relationship part");

	if (!ctx->start_part)
		return fz_throw("cannot find fixed document sequence start part");

	code = xps_read_and_process_metadata_part(ctx, ctx->start_part);
	if (code)
		return fz_rethrow(code, "cannot process FixedDocumentSequence part");

	for (doc = ctx->first_fixdoc; doc; doc = doc->next)
	{
		code = xps_read_and_process_metadata_part(ctx, doc->name);
		if (code)
			return fz_rethrow(code, "cannot process FixedDocument part");
	}

	return fz_okay;
}

int
xps_count_pages(xps_context_t *ctx)
{
	xps_page_t *page;
	int n = 0;
	for (page = ctx->first_page; page; page = page->next)
		n ++;
	return n;
}

xps_page_t *
xps_load_page(xps_context_t *ctx, int number)
{
	xps_page_t *page;
	int code;
	int n = 0;

	for (page = ctx->first_page; page; page = page->next)
	{
		if (n == number)
		{
			if (!page->root)
			{
				code = xps_load_fixed_page(ctx, page);
				if (code)
					fz_catch(code, "ignoring errors on page");
			}
			return page;
		}
		n ++;
	}
	return nil;
}

xps_context_t *
xps_new_context(void)
{
	xps_context_t *ctx;

	ctx = fz_malloc(sizeof(xps_context_t));

	memset(ctx, 0, sizeof(xps_context_t));

	ctx->font_table = xps_hash_new(ctx);
	ctx->colorspace_table = xps_hash_new(ctx);

	ctx->start_part = NULL;

	ctx->use_transparency = 1;
	if (getenv("XPS_DISABLE_TRANSPARENCY"))
		ctx->use_transparency = 0;

	ctx->opacity_only = 0;
	ctx->fill_rule = 0;

	return ctx;
}

static void xps_free_key_func(xps_context_t *ctx, void *ptr)
{
	xps_free(ctx, ptr);
}

static void xps_free_font_func(xps_context_t *ctx, void *ptr)
{
	fz_dropfont(ptr);
}

/* Wrap up interp instance after a "job" */
int
xps_free_context(xps_context_t *ctx)
{
	int i;

	if (ctx->file)
		fclose(ctx->file);

	for (i = 0; i < ctx->zip_count; i++)
		xps_free(ctx, ctx->zip_table[i].name);
	xps_free(ctx, ctx->zip_table);

	/* TODO: free resources too */
	xps_hash_free(ctx, ctx->font_table, xps_free_key_func, xps_free_font_func);
	xps_hash_free(ctx, ctx->colorspace_table, xps_free_key_func, NULL);

	xps_free_fixed_pages(ctx);
	xps_free_fixed_documents(ctx);

	return 0;
}
