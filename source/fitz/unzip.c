#include "mupdf/fitz.h"
#include "fitz-imp.h"

#include <string.h>

#include <zlib.h>

#if !defined (INT32_MAX)
#define INT32_MAX 2147483647L
#endif

#define ZIP_LOCAL_FILE_SIG 0x04034b50
#define ZIP_DATA_DESC_SIG 0x08074b50
#define ZIP_CENTRAL_DIRECTORY_SIG 0x02014b50
#define ZIP_END_OF_CENTRAL_DIRECTORY_SIG 0x06054b50

#define ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIG 0x07064b50
#define ZIP64_END_OF_CENTRAL_DIRECTORY_SIG 0x06064b50
#define ZIP64_EXTRA_FIELD_SIG 0x0001

#define ZIP_ENCRYPTED_FLAG 0x1

typedef struct zip_entry_s zip_entry;
typedef struct fz_zip_archive_s fz_zip_archive;

struct zip_entry_s
{
	char *name;
	int offset, csize, usize;
};

struct fz_zip_archive_s
{
	fz_archive super;

	int count;
	zip_entry *entries;
};

static void drop_zip_archive(fz_context *ctx, fz_archive *arch)
{
	fz_zip_archive *zip = (fz_zip_archive *) arch;
	int i;
	for (i = 0; i < zip->count; ++i)
		fz_free(ctx, zip->entries[i].name);
	fz_free(ctx, zip->entries);
}

static void read_zip_dir_imp(fz_context *ctx, fz_zip_archive *zip, int start_offset)
{
	fz_stream *file = zip->super.file;
	int sig;
	int i, count, offset, csize, usize;
	int namesize, metasize, commentsize;
	char *name;
	size_t n;

	zip->count = 0;

	fz_seek(ctx, file, start_offset, 0);

	sig = fz_read_int32_le(ctx, file);
	if (sig != ZIP_END_OF_CENTRAL_DIRECTORY_SIG)
		fz_throw(ctx, FZ_ERROR_GENERIC, "wrong zip end of central directory signature (0x%x)", sig);

	(void) fz_read_int16_le(ctx, file); /* this disk */
	(void) fz_read_int16_le(ctx, file); /* start disk */
	(void) fz_read_int16_le(ctx, file); /* entries in this disk */
	count = fz_read_int16_le(ctx, file); /* entries in central directory disk */
	(void) fz_read_int32_le(ctx, file); /* size of central directory */
	offset = fz_read_int32_le(ctx, file); /* offset to central directory */

	/* ZIP64 */
	if (count == 0xFFFF || offset == 0xFFFFFFFF)
	{
		int64_t offset64, count64;

		fz_seek(ctx, file, start_offset - 20, 0);

		sig = fz_read_int32_le(ctx, file);
		if (sig != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIG)
			fz_throw(ctx, FZ_ERROR_GENERIC, "wrong zip64 end of central directory locator signature (0x%x)", sig);

		(void) fz_read_int32_le(ctx, file); /* start disk */
		offset64 = fz_read_int64_le(ctx, file); /* offset to end of central directory record */
		if (offset64 > INT32_MAX)
			fz_throw(ctx, FZ_ERROR_GENERIC, "zip64 files larger than 2 GB aren't supported");

		fz_seek(ctx, file, offset64, 0);

		sig = fz_read_int32_le(ctx, file);
		if (sig != ZIP64_END_OF_CENTRAL_DIRECTORY_SIG)
			fz_throw(ctx, FZ_ERROR_GENERIC, "wrong zip64 end of central directory signature (0x%x)", sig);

		(void) fz_read_int64_le(ctx, file); /* size of record */
		(void) fz_read_int16_le(ctx, file); /* version made by */
		(void) fz_read_int16_le(ctx, file); /* version to extract */
		(void) fz_read_int32_le(ctx, file); /* disk number */
		(void) fz_read_int32_le(ctx, file); /* disk number start */
		count64 = fz_read_int64_le(ctx, file); /* entries in central directory disk */
		(void) fz_read_int64_le(ctx, file); /* entries in central directory */
		(void) fz_read_int64_le(ctx, file); /* size of central directory */
		offset64 = fz_read_int64_le(ctx, file); /* offset to central directory */

		if (count == 0xFFFF)
		{
			if (count64 > INT32_MAX)
				fz_throw(ctx, FZ_ERROR_GENERIC, "zip64 files larger than 2 GB aren't supported");
			count = count64;
		}
		if (offset == 0xFFFFFFFF)
		{
			if (offset64 > INT32_MAX)
				fz_throw(ctx, FZ_ERROR_GENERIC, "zip64 files larger than 2 GB aren't supported");
			offset = offset64;
		}
	}

	fz_seek(ctx, file, offset, 0);

	for (i = 0; i < count; i++)
	{
		sig = fz_read_int32_le(ctx, file);
		if (sig != ZIP_CENTRAL_DIRECTORY_SIG)
			fz_throw(ctx, FZ_ERROR_GENERIC, "wrong zip central directory signature (0x%x)", sig);

		(void) fz_read_int16_le(ctx, file); /* version made by */
		(void) fz_read_int16_le(ctx, file); /* version to extract */
		(void) fz_read_int16_le(ctx, file); /* general */
		(void) fz_read_int16_le(ctx, file); /* method */
		(void) fz_read_int16_le(ctx, file); /* last mod file time */
		(void) fz_read_int16_le(ctx, file); /* last mod file date */
		(void) fz_read_int32_le(ctx, file); /* crc-32 */
		csize = fz_read_int32_le(ctx, file);
		usize = fz_read_int32_le(ctx, file);
		namesize = fz_read_int16_le(ctx, file);
		metasize = fz_read_int16_le(ctx, file);
		commentsize = fz_read_int16_le(ctx, file);
		(void) fz_read_int16_le(ctx, file); /* disk number start */
		(void) fz_read_int16_le(ctx, file); /* int file atts */
		(void) fz_read_int32_le(ctx, file); /* ext file atts */
		offset = fz_read_int32_le(ctx, file);

		name = fz_malloc(ctx, namesize + 1);
		n = fz_read(ctx, file, (unsigned char*)name, namesize);
		if (n < (size_t)namesize)
			fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of data in zip entry name");
		name[namesize] = '\0';

		while (metasize > 0)
		{
			int type = fz_read_int16_le(ctx, file);
			int size = fz_read_int16_le(ctx, file);
			if (type == ZIP64_EXTRA_FIELD_SIG)
			{
				int sizeleft = size;
				if (usize == 0xFFFFFFFF && sizeleft >= 8)
				{
					usize = fz_read_int64_le(ctx, file);
					sizeleft -= 8;
				}
				if (csize == 0xFFFFFFFF && sizeleft >= 8)
				{
					csize = fz_read_int64_le(ctx, file);
					sizeleft -= 8;
				}
				if (offset == 0xFFFFFFFF && sizeleft >= 8)
				{
					offset = fz_read_int64_le(ctx, file);
					sizeleft -= 8;
				}
				fz_seek(ctx, file, sizeleft - size, 1);
			}
			fz_seek(ctx, file, size, 1);
			metasize -= 4 + size;
		}
		if (usize < 0 || csize < 0 || offset < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "zip64 files larger than 2 GB are not supported");

		fz_seek(ctx, file, commentsize, 1);

		zip->entries = fz_resize_array(ctx, zip->entries, zip->count + 1, sizeof *zip->entries);

		zip->entries[zip->count].name = name;
		zip->entries[zip->count].offset = offset;
		zip->entries[zip->count].csize = csize;
		zip->entries[zip->count].usize = usize;

		zip->count++;
	}
}

static int read_zip_entry_header(fz_context *ctx, fz_zip_archive *zip, zip_entry *ent)
{
	fz_stream *file = zip->super.file;
	int sig, general, method, namelength, extralength;

	fz_seek(ctx, file, ent->offset, 0);

	sig = fz_read_int32_le(ctx, file);
	if (sig != ZIP_LOCAL_FILE_SIG)
		fz_throw(ctx, FZ_ERROR_GENERIC, "wrong zip local file signature (0x%x)", sig);

	(void) fz_read_int16_le(ctx, file); /* version */
	general = fz_read_int16_le(ctx, file); /* general */
	if (general & ZIP_ENCRYPTED_FLAG)
		fz_throw(ctx, FZ_ERROR_GENERIC, "zip content is encrypted");

	method = fz_read_int16_le(ctx, file);
	(void) fz_read_int16_le(ctx, file); /* file time */
	(void) fz_read_int16_le(ctx, file); /* file date */
	(void) fz_read_int32_le(ctx, file); /* crc-32 */
	(void) fz_read_int32_le(ctx, file); /* csize */
	(void) fz_read_int32_le(ctx, file); /* usize */
	namelength = fz_read_int16_le(ctx, file);
	extralength = fz_read_int16_le(ctx, file);

	fz_seek(ctx, file, namelength + extralength, 1);

	return method;
}

static void ensure_zip_entries(fz_context *ctx, fz_zip_archive *zip)
{
	fz_stream *file = zip->super.file;
	unsigned char buf[512];
	size_t size, back, maxback;
	size_t i, n;

	fz_seek(ctx, file, 0, FZ_SEEK_END);
	size = fz_tell(ctx, file);

	maxback = fz_minz(size, 0xFFFF + sizeof buf);
	back = fz_minz(maxback, sizeof buf);

	while (back < maxback)
	{
		fz_seek(ctx, file, (fz_off_t)(size - back), 0);
		n = fz_read(ctx, file, buf, sizeof buf);
		if (n < 4)
			break;
		for (i = n - 4; i > 0; i--)
			if (!memcmp(buf + i, "PK\5\6", 4))
			{
				read_zip_dir_imp(ctx, zip, (int)(size - back + i));
				return;
			}
		back += sizeof buf - 4;
	}

	fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find end of central directory");
}

static zip_entry *lookup_zip_entry(fz_context *ctx, fz_zip_archive *zip, const char *name)
{
	int i;
	for (i = 0; i < zip->count; i++)
		if (!fz_strcasecmp(name, zip->entries[i].name))
			return &zip->entries[i];
	return NULL;
}

static fz_stream *open_zip_entry(fz_context *ctx, fz_archive *arch, const char *name)
{
	fz_zip_archive *zip = (fz_zip_archive *) arch;
	fz_stream *file = zip->super.file;
	int method;
	zip_entry *ent;

	ent = lookup_zip_entry(ctx, zip, name);
	if (!ent)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find named zip archive entry");

	method = read_zip_entry_header(ctx, zip, ent);
	if (method == 0)
		return fz_open_null(ctx, file, ent->usize, fz_tell(ctx, file));
	if (method == 8)
		return fz_open_flated(ctx, file, -15);
	fz_throw(ctx, FZ_ERROR_GENERIC, "unknown zip method: %d", method);
}

static fz_buffer *read_zip_entry(fz_context *ctx, fz_archive *arch, const char *name)
{
	fz_zip_archive *zip = (fz_zip_archive *) arch;
	fz_stream *file = zip->super.file;
	fz_buffer *ubuf;
	unsigned char *cbuf;
	int method;
	z_stream z;
	int code;
	int len;
	zip_entry *ent;

	ent = lookup_zip_entry(ctx, zip, name);
	if (!ent)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find named zip archive entry");

	method = read_zip_entry_header(ctx, zip, ent);
	ubuf = fz_new_buffer(ctx, ent->usize + 1); /* +1 because many callers will add a terminating zero */

	if (method == 0)
	{
		fz_try(ctx)
		{
			ubuf->len = fz_read(ctx, file, ubuf->data, ent->usize);
			if (ubuf->len < (size_t)ent->usize)
				fz_warn(ctx, "premature end of data in stored zip archive entry");
		}
		fz_catch(ctx)
		{
			fz_drop_buffer(ctx, ubuf);
			fz_rethrow(ctx);
		}
		return ubuf;
	}
	else if (method == 8)
	{
		cbuf = fz_malloc(ctx, ent->csize);
		fz_try(ctx)
		{
			fz_read(ctx, file, cbuf, ent->csize);

			z.zalloc = (alloc_func) fz_malloc_array;
			z.zfree = (free_func) fz_free;
			z.opaque = ctx;
			z.next_in = cbuf;
			z.avail_in = ent->csize;
			z.next_out = ubuf->data;
			z.avail_out = ent->usize;

			code = inflateInit2(&z, -15);
			if (code != Z_OK)
			{
				fz_throw(ctx, FZ_ERROR_GENERIC, "zlib inflateInit2 error: %s", z.msg);
			}
			code = inflate(&z, Z_FINISH);
			if (code != Z_STREAM_END)
			{
				inflateEnd(&z);
				fz_throw(ctx, FZ_ERROR_GENERIC, "zlib inflate error: %s", z.msg);
			}
			code = inflateEnd(&z);
			if (code != Z_OK)
			{
				fz_throw(ctx, FZ_ERROR_GENERIC, "zlib inflateEnd error: %s", z.msg);
			}

			len = ent->usize - z.avail_out;
			if (len < ent->usize)
				fz_warn(ctx, "premature end of data in compressed archive entry");
			ubuf->len = len;
		}
		fz_always(ctx)
		{
			fz_free(ctx, cbuf);
		}
		fz_catch(ctx)
		{
			fz_drop_buffer(ctx, ubuf);
			fz_rethrow(ctx);
		}
		return ubuf;
	}

	fz_drop_buffer(ctx, ubuf);
	fz_throw(ctx, FZ_ERROR_GENERIC, "unknown zip method: %d", method);
}

static int has_zip_entry(fz_context *ctx, fz_archive *arch, const char *name)
{
	fz_zip_archive *zip = (fz_zip_archive *) arch;
	zip_entry *ent = lookup_zip_entry(ctx, zip, name);
	return ent != NULL;
}

static const char *list_zip_entry(fz_context *ctx, fz_archive *arch, int idx)
{
	fz_zip_archive *zip = (fz_zip_archive *) arch;
	if (idx < 0 || idx >= zip->count)
		return NULL;
	return zip->entries[idx].name;
}

static int count_zip_entries(fz_context *ctx, fz_archive *arch)
{
	fz_zip_archive *zip = (fz_zip_archive *) arch;
	return zip->count;
}

int
fz_is_zip_archive(fz_context *ctx, fz_stream *file)
{
	const unsigned char signature[4] = { 'P', 'K', 0x03, 0x04 };
	unsigned char data[4];
	size_t n;

	fz_seek(ctx, file, 0, 0);
	n = fz_read(ctx, file, data, nelem(data));
	if (n != nelem(signature))
		return 0;
	if (memcmp(data, signature, nelem(signature)))
		return 0;

	return 1;
}

fz_archive *
fz_open_zip_archive_with_stream(fz_context *ctx, fz_stream *file)
{
	fz_zip_archive *zip;

	if (!fz_is_zip_archive(ctx, file))
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot recognize zip archive");

	zip = fz_new_derived_archive(ctx, file, fz_zip_archive);
	zip->super.format = "zip";
	zip->super.count_entries = count_zip_entries;
	zip->super.list_entry = list_zip_entry;
	zip->super.has_entry = has_zip_entry;
	zip->super.read_entry = read_zip_entry;
	zip->super.open_entry = open_zip_entry;
	zip->super.drop_archive = drop_zip_archive;

	fz_try(ctx)
	{
		ensure_zip_entries(ctx, zip);
	}
	fz_catch(ctx)
	{
		fz_drop_archive(ctx, &zip->super);
		fz_rethrow(ctx);
	}

	return &zip->super;
}

fz_archive *
fz_open_zip_archive(fz_context *ctx, const char *filename)
{
	fz_archive *zip = NULL;
	fz_stream *file;

	file = fz_open_file(ctx, filename);

	fz_var(zip);

	fz_try(ctx)
		zip = fz_open_zip_archive_with_stream(ctx, file);
	fz_always(ctx)
		fz_drop_stream(ctx, file);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return zip;
}
