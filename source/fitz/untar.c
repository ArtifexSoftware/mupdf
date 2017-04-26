#include "mupdf/fitz.h"
#include "fitz-imp.h"

#include <string.h>

typedef struct tar_entry_s tar_entry;
typedef struct fz_tar_archive_s fz_tar_archive;

struct tar_entry_s
{
	char *name;
	int offset, size;
};

struct fz_tar_archive_s
{
	fz_archive super;

	int count;
	tar_entry *entries;
};

static inline int isoctdigit(char c)
{
	return c >= '0' && c <= '7';
}

static inline int otoi(const char *s)
{
	int value = 0;

	while (*s && isoctdigit(*s))
	{
		value *= 8;
		value += (*s) - '0';
		s++;
	}

	return value;
}

static void drop_tar_archive(fz_context *ctx, fz_archive *arch)
{
	fz_tar_archive *tar = (fz_tar_archive *) arch;
	int i;
	for (i = 0; i < tar->count; ++i)
		fz_free(ctx, tar->entries[i].name);
	fz_free(ctx, tar->entries);
}

static void ensure_tar_entries(fz_context *ctx, fz_tar_archive *tar)
{
	fz_stream *file = tar->super.file;
	char name[100];
	char octsize[12];
	char typeflag;
	int offset, blocks, size;
	size_t n;

	tar->count = 0;

	fz_seek(ctx, file, 0, FZ_SEEK_SET);

	while (1)
	{
		offset = fz_tell(ctx, file);
		n = fz_read(ctx, file, (unsigned char *) name, nelem(name));
		if (n < nelem(name))
			fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of data in zip entry name");
		name[nelem(name) - 1] = '\0';

		if (strlen(name) == 0)
			break;

		fz_seek(ctx, file, 24, 1);
		n = fz_read(ctx, file, (unsigned char *) octsize, nelem(octsize));
		if (n < nelem(octsize))
			fz_throw(ctx, FZ_ERROR_GENERIC, "premature end of data in zip entry size");
		size = otoi(octsize);

		fz_seek(ctx, file, 20, 1);
		typeflag = fz_read_byte(ctx, file);

		fz_seek(ctx, file, 355, 1);
		blocks = (size + 511) / 512;
		fz_seek(ctx, file, blocks * 512, 1);

		if (typeflag != '0')
			continue;

		tar->entries = fz_resize_array(ctx, tar->entries, tar->count + 1, sizeof *tar->entries);

		tar->entries[tar->count].name = fz_strdup(ctx, name);
		tar->entries[tar->count].offset = offset;
		tar->entries[tar->count].size = size;

		tar->count++;
	}
}

static tar_entry *lookup_tar_entry(fz_context *ctx, fz_tar_archive *tar, const char *name)
{
	int i;
	for (i = 0; i < tar->count; i++)
		if (!fz_strcasecmp(name, tar->entries[i].name))
			return &tar->entries[i];
	return NULL;
}

static fz_stream *open_tar_entry(fz_context *ctx, fz_archive *arch, const char *name)
{
	fz_tar_archive *tar = (fz_tar_archive *) arch;
	fz_stream *file = tar->super.file;
	tar_entry *ent;

	ent = lookup_tar_entry(ctx, tar, name);
	if (!ent)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find named tar archive entry");

	fz_seek(ctx, file, ent->offset + 512, 0);
	return fz_open_null(ctx, file, ent->size, fz_tell(ctx, file));
}

static fz_buffer *read_tar_entry(fz_context *ctx, fz_archive *arch, const char *name)
{
	fz_tar_archive *tar = (fz_tar_archive *) arch;
	fz_stream *file = tar->super.file;
	fz_buffer *ubuf;
	tar_entry *ent;

	ent = lookup_tar_entry(ctx, tar, name);
	if (!ent)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find named tar archive entry");

	ubuf = fz_new_buffer(ctx, ent->size);

	fz_try(ctx)
	{
		fz_seek(ctx, file, ent->offset + 512, 0);
		ubuf->len = fz_read(ctx, file, ubuf->data, ent->size);
		if (ubuf->len != ent->size)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot read entire archive entry");
	}
	fz_catch(ctx)
	{
		fz_drop_buffer(ctx, ubuf);
		fz_rethrow(ctx);
	}

	return ubuf;
}

static int has_tar_entry(fz_context *ctx, fz_archive *arch, const char *name)
{
	fz_tar_archive *tar = (fz_tar_archive *) arch;
	tar_entry *ent = lookup_tar_entry(ctx, tar, name);
	return ent != NULL;
}

static const char *list_tar_entry(fz_context *ctx, fz_archive *arch, int idx)
{
	fz_tar_archive *tar = (fz_tar_archive *) arch;
	if (idx < 0 || idx >= tar->count)
		return NULL;
	return tar->entries[idx].name;
}

static int count_tar_entries(fz_context *ctx, fz_archive *arch)
{
	fz_tar_archive *tar = (fz_tar_archive *) arch;
	return tar->count;
}

int
fz_is_tar_archive(fz_context *ctx, fz_stream *file)
{
	const unsigned char signature[6] = { 'u', 's', 't', 'a', 'r', ' ' };
	unsigned char data[6];
	size_t n;

	fz_seek(ctx, file, 257, 0);
	n = fz_read(ctx, file, data, nelem(data));
	if (n != nelem(signature))
		return 0;
	if (memcmp(data, signature, nelem(signature)))
		return 0;

	return 1;
}

fz_archive *
fz_open_tar_archive_with_stream(fz_context *ctx, fz_stream *file)
{
	fz_tar_archive *tar;

	if (!fz_is_tar_archive(ctx, file))
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot recognize tar archive");

	tar = fz_new_derived_archive(ctx, file, fz_tar_archive);
	tar->super.format = "tar";
	tar->super.count_entries = count_tar_entries;
	tar->super.list_entry = list_tar_entry;
	tar->super.has_entry = has_tar_entry;
	tar->super.read_entry = read_tar_entry;
	tar->super.open_entry = open_tar_entry;
	tar->super.drop_archive = drop_tar_archive;

	fz_try(ctx)
	{
		ensure_tar_entries(ctx, tar);
	}
	fz_catch(ctx)
	{
		fz_drop_archive(ctx, &tar->super);
		fz_rethrow(ctx);
	}

	return &tar->super;
}

fz_archive *
fz_open_tar_archive(fz_context *ctx, const char *filename)
{
	fz_archive *tar = NULL;
	fz_stream *file;

	file = fz_open_file(ctx, filename);

	fz_try(ctx)
		tar = fz_open_tar_archive_with_stream(ctx, file);
	fz_always(ctx)
		fz_drop_stream(ctx, file);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return tar;
}
