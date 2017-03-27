#ifndef MUPDF_FITZ_ARCHIVE_H
#define MUPDF_FITZ_ARCHIVE_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/buffer.h"
#include "mupdf/fitz/stream.h"

typedef struct fz_archive_s fz_archive;

struct fz_archive_s
{
	fz_stream *file;
	const char *format;

	void (*drop_archive)(fz_context *ctx, fz_archive *arch);
	int (*count_entries)(fz_context *ctx, fz_archive *arch);
	const char *(*list_entry)(fz_context *ctx, fz_archive *arch, int idx);
	int (*has_entry)(fz_context *ctx, fz_archive *arch, const char *name);
	fz_buffer *(*read_entry)(fz_context *ctx, fz_archive *arch, const char *name);
	fz_stream *(*open_entry)(fz_context *ctx, fz_archive *arch, const char *name);
};

/*
	fz_new_archive: Create and initialize an archive struct.
*/
fz_archive *fz_new_archive_of_size(fz_context *ctx, fz_stream *file, int size);

#define fz_new_derived_archive(C,F,M) \
	((M*)Memento_label(fz_new_archive_of_size(C, F, sizeof(M)), #M))

/*
	fz_open_archive: Open a zip or tar archive

	Open a file and identify its archive type based on the archive
	signature contained inside.

	filename: a path to a file as it would be given to open(2).
*/
fz_archive *fz_open_archive(fz_context *ctx, const char *filename);

/*
	fz_open_archive_with_stream: Open zip or tar archive stream.

	Open an archive using a seekable stream object rather than
	opening a file or directory on disk.
*/
fz_archive *fz_open_archive_with_stream(fz_context *ctx, fz_stream *file);

/*
	fz_open_directory: Open a directory as if it was an archive.

	A special case where a directory is opened as if it was an
	archive.

	Note that for directories it is not possible to retrieve the
	number of entries or list the entries. It is however possible
	to check if the archive has a particular entry.

	path: a path to a directory as it would be given to opendir(3).
*/
fz_archive *fz_open_directory(fz_context *ctx, const char *path);

/*
	fz_drop_archive: Release an open archive.

	Any allocations for the archive are freed.
*/
void fz_drop_archive(fz_context *ctx, fz_archive *arch);

/*
	fz_archive_format: Returns the name of the archive format.
*/
const char *fz_archive_format(fz_context *ctx, fz_archive *arch);

/*
	fz_count_archive_entries: Number of entries in archive.

	Will always return a value >= 0.
*/
int fz_count_archive_entries(fz_context *ctx, fz_archive *arch);

/*
	fz_list_archive_entry: Get listed name of entry position idx.

	idx: Must be a value >= 0 < return value from
	fz_count_archive_entries. If not in range NULL will be
	returned.
*/
const char *fz_list_archive_entry(fz_context *ctx, fz_archive *arch, int idx);

/*
	fz_has_archive_entry: Check if entry by given name exists.

	If named entry does not exist 0 will be returned, if it does
	exist 1 is returned.

	name: Entry name to look for, this must be an exact match to
	the entry name in the archive.
*/
int fz_has_archive_entry(fz_context *ctx, fz_archive *arch, const char *name);

/*
	fz_open_archive_entry: Opens an archive entry as a stream.

	name: Entry name to look for, this must be an exact match to
	the entry name in the archive.
*/
fz_stream *fz_open_archive_entry(fz_context *ctx, fz_archive *arch, const char *name);

/*
	fz_read_archive_entry: Reads all bytes in an archive entry
	into a buffer.

	name: Entry name to look for, this must be an exact match to
	the entry name in the archive.
*/

fz_buffer *fz_read_archive_entry(fz_context *ctx, fz_archive *arch, const char *name);

/*
	fz_is_tar_archive: Detect if stream object is a tar achieve.

	Assumes that the stream object is seekable.
*/
int fz_is_tar_archive(fz_context *ctx, fz_stream *file);

/*
	fz_open_tar_archive: Open a tar archive file.

	An exception is throw if the file is not a tar archive as
	indicated by the presence of a tar signature.

	filename: a path to a tar archive file as it would be given to
	open(2).
*/
fz_archive *fz_open_tar_archive(fz_context *ctx, const char *filename);

/*
	fz_open_tar_archive_with_stream: Open a tar archive stream.

	Open an archive using a seekable stream object rather than
	opening a file or directory on disk.

	An exception is throw if the stream is not a tar archive as
	indicated by the presence of a tar signature.

*/
fz_archive *fz_open_tar_archive_with_stream(fz_context *ctx, fz_stream *file);

/*
	fz_is_zip_archive: Detect if stream object is a zip archive.

	Assumes that the stream object is seekable.
*/
int fz_is_zip_archive(fz_context *ctx, fz_stream *file);

/*
	fz_open_zip_archive: Open a zip archive file.

	An exception is throw if the file is not a zip archive as
	indicated by the presence of a zip signature.

	filename: a path to a zip archive file as it would be given to
	open(2).
*/
fz_archive *fz_open_zip_archive(fz_context *ctx, const char *path);

/*
	fz_open_zip_archive: Open a zip archive stream.

	Open an archive using a seekable stream object rather than
	opening a file or directory on disk.

	An exception is throw if the stream is not a zip archive as
	indicated by the presence of a zip signature.

*/
fz_archive *fz_open_zip_archive_with_stream(fz_context *ctx, fz_stream *file);

typedef struct fz_zip_writer_s fz_zip_writer;

fz_zip_writer *fz_new_zip_writer(fz_context *ctx, const char *filename);
void fz_write_zip_entry(fz_context *ctx, fz_zip_writer *zip, const char *name, fz_buffer *buf, int compress);
void fz_close_zip_writer(fz_context *ctx, fz_zip_writer *zip);
void fz_drop_zip_writer(fz_context *ctx, fz_zip_writer *zip);

#endif
