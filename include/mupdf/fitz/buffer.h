#ifndef MUPDF_FITZ_BUFFER_H
#define MUPDF_FITZ_BUFFER_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"

/*
	fz_buffer is a wrapper around a dynamically allocated array of bytes.

	Buffers have a capacity (the number of bytes storage immediately
	available) and a current size.
*/
typedef struct fz_buffer_s fz_buffer;

/*
	fz_keep_buffer: Increment the reference count for a buffer.

	Returns a pointer to the buffer.
*/
fz_buffer *fz_keep_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_drop_buffer: Decrement the reference count for a buffer.
*/
void fz_drop_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_buffer_storage: Retrieve internal memory of buffer.

	datap: Output parameter that will be pointed to the data.

	Returns the current size of the data in bytes.
*/
size_t fz_buffer_storage(fz_context *ctx, fz_buffer *buf, unsigned char **datap);

/*
	fz_string_from_buffer: Ensure that a buffer's data ends in a
	0 byte, and return a pointer to it.
*/
const char *fz_string_from_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_new_buffer: Create a new buffer.

	capacity: Initial capacity.

	Returns pointer to new buffer.
*/
fz_buffer *fz_new_buffer(fz_context *ctx, size_t capacity);

/*
	fz_new_buffer_from_data: Create a new buffer with existing data.

	data: Pointer to existing data.
	size: Size of existing data.

	Takes ownership of data. Does not make a copy. Calls fz_free on the
	data when the buffer is deallocated. Do not use 'data' after passing
	to this function.

	Returns pointer to new buffer. Throws exception on allocation
	failure.
*/
fz_buffer *fz_new_buffer_from_data(fz_context *ctx, unsigned char *data, size_t size);

/*
	fz_new_buffer_from_shared_data: Like fz_new_buffer, but does not take ownership.
*/
fz_buffer *fz_new_buffer_from_shared_data(fz_context *ctx, const char *data, size_t size);

/*
	fz_new_buffer_from_base64: Create a new buffer with data decoded from a base64 input string.
*/
fz_buffer *fz_new_buffer_from_base64(fz_context *ctx, const char *data, size_t size);

/*
	fz_resize_buffer: Ensure that a buffer has a given capacity,
	truncating data if required.

	capacity: The desired capacity for the buffer. If the current size
	of the buffer contents is smaller than capacity, it is truncated.
*/
void fz_resize_buffer(fz_context *ctx, fz_buffer *buf, size_t capacity);

/*
	fz_grow_buffer: Make some space within a buffer (i.e. ensure that
	capacity > size).
*/
void fz_grow_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_trim_buffer: Trim wasted capacity from a buffer by resizing internal memory.
*/
void fz_trim_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_append_buffer: Append the contents of source buffer to destination buffer.
*/
void fz_append_buffer(fz_context *ctx, fz_buffer *destination, fz_buffer *source);

/*
	fz_append_*: Append data to a buffer.
	fz_append_printf: Format and append data to buffer using printf-like formatting (see fz_vsnprintf).
	fz_append_pdf_string: Append a string with PDF syntax quotes and escapes.
	The buffer will automatically grow as required.
*/
void fz_append_data(fz_context *ctx, fz_buffer *buf, const void *data, size_t len);
void fz_append_string(fz_context *ctx, fz_buffer *buf, const char *data);
void fz_append_byte(fz_context *ctx, fz_buffer *buf, int c);
void fz_append_rune(fz_context *ctx, fz_buffer *buf, int c);
void fz_append_int32_le(fz_context *ctx, fz_buffer *buf, int x);
void fz_append_int16_le(fz_context *ctx, fz_buffer *buf, int x);
void fz_append_bits(fz_context *ctx, fz_buffer *buf, int value, int count);
void fz_append_bits_pad(fz_context *ctx, fz_buffer *buf);
void fz_append_printf(fz_context *ctx, fz_buffer *buffer, const char *fmt, ...);
void fz_append_vprintf(fz_context *ctx, fz_buffer *buffer, const char *fmt, va_list args);
void fz_append_pdf_string(fz_context *ctx, fz_buffer *buffer, const char *text);

/*
	fz_terminate_buffer: Zero-terminate buffer in order to use as a C string.

	This byte is invisible and does not affect the length of the buffer as returned by fz_buffer_storage.
	The zero byte is written *after* the data, and subsequent writes will overwrite the terminating byte.
*/
void fz_terminate_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_md5_buffer: Create MD5 digest of buffer contents.
*/
void fz_md5_buffer(fz_context *ctx, fz_buffer *buffer, unsigned char digest[16]);

/*
	fz_buffer_extract: Take ownership of buffer contents.
	Performs the same task as fz_buffer_storage, but ownership of
	the data buffer returns with this call. The buffer is left
	empty.

	Note: Bad things may happen if this is called on a buffer with
	multiple references that is being used from multiple threads.

	data: Pointer to place to retrieve data pointer.

	Returns length of stream.
*/
size_t fz_buffer_extract(fz_context *ctx, fz_buffer *buf, unsigned char **data);

#endif
