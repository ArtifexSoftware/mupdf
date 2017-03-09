#ifndef MUPDF_FITZ_OUTPUT_H
#define MUPDF_FITZ_OUTPUT_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/buffer.h"
#include "mupdf/fitz/string-util.h"

/*
	Generic output streams - generalise between outputting to a file,
	a buffer, etc.
*/
typedef struct fz_output_s fz_output;

/*
	fz_output_write_fn: A function type for use when implementing
	fz_outputs. The supplied function of this type is called
	whenever data is written to the output.

	state: The state for the output stream.

	data: a pointer to a buffer of data to write.

	n: The number of bytes of data to write.
*/
typedef void (fz_output_write_fn)(fz_context *ctx, void *state, const void *data, size_t n);

/*
	fz_output_seek_fn: A function type for use when implementing
	fz_outputs. The supplied function of this type is called when
	fz_seek_output is requested.

	state: The output stream state to seek within.

	offset, whence: as defined for fs_seek_output.
*/
typedef void (fz_output_seek_fn)(fz_context *ctx, void *state, fz_off_t offset, int whence);

/*
	fz_output_tell_fn: A function type for use when implementing
	fz_outputs. The supplied function of this type is called when
	fz_tell_output is requested.

	state: The output stream state to report on.

	Returns the offset within the output stream.
*/
typedef fz_off_t (fz_output_tell_fn)(fz_context *ctx, void *state);

/*
	fz_output_close_fn: A function type for use when implementing
	fz_outputs. The supplied function of this type is called
	when the output stream is closed, to release the stream specific
	state information.

	state: The output stream state to release.
*/
typedef void (fz_output_close_fn)(fz_context *ctx, void *state);

struct fz_output_s
{
	void *state;
	fz_output_write_fn *write;
	fz_output_seek_fn *seek;
	fz_output_tell_fn *tell;
	fz_output_close_fn *close;
};

/*
	fz_new_output: Create a new output object with the given
	internal state and function pointers.

	state: Internal state (opaque to everything but implementation).

	write: Function to output a given buffer.

	close: Cleanup function to destroy state when output closed.
	May permissibly be null.
*/
fz_output *fz_new_output(fz_context *ctx, void *state, fz_output_write_fn *write, fz_output_close_fn *close);

/*
	fz_new_output_with_file: Open an output stream that writes to a
	FILE *.

	file: The file to write to.

	close: non-zero if we should close the file when the fz_output
	is closed.
*/
fz_output *fz_new_output_with_file_ptr(fz_context *ctx, FILE *file, int close);

/*
	fz_new_output_with_path: Open an output stream that writes to a
	given path.

	filename: The filename to write to (specified in UTF-8).

	append: non-zero if we should append to the file, rather than
	overwriting it.
*/
fz_output *fz_new_output_with_path(fz_context *, const char *filename, int append);

/*
	fz_new_output_with_buffer: Open an output stream that appends
	to a buffer.

	buf: The buffer to append to.
*/
fz_output *fz_new_output_with_buffer(fz_context *ctx, fz_buffer *buf);

/*
	fz_stdout: The standard out output stream. By default
	this stream writes to stdout. This may be overridden
	using fz_set_stdout.
*/
fz_output *fz_stdout(fz_context *ctx);

/*
	fz_stderr: The standard error output stream. By default
	this stream writes to stderr. This may be overridden
	using fz_set_stderr.
*/
fz_output *fz_stderr(fz_context *ctx);

/*
	fz_set_stdout: Replace default standard output stream
	with a given stream.

	out: The new stream to use.
*/
void fz_set_stdout(fz_context *ctx, fz_output *out);

/*
	fz_set_stderr: Replace default standard error stream
	with a given stream.

	err: The new stream to use.
*/
void fz_set_stderr(fz_context *ctx, fz_output *err);

/*
	fz_printf: fprintf equivalent for output streams. See fz_snprintf.
*/
void fz_printf(fz_context *ctx, fz_output *out, const char *fmt, ...);

/*
	fz_vprintf: vfprintf equivalent for output streams. See fz_vsnprintf.
*/
void fz_vprintf(fz_context *ctx, fz_output *out, const char *fmt, va_list ap);

/*
	fz_putc: fputc equivalent for output streams.
*/
#define fz_putc(C,O,B) fz_write_byte(C, O, B)

/*
	fz_puts: fputs equivalent for output streams.
*/
#define fz_puts(C,O,S) fz_write(C, O, (S), strlen(S))

/*
	fz_putrune: fz_putc equivalent for utf-8 output.
*/
#define fz_putrune(C,O,R) fz_write_rune(C, O, R)

/*
	fz_seek_output: Seek to the specified file position. See fseek
	for arguments.

	Throw an error on unseekable outputs.
*/
void fz_seek_output(fz_context *ctx, fz_output *out, fz_off_t off, int whence);

/*
	fz_tell_output: Return the current file position. Throw an error
	on untellable outputs.
*/
fz_off_t fz_tell_output(fz_context *ctx, fz_output *out);

/*
	fz_drop_output: Close and free an output stream.
*/
void fz_drop_output(fz_context *, fz_output *);

/*
	fz_write: Write data to output. Designed to parallel
	fwrite.

	out: Output stream to write to.

	data: Pointer to data to write.

	size: Length of data to write.
*/
static inline void fz_write(fz_context *ctx, fz_output *out, const void *data, size_t size)
{
	if (out)
		out->write(ctx, out->state, data, size);
}

/*
	fz_write_int32_be: Write a big-endian 32-bit binary integer.
*/
static inline void fz_write_int32_be(fz_context *ctx, fz_output *out, int x)
{
	char data[4];

	data[0] = x>>24;
	data[1] = x>>16;
	data[2] = x>>8;
	data[3] = x;

	fz_write(ctx, out, data, 4);
}

/*
	fz_write_int32_le: Write a little-endian 32-bit binary integer.
*/
static inline void fz_write_int32_le(fz_context *ctx, fz_output *out, int x)
{
	char data[4];

	data[0] = x;
	data[1] = x>>8;
	data[2] = x>>16;
	data[3] = x>>24;

	fz_write(ctx, out, data, 4);
}

/*
	fz_write_int16_be: Write a big-endian 16-bit binary integer.
*/
static inline void fz_write_int16_be(fz_context *ctx, fz_output *out, int x)
{
	char data[2];

	data[0] = x>>8;
	data[1] = x;

	fz_write(ctx, out, data, 2);
}

/*
	fz_write_int16_le: Write a little-endian 16-bit binary integer.
*/
static inline void fz_write_int16_le(fz_context *ctx, fz_output *out, int x)
{
	char data[2];

	data[0] = x;
	data[1] = x>>8;

	fz_write(ctx, out, data, 2);
}

/*
	fz_write_byte: Write a single byte.

	out: stream to write to.

	x: value to write
*/
static inline void fz_write_byte(fz_context *ctx, fz_output *out, unsigned char x)
{
	fz_write(ctx, out, &x, 1);
}

/*
	fz_write_rune: Write a UTF-8 encoded unicode character.

	out: stream to write to.

	x: value to write
*/
static inline void fz_write_rune(fz_context *ctx, fz_output *out, int rune)
{
	char data[10];
	fz_write(ctx, out, data, fz_runetochar(data, rune));
}

/*
	fz_vsnprintf: Our customised vsnprintf routine. Takes %c, %d, %o, %s, %u, %x, as usual.
	Modifiers are not supported except for zero-padding ints (e.g. %02d, %03o, %04x, etc).
	%f and %g both output in "as short as possible hopefully lossless non-exponent" form,
	see fz_ftoa for specifics.
	%C outputs a utf8 encoded int.
	%M outputs a fz_matrix*. %R outputs a fz_rect*. %P outputs a fz_point*.
	%q and %( output escaped strings in C/PDF syntax.
	%ll{d,u,x} indicates that the values are 64bit.
	%z{d,u,x} indicates that the value is a size_t.
	%Z{d,u,x} indicates that the value is a fz_off_t.
*/
size_t fz_vsnprintf(char *buffer, size_t space, const char *fmt, va_list args);

/*
	fz_snprintf: The non va_list equivalent of fz_vsnprintf.
*/
size_t fz_snprintf(char *buffer, size_t space, const char *fmt, ...);

/*
	fz_tempfilename: Get a temporary filename based upon 'base'.

	'hint' is the path of a file (normally the existing document file)
	supplied to give the function an idea of what directory to use. This
	may or may not be used depending on the implementation's whim.

	The returned path must be freed.
*/
char *fz_tempfilename(fz_context *ctx, const char *base, const char *hint);

/*
	fz_save_buffer: Save contents of a buffer to file.
*/
void fz_save_buffer(fz_context *ctx, fz_buffer *buf, const char *filename);

/*
	fz_band_writer
*/
typedef struct fz_band_writer_s fz_band_writer;

typedef void (fz_write_header_fn)(fz_context *ctx, fz_band_writer *writer);
typedef void (fz_write_band_fn)(fz_context *ctx, fz_band_writer *writer, int stride, int band_start, int band_height, const unsigned char *samples);
typedef void (fz_write_trailer_fn)(fz_context *ctx, fz_band_writer *writer);
typedef void (fz_drop_band_writer_fn)(fz_context *ctx, fz_band_writer *writer);

struct fz_band_writer_s
{
	fz_drop_band_writer_fn *drop;
	fz_write_header_fn *header;
	fz_write_band_fn *band;
	fz_write_trailer_fn *trailer;
	fz_output *out;
	int w;
	int h;
	int n;
	int alpha;
	int xres;
	int yres;
	int pagenum;
	int line;
};

fz_band_writer *fz_new_band_writer_of_size(fz_context *ctx, size_t size, fz_output *out);
#define fz_new_band_writer(C,M,O) ((M *)Memento_label(fz_new_band_writer_of_size(ctx, sizeof(M), O), #M))

/*
	fz_write_header: Cause a band writer to write the header for
	a banded image with the given properties/dimensions etc. This
	also configures the bandwriter for the format of the data to be
	passed in future calls.

	w, h: Width and Height of the entire page.

	n: Number of components (including alphas).

	alpha: Number of alpha components.

	xres, yres: X and Y resolutions in dpi.

	pagenum: Page number

	Throws exception if incompatible data format.
*/
void fz_write_header(fz_context *ctx, fz_band_writer *writer, int w, int h, int n, int alpha, int xres, int yres, int pagenum);

/*
	fz_write_band: Cause a band writer to write the next band
	of data for an image.

	stride: The byte offset from the first byte of the data
	for a pixel to the first byte of the data for the same pixel
	on the row below.

	band_height: The number of lines in this band.

	samples: Pointer to first byte of the data.
*/
void fz_write_band(fz_context *ctx, fz_band_writer *writer, int stride, int band_height, const unsigned char *samples);

void fz_drop_band_writer(fz_context *ctx, fz_band_writer *writer);

#endif
