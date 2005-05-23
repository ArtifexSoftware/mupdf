/*
 * Minimal TIFF image loader. Baseline TIFF 6.0 with a few extensions,
 * as specified in the Metro specification.
 */

#include "fitz.h"
#include "samus.h"

typedef struct sa_tiff_s sa_tiff;

struct sa_tiff_s
{
	/* file and byte order */
	fz_file *file;
	unsigned order;

	/* where we can find the strips of image data */
	unsigned rowsperstrip;
	unsigned *stripoffsets;
	unsigned *stripbytecounts;

	/* colormap */
	unsigned *colormap;

	/* assorted tags */
	unsigned interpretation;
	unsigned compression;
	unsigned imagewidth;
	unsigned imagelength;
	unsigned samplesperpixel;
	unsigned bitspersample;
	unsigned xresolution;
	unsigned yresolution;
	unsigned resolutionunit;
};

enum
{
	TII = ('I' << 8) + 'I',
	TMM = ('M' << 8) + 'M',
	TBYTE = 1,
	TASCII = 2,
	TSHORT = 3,
	TLONG = 4,
	TRATIONAL = 5
};

#define ImageWidth					256
#define ImageLength					257
#define BitsPerSample				258
#define Compression					259
#define PhotometricInterpretation	262
#define StripOffsets				273
#define SamplesPerPixel				277
#define RowsPerStrip				278
#define StripByteCounts				279
#define XResolution					282
#define YResolution					283
#define ResolutionUnit				296
#define ColorMap					320

static inline unsigned readshort(sa_tiff *tiff)
{
	unsigned a = fz_readbyte(tiff->file);
	unsigned b = fz_readbyte(tiff->file);
	if (tiff->order == TII)
		return (b << 8) | a;
	return (a << 8) | b;
}

static inline unsigned readlong(sa_tiff *tiff)
{
	unsigned a = fz_readbyte(tiff->file);
	unsigned b = fz_readbyte(tiff->file);
	unsigned c = fz_readbyte(tiff->file);
	unsigned d = fz_readbyte(tiff->file);
	if (tiff->order == TII)
		return (d << 24) | (c << 16) | (b << 8) | a;
	return (a << 24) | (b << 16) | (c << 8) | d;
}

static void
readtagval(unsigned *p, sa_tiff *tiff, unsigned type, unsigned ofs, unsigned n)
{
	fz_seek(tiff->file, ofs, 0);
	while (n--)
	{
		switch (type)
		{
		case TRATIONAL:
			*p = readlong(tiff);
			*p = *p / readlong(tiff);
			p ++;
			break;
		case TBYTE: *p++ = fz_readbyte(tiff->file); break;
		case TSHORT: *p++ = readshort(tiff); break;
		case TLONG: *p++ = readlong(tiff); break;
		default: *p++ = 0; break;
		}
	}
}

static void
tiffdebug(sa_tiff *tiff)
{
	int i, n;

	printf("TIFF <<\n");
	printf("\t/ImageWidth %u\n", tiff->imagewidth);
	printf("\t/ImageLength %u\n", tiff->imagelength);
	printf("\t/BitsPerSample %u\n", tiff->bitspersample);
	printf("\t/Compression %u\n", tiff->compression);
	printf("\t/PhotometricInterpretation %u\n", tiff->interpretation);
	printf("\t/SamplesPerPixel %u\n", tiff->samplesperpixel);
	printf("\t/XResolution %u\n", tiff->xresolution);
	printf("\t/YResolution %u\n", tiff->yresolution);
	printf("\t/ResolutionUnit %u\n", tiff->resolutionunit);

	printf("\t/ColorMap $%p\n", tiff->colormap);

	n = (tiff->imagelength + tiff->rowsperstrip - 1) / tiff->rowsperstrip;

	printf("\t/RowsPerStrip %u\n", tiff->rowsperstrip);

	if (tiff->stripoffsets)
	{
		printf("\t/StripOffsets [\n");
		for (i = 0; i < n; i++)
			printf("\t\t%u\n", tiff->stripoffsets[i]);
		printf("\t]\n");
	}

	if (tiff->stripbytecounts)
	{
		printf("\t/StripByteCounts [\n");
		for (i = 0; i < n; i++)
			printf("\t\t%u\n", tiff->stripbytecounts[i]);
		printf("\t]\n");
	}

	printf(">>\n");
}

static fz_error *
tiffreadstrips(sa_tiff *tiff)
{
	/* switch on compression to create a filter */
	/* feed each strip to the filter */
	/* read out the data and pack the samples into an sa_image */

	/* packbits -- nothing special (same row-padding as PDF) */
	/* ccitt type 2 -- no EOL, no RTC, rows are byte-aligned */

	fz_error *error;
	fz_obj *params;
	fz_buffer *buf;
	fz_file *file;
	fz_filter *filter;

	int row;
	int strip;
	int len;

printf("TIFF ");
printf("w=%d h=%d n=%d bpc=%d ",
		tiff->imagewidth, tiff->imagelength,
		tiff->samplesperpixel, tiff->bitspersample);

	switch (tiff->interpretation)
	{
	case 0: printf("WhiteIsZero "); break;
	case 1: printf("BlackIsZero "); break;
	case 2: printf("RGB "); break;
	case 3: printf("RGBPal "); break;
	case 5: printf("CMYK "); break;
	default:
		return fz_throw("ioerror: unknown color space in TIFF");
	}

	switch (tiff->compression)
	{
	case 1:
		printf("Uncompressed ");
		filter = nil;
		break;

	case 2:
		printf("CCITT ");

		if (tiff->interpretation != 0 && tiff->interpretation != 1)
			return fz_throw("ioerror: ccitt encoding on color TIFF");
		if (tiff->samplesperpixel != 1)
			return fz_throw("ioerror: ccitt encoding on multi-component TIFF");
		if (tiff->bitspersample != 1)
			return fz_throw("ioerror: ccitt encoding on multi-bit TIFF");

		error = fz_packobj(&params, "<<"
			"/K 0"
			"/EndOfLine false"
			"/EncodedByteAlign true"
			"/Columns %i"
			"/Rows %i"
			"/EndOfBlock false"
			"/BlackIs1 %b"
			">>",
			tiff->imagewidth,
			tiff->imagelength,
			tiff->interpretation == 0);
		if (error)
			return error;

		error = fz_newfaxd(&filter, params);
		fz_dropobj(params);
		if (error)
			return error;
		break;

	case 32773:
		printf("PackBits ");
		error = fz_newrld(&filter, 0);
		if (error)
			return error;
		break;

	case 3:
		return fz_throw("ioerror: unsupported compression (G3 Fax) in TIFF");
	case 4:
		return fz_throw("ioerror: unsupported compression (G4 Fax) in TIFF");
	case 5:
		return fz_throw("ioerror: unsupported compression (LZW) in TIFF");
	case 6:
		return fz_throw("ioerror: unsupported compression (JPEG) in TIFF");
	default:
		return fz_throw("ioerror: unknown compression in TIFF");
	}

	printf("\n");

	error = fz_newbuffer(&buf, 4096);
	error = fz_openbuffer(&file, buf, FZ_WRITE);

	if (filter)
	{
		error = fz_pushfilter(file, filter);
		if (error)
		{
			fz_dropfilter(filter);
			fz_closefile(file);
			return error;
		}
	}

	strip = 0;
	for (row = 0; row < tiff->imagelength; row += tiff->rowsperstrip)
	{
		unsigned offset = tiff->stripoffsets[strip];
		unsigned length = tiff->stripbytecounts[strip];
		unsigned char buffer[length];

		fz_seek(tiff->file, offset, 0);

		len = fz_read(tiff->file, buffer, length);
		if (len < 0)
			return fz_ferror(tiff->file);

		len = fz_write(file, buffer, length);
		if (len < 0)
			return fz_ferror(file);

		strip ++;
	}

	if (filter)
	{
		fz_popfilter(file);
		fz_dropfilter(filter);
	}

	fz_closefile(file);

	if (tiff->interpretation == 3 && tiff->colormap)
	{
		/* TODO expand RGBPal datain buf via colormap to output */
		printf("  read %d bytes (indexed)\n", buf->wp - buf->rp);
	}
	else
	{
		/* TODO copy buf to output */
		printf("  read %d bytes\n", buf->wp - buf->rp);
	}

	fz_dropbuffer(buf);

	return nil;
}

static fz_error *
tiffreadtag(sa_tiff *tiff, unsigned offset)
{
	unsigned tag;
	unsigned type;
	unsigned count;
	unsigned value;

	fz_seek(tiff->file, offset, 0);
	tag = readshort(tiff);
	type = readshort(tiff);
	count = readlong(tiff);

	if ((type == TBYTE && count <= 4) ||
			(type == TSHORT && count <= 2) ||
			(type == TLONG && count <= 1))
		value = fz_tell(tiff->file);
	else
		value = readlong(tiff);

	switch (tag)
	{
	case ImageWidth:
		readtagval(&tiff->imagewidth, tiff, type, value, 1);
		break;
	case ImageLength:
		readtagval(&tiff->imagelength, tiff, type, value, 1);
		break;
	case BitsPerSample:
		readtagval(&tiff->bitspersample, tiff, type, value, 1);
		break;
	case Compression:
		readtagval(&tiff->compression, tiff, type, value, 1);
		break;
	case PhotometricInterpretation:
		readtagval(&tiff->interpretation, tiff, type, value, 1);
		break;
	case SamplesPerPixel:
		readtagval(&tiff->samplesperpixel, tiff, type, value, 1);
		break;
	case RowsPerStrip:
		readtagval(&tiff->rowsperstrip, tiff, type, value, 1);
		break;
	case XResolution:
		readtagval(&tiff->xresolution, tiff, type, value, 1);
		break;
	case YResolution:
		readtagval(&tiff->yresolution, tiff, type, value, 1);
		break;
	case ResolutionUnit:
		readtagval(&tiff->resolutionunit, tiff, type, value, 1);
		break;

	case StripOffsets:
		tiff->stripoffsets = fz_malloc(count * sizeof(unsigned));
		if (!tiff->stripoffsets)
			return fz_outofmem;
		readtagval(tiff->stripoffsets, tiff, type, value, count);
		break;

	case StripByteCounts:
		tiff->stripbytecounts = fz_malloc(count * sizeof(unsigned));
		if (!tiff->stripbytecounts)
			return fz_outofmem;
		readtagval(tiff->stripbytecounts, tiff, type, value, count);
		break;

	case ColorMap:
		tiff->colormap = fz_malloc(count * sizeof(unsigned));
		if (!tiff->colormap)
			return fz_outofmem;
		readtagval(tiff->colormap, tiff, type, value, count);
		break;

	default:
		/*
		printf("unknown tag: %d t=%d n=%d\n", tag, type, count);
		*/
		break;
	}

	return nil;
}

static fz_error *
tiffreadifd(sa_tiff *tiff, unsigned offset)
{
	fz_error *error;
	unsigned count;
	unsigned i;

	fz_seek(tiff->file, offset, 0);
	count = readshort(tiff);

	offset += 2;
	for (i = 0; i < count; i++)
	{
		error = tiffreadtag(tiff, offset);
		if (error)
			return error;
		offset += 12;
	}

	return tiffreadstrips(tiff);
}

static fz_error *
tiffreadifh(sa_tiff *tiff, fz_file *file)
{
	unsigned version;
	unsigned offset;

	memset(tiff, 0, sizeof(sa_tiff));
	tiff->file = file;

	/* tag defaults, where applicable */
	tiff->bitspersample = 1;
	tiff->compression = 1;
	tiff->samplesperpixel = 1;
	tiff->resolutionunit = 2;
	tiff->rowsperstrip = 0xFFFFFFFF;

	/* get byte order marker */
	tiff->order = TII;
	tiff->order = readshort(tiff);
	if (tiff->order != TII && tiff->order != TMM)
		return fz_throw("ioerror: not a TIFF file");

	/* check version */
	version = readshort(tiff);
	if (version != 42)
		return fz_throw("ioerror: not a TIFF file");

	/* get offset of IFD and then read it */
	offset = readlong(tiff);
	return tiffreadifd(tiff, offset);
}

fz_error *
sa_readtiff(fz_file *file)
{
	fz_error *error;
	fz_buffer *buf;
	fz_file *newfile;
	sa_tiff tiff;

	/* TIFF requires random access. In Metro TIFFs are embedded in ZIP files.
	 * Compressed streams are not seekable, so we copy the data to an
	 * in-memory data buffer instead of reading from the original stream.
	 */

	error = fz_readfile(&buf, file);
	if (error)
		return error;

	error = fz_openbuffer(&newfile, buf, FZ_READ);
	if (error)
	{
		fz_dropbuffer(buf);
		return error;
	}

	error = tiffreadifh(&tiff, newfile);

	if (getenv("TIFFDEBUG"))
		tiffdebug(&tiff);

	fz_free(tiff.colormap);
	fz_free(tiff.stripoffsets);
	fz_free(tiff.stripbytecounts);

	fz_closefile(newfile);
	fz_dropbuffer(buf);

	return error;
}

