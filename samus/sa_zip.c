/*
 * Support for a subset of PKZIP format v4.5:
 *   - no encryption
 *   - no multi-disk
 *   - only Store and Deflate
 *   - ZIP64 format (long long sizes and offsets) [TODO]
 */

#include "fitz.h"
#include "samus.h"

typedef struct sa_zip_s sa_zip;
typedef struct sa_zipent_s sa_zipent;

struct sa_zipent_s
{
	unsigned offset;
	char *name;
	unsigned csize;
	unsigned usize;
};

struct sa_zip_s
{
	fz_file *file;
	int len, cap;
	sa_zipent *table;
};

typedef unsigned char byte;
typedef unsigned short ushort;
typedef unsigned long ulong;

static inline ushort read2(fz_file *f)
{
	byte a = fz_readbyte(f);
	byte b = fz_readbyte(f);
	return (b << 8) | a;
}

static inline ulong read4(fz_file *f)
{
	byte a = fz_readbyte(f);
	byte b = fz_readbyte(f);
	byte c = fz_readbyte(f);
	byte d = fz_readbyte(f);
	return (d << 24) | (c << 16) | (b << 8) | a;
}

static fz_error *growzip(sa_zip *zip)
{
	sa_zipent *newtab;
	int newcap;

	if (zip->cap)
		newcap = zip->cap * 2;
	else
		newcap = 100;

	newtab = fz_realloc(zip->table, newcap * sizeof(sa_zipent));
	if (!newtab)
		return fz_outofmem;

	memset(newtab + zip->cap, 0, (newcap - zip->cap) * sizeof(sa_zipent));
	zip->cap = newcap;
	zip->table = newtab;

	return nil;
}

static fz_error *scanzipent(sa_zip *zip, sa_zipent *ent)
{
	ulong csize, usize;
	ulong namesize, metasize;

	(void) read2(zip->file);	/* version */
	(void) read2(zip->file);	/* general */
	(void) read2(zip->file);	/* method */
	(void) read2(zip->file);	/* time */
	(void) read2(zip->file);	/* date */
	(void) read4(zip->file);	/* crc-32 */
	csize = read4(zip->file);
	usize = read4(zip->file);
	namesize = read2(zip->file);
	metasize = read2(zip->file);

	ent->name = fz_malloc(namesize + 1);
	if (!ent->name)
		return fz_outofmem;

	fz_read(zip->file, ent->name, namesize);
	ent->name[namesize] = 0;
	ent->csize = csize;
	ent->usize = usize;

	fz_seek(zip->file, metasize, 1);
	fz_seek(zip->file, csize, 1);

	return nil;
}

static fz_error *scanzip(sa_zip *zip)
{
	fz_error *error;
	ulong offset;
	ulong sign;

	fz_seek(zip->file, 0, 0);

	while (1)
	{
		offset = fz_tell(zip->file);

		sign = read4(zip->file);

		switch (sign)
		{

		/* local file header */
		case 0x04034b50:
			if (zip->len + 1 > zip->cap)
			{
				error = growzip(zip);
				if (error)
					return error;
			}

			zip->table[zip->len].offset = offset;

			error = scanzipent(zip, zip->table + zip->len);
			if (error)
				return error;

			zip->len ++;

			break;

		/* data descriptor */
		case 0x08074b50:
			(void) read4(zip->file);	/* crc-32 */
			(void) read4(zip->file);	/* compressed size */
			(void) read4(zip->file);	/* uncompressed size */
			break;

		/* central directory */
		case 0x02014b50:
			return fz_ferror(zip->file);

		default:
			return fz_throw("ioerror: unknown zip signature");
		}
	}
}

static fz_error *readzipdir(sa_zip *zip, int startoffset)
{
	ulong sign;
	ulong csize, usize;
	ulong namesize, metasize, comsize;
	ulong offset;
	int i;

	fz_seek(zip->file, startoffset, 0);

	for (i = 0; i < zip->len; i++)
	{
		sign = read4(zip->file);
		if (sign != 0x02014b50)
			return fz_throw("ioerror: unknown zip signature");

		(void) read2(zip->file);	/* version made by */
		(void) read2(zip->file);	/* version to extract */
		(void) read2(zip->file);	/* general */
		(void) read2(zip->file);	/* method */
		(void) read2(zip->file);	/* last mod file time */
		(void) read2(zip->file);	/* last mod file date */
		(void) read4(zip->file);	/* crc-32 */
		csize = read4(zip->file);
		usize = read4(zip->file);
		namesize = read2(zip->file);
		metasize = read2(zip->file);
		comsize = read2(zip->file);
		(void) read2(zip->file);	/* disk number start */
		(void) read2(zip->file);	/* int file atts */
		(void) read4(zip->file);	/* ext file atts */
		offset = read4(zip->file);

		zip->table[i].offset = offset;
		zip->table[i].name = fz_malloc(namesize + 1);
		zip->table[i].csize = csize;
		zip->table[i].usize = usize;
		if (!zip->table[i].name)
			return fz_outofmem;

		fz_read(zip->file, zip->table[i].name, namesize);
		zip->table[i].name[namesize] = 0;

		fz_seek(zip->file, metasize, 1);
		fz_seek(zip->file, comsize, 1);
	}

	return fz_ferror(zip->file);
}

static fz_error *readzipendofdir(sa_zip *zip, int startoffset)
{
	ulong sign;
	ulong count;
	ulong offset;

	fz_seek(zip->file, startoffset, 0);

	sign = read4(zip->file);
	if (sign != 0x06054b50)
		return fz_throw("ioerror: unknown zip signature");

	(void) read2(zip->file);	/* this disk */
	(void) read2(zip->file);	/* start disk */
	(void) read2(zip->file);	/* ents in this disk */
	count = read2(zip->file);	/* ents in central directory */
	(void) read4(zip->file);	/* size of central directory */
	offset = read4(zip->file);	/* offset to central directory */

	zip->len = zip->cap = count;
	zip->table = fz_malloc(zip->cap * sizeof(sa_zipent));
	if (!zip->table)
		return fz_outofmem;

	memset(zip->table, 0, zip->cap * sizeof(sa_zipent));

	return readzipdir(zip, offset);
}

static fz_error *findzipendofdir(sa_zip *zip)
{
	byte buf[512];
	int filesize;
	int maxback;
	int backread;
	int offset;
	int len;
	int i;

	filesize = fz_seek(zip->file, 0, 2);
	if (filesize == -1)
		return fz_ferror(zip->file);

	maxback = MIN(filesize, 0xFFFF + sizeof buf);

	backread = MIN(maxback, sizeof buf);
	while (backread < maxback)
	{
		fz_seek(zip->file, filesize - backread, 0);
		len = fz_read(zip->file, buf, sizeof buf);
		if (len < 0)
			return fz_ferror(zip->file);

		for (i = len - 4; i > 0; i--)
		{
			if (buf[i+0] == 0x50 && buf[i+1] == 0x4b &&
					buf[i+2] == 0x05 && buf[i+3] == 0x06)
			{
				offset = filesize - backread + i;
				return readzipendofdir(zip, offset);
			}
		}

		backread += sizeof buf - 4;
	}

	return fz_throw("ioerror: no 'end of central directory' in zip");
}

/*
 * Open a ZIP archive for reading.
 * Load the table of contents.
 */
fz_error *
sa_openzip(sa_zip **zipp, char *filename)
{
	fz_error *error;
	sa_zip *zip;

	zip = *zipp = fz_malloc(sizeof(sa_zip));
	if (!zip)
		return fz_outofmem;

	zip->file = nil;
	zip->len = 0;
	zip->cap = 0;
	zip->table = nil;

	error = fz_openfile(&zip->file, filename, FZ_READ);
	if (error)
		return error;

	error = findzipendofdir(zip);
	if (error)
	{
		fz_warn("%s", error->msg);
		fz_droperror(error);
		return scanzip(zip);
	}

	return nil;
}

/*
 * Free the table of contents and close the underlying file.
 */
void
sa_closezip(sa_zip *zip)
{
	int i;

	if (zip->file)
		fz_closefile(zip->file);

	for (i = 0; i < zip->len; i++)
		if (zip->table[i].name)
			fz_free(zip->table[i].name);

	fz_free(zip->table);
}

/*
 * Print a table of contents of the zip archive
 */
void
sa_debugzip(sa_zip *zip)
{
	int i;

	for (i = 0; i < zip->len; i++)
	{
		printf("%6u ", zip->table[i].csize);
		printf("%6u ", zip->table[i].usize);
		printf("%s\n", zip->table[i].name);
	}
}

/*
 * Seek and push decoding filter to read an individual file in the zip archive.
 */
fz_error *
sa_openzipstream(sa_zip *zip, char *name)
{
	fz_error *error;
	fz_filter *filter;
	fz_obj *obj;
	ulong sign, version, general, method;
	ulong csize, usize;
	ulong namesize, metasize;
	int t;
	int i;

	for (i = 0; i < zip->len; i++)
	{
		if (!strcmp(name, zip->table[i].name))
		{
			t = fz_seek(zip->file, zip->table[i].offset, 0);
			if (t < 0)
				return fz_ferror(zip->file);

			sign = read4(zip->file);
			if (sign != 0x04034b50)
				return fz_throw("ioerror: unknown zip signature");

			version = read2(zip->file);
			general = read2(zip->file);
			method = read2(zip->file);
			(void) read2(zip->file);	/* time */
			(void) read2(zip->file);	/* date */
			(void) read4(zip->file);	/* crc-32 */
			csize = read4(zip->file);
			usize = read4(zip->file);
			namesize = read2(zip->file);
			metasize = read2(zip->file);

			fz_seek(zip->file, namesize, 1);
			fz_seek(zip->file, metasize, 1);

			if ((version & 0xff) > 45)
				return fz_throw("ioerror: unsupported zip version");
			if (general & 0x0001)
				return fz_throw("ioerror: encrypted zip entry");

			switch (method)
			{	
			case 0:
printf("null filter\n");
				error = fz_newnullfilter(&filter, csize);
				break;
			case 8:
printf("flated filter\n");
				error = fz_packobj(&obj, "<</ZIP true>>");
				if (error)
					return error;
				error = fz_newflated(&filter, obj);
				fz_dropobj(obj);
				break;
			default:
				error = fz_throw("ioerror: unsupported compression method");
				break;
			}
			if (error)
				return error;

			error = fz_pushfilter(zip->file, filter);
			fz_dropfilter(filter);
			if (error)
				return error;

			return nil;
		}
	}

	return fz_throw("ioerror: file not found in zip: '%s'", name);
}

/*
 * Pop decompression filter and clean up after reading a file in the archive.
 */
void
sa_closezipstream(sa_zip *zip)
{
	fz_popfilter(zip->file);
}


int main(int argc, char **argv)
{
	fz_error *error;
	fz_buffer *buf;
	sa_zip *zip;
	int i;

	error = sa_openzip(&zip, argv[1]);
	if (error)
		fz_abort(error);

	sa_debugzip(zip);

	for (i = 2; i < argc; i++)
	{
		error = sa_openzipstream(zip, argv[i]);
		if (error)
			fz_abort(error);
		error = fz_readfile(&buf, zip->file);
		if (error)
			fz_abort(error);
		sa_closezipstream(zip);

		fwrite(buf->rp, 1, buf->wp - buf->rp, stdout);

		fz_dropbuffer(buf);
	}

	sa_closezip(zip);
	
	return 0;
}

