#include <fitz.h>
#include <mupdf.h>

static inline int iswhite(int ch)
{
	return	ch == '\000' || ch == '\011' || ch == '\012' ||
			ch == '\014' || ch == '\015' || ch == '\040';
}

/*
 * magic version tag and startxref
 */

static fz_error *
loadversion(float *version, fz_file *file)
{
	char buf[20];
	int n;

	n = fz_seek(file, 0);
	if (n < 0)
		return fz_ferror(file);

	fz_readline(file, buf, sizeof buf);
	if (memcmp(buf, "%PDF-", 5) != 0)
		return fz_throw("syntaxerror: missing magic pdf marker");

	*version = atof(buf + 5);

	return nil;
}

static fz_error *
readstartxref(int *ofs, int fd)
{
	unsigned char buf[1024];
	int t, n;
	int i;

	t = lseek(fd, 0, 2);
	if (t == -1)
		return fz_throw("ioerror in startxref: lseek: %s", strerror(errno));

	t = lseek(fd, MAX(0, t - ((int)sizeof buf)), 0);
	if (t == -1)
		return fz_throw("ioerror in startxref: lseek: %s", strerror(errno));

	n = read(fd, buf, sizeof buf);
	if (n == -1)
		return fz_throw("ioerror in startxref: read: %s", strerror(errno));

	for (i = n - 9; i >= 0; i--) {
		if (memcmp(buf + i, "startxref", 9) == 0) {
			i += 9;
			while (iswhite(buf[i]) && i < n)
				i ++;
			*ofs = atoi(buf + i);
			return nil;
		}
	}

	return fz_throw("syntaxerror: missing startxref");
}

/*
 * trailer dictionary
 */

static fz_error *
readoldtrailer(fz_obj **objp, fz_file *file, unsigned char *buf, int cap)
{
	int ofs, len;
	char *s;
	int n;
	int t;
	int c;

	fz_readline(file, buf, cap);
	if (strcmp(buf, "xref") != 0)
		return fz_throw("syntaxerror: missing xref");

	while (1)
	{
		c = fz_peekbyte(file);
		if (!(c >= '0' && c <= '9'))
			break;

		n = fz_readline(file, buf, cap);
		if (n < 0) return fz_ferror(file);

		s = buf;
		ofs = atoi(strsep(&s, " "));
		len = atoi(strsep(&s, " "));

		t = fz_tell(file);
		if (t < 0) return fz_ferror(file);

		n = fz_seek(file, t + 20 * len);
		if (n < 0) return fz_ferror(file);
	}

	t = pdf_lex(file, buf, cap, &n);
	if (t != PDF_TTRAILER)
		return fz_throw("syntaxerror: missing trailer");

	t = pdf_lex(file, buf, cap, &n);
	if (t != PDF_TODICT)
		return fz_throw("syntaxerror: trailer must be dictionary");

	return pdf_parsedict(objp, file, buf, cap);
}

static fz_error *
readnewtrailer(fz_obj **objp, fz_file *file, unsigned char *buf, int cap)
{
	return pdf_parseindobj(objp, file, buf, cap, nil, nil, nil);
}

static fz_error *
readtrailer(fz_obj **objp, fz_file *file, int ofs, unsigned char *buf, int cap)
{
	int n;
	int c;

	n = fz_seek(file, ofs);
	if (n < 0)
		return fz_ferror(file);

	c = fz_peekbyte(file);
	if (c == 'x')
		return readoldtrailer(objp, file, buf, cap);
	else if (c >= '0' && c <= '9')
		return readnewtrailer(objp, file, buf, cap);

	return fz_throw("syntaxerror: missing xref");
}

/*
 * xref tables
 */

static fz_error *
readoldxref(fz_obj **trailerp, pdf_xref *xref, unsigned char *buf, int cap)
{
	int ofs, len;
	char *s;
	int n;
	int t;
	int i;
	int c;

	fz_readline(xref->file, buf, cap);
	if (strcmp(buf, "xref") != 0)
		return fz_throw("syntaxerror: missing xref");

	while (1)
	{
		c = fz_peekbyte(xref->file);
		if (!(c >= '0' && c <= '9'))
			break;

		n = fz_readline(xref->file, buf, cap);
		if (n < 0) return fz_ferror(xref->file);
		
		s = buf;
		ofs = atoi(strsep(&s, " "));
		len = atoi(strsep(&s, " "));

		for (i = 0; i < len; i++)
		{
			n = fz_read(xref->file, buf, 20);
			if (n < 0) return fz_ferror(xref->file);
			if (n != 20) return fz_throw("syntaxerror: truncated xref table");
			if (!xref->table[ofs + i].type)
			{
				s = buf;
				xref->table[ofs + i].ofs = atoi(strsep(&s, " "));
				xref->table[ofs + i].gen = atoi(strsep(&s, " "));
				xref->table[ofs + i].type = strsep(&s, " ")[0];
			}
		}
	}

	t = pdf_lex(xref->file, buf, cap, &n);
	if (t != PDF_TTRAILER)
		return fz_throw("syntaxerror: missing trailer");
	t = pdf_lex(xref->file, buf, cap, &n);
	if (t != PDF_TODICT)
		return fz_throw("syntaxerror: trailer must be dictionary");

	return pdf_parsedict(trailerp, xref->file, buf, cap);
}

static fz_error *
readnewxref(fz_obj **trailerp, pdf_xref *xref, unsigned char *buf, int cap)
{
	fz_error *error;
	fz_obj *trailer;
	fz_obj *obj;
	int oid, gid, stmofs;
	int size, w0, w1, w2, i0, i1;
	int i, n;

	error = pdf_parseindobj(&trailer, xref->file, buf, cap, &oid, &gid, &stmofs);
	if (error)
		return error;

	obj = fz_dictgets(trailer, "Size");
	if (!obj) {
		error = fz_throw("syntaxerror: xref stream missing Size entry");
		goto cleanup;
	}
	size = fz_toint(obj);

	obj = fz_dictgets(trailer, "W");
	if (!obj) {
		error = fz_throw("syntaxerror: xref stream missing W entry");
		goto cleanup;
	}
	w0 = fz_toint(fz_arrayget(obj, 0));
	w1 = fz_toint(fz_arrayget(obj, 1));
	w2 = fz_toint(fz_arrayget(obj, 2));

	obj = fz_dictgets(trailer, "Index");
	if (obj) {
		i0 = fz_toint(fz_arrayget(obj, 0));
		i1 = fz_toint(fz_arrayget(obj, 1));
	}
	else {
		i0 = 0;
		i1 = size;
	}

	if (i0 < 0 || i1 > xref->size) {
		error = fz_throw("syntaxerror: xref stream has too many entries");
		goto cleanup;
	}

	error = pdf_openstream0(xref, trailer, oid, gid, stmofs);
	if (error)
		goto cleanup;

	for (i = i0; i < i0 + i1; i++)
	{
		int a = 0;
		int b = 0;
		int c = 0;

		if (fz_peekbyte(xref->file) == EOF)
		{
			error = fz_ferror(xref->file);
			if (!error)
				error = fz_throw("syntaxerror: truncated xref stream");
			pdf_closestream(xref);
			goto cleanup;
		}

		for (n = 0; n < w0; n++)
			a = (a << 8) + fz_readbyte(xref->file);
		for (n = 0; n < w1; n++)
			b = (b << 8) + fz_readbyte(xref->file);
		for (n = 0; n < w2; n++)
			c = (c << 8) + fz_readbyte(xref->file);

		if (!xref->table[i].type)
		{
			int t = w0 ? a : 1;
			xref->table[i].type = t == 0 ? 'f' : t == 1 ? 'n' : t == 2 ? 'o' : 0;
			xref->table[i].ofs = w2 ? b : 0;
			xref->table[i].gen = w1 ? c : 0;
		}
	}

	pdf_closestream(xref);

	*trailerp = trailer;

	return nil;

cleanup:
	fz_dropobj(trailer);
	return error;
}

static fz_error *
readxref(fz_obj **trailerp, pdf_xref *xref, int ofs, unsigned char *buf, int cap)
{
	int n;
	int c;

	n = fz_seek(xref->file, ofs);
	if (n < 0)
		return fz_ferror(xref->file);

	c = fz_peekbyte(xref->file);
	if (c == 'x')
		return readoldxref(trailerp, xref, buf, cap);
	else if (c >= '0' && c <= '9')
		return readnewxref(trailerp, xref, buf, cap);

	return fz_throw("syntaxerror: missing xref");
}

static fz_error *
readxrefsections(pdf_xref *xref, int ofs, unsigned char *buf, int cap)
{
	fz_error *error;
	fz_obj *trailer;
	fz_obj *prev;
	fz_obj *xrefstm;

	error = readxref(&trailer, xref, ofs, buf, cap);
	if (error)
		return error;

	/* FIXME: do we overwrite free entries properly? */
	xrefstm = fz_dictgets(trailer, "XrefStm");
	if (xrefstm)
	{
		error = readxrefsections(xref, fz_toint(xrefstm), buf, cap);
		if (error)
			goto cleanup;
	}

	prev = fz_dictgets(trailer, "Prev");
	if (prev)
	{
		error = readxrefsections(xref, fz_toint(prev), buf, cap);
		if (error)
			goto cleanup;
	}

	fz_dropobj(trailer);
	return nil;

cleanup:
	fz_dropobj(trailer);
	return error;
}

/*
 * compressed object streams
 */

fz_error *
pdf_readobjstm(pdf_xref *xref, int oid, int gid, unsigned char *buf, int cap)
{
	fz_error *error;
	fz_obj *objstm;
	int *oidbuf;
	int *ofsbuf;

	fz_obj *obj;
	int stmofs;
	int first;
	int count;
	int i, n, t;

	error = pdf_loadobject0(&objstm, xref, oid, gid, &stmofs);
	if (error)
		return error;

	count = fz_toint(fz_dictgets(objstm, "N"));
	first = fz_toint(fz_dictgets(objstm, "First"));

	oidbuf = fz_malloc(count * sizeof(int));
	if (!oidbuf) { error = fz_outofmem; goto cleanup1; }

	ofsbuf = fz_malloc(count * sizeof(int));
	if (!ofsbuf) { error = fz_outofmem; goto cleanup2; }

	error = pdf_openstream0(xref, objstm, oid, gid, stmofs);
	if (error)
		goto cleanup3;

	for (i = 0; i < count; i++)
	{
		t = pdf_lex(xref->file, buf, cap, &n);
		if (t != PDF_TINT)
		{
			error = fz_throw("syntaxerror: corrupt object stream");
			goto cleanup4;
		}
		oidbuf[i] = atoi(buf);

		t = pdf_lex(xref->file, buf, cap, &n);
		if (t != PDF_TINT)
		{
			error = fz_throw("syntaxerror: corrupt object stream");
			goto cleanup4;
		}
		ofsbuf[i] = atoi(buf);
	}

	n = fz_seek(xref->file, first);
	if (n < 0)
	{
		error = fz_ferror(xref->file);
		goto cleanup4;
	}

	for (i = 0; i < count; i++)
	{
		/* FIXME: seek to first + ofsbuf[i] */

		error = pdf_parsestmobj(&obj, xref->file, buf, cap);
		if (error)
			goto cleanup4;

		if (oidbuf[i] < 1 || oidbuf[i] >= xref->size)
		{
			error = fz_throw("rangecheck: object number out of range");
			goto cleanup4;
		}

		error = pdf_storeobject(xref->store, oidbuf[i], 0, obj);
		if (error)
			goto cleanup4;
	}

	pdf_closestream(xref);
	fz_free(ofsbuf);
	fz_free(oidbuf);
	fz_dropobj(objstm);
	return nil;

cleanup4:
	pdf_closestream(xref);
cleanup3:
	fz_free(ofsbuf);
cleanup2:
	fz_free(oidbuf);
cleanup1:
	fz_dropobj(objstm);
	return error;
}

/*
 * open xref in normal mode (as opposed to repair mode)
 */

fz_error *
pdf_openxref(pdf_xref *xref, char *filename)
{
	fz_error *error;
	fz_obj *size;
	int i;

	unsigned char buf[65536];	/* yeowch! */

	error = fz_openfile(&xref->file, filename, O_RDONLY);
	if (error)
		return error;

	error = loadversion(&xref->version, xref->file);
	if (error)
		return error;

	error = readstartxref(&xref->startxref, xref->file->fd);
	if (error)
		return error;

	error = readtrailer(&xref->trailer, xref->file, xref->startxref, buf, sizeof buf);
	if (error)
		return error;

	size = fz_dictgets(xref->trailer, "Size");
	if (!size)
		return fz_throw("syntaxerror: trailer missing Size entry");

	xref->capacity = fz_toint(size);
	xref->size = fz_toint(size);

	xref->table = fz_malloc(xref->capacity * sizeof(pdf_xrefentry));
	if (!xref->table)
		return fz_outofmem;

	for (i = 0; i < xref->size; i++)
	{
		xref->table[i].ofs = 0;
		xref->table[i].gen = 0;
		xref->table[i].type = 0;
		xref->table[i].mark = 0;
	}

	error = readxrefsections(xref, xref->startxref, buf, sizeof buf);
	if (error)
		return error;

	return nil;
}

