#include <fitz.h>
#include <mupdf.h>

#define TIGHT 0

static fz_error *
writestm(fz_file *out, pdf_xref *xref, pdf_crypt *encrypt, int oid, int gen)
{
	fz_error *error;
	unsigned char buf[4096];
	fz_filter *ef;
	int n;

	fz_print(out, "stream\n");

	if (encrypt)
	{
		error = pdf_cryptstm(&ef, encrypt, oid, gen);
		if (error)
			return error;

		error = fz_pushfilter(out, ef);
		if (error) {
			fz_freefilter(ef);
			return error;
		}
	}

	error = pdf_openrawstream(xref, oid, gen);
	if (error)
		goto cleanup;

	while (1)
	{
		n = fz_read(xref->stream, buf, sizeof buf);
		if (n == 0)
			break;
		if (n < 0)
		{
			error = fz_ferror(xref->stream);
			pdf_closestream(xref);
			goto cleanup;
		}
		fz_write(out, buf, n);
	}

	pdf_closestream(xref);

	if (encrypt)
		fz_popfilter(out);

	fz_print(out, "endstream\n");

	return nil;

cleanup:
	if (encrypt)
		fz_popfilter(out);
	return error;
}

static fz_error *
writeobj(fz_file *out, pdf_xref *xref, pdf_crypt *encrypt, int oid, int gen)
{
	pdf_xrefentry *x = xref->table + oid;
	fz_error *error;

	error = pdf_cacheobject(xref, oid, gen);
	if (error)
		return error;

	if (encrypt)
		pdf_cryptobj(encrypt, x->obj, oid, gen);

	fz_print(out, "%d %d obj\n", oid, gen);
	fz_printobj(out, x->obj, TIGHT);
	fz_print(out, "\n");

	if (encrypt)
		pdf_cryptobj(encrypt, x->obj, oid, gen);

	if (x->stmbuf || x->stmofs)
	{
		error = writestm(out, xref, encrypt, oid, gen);
		if (error)
			return error;
	}

	fz_print(out, "endobj\n\n");

	error = fz_ferror(out);
	if (error)
		return error;

	return nil;
}

#if 0

static int countmodified(pdf_xref *xref, int oid)
{
	int i;
	for (i = oid; i < xref->len; i++)
		if (xref->table[i].type != 'a' && xref->table[i].type != 'd')
			return i - oid;
	return i - oid;
}

fz_error *
pdf_updatepdf(pdf_xref *xref, char *path)
{
	fz_error *error;
	fz_file *out;
	int oid;
	int i, n;
	int startxref;
	fz_obj *obj;

	error = fz_openfile(&out, path, FZ_APPEND);
	if (error)
		return error;

	fz_print(out, "\n");

	for (oid = 0; oid < xref->len; oid++)
	{
		if (xref->table[oid].type == 'a')
		{
			xref->table[oid].ofs = fz_tell(out);
			error = writestoredobj(out, xref, xref->crypt, oid, xref->table[oid].gen);
			if (error)
				goto cleanup;
		}
	}

	/* always write out entry 0 in appended xref sections */
	xref->table[0].type = 'd';

	startxref = fz_tell(out);
	fz_print(out, "xref\n");

	oid = 0;
	while (oid < xref->len)
	{
		n = countmodified(xref, oid);

		fz_print(out, "%d %d\n", oid, n);

		for (i = 0; i < n; i++)
		{
			if (xref->table[oid + i].type == 'd')
				xref->table[oid + i].type = 'f';
			if (xref->table[oid + i].type == 'a')
				xref->table[oid + i].type = 'n';

			fz_print(out, "%010d %05d %c \n",
				xref->table[oid + i].ofs,
				xref->table[oid + i].gen,
				xref->table[oid + i].type);
		}

		oid += n;
		while (oid < xref->len &&
				xref->table[oid].type != 'a' &&
				xref->table[oid].type != 'd')
			oid ++;
	}

	fz_print(out, "\n");

	fz_print(out, "trailer\n<<\n  /Size %d\n  /Prev %d", xref->len, xref->startxref);

	obj = fz_dictgets(xref->trailer, "Root");
	fz_print(out,"\n  /Root %d %d R", fz_toobjid(obj), fz_togenid(obj));

	obj = fz_dictgets(xref->trailer, "Info");
	if (obj)
		fz_print(out,"\n  /Info %d %d R", fz_toobjid(obj), fz_togenid(obj));

	obj = fz_dictgets(xref->trailer, "Encrypt");
	if (obj) {
		fz_print(out,"\n  /Encrypt ");
		fz_printobj(out, obj, TIGHT);
	}

	obj = fz_dictgets(xref->trailer, "ID");
	if (obj) {
		fz_print(out,"\n  /ID ");
		fz_printobj(out, obj, TIGHT);
	}

	fz_print(out, "\n>>\n\n");

	fz_print(out, "startxref\n");
	fz_print(out, "%d\n", startxref);
	fz_print(out, "%%%%EOF\n");

	xref->startxref = startxref;

	fz_closefile(out);
	return nil;

cleanup:
	fz_closefile(out);
	return error;
}

#endif

fz_error *
pdf_savepdf(pdf_xref *xref, char *path, pdf_crypt *encrypt)
{
	fz_error *error;
	fz_file *out;
	int oid;
	int startxref;
	int *ofsbuf;
	fz_obj *obj;

	ofsbuf = fz_malloc(sizeof(int) * xref->len);
	if (!ofsbuf)
		return fz_outofmem;

	error = fz_openfile(&out, path, FZ_WRITE);
	if (error)
	{
		fz_free(ofsbuf);
		return error;
	}

	fz_print(out, "%%PDF-%1.1f\n", xref->version);
	fz_print(out, "%%\342\343\317\323\n\n");

	for (oid = 0; oid < xref->len; oid++)
	{
		pdf_xrefentry *x = xref->table + oid;
		if (x->type == 'n' || x->type == 'o' || x->type == 'a')
		{
			ofsbuf[oid] = fz_tell(out);
			error = writeobj(out, xref, encrypt, oid, x->type == 'o' ? 0 : x->gen);
			if (error)
				goto cleanup;
		}
		else
		{
			ofsbuf[oid] = x->ofs;
		}
	}

	startxref = fz_tell(out);
	fz_print(out, "xref\n");
	fz_print(out, "0 %d\n", xref->len);

	for (oid = 0; oid < xref->len; oid++)
	{
		int gen = xref->table[oid].gen;
		int type = xref->table[oid].type;
		if (type == 'o')
			gen = 0;
		if (type == 'a' || type == 'o')
			type = 'n';
		if (type == 'd')
			type = 'f';
		fz_print(out, "%010d %05d %c \n", ofsbuf[oid], gen, type);
	}

	fz_print(out, "\n");

	fz_print(out, "trailer\n<<\n  /Size %d", xref->len);
	obj = fz_dictgets(xref->trailer, "Root");
	fz_print(out, "\n  /Root %d %d R", fz_tonum(obj), fz_togen(obj));
	obj = fz_dictgets(xref->trailer, "Info");
	if (obj)
		fz_print(out, "\n  /Info %d %d R", fz_tonum(obj), fz_togen(obj));
	if (encrypt)
	{
		fz_print(out, "\n  /Encrypt ");
		fz_printobj(out, encrypt->encrypt, 1);
		fz_print(out, "\n  /ID [");
		fz_printobj(out, encrypt->id, 1);
		fz_printobj(out, encrypt->id, 1);
		fz_print(out, "]");
	}
	fz_print(out, "\n>>\n\n");

	fz_print(out, "startxref\n");
	fz_print(out, "%d\n", startxref);
	fz_print(out, "%%%%EOF\n");

	xref->startxref = startxref;

	fz_closefile(out);
	return nil;

cleanup:
	fz_closefile(out);
	return error;
}

