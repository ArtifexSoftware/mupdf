#include <fitz.h>
#include <mupdf.h>

static fz_error *writestored(FILE *out, pdf_xref *xref, int oid)
{
	pdf_xrefentry *x = xref->table + oid;
	fz_obj *obj;
	fz_buffer *stm;

	obj = pdf_findstoredobject(xref->store, oid, x->gen);
	stm = pdf_findstoredstream(xref->store, oid, x->gen);

	if (!obj)
		return fz_throw("could not find stored object");

	if (xref->crypt)
		pdf_cryptobj(xref->crypt, obj, oid, x->gen);

	fprintf(out, "%d %d obj\n", oid, x->gen);
	fz_debugobj(obj);
	fprintf(out, "\n");

	if (stm)
	{
		fprintf(out, "stream\n");
		fwrite(stm->rp, 1, stm->wp - stm->rp, out);
		fprintf(out, "endstream\n");
	}

	fprintf(out, "endobj\n\n");

	if (ferror(out))
		return fz_throw("ioerror: write failed");

	return nil;
}

static fz_error *writecopy(FILE *out, pdf_xref *xref, int oid)
{
	pdf_xrefentry *x = xref->table + oid;
	fz_error *error;
	fz_obj *length;
	fz_obj *obj;
	int stmofs;
	fz_filter *cf;
	fz_filter *nf;
	fz_filter *pipe;
	int n;
	unsigned char buf[4096];

	error = pdf_loadobject0(&obj, xref, oid, x->gen, &stmofs);
	if (error)
		return error;

	fprintf(out, "%d %d obj\n", oid, x->gen);
    fz_debugobj(obj);
    fprintf(out, "\n");

	if (stmofs != -1)
	{
		fprintf(out, "stream\n");

		length = fz_dictgets(obj, "Length");
		error = pdf_resolve(&length, xref);
		if (error)
			goto cleanup;

		if (xref->crypt)
		{
			error = fz_newnullfilter(&nf, fz_toint(length));
			if (error)
				goto cleanup;
			error = pdf_cryptstm(&cf, xref->crypt, oid, x->gen);
			if (error)
				goto cleanup;
			error = fz_newpipeline(&pipe, nf, cf);
			if (error)
				goto cleanup;
		}
		else
		{
			error = fz_newnullfilter(&pipe, fz_toint(length));
			if (error)
				goto cleanup;
		}

		fz_seek(xref->file, stmofs);
		fz_pushfilter(xref->file, pipe);

		while (1)
		{
			n = fz_read(xref->file, buf, sizeof buf);
			if (n == 0)
				break;
			if (n < 0)
			{
				error = fz_ferror(xref->file);
				fz_popfilter(xref->file);
				goto cleanup;
			}
			fwrite(buf, 1, n, out);
		}

		fz_popfilter(xref->file);

		fprintf(out, "endstream\n");
	}

	fprintf(out, "endobj\n\n");

	fz_dropobj(obj);

	if (ferror(out))
        return fz_throw("ioerror: write failed");

	return nil;

cleanup:
	fz_dropobj(obj);
	return error;
}

static int countmodified(pdf_xref *xref, int oid)
{
	int i;
	for (i = oid; i < xref->size; i++)
		if (xref->table[i].type != 'a' && xref->table[i].type != 'd')
			return i - oid;
	return i - oid;
}

fz_error *
pdf_saveincrementalpdf(pdf_xref *xref, char *path)
{
	fz_error *error;
	FILE *out;
	int oid;
	int i, n;
	int startxref;
	fz_obj *obj;

	out = fopen(path, "ab");
	if (!out)
		return fz_throw("ioerror: could not open '%s': %s", path, strerror(errno));
	fprintf(out, "\n");

	for (oid = 0; oid < xref->size; oid++)
	{
		if (xref->table[oid].type == 'a')
		{
			xref->table[oid].ofs = ftell(out);
			error = writestored(out, xref, oid);
			if (error)
				goto cleanup;
		}
	}

	/* always write out entry 0 in appended xref sections */
	xref->table[0].type = 'd';

	startxref = ftell(out);
	fprintf(out, "xref\n");

	oid = 0;
	while (oid < xref->size)
	{
		n = countmodified(xref, oid);

		fprintf(out, "%d %d\n", oid, n);

		for (i = 0; i < n; i++)
		{
			if (xref->table[oid + i].type == 'd')
				xref->table[oid + i].type = 'f';
			if (xref->table[oid + i].type == 'a')
				xref->table[oid + i].type = 'n';

			fprintf(out, "%010d %05d %c \n",
				xref->table[oid + i].ofs,
				xref->table[oid + i].gen,
				xref->table[oid + i].type);
		}

		oid += n;
		while (oid < xref->size &&
				xref->table[oid].type != 'a' &&
				xref->table[oid].type != 'd')
			oid ++;
	}

	fprintf(out, "\n");

	fprintf(out, "trailer\n<<\n  /Size %d\n  /Prev %d", xref->size, xref->startxref);

	obj = fz_dictgets(xref->trailer, "Root");
	fprintf(out,"\n  /Root %d %d R", fz_toobjid(obj), fz_togenid(obj));

	obj = fz_dictgets(xref->trailer, "Info");
	if (obj)
		fprintf(out,"\n  /Info %d %d R", fz_toobjid(obj), fz_togenid(obj));

	obj = fz_dictgets(xref->trailer, "Encrypt");
	if (obj) {
		fprintf(out,"\n  /Encrypt ");
		fz_debugobj(obj);
	}

	obj = fz_dictgets(xref->trailer, "ID");
	if (obj) {
		fprintf(out,"\n  /ID ");
		fz_debugobj(obj);
	}

	fprintf(out, "\n>>\n\n");

	fprintf(out, "startxref\n");
	fprintf(out, "%d\n", startxref);
	fprintf(out, "%%%%EOF\n");

	xref->startxref = startxref;

	fclose(out);
	return nil;

cleanup:
	fclose(out);
	return error;
}

fz_error *
pdf_savepdf(pdf_xref *xref, char *path)
{
	fz_error *error;
	FILE *out;
	int oid;
	int startxref;
	int *ofsbuf;
	fz_obj *obj;

	ofsbuf = fz_malloc(sizeof(int) * xref->size);
	if (!ofsbuf)
		return fz_outofmem;

	out = fopen(path, "wb");
	if (!out)
	{
		fz_free(ofsbuf);
		return fz_throw("ioerror: could not open '%s': %s", path, strerror(errno));
	}

	fprintf(out, "%%PDF-%1.1f\n", xref->version);
	fprintf(out, "%%\342\343\317\323\n\n");

	for (oid = 0; oid < xref->size; oid++)
	{
		if (xref->table[oid].type == 'n' || xref->table[oid].type == 'o')
		{
			ofsbuf[oid] = ftell(out);
			error = writecopy(out, xref, oid);
			if (error)
				goto cleanup;
		}
		else if (xref->table[oid].type == 'a')
		{
			ofsbuf[oid] = ftell(out);
			error = writestored(out, xref, oid);
			if (error)
				goto cleanup;
		}
		else
		{
			ofsbuf[oid] = xref->table[oid].ofs;
		}
	}

	startxref = ftell(out);
	fprintf(out, "xref\n");
	fprintf(out, "0 %d\n", xref->size);

	for (oid = 0; oid < xref->size; oid++)
	{
		int type = xref->table[oid].type;
		if (type == 'a' || type == 'o')
			type = 'n';
		if (type == 'd')
			type = 'f';
		fprintf(out, "%010d %05d %c \n", ofsbuf[oid], xref->table[oid].gen, type);
	}

	fprintf(out, "\n");

	fprintf(out, "trailer\n<<\n  /Size %d", xref->size);
	obj = fz_dictgets(xref->trailer, "Root");
	fprintf(out,"\n  /Root %d %d R", fz_toobjid(obj), fz_togenid(obj));
	obj = fz_dictgets(xref->trailer, "Info");
	if (obj)
		fprintf(out,"\n  /Info %d %d R", fz_toobjid(obj), fz_togenid(obj));
	fprintf(out, "\n>>\n\n");

	fprintf(out, "startxref\n");
	fprintf(out, "%d\n", startxref);
	fprintf(out, "%%%%EOF\n");

	xref->startxref = startxref;

	fclose(out);
	return nil;

cleanup:
	fclose(out);
	return error;
}

