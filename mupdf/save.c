#include <fitz.h>
#include <mupdf.h>

#define TIGHT 0

static fz_error *
writestored(fz_file *out, pdf_xref *xref, pdf_crypt *encrypt, int oid)
{
	pdf_xrefentry *x = xref->table + oid;
	fz_error *error;
	fz_obj *obj;
	fz_buffer *stm;
	fz_filter *filter;
	int gid;

	gid = x->gen;	
	if (x->type == 'o')
		gid = 0;

	obj = pdf_findstoredobject(xref->store, oid, gid);
	stm = pdf_findstoredstream(xref->store, oid, gid);

	if (!obj)
		return fz_throw("could not find stored object");

	if (encrypt)
		pdf_cryptobj(encrypt, obj, oid, gid);

	fz_print(out, "%d %d obj\n", oid, gid);
	fz_printobj(out, obj, TIGHT);
	fz_print(out, "\n");

	if (stm)
	{
		fz_print(out, "stream\n");

		if (encrypt)
		{
			error = pdf_cryptstm(&filter, encrypt, oid, gid);
			if (error)
				return error;
			error = fz_pushfilter(out, filter);
			if (error) {
				fz_freefilter(filter);
				return error;
			}
		}

		fz_write(out, stm->rp, stm->wp - stm->rp);

		if (encrypt)
			fz_popfilter(out);

		fz_print(out, "endstream\n");
	}

	fz_print(out, "endobj\n\n");

	error = fz_ferror(out);
	if (error)
		return error;

	return nil;
}

static fz_error *
writecopy(fz_file *out, pdf_xref *xref, pdf_crypt *encrypt, int oid)
{
	pdf_xrefentry *x = xref->table + oid;
	fz_error *error;
	fz_obj *length;
	fz_obj *obj;
	int stmofs;
	fz_filter *cf;
	fz_filter *nf;
	fz_filter *pipe;
	fz_filter *ef;
	int gid;
	int n;
	unsigned char buf[4096];

	gid = x->gen;	
	if (x->type == 'o')
		gid = 0;

	error = pdf_loadobject0(&obj, xref, oid, gid, &stmofs);
	if (error)
		return error;

	if (encrypt)
		pdf_cryptobj(encrypt, obj, oid, gid);

	fz_print(out, "%d %d obj\n", oid, gid);
	fz_printobj(out, obj, TIGHT);
	fz_print(out, "\n");

	if (stmofs != -1)
	{
		fz_print(out, "stream\n");

		length = fz_dictgets(obj, "Length");
		error = pdf_resolve(&length, xref);
		if (error)
			goto cleanup;

		if (xref->crypt)
		{
			error = fz_newnullfilter(&nf, fz_toint(length));
			if (error)
				goto cleanup;
			error = pdf_cryptstm(&cf, xref->crypt, oid, gid);
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

		if (encrypt)
		{
			error = pdf_cryptstm(&ef, encrypt, oid, gid);
			if (error)
				return error;
			error = fz_pushfilter(out, ef);
			if (error) {
				fz_freefilter(ef);
				goto cleanup;
			}
		}

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
				if (encrypt)
					fz_popfilter(out);
			}
			fz_write(out, buf, n);
		}

		if (encrypt)
			fz_popfilter(out);

		fz_popfilter(xref->file);

		fz_print(out, "endstream\n");
	}

	fz_print(out, "endobj\n\n");

	error = fz_ferror(out);
	if (error)
		goto cleanup;

	fz_dropobj(obj);

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
	fz_file *out;
	int oid;
	int i, n;
	int startxref;
	fz_obj *obj;

	error = fz_openfile(&out, path, O_APPEND);
	if (error)
		return error;

	fz_print(out, "\n");

	for (oid = 0; oid < xref->size; oid++)
	{
		if (xref->table[oid].type == 'a')
		{
			xref->table[oid].ofs = fz_tell(out);
			error = writestored(out, xref, xref->crypt, oid);
			if (error)
				goto cleanup;
		}
	}

	/* always write out entry 0 in appended xref sections */
	xref->table[0].type = 'd';

	startxref = fz_tell(out);
	fz_print(out, "xref\n");

	oid = 0;
	while (oid < xref->size)
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
		while (oid < xref->size &&
				xref->table[oid].type != 'a' &&
				xref->table[oid].type != 'd')
			oid ++;
	}

	fz_print(out, "\n");

	fz_print(out, "trailer\n<<\n  /Size %d\n  /Prev %d", xref->size, xref->startxref);

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

fz_error *
pdf_savepdf(pdf_xref *xref, char *path, pdf_crypt *encrypt)
{
	fz_error *error;
	fz_file *out;
	int oid;
	int startxref;
	int *ofsbuf;
	fz_obj *obj;

	ofsbuf = fz_malloc(sizeof(int) * xref->size);
	if (!ofsbuf)
		return fz_outofmem;

	error = fz_openfile(&out, path, O_WRONLY);
	if (error)
	{
		fz_free(ofsbuf);
		return error;
	}

	fz_print(out, "%%PDF-%1.1f\n", xref->version);
	fz_print(out, "%%\342\343\317\323\n\n");

	for (oid = 0; oid < xref->size; oid++)
	{
		if (xref->table[oid].type == 'n' || xref->table[oid].type == 'o')
		{
			ofsbuf[oid] = fz_tell(out);
			error = writecopy(out, xref, encrypt, oid);
			if (error)
				goto cleanup;
		}
		else if (xref->table[oid].type == 'a')
		{
			ofsbuf[oid] = fz_tell(out);
			error = writestored(out, xref, encrypt, oid);
			if (error)
				goto cleanup;
		}
		else
		{
			ofsbuf[oid] = xref->table[oid].ofs;
		}
	}

	startxref = fz_tell(out);
	fz_print(out, "xref\n");
	fz_print(out, "0 %d\n", xref->size);

	for (oid = 0; oid < xref->size; oid++)
	{
		int type = xref->table[oid].type;
		if (type == 'a' || type == 'o')
			type = 'n';
		if (type == 'd')
			type = 'f';
		fz_print(out, "%010d %05d %c \n", ofsbuf[oid], xref->table[oid].gen, type);
	}

	fz_print(out, "\n");

	fz_print(out, "trailer\n<<\n  /Size %d", xref->size);
	obj = fz_dictgets(xref->trailer, "Root");
	fz_print(out, "\n  /Root %d %d R", fz_toobjid(obj), fz_togenid(obj));
	obj = fz_dictgets(xref->trailer, "Info");
	if (obj)
		fz_print(out, "\n  /Info %d %d R", fz_toobjid(obj), fz_togenid(obj));
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

