#include <fitz.h>
#include <mupdf.h>

/*
 * initialize new empty xref
 */

fz_error *
pdf_newpdf(pdf_xref **xrefp)
{
	pdf_xref *xref;

	xref = fz_malloc(sizeof (pdf_xref));
	if (!xref)
		return fz_outofmem;

	xref->file = nil;
	xref->version = 1.3;
	xref->startxref = 0;
	xref->trailer = nil;
	xref->crypt = nil;

	xref->cap = 256;
	xref->len = 1;
	xref->table = fz_malloc(xref->cap * sizeof(pdf_xrefentry));
	if (!xref->table) {
		fz_free(xref);
		return fz_outofmem;
	}

	xref->table[0].type = 'f';
    xref->table[0].mark = 0;
    xref->table[0].ofs = 0;
    xref->table[0].gen = 65535;
    xref->table[0].stmbuf = nil;
    xref->table[0].stmofs = 0;
    xref->table[0].obj = nil;

	*xrefp = xref;
	return nil;
}

fz_error *
pdf_decryptpdf(pdf_xref *xref)
{
	fz_error *error;
	fz_obj *encrypt;
	fz_obj *id;

	encrypt = fz_dictgets(xref->trailer, "Encrypt");
	id = fz_dictgets(xref->trailer, "ID");

	if (encrypt && id)
	{
		error = pdf_resolve(&encrypt, xref);
		if (error)
			goto cleanup;

		error = pdf_resolve(&id, xref);
		if (error)
			goto cleanup;

		error = pdf_newdecrypt(&xref->crypt, encrypt, id);
		if (error)
			goto cleanup;

		fz_dropobj(encrypt);
		fz_dropobj(id);
	}

	return nil;

cleanup:
	if (encrypt) fz_dropobj(encrypt);
	if (id) fz_dropobj(id);
	return error;
}

void
pdf_closepdf(pdf_xref *xref)
{
	int i;

	if (xref->table)
	{
		for (i = 0; i < xref->len; i++)
		{
			if (xref->table[i].stmbuf)
				fz_freebuffer(xref->table[i].stmbuf);
			if (xref->table[i].obj)
				fz_dropobj(xref->table[i].obj);
		}
		fz_free(xref->table);
	}

	if (xref->file)
		fz_closefile(xref->file);

	if (xref->trailer)
		fz_dropobj(xref->trailer);

	fz_free(xref);
}

void
pdf_debugpdf(pdf_xref *xref)
{
	int i;
	printf("xref\n0 %d\n", xref->len);
	for (i = 0; i < xref->len; i++)
	{
		printf("%010d %05d %c | %d %d\n",
			xref->table[i].ofs,
			xref->table[i].gen,
			xref->table[i].type,
			xref->table[i].obj ? xref->table[i].obj->refcount : 0,
			xref->table[i].stmofs);
	}
}

/*
 * mutate objects
 */

static int findprev(pdf_xref *xref, int oid)
{
	int prev;
	for (prev = oid - 1; prev >= 0; prev--)
		if (xref->table[prev].type == 'f' || xref->table[prev].type == 'd')
			return prev;
	return 0;
}

static int findnext(pdf_xref *xref, int oid)
{
	int next;
	for (next = oid + 1; next < xref->len; next++)
		if (xref->table[next].type == 'f' || xref->table[next].type == 'd')
			return next;
	return 0;
}

fz_error *
pdf_allocobject(pdf_xref *xref, int *oidp, int *genp)
{
	pdf_xrefentry *x;
	int prev, next;
	int oid = 0;

	while (1)
	{
		x = xref->table + oid;

		if (x->type == 'f' || x->type == 'd')
		{
			if (x->gen < 65535)
			{
				*oidp = oid;
				*genp = x->gen;

				x->type = 'a';
				x->ofs = 0;

				prev = findprev(xref, oid);
				next = findnext(xref, oid);
				xref->table[prev].type = 'd';
				xref->table[prev].ofs = next;

				return nil;
			}
		}

		oid = x->ofs;

		if (oid == 0)
			break;
	}

	if (xref->len + 1 >= xref->cap)
	{
		int newcap = xref->cap + 256;
		pdf_xrefentry *newtable;

		newtable = fz_realloc(xref->table, sizeof(pdf_xrefentry) * newcap);
		if (!newtable)
			return fz_outofmem;

		xref->table = newtable;
		xref->cap = newcap;
	}

	oid = xref->len ++;

	xref->table[oid].type = 'a';
	xref->table[oid].mark = 0;
	xref->table[oid].ofs = 0;
	xref->table[oid].gen = 0;
	xref->table[oid].stmbuf = nil;
	xref->table[oid].stmofs = 0;
	xref->table[oid].obj = nil;

	*oidp = oid;
	*genp = 0;

	prev = findprev(xref, oid);
	next = findnext(xref, oid);
	xref->table[prev].type = 'd';
	xref->table[prev].ofs = next;

	return nil;
}

fz_error *
pdf_deleteobject(pdf_xref *xref, int oid, int gen)
{
	pdf_xrefentry *x;
	int prev;

	if (oid < 0 || oid >= xref->len)
		return fz_throw("rangecheck: object number out of range: %d", oid);

	x = xref->table + oid;

	x->type = 'd';
	x->ofs = findnext(xref, oid);
	x->gen ++;

	if (x->stmbuf)
		fz_freebuffer(x->stmbuf);
	x->stmbuf = nil;

	if (x->obj)
		fz_dropobj(x->obj);
	x->obj = nil;

	prev = findprev(xref, oid);
	xref->table[prev].type = 'd';
	xref->table[prev].ofs = oid;

	return nil;
}

fz_error *
pdf_updateobject(pdf_xref *xref, int oid, int gen, fz_obj *obj)
{
	pdf_xrefentry *x;

	if (oid < 0 || oid >= xref->len)
		return fz_throw("rangecheck: object number out of range: %d", oid);

	x = xref->table + oid;

	if (x->obj)
		fz_dropobj(x->obj);

	x->obj = fz_keepobj(obj);

	if (x->type == 'f' || x->type == 'd')
	{
		int prev = findprev(xref, oid);
		int next = findnext(xref, oid);
		xref->table[prev].type = 'd';
		xref->table[prev].ofs = next;
	}

	x->type = 'a';

	return nil;
}

fz_error *
pdf_updatestream(pdf_xref *xref, int oid, int gen, fz_buffer *stm)
{
	pdf_xrefentry *x;

	if (oid < 0 || oid >= xref->len)
		return fz_throw("rangecheck: object number out of range: %d", oid);

	x = xref->table + oid;

	if (x->stmbuf)
		fz_freebuffer(x->stmbuf);
	x->stmbuf = stm;

	return nil;
}

/*
 * object loading
 */

fz_error *
pdf_cacheobject(pdf_xref *xref, int oid, int gen)
{
	unsigned char buf[65536];	/* yeowch! */

	fz_error *error;
	pdf_xrefentry *x;
	int roid, rgen;
	int n;

	if (oid < 0 || oid >= xref->len)
		return fz_throw("rangecheck: object number out of range: %d", oid);

	x = &xref->table[oid];

	if (x->obj)
		return nil;

	if (x->type == 'f' || x->type == 'd')
		return fz_throw("rangecheck: tried to load free object");

	if (x->type == 'n')
	{
		n = fz_seek(xref->file, x->ofs, 0);
		if (n < 0)
			return fz_ferror(xref->file);

		error = pdf_parseindobj(&x->obj, xref->file, buf, sizeof buf,
					&roid, &rgen, &x->stmofs);
		if (error)
			return error;

		if (roid != oid || rgen != gen)
			return fz_throw("syntaxerror: found wrong object");

		if (xref->crypt)
			pdf_cryptobj(xref->crypt, x->obj, oid, gen);
	}

	else if (x->type == 'o')
	{
		if (!x->obj)
		{
			error = pdf_loadobjstm(xref, x->ofs, 0, buf, sizeof buf);
			if (error)
				return error;
		}
	}

	return nil;
}

fz_error *
pdf_loadobject(fz_obj **objp, pdf_xref *xref, int oid, int gen)
{
	fz_error *error;

	error = pdf_cacheobject(xref, oid, gen);
	if (error)
		return error;

	*objp = fz_keepobj(xref->table[oid].obj);

	return nil;
}

fz_error *
pdf_loadindirect(fz_obj **objp, pdf_xref *xref, fz_obj *ref)
{
	assert(ref != nil);
	return pdf_loadobject(objp, xref, fz_tonum(ref), fz_togen(ref));
}

fz_error *
pdf_resolve(fz_obj **objp, pdf_xref *xref)
{
	if (fz_isindirect(*objp))
		return pdf_loadindirect(objp, xref, *objp);
	fz_keepobj(*objp);
	return nil;
}

