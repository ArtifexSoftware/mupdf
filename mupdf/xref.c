#include <fitz.h>
#include <mupdf.h>

/*
 * initialize xref
 */

fz_error *
pdf_newxref(pdf_xref **xrefp)
{
	fz_error *error;
	pdf_xref *xref;

	xref = *xrefp = fz_malloc(sizeof(pdf_xref));
	if (!xref)
		return fz_outofmem;

	xref->version = 1.3;
	xref->crypt = nil;
	xref->file = nil;
	xref->size = 0;
	xref->capacity = 0;
	xref->table = nil;
	xref->trailer = nil;
	xref->startxref = -1;

	error = fz_newhash(&xref->store, 256, sizeof(int) * 3);
	if (error)
	{
		fz_free(xref);
		return error;
	}

	return nil;
}

fz_error *
pdf_decryptxref(pdf_xref *xref)
{
	fz_error *error;
	fz_obj *encrypt;
	fz_obj *id;

	if (xref->size < 0)
		return fz_throw("rangecheck: xref missing first slot");

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
pdf_closexref(pdf_xref *xref)
{
	int *key;
	void *val;
	int i;

	if (xref->store)
	{
		for (i = 0; i < fz_hashlen(xref->store); i++)
		{
			key = fz_gethashkey(xref->store, i);
			val = fz_gethashval(xref->store, i);
			if (val && key[2] == 0)
				fz_dropobj((fz_obj*)val);
			if (val && key[2] == 1)
				fz_freebuffer((fz_buffer*)val);
		}
		fz_freehash(xref->store);
	}

	if (xref->table)
		fz_free(xref->table);
	if (xref->trailer)
		fz_dropobj(xref->trailer);
	if (xref->file)
		fz_closefile(xref->file);
	fz_free(xref);
}

void
pdf_debugxref(pdf_xref *xref)
{
	int i;
	printf("%%!PDF-%g\n", xref->version);
	printf("xref\n0 %d\n", xref->size);
	for (i = 0; i < xref->size; i++)
	{
		printf("%010d %05d %c \n",
			xref->table[i].ofs,
			xref->table[i].gen,
			xref->table[i].type);
	}
	printf("trailer\n");
	fz_debugobj(xref->trailer);
	printf("\n");
}

/*
 * object and stream store (cached from objstm and saved for mutation)
 */

fz_obj *
pdf_findstoredobject(fz_hashtable *store, int oid, int gid)
{
	int key[3];
	key[0] = oid;
	key[1] = gid;
	key[2] = 0;
	return fz_hashfind(store, key);
}

fz_buffer *
pdf_findstoredstream(fz_hashtable *store, int oid, int gid)
{
	int key[3];
	key[0] = oid;
	key[1] = gid;
	key[2] = 1;
	return fz_hashfind(store, key);
}

fz_error *
pdf_deletestoredobject(fz_hashtable *store, int oid, int gid)
{
	int key[3];
	fz_obj *obj;
	key[0] = oid;
	key[1] = gid;
	key[2] = 0;
	obj = fz_hashfind(store, key);
	if (obj)
		fz_dropobj(obj);
	return fz_hashremove(store, key);
}

fz_error *
pdf_deletestoredstream(fz_hashtable *store, int oid, int gid)
{
	int key[3];
	fz_buffer *stm;
	key[0] = oid;
	key[1] = gid;
	key[2] = 1;
	stm = fz_hashfind(store, key);
	if (stm)
		fz_freebuffer(stm);
	return fz_hashremove(store, key);
}

fz_error *
pdf_storeobject(fz_hashtable *store, int oid, int gid, fz_obj *obj)
{
	int key[3];	
	key[0] = oid;
	key[1] = gid;
	key[2] = 0;
	return fz_hashinsert(store, key, obj);
}

fz_error *
pdf_storestream(fz_hashtable *store, int oid, int gid, fz_buffer *buf)
{
	int key[3];	
	key[0] = oid;
	key[1] = gid;
	key[2] = 1;
	return fz_hashinsert(store, key, buf);
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
	for (next = oid + 1; next < xref->size; next++)
		if (xref->table[next].type == 'f' || xref->table[next].type == 'd')
			return next;
	return 0;
}

fz_error *
pdf_createobject(pdf_xref *xref, int *oidp, int *gidp)
{
	pdf_xrefentry *x;
	int prev;
	int oid = 0;

	while (1)
	{
		x = xref->table + oid;

		if (x->type == 'f' || x->type == 'd')
		{
			if (x->gen < 65535)
			{
				*oidp = oid;
				*gidp = x->gen;
				return nil;
			}
		}

		oid = x->ofs;

		if (oid == 0)
			break;
	}

	if (xref->size + 1 >= xref->capacity)
	{
		int newcap = xref->capacity + 256;
		pdf_xrefentry *newtable;

		newtable = fz_realloc(xref->table, sizeof(pdf_xrefentry) * newcap);
		if (!newtable)
			return fz_outofmem;

		xref->table = newtable;
		xref->capacity = newcap;
	}

	oid = xref->size ++;

	xref->table[oid].type = 'd';
	xref->table[oid].mark = 0;
	xref->table[oid].ofs = 0;
	xref->table[oid].gen = 0;

	prev = findprev(xref, oid);
	xref->table[prev].type = 'd';
	xref->table[prev].ofs = oid;

	*oidp = oid;
	*gidp = 0;

	return nil;
}

fz_error *
pdf_deleteobject(pdf_xref *xref, int oid, int gid)
{
	pdf_xrefentry *x;
	int prev;

	if (oid < 0 || oid >= xref->size)
		return fz_throw("rangecheck: invalid object number");

	x = xref->table + oid;

	if (x->type != 'n' && x->type != 'o' && x->type == 'a')
		return fz_throw("rangecheck: delete nonexistant object");

	x->type = 'd';
	x->ofs = findnext(xref, oid);
	x->gen ++;

	prev = findprev(xref, oid);
	xref->table[prev].type = 'd';
	xref->table[prev].ofs = oid;

	return nil;
}

fz_error *
pdf_saveobject(pdf_xref *xref, int oid, int gid, fz_obj *obj)
{
	fz_error *error;
	pdf_xrefentry *x;

	if (oid < 0 || oid >= xref->size)
		return fz_throw("rangecheck: invalid object number");

	error = pdf_storeobject(xref->store, oid, gid, obj);
	if (error)
		return error;

	x = xref->table + oid;

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
pdf_savestream(pdf_xref *xref, int oid, int gid, fz_buffer *buf)
{
	return pdf_storestream(xref->store, oid, gid, buf);
}

fz_error *
pdf_deletestream(pdf_xref *xref, int oid, int gid)
{
	return pdf_deletestoredstream(xref->store, oid, gid);
}

/*
 * object loading
 */

fz_error *
pdf_loadobject0(fz_obj **objp, pdf_xref *xref, int oid, int gid, int *stmofs)
{
	unsigned char buf[65536];	/* yeowch! */

	fz_error *error;
	pdf_xrefentry *x;
	int roid, rgid;
	int n;

	if (oid < 0 || oid >= xref->size)
		return fz_throw("rangecheck: object number out of range: %d", oid);

	if (stmofs)
		*stmofs = -1;

	x = &xref->table[oid];

	if (x->type == 'f' || x->type == 'd')
		return fz_throw("rangecheck: tried to load free object");

	else if (x->type == 'n')
	{
		n = fz_seek(xref->file, x->ofs);
		if (n < 0)
			return fz_ferror(xref->file);

		error = pdf_parseindobj(objp, xref->file, buf, sizeof buf,
					&roid, &rgid, stmofs);
		if (error)
			return error;

		if (xref->crypt)
			pdf_cryptobj(xref->crypt, *objp, oid, gid);
	}

	else if (x->type == 'o')
	{
		*objp = pdf_findstoredobject(xref->store, oid, gid);
		if (*objp)
			return nil;

		error = pdf_readobjstm(xref, x->ofs, 0, buf, sizeof buf);
		if (error)
			return error;

		*objp = pdf_findstoredobject(xref->store, oid, gid);
		if (!*objp)
			return fz_throw("rangecheck: could not find object");
	}

	else if (x->type == 'a')
	{
		*objp = pdf_findstoredobject(xref->store, oid, gid);
		if (!*objp)
			return fz_throw("rangecheck: could not find object");
	}

	else
		return fz_throw("rangecheck: unknown object type");

	return nil;
}

fz_error *
pdf_loadobject(fz_obj **objp, pdf_xref *xref, fz_obj *ref, int *stmofs)
{
	return pdf_loadobject0(objp, xref, fz_toobjid(ref), fz_togenid(ref), stmofs);
}

fz_error *
pdf_resolve(fz_obj **objp, pdf_xref *xref)
{
	if (fz_isindirect(*objp))
		return pdf_loadobject(objp, xref, *objp, nil);
	fz_keepobj(*objp);
	return nil;
}

