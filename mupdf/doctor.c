#include <fitz.h>
#include <mupdf.h>

/*
 * Garbage collection
 */

static fz_error *sweepref(pdf_xref *xref, fz_obj *ref);

static fz_error *
sweepobj(pdf_xref *xref, fz_obj *obj)
{
	fz_error *error;
	int i;

	if (fz_isdict(obj))
	{
		for (i = 0; i < fz_dictlen(obj); i++)
		{
			error = sweepobj(xref, fz_dictgetval(obj, i));
			if (error)
				return error;
		}
	}

	if (fz_isarray(obj))
	{
		for (i = 0; i < fz_arraylen(obj); i++)
		{
			error = sweepobj(xref, fz_arrayget(obj, i));
			if (error)
				return error;
		}
	}

	if (fz_isindirect(obj))
		return sweepref(xref, obj);

	return nil;
}

static fz_error *
sweepref(pdf_xref *xref, fz_obj *ref)
{
	fz_error *error;
	fz_obj *obj;
	int oid;

	oid = fz_toobjid(ref);

	if (oid < 0 || oid >= xref->size)
		return fz_throw("rangecheck: object number out of range");

	if (xref->table[oid].mark)
		return nil;

	xref->table[oid].mark = 1;

	error = pdf_loadobject(&obj, xref, ref, nil);
	if (error)
		return error;

	error = sweepobj(xref, obj);
	if (error)
	{
		fz_dropobj(obj);
		return error;
	}

	fz_dropobj(obj);
	return nil;
}

fz_error *
pdf_garbagecollect(pdf_xref *xref)
{
	fz_error *error;
	int i, g;

	for (i = 0; i < xref->size; i++)
		xref->table[i].mark = 0;

	error = sweepobj(xref, xref->trailer);
	if (error)
		return error;

	for (i = 0; i < xref->size; i++)
	{
		pdf_xrefentry *x = xref->table + i;
		g = x->gen;
		if (x->type == 'o')
			g = 0;

		if (!x->mark && x->type != 'f' && x->type != 'd')
		{
			error = pdf_deleteobject(xref, i, g);
			if (error)
				return error;
		}
	}

	return nil;
}

