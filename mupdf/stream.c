#include <fitz.h>
#include <mupdf.h>

/* TODO: error cleanup */

static fz_error *
buildonefilter(fz_filter **fp, fz_obj *f, fz_obj *p)
{
	fz_filter *predf;
	fz_filter *realf;
	fz_error *error;
	char *s;

	s = fz_toname(f);

	if (!strcmp(s, "ASCIIHexDecode") || !strcmp(s, "AHx"))
		return fz_newahxd(fp, p);

	if (!strcmp(s, "ASCII85Decode") || !strcmp(s, "A85"))
		return fz_newa85d(fp, p);

	if (!strcmp(s, "CCITTFaxDecode") || !strcmp(s, "CCF"))
		return fz_newfaxd(fp, p);

	if (!strcmp(s, "DCTDecode") || !strcmp(s, "DCT"))
		return fz_newdctd(fp, p);

	if (!strcmp(s, "RunLengthDecode") || !strcmp(s, "RL"))
		return fz_newrld(fp, p);

	if (!strcmp(s, "JPXDecode"))
		return fz_newjpxd(fp, p);

	if (!strcmp(s, "FlateDecode") || !strcmp(s, "Fl"))
	{
		if (fz_isdict(p))
		{
			fz_obj *obj = fz_dictgets(p, "Predictor");
			if (obj) {
				error = fz_newflated(&realf, p);
				error = fz_newpredictd(&predf, p);
				error = fz_newpipeline(fp, realf, predf);
				return nil;
			}
		}
		return fz_newflated(fp, p);
	}

	if (!strcmp(s, "LZWDecode") || !strcmp(s, "LZW"))
	{
		if (fz_isdict(p))
		{
			fz_obj *obj = fz_dictgets(p, "Predictor");
			if (obj) {
				error = fz_newlzwd(&realf, p);
				error = fz_newpredictd(&predf, p);
				error = fz_newpipeline(fp, realf, predf);
				return nil;
			}
		}
		return fz_newlzwd(fp, p);
	}

	if (!strcmp(s, "JBIG2Decode")) {
		/* TODO: extract and feed JBIG2Global */
		return fz_newjbig2d(fp, p);
	}

	return fz_throw("syntaxerror: unknown filter: %s", s);
}

static fz_error *
buildfilters(fz_filter **filterp, fz_filter *head, fz_obj *fs, fz_obj *ps)
{
	fz_error *error;
	fz_filter *tail;
	fz_obj *f;
	fz_obj *p;
	int i;

	for (i = 0; i < fz_arraylen(fs); i++)
	{
		f = fz_arrayget(fs, i);
		if (fz_isarray(ps))
			p = fz_arrayget(ps, i);
		else
			p = nil;

		error = buildonefilter(&tail, f, p);
		error = fz_newpipeline(&head, head, tail);
	}

	*filterp = head;
	return nil;
}

static fz_error *
makerawfilter(fz_filter **filterp, pdf_xref *xref, fz_obj *stmobj, int oid, int gen)
{
	fz_error *error;
	fz_filter *pipe, *cf;
	fz_obj *stmlen;

	stmlen = fz_dictgets(stmobj, "Length");
	error = pdf_resolve(&stmlen, xref);

	error = fz_newnullfilter(&pipe, fz_toint(stmlen));

	if (xref->crypt)
	{
		error = pdf_cryptstm(&cf, xref->crypt, oid, gen);
		error = fz_newpipeline(&pipe, pipe, cf);
	}

	fz_dropobj(stmlen);

	*filterp = pipe;
	return nil;
}

static fz_error *
makedecodefilter(fz_filter **filterp, pdf_xref *xref, fz_obj *stmobj, int oid, int gen)
{
	fz_error *error;
	fz_filter *pipe, *tmp;
	fz_obj *filters;
	fz_obj *params;

	error = makerawfilter(&pipe, xref, stmobj, oid, gen);

	filters = fz_dictgets(stmobj, "Filter");
	params = fz_dictgets(stmobj, "DecodeParms");

	if (filters)
	{
		error = pdf_resolve(&filters, xref);
		if (params)
			error = pdf_resolve(&params, xref);

		if (fz_isname(filters))
		{
			error = buildonefilter(&tmp, filters, params);
			error = fz_newpipeline(&pipe, pipe, tmp);
		}
		else
			error = buildfilters(&pipe, pipe, filters, params);

		if (params)
			fz_dropobj(params);
		fz_dropobj(filters);
	}

	*filterp = pipe;

	return nil;
}

int
pdf_isstream(pdf_xref *xref, int oid, int gen)
{
	fz_error *error;

	if (oid < 0 || oid >= xref->len)
		return 0;

	error = pdf_cacheobject(xref, oid, gen);
	if (error) {
		fz_warn("%s", error);
		fz_droperror(error);
		return 0;
	}

	return xref->table[oid].stmbuf || xref->table[oid].stmofs;
}

fz_error *
pdf_openrawstream(pdf_xref *xref, int oid, int gen)
{
	pdf_xrefentry *x;
	fz_error *error;
	fz_filter *filter;
	int n;

	if (oid < 0 || oid >= xref->len)
		return fz_throw("rangecheck: object id out of range");

	x = xref->table + oid;

	error = pdf_cacheobject(xref, oid, gen);

	if (x->stmbuf)
	{
		return fz_openbuffer(&xref->stream, x->stmbuf, FZ_READ);
	}

	if (x->stmofs)
	{
		error = makerawfilter(&filter, xref, x->obj, oid, gen);
		n = fz_seek(xref->file, x->stmofs, 0);
		error = fz_pushfilter(xref->file, filter);
		xref->stream = xref->file;
		return nil;
	}

	return fz_throw("syntaxerror: object is not a stream");
}

fz_error *
pdf_openstream(pdf_xref *xref, int oid, int gen)
{
	pdf_xrefentry *x;
	fz_error *error;
	fz_filter *filter;
	int n;

	if (oid < 0 || oid >= xref->len)
		return fz_throw("rangecheck: object id out of range");

	x = xref->table + oid;

	error = pdf_cacheobject(xref, oid, gen);

	if (x->stmbuf)
	{
		error = makedecodefilter(&filter, xref, x->obj, oid, gen);
		error = fz_openbuffer(&xref->stream, x->stmbuf, FZ_READ);
		error = fz_pushfilter(xref->stream, filter);
		return nil;
	}

	if (x->stmofs)
	{
		error = makedecodefilter(&filter, xref, x->obj, oid, gen);
		n = fz_seek(xref->file, x->stmofs, 0);
		error = fz_pushfilter(xref->file, filter);
		xref->stream = xref->file;
		return nil;
	}

	return fz_throw("syntaxerror: object is not a stream");
}

void
pdf_closestream(pdf_xref *xref)
{
	if (xref->stream == xref->file)
		fz_popfilter(xref->file);
	else
		fz_closefile(xref->stream);
	xref->stream = nil;
}


fz_error *
pdf_loadrawstream(fz_buffer **bufp, pdf_xref *xref, int oid, int gen)
{
	fz_error *error;

	error = pdf_openrawstream(xref, oid, gen);
	if (error)
		return error;

	error = fz_readfile(bufp, xref->stream);

	pdf_closestream(xref);

	return error;
}

fz_error *
pdf_loadstream(fz_buffer **bufp, pdf_xref *xref, int oid, int gen)
{
	fz_error *error;

	error = pdf_openstream(xref, oid, gen);
	if (error)
		return error;

	error = fz_readfile(bufp, xref->stream);

	pdf_closestream(xref);

	return error;
}

