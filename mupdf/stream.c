#include <fitz.h>
#include <mupdf.h>

static fz_error *
makefilter(fz_filter **fp, fz_obj *f, fz_obj *p)
{
	fz_filter *predf = nil;
	fz_filter *realf = nil;
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
		if (fz_isdict(p)) {
			fz_obj *obj = fz_dictgets(p, "Predictor");
			if (obj) {
				error = fz_newflated(&realf, p);
				if (error) goto cleanup;
				error = fz_newpredictd(&predf, p);
				if (error) goto cleanup;
				error = fz_newpipeline(fp, realf, predf);
				if (error) goto cleanup;
				return nil;
			}
		}
		return fz_newflated(fp, p);
	}

	if (!strcmp(s, "LZWDecode") || !strcmp(s, "LZW"))
	{
		if (fz_isdict(p)) {
			fz_obj *obj = fz_dictgets(p, "Predictor");
			if (obj) {
				error = fz_newlzwd(&realf, p);
				if (error) goto cleanup;
				error = fz_newpredictd(&predf, p);
				if (error) goto cleanup;
				error = fz_newpipeline(fp, realf, predf);
				if (error) goto cleanup;
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

cleanup:
	if (realf) fz_freefilter(realf);
	if (predf) fz_freefilter(predf);
	return error;
}

static fz_error *
makepipeline(fz_filter **fp, fz_obj *fs, fz_obj *ps)
{
	fz_error *error;
	fz_filter *filter = nil;
	fz_filter *pipe = nil;
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

		error = makefilter(&filter, f, p);
		if (error) { if (pipe) fz_freefilter(pipe); return error; }

		if (pipe) {
			fz_filter *np;
			error = fz_newpipeline(&np, pipe, filter);
			if (error) { fz_freefilter(pipe); return error; }
			pipe = np;
		}
		else pipe = filter;
	}

	*fp = pipe;
	return nil;
}

fz_error *
pdf_buildfilter(fz_filter **fp, pdf_xref *xref, fz_obj *stmobj, int oid, int gid)
{
	fz_error *error;
	fz_filter *filter;
	fz_obj *filters;
	fz_obj *params;
	fz_obj *obj;
	int len;

	obj = fz_dictgets(stmobj, "Length");
	error = pdf_resolve(&obj, xref);
	if (error)
		return error;
	len = fz_toint(obj);
	fz_dropobj(obj);

	filters = fz_dictgets(stmobj, "Filter");
	params = fz_dictgets(stmobj, "DecodeParms");

	if (!filters)
	{
		error = fz_newnullfilter(&filter, len);
		if (error)
			return error;
	}

	else if (fz_isname(filters))
	{
		error = makefilter(&filter, filters, params);
		if (error)
			return error;
	}

	else if (fz_isarray(filters))
	{
		if (fz_arraylen(filters) == 0)
			error = fz_newnullfilter(&filter, len);
		else
			error = makepipeline(&filter, filters, params);
		if (error)
			return error;
	}

	else
	{
		return fz_throw("typecheck in buildstream");
	}

	if (xref->crypt)
	{
		fz_filter *cryptfilter;
		fz_filter *pipeline;

		error = pdf_cryptstm(&cryptfilter, xref->crypt, oid, gid);
		if (error)
		{
			fz_freefilter(filter);
			return error;
		}

		error = fz_newpipeline(&pipeline, cryptfilter, filter);
		if (error)
		{
			fz_freefilter(cryptfilter);
			fz_freefilter(filter);
			return error;
		}

		filter = pipeline;
	}

	*fp = filter;

	return nil;
}

fz_error *
pdf_openstream0(pdf_xref *xref, fz_obj *stmobj, int oid, int gid, int ofs)
{
	fz_error *error;
	fz_filter *filter;

	error = pdf_buildfilter(&filter, xref, stmobj, oid, gid);
	if (error)
		return error;

	ofs = fz_seek(xref->file, ofs);
	if (ofs < 0) {
		fz_freefilter(filter);
		return fz_ferror(xref->file);
	}

	error = fz_pushfilter(xref->file, filter);
	if (error) {
		fz_freefilter(filter);
		return error;
	}

	return nil;
}

fz_error *
pdf_openstream(pdf_xref *xref, fz_obj *stmref)
{
	fz_error *error;
	fz_obj *stmobj;
	int oid, gid, ofs;

	oid = fz_toobjid(stmref);
	gid = fz_togenid(stmref);

	error = pdf_loadobject0(&stmobj, xref, oid, gid, &ofs);
	if (error)
		return error;

	error = pdf_openstream0(xref, stmobj, oid, gid, ofs);
	if (error) {
		fz_dropobj(stmobj);
		return error;
	}

	fz_dropobj(stmobj);

	return nil;
}

void
pdf_closestream(pdf_xref *xref)
{
	fz_popfilter(xref->file);
}

fz_error *
pdf_readstream0(fz_buffer **bufp, pdf_xref *xref, fz_obj *stmobj, int oid, int gid, int ofs)
{
	fz_error *error;

	error = pdf_openstream0(xref, stmobj, oid, gid, ofs);
	if (error)
		return error;

	error = fz_readfile(bufp, xref->file);

	pdf_closestream(xref);

	return error;
}

fz_error *
pdf_readstream(fz_buffer **bufp, pdf_xref *xref, fz_obj *stmref)
{
	fz_error *error;

	error = pdf_openstream(xref, stmref);
	if (error)
		return error;

	error = fz_readfile(bufp, xref->file);

	pdf_closestream(xref);

	return error;
}

