#include <fitz.h>
#include <mupdf.h>

void
pdf_droppattern(pdf_pattern *pat)
{
	if (pat->tree)
		fz_droptree(pat->tree);
	fz_free(pat);
}

fz_error *
pdf_loadpattern(pdf_pattern **patp, pdf_xref *xref, fz_obj *dict, fz_obj *stmref)
{
	fz_error *error;
	pdf_pattern *pat;
	fz_obj *resources;
	fz_obj *obj;
	pdf_csi *csi;

printf("loading pattern %d %d\n", fz_tonum(stmref), fz_togen(stmref));

	pat = fz_malloc(sizeof(pdf_pattern));
	if (!pat)
		return fz_outofmem;

	pat->tree = nil;
	pat->ismask = fz_toint(fz_dictgets(dict, "PaintType")) == 2;
	pat->xstep = fz_toreal(fz_dictgets(dict, "XStep"));
	pat->ystep = fz_toreal(fz_dictgets(dict, "YStep"));

	obj = fz_dictgets(dict, "BBox");
	pat->bbox.min.x = fz_toreal(fz_arrayget(obj, 0));
	pat->bbox.min.y = fz_toreal(fz_arrayget(obj, 1));
	pat->bbox.max.x = fz_toreal(fz_arrayget(obj, 2));
	pat->bbox.max.y = fz_toreal(fz_arrayget(obj, 3));

	obj = fz_dictgets(dict, "Matrix");
	if (obj)
	{
		pat->matrix.a = fz_toreal(fz_arrayget(obj, 0));
		pat->matrix.b = fz_toreal(fz_arrayget(obj, 1));
		pat->matrix.c = fz_toreal(fz_arrayget(obj, 2));
		pat->matrix.d = fz_toreal(fz_arrayget(obj, 3));
		pat->matrix.e = fz_toreal(fz_arrayget(obj, 4));
		pat->matrix.f = fz_toreal(fz_arrayget(obj, 5));
	}
	else
	{
		pat->matrix = fz_identity();
	}

printf("  mask %d\n", pat->ismask);
printf("  xstep %g\n", pat->xstep);
printf("  ystep %g\n", pat->ystep);

	/*
	 * Resources
	 */

	obj = fz_dictgets(dict, "Resources");
	if (!obj) {
		error = fz_throw("syntaxerror: Pattern missing Resources");
		goto cleanup;
	}

	error = pdf_resolve(&obj, xref);
	if (error)
		goto cleanup;

	error = pdf_loadresources(&resources, xref, obj);

	fz_dropobj(obj);

	if (error)
		goto cleanup;

	/*
	 * Content stream
	 */

	error = pdf_newcsi(&csi, pat->ismask);
	if (error)
		goto cleanup;

	error = pdf_openstream(xref, fz_tonum(stmref), fz_togen(stmref));
	if (error)
		goto cleanup2;

	error = pdf_runcsi(csi, xref, resources, xref->stream);

	pdf_closestream(xref);

	if (error)
		goto cleanup2;

	if (csi->tree)
		fz_debugtree(csi->tree);

	pat->tree = csi->tree;
	csi->tree = nil;

	pdf_dropcsi(csi);

	fz_dropobj(resources);

	*patp = pat;
	return nil;

cleanup2:
	pdf_dropcsi(csi);
cleanup:
	pdf_droppattern(pat);
	return error;
}

