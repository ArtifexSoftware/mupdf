#include <fitz.h>
#include <mupdf.h>

static fz_error *
runcsi(pdf_csi *csi, pdf_xref *xref, fz_obj *rdb, fz_obj *stmref)
{
	fz_error *error;

	error = pdf_openstream(xref, fz_tonum(stmref), fz_togen(stmref));
	if (error)
		return error;

	error = pdf_runcsi(csi, xref, rdb, xref->stream);

	pdf_closestream(xref);

	return error;
}

static fz_error *
loadpagecontents(fz_tree **treep, pdf_xref *xref, fz_obj *rdb, fz_obj *ref)
{
	fz_error *error;
	fz_obj *obj;
	pdf_csi *csi;
	int i;

	error = pdf_newcsi(&csi, 0);
	if (error)
		return error;

	if (fz_isindirect(ref))
	{
		error = pdf_loadindirect(&obj, xref, ref);
		if (error)
			return error;

		if (fz_isarray(obj))
		{
			for (i = 0; i < fz_arraylen(obj); i++)
			{
				error = runcsi(csi, xref, rdb, fz_arrayget(obj, i));
				if (error) {
					fz_dropobj(obj);
					goto cleanup;
				}
			}
		}
		else
		{
			error = runcsi(csi, xref, rdb, ref);
			if (error) {
				fz_dropobj(obj);
				goto cleanup;
			}
		}

		fz_dropobj(obj);
	}

	else if (fz_isarray(ref))
	{
		for (i = 0; i < fz_arraylen(ref); i++)
		{
			error = runcsi(csi, xref, rdb, fz_arrayget(ref, i));
			if (error)
				goto cleanup;
		}
	}

	*treep = csi->tree;
	csi->tree = nil;
	error = nil;

cleanup:
	pdf_dropcsi(csi);
	return error;
}

fz_error *
pdf_loadpage(pdf_page **pagep, pdf_xref *xref, fz_obj *dict)
{
	fz_error *error;
	fz_obj *obj;
	pdf_page *page;
	fz_obj *rdb;
	fz_tree *tree;
	fz_rect bbox;
	int rotate;

	obj = fz_dictgets(dict, "MediaBox");
	if (!fz_isarray(obj))
		return fz_throw("syntaxerror: Page missing MediaBox");
	bbox.min.x = fz_toreal(fz_arrayget(obj, 0));
	bbox.min.y = fz_toreal(fz_arrayget(obj, 1));
	bbox.max.x = fz_toreal(fz_arrayget(obj, 2));
	bbox.max.y = fz_toreal(fz_arrayget(obj, 3));

	obj = fz_dictgets(dict, "Rotate");
	if (fz_isint(obj))
		rotate = fz_toint(obj);
	else
		rotate = 0;

	/*
	 * Load resources
	 */

	obj = fz_dictgets(dict, "Resources");
	if (!obj)
		return fz_throw("syntaxerror: Page missing Resources");
	error = pdf_resolve(&obj, xref);
	if (error) return error;
	error = pdf_loadresources(&rdb, xref, obj);
	fz_dropobj(obj);
	if (error) return error;

	/*
	 * Interpret content stream to build display tree
 	 */

	obj = fz_dictgets(dict, "Contents");

	error = loadpagecontents(&tree, xref, rdb, obj);
	if (error) {
		fz_dropobj(rdb);
		return error;
	}

	error = fz_optimizetree(tree);
	if (error) {
		fz_dropobj(rdb);
		return error;
	}

	/*
	 * Create page object
	 */

	page = *pagep = fz_malloc(sizeof(pdf_page));
	if (!page) {
		fz_droptree(tree);
		fz_dropobj(rdb);
		return fz_outofmem;
	}

	page->mediabox.min.x = MIN(bbox.min.x, bbox.max.x);
	page->mediabox.min.y = MIN(bbox.min.y, bbox.max.y);
	page->mediabox.max.x = MAX(bbox.min.x, bbox.max.x);
	page->mediabox.max.y = MAX(bbox.min.y, bbox.max.y);
	page->rotate = rotate;
	page->resources = rdb;
	page->tree = tree;

	return nil;
}

void
pdf_droppage(pdf_page *page)
{
	fz_dropobj(page->resources);
	fz_droptree(page->tree);
	fz_free(page);
}

