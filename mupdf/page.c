#include <fitz.h>
#include <mupdf.h>

static fz_error *
runone(pdf_csi *csi, pdf_xref *xref, fz_obj *rdb, fz_obj *stmref)
{
	fz_error *error;

	error = pdf_openstream(xref, fz_tonum(stmref), fz_togen(stmref));
	if (error)
		return error;

	error = pdf_runcsi(csi, xref, rdb, xref->stream);

	pdf_closestream(xref);

	return error;
}

/* we need to combine all sub-streams into one for pdf_runcsi
 * to deal with split dictionaries etc.
 */
static fz_error *
runmany(pdf_csi *csi, pdf_xref *xref, fz_obj *rdb, fz_obj *list)
{
	fz_error *error;
	fz_file *file;
	fz_buffer *big;
	fz_buffer *one;
	fz_obj *stm;
	int n;
	int i;

	error = fz_newbuffer(&big, 32 * 1024);
	if (error)
		return error;

	error = fz_openbuffer(&file, big, FZ_WRITE);
	if (error)
		goto cleanup0;

	for (i = 0; i < fz_arraylen(list); i++)
	{
		stm = fz_arrayget(list, i);
		error = pdf_loadstream(&one, xref, fz_tonum(stm), fz_togen(stm));
		if (error)
			goto cleanup1;

		n = fz_write(file, one->rp, one->wp - one->rp);

		fz_dropbuffer(one);

		if (n == -1)
		{
			error = fz_ferror(file);
			goto cleanup1;
		}

		n = fz_printstring(file, " ");
		if (n == -1)
		{
			error = fz_ferror(file);
			goto cleanup1;
		}
	}

	fz_closefile(file);

	error = fz_openbuffer(&file, big, FZ_READ);
	if (error)
		goto cleanup0;

	error = pdf_runcsi(csi, xref, rdb, file);

	fz_closefile(file);
	fz_dropbuffer(big);

	return error;

cleanup1:
	fz_closefile(file);
cleanup0:
	fz_dropbuffer(big);
	return error;
}

static fz_error *
loadpagecontents(fz_tree **treep, pdf_xref *xref, fz_obj *rdb, fz_obj *ref)
{
	fz_error *error;
	fz_obj *obj;
	pdf_csi *csi;

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
			if (fz_arraylen(obj) == 1)
				error = runone(csi, xref, rdb, fz_arrayget(obj, 0));
			else
				error = runmany(csi, xref, rdb, obj);
		}
		else
			error = runone(csi, xref, rdb, ref);

		fz_dropobj(obj);
		if (error)
			goto cleanup;
	}

	else if (fz_isarray(ref))
	{
		if (fz_arraylen(ref) == 1)
			error = runone(csi, xref, rdb, fz_arrayget(ref, 0));
		else
			error = runmany(csi, xref, rdb, ref);
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

	obj = fz_dictgets(dict, "CropBox");
	if (!obj)
		obj = fz_dictgets(dict, "MediaBox");
	if (!fz_isarray(obj))
		return fz_throw("syntaxerror: Page missing MediaBox");
	bbox = pdf_torect(obj);

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

