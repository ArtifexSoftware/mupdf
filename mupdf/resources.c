#include <fitz.h>
#include <mupdf.h>

static fz_error *
loadextgstatefonts(pdf_resources *rdb, pdf_xref *xref)
{
	fz_error *err;
	char name[64];
	pdf_font *font;
	fz_obj *extgstate;
	fz_obj *obj;
	fz_obj *ptr;
	fz_obj *ref;
	int i;

	for (i = 0; i < fz_dictlen(rdb->extgstate); i++)
	{
		extgstate = fz_dictgetval(rdb->extgstate, i);

		obj = fz_dictgets(extgstate, "Font");
		if (obj)
		{
			font = nil;
			ptr = nil;

			if (!fz_isarray(obj) || fz_arraylen(obj) != 2)
				return fz_throw("syntaxerror in ExtGState/Font");

			ref = fz_arrayget(obj, 0);
			sprintf(name, "$f.%d.%d", fz_tonum(ref), fz_togen(ref));

			err = pdf_resolve(&ref, xref);
			if (err) return err;

			err = pdf_loadfont(&font, xref, ref);
			if (err) goto cleanup;

			err = fz_newpointer(&ptr, font);
			if (err) goto cleanup;

			err = fz_dictputs(rdb->font, name, ptr);
			if (err) goto cleanup;

			fz_dropobj(ptr);
			fz_dropobj(ref);
		}
	}

	return nil;

cleanup:
	if (font) fz_freefont((fz_font*)font);
	if (ptr) fz_dropobj(ptr);
	fz_dropobj(ref);
	return err;
}

static fz_error *
loadextgstates(pdf_resources *rdb, pdf_xref *xref, fz_obj *dict)
{
	fz_error *err;
	fz_obj *key, *val;
	int i;

	for (i = 0; i < fz_dictlen(dict); i++)
	{
		key = fz_dictgetkey(dict, i);
		val = fz_dictgetval(dict, i);

		err = pdf_resolve(&val, xref);
		if (err) return err;

		err = fz_dictput(rdb->extgstate, key, val);
		if (err) { fz_dropobj(val); return err; }

		fz_dropobj(val);
	}

	return nil;
}

static fz_error *
loadfonts(pdf_resources *rdb, pdf_xref *xref, fz_obj *dict)
{
	fz_error *err;
	pdf_font *font;
	fz_obj *key, *val;
	fz_obj *ptr;
	int i;

	for (i = 0; i < fz_dictlen(dict); i++)
	{
		font = nil;
		ptr = nil;

		key = fz_dictgetkey(dict, i);
		val = fz_dictgetval(dict, i);

		err = pdf_resolve(&val, xref);
		if (err) return err;

		err = pdf_loadfont(&font, xref, val);
		if (err) goto cleanup;

		err = fz_newpointer(&ptr, font);
		if (err) goto cleanup;

		err = fz_dictput(rdb->font, key, ptr);
		if (err) goto cleanup;

		fz_dropobj(ptr);
		fz_dropobj(val);
	}

	return nil;

cleanup:
	if (font) fz_freefont((fz_font*)font);
	if (ptr) fz_dropobj(ptr);
	fz_dropobj(val);
	return err;
}

fz_error *
pdf_loadresources(pdf_resources **rdbp, pdf_xref *xref, fz_obj *topdict)
{
	fz_error *err;
	pdf_resources *rdb;
	fz_obj *subdict;

	rdb = *rdbp = fz_malloc(sizeof (pdf_resources));
	if (!rdb)
		return fz_outofmem;

	rdb->extgstate = nil;
	rdb->font = nil;
	rdb->colorspace = nil;
	rdb->ximage = nil;
	rdb->xform = nil;

	err = fz_newdict(&rdb->extgstate, 5);
	if (err) { pdf_freeresources(rdb); return err; }

	subdict = fz_dictgets(topdict, "ExtGState");
	if (subdict)
	{
		err = pdf_resolve(&subdict, xref);
		if (err) { pdf_freeresources(rdb); return err; }
		err = loadextgstates(rdb, xref, subdict);
		fz_dropobj(subdict);
		if (err) { pdf_freeresources(rdb); return err; }
	}

	err = fz_newdict(&rdb->font, 15);
	if (err) { pdf_freeresources(rdb); return err; }

	err = loadextgstatefonts(rdb, xref);
	if (err) { pdf_freeresources(rdb); return err; }

	subdict = fz_dictgets(topdict, "Font");
	if (subdict)
	{
		err = pdf_resolve(&subdict, xref);
		if (err) { pdf_freeresources(rdb); return err; }
		err = loadfonts(rdb, xref, subdict);
		fz_dropobj(subdict);
		if (err) { pdf_freeresources(rdb); return err; }
	}

	return nil;
}

void
pdf_freeresources(pdf_resources *rdb)
{
	/* TODO freefont */
	if (rdb->extgstate) fz_dropobj(rdb->extgstate);
	if (rdb->colorspace) fz_dropobj(rdb->colorspace);
	if (rdb->font) fz_dropobj(rdb->font);
	if (rdb->ximage) fz_dropobj(rdb->ximage);
	if (rdb->xform) fz_dropobj(rdb->xform);
	fz_free(rdb);
}

