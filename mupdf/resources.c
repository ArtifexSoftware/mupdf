#include <fitz.h>
#include <mupdf.h>

/* TODO: use binary search ... realizm.pdf */

void *
pdf_findresource(pdf_rsrc *rsrc, fz_obj *key)
{
	if (key == nil)
		return nil;
	while (rsrc)
	{
		if (!fz_cmpobj(rsrc->key, key))
			return rsrc->val;
		rsrc = rsrc->next;
	}
	return nil;
}

/*
Load resources:

Go through resource dictionary and resolve some levels of
indirect references so we end up with a stylized structure:

<<
	/Font <<
		/F0 1 0 R
		/F1 2 0 R
		/F2 3 0 R
	>>
	/ExtGState <<
		/Gs0 << ... /Font 1 0 R ... >>
		/Gs1 << ... >>
	>>
	/ColorSpace <<
		/Cs0 5 0 R
		/Cs1 [ /ICCBased 5 0 R ]
		/Cs2 [ /CalRGB << ... >> ]
		/CsX [ /Pattern /DeviceRGB ]
	>>
	/Pattern <<
		/Pat0 20 0 R
	>>
	/Shading << 
		/Sh0 30 0 R
	>>
	/XObject <<
		/Im0 10 0 R
		/Fm0 11 0 R
	>>
>>

Then all references to actual resources will get
parsed and inserted into the pdf_xref resource lists.

*/

static fz_error *
preloadcolorspace(pdf_xref *xref, fz_obj *ref)
{
	fz_error *error;
	fz_colorspace *colorspace;
	pdf_rsrc *rsrc;
	fz_obj *obj = ref;

	if (pdf_findresource(xref->rcolorspace, ref))
		return nil;

	if (!fz_isindirect(ref))
		pdf_logrsrc("inline colorspace resource\n");

	rsrc = fz_malloc(sizeof(pdf_rsrc));
	if (!rsrc)
		return fz_outofmem;

	error = pdf_resolve(&obj, xref);
	if (error)
		return error;
	error = pdf_loadcolorspace(&colorspace, xref, obj);
	fz_dropobj(obj);
	if (error) {
		fz_free(rsrc);
		return error;
	}

	rsrc->key = fz_keepobj(ref);
	rsrc->val = colorspace;
	rsrc->next = xref->rcolorspace;
	xref->rcolorspace = rsrc;
	return nil;
}

static fz_error *
preloadpattern(pdf_xref *xref, fz_obj *ref)
{
	fz_error *error;
	pdf_rsrc *rsrc;
	fz_obj *type;
	fz_obj *obj = ref;

	if (pdf_findresource(xref->rpattern, ref))
		return nil;
	if (pdf_findresource(xref->rshade, ref))
		return nil;

	if (!fz_isindirect(ref))
		pdf_logrsrc("inline pattern resource\n");

	rsrc = fz_malloc(sizeof(pdf_rsrc));
	if (!rsrc)
		return fz_outofmem;

	error = pdf_resolve(&obj, xref);
	if (error)
		return error;

	type = fz_dictgets(obj, "PatternType");

	if (fz_toint(type) == 1)
	{
		error = pdf_loadpattern((pdf_pattern**)&rsrc->val, xref, obj, ref);
		fz_dropobj(obj);
		if (error) {
			fz_free(rsrc);
			return error;
		}
		rsrc->key = fz_keepobj(ref);
		rsrc->next = xref->rpattern;
		xref->rpattern = rsrc;
		return nil;
	}

	else if (fz_toint(type) == 2)
	{
		error = pdf_loadshade((fz_shade**)&rsrc->val, xref, obj, ref);
		fz_dropobj(obj);
		if (error) {
			fz_free(rsrc);
			return error;
		}
		rsrc->key = fz_keepobj(ref);
		rsrc->next = xref->rshade;
		xref->rshade = rsrc;
		return nil;
	}

	else
	{
		fz_dropobj(obj);
		fz_free(rsrc);
		return fz_throw("syntaxerror: unknown Pattern type");
	}
}

static fz_error *
preloadshading(pdf_xref *xref, fz_obj *ref)
{
	fz_error *error;
	pdf_rsrc *rsrc;
	fz_obj *obj = ref;

	if (pdf_findresource(xref->rshade, ref))
		return nil;

	if (!fz_isindirect(ref))
		pdf_logrsrc("inline shading resource\n");

	rsrc = fz_malloc(sizeof(pdf_rsrc));
	if (!rsrc)
		return fz_outofmem;

	error = pdf_resolve(&obj, xref);
	if (error)
		return error;

	error = pdf_loadshade((fz_shade**)&rsrc->val, xref, obj, ref);
	fz_dropobj(obj);
	if (error) {
		fz_free(rsrc);
		return error;
	}

	rsrc->key = fz_keepobj(ref);
	rsrc->next = xref->rshade;
	xref->rshade = rsrc;
	return nil;
}

static fz_error *
preloadxobject(pdf_xref *xref, fz_obj *ref)
{
	fz_error *error;
	pdf_rsrc *rsrc;
	fz_obj *obj = ref;
	fz_obj *subtype;

	if (pdf_findresource(xref->rxobject, ref))
		return nil;
	if (pdf_findresource(xref->rimage, ref))
		return nil;

	if (!fz_isindirect(ref))
		pdf_logrsrc("inline xobject resource\n");

	rsrc = fz_malloc(sizeof(pdf_rsrc));
	if (!rsrc)
		return fz_outofmem;

	error = pdf_resolve(&obj, xref);
	if (error)
		return error;

	subtype = fz_dictgets(obj, "Subtype");

	if (!strcmp(fz_toname(subtype), "Form"))
	{
		error = pdf_loadxobject((pdf_xobject**)&rsrc->val, xref, obj, ref);
		fz_dropobj(obj);
		if (error) {
			fz_free(rsrc);
			return error;
		}
		rsrc->key = fz_keepobj(ref);
		rsrc->next = xref->rxobject;
		xref->rxobject = rsrc;
		return nil;
	}

	else if (!strcmp(fz_toname(subtype), "Image"))
	{
		error = pdf_loadimage((pdf_image**)&rsrc->val, xref, obj, ref);
		fz_dropobj(obj);
		if (error) {
			fz_free(rsrc);
			return error;
		}
		rsrc->key = fz_keepobj(ref);
		rsrc->next = xref->rimage;
		xref->rimage = rsrc;
		return nil;
	}

	else
	{
		fz_dropobj(obj);
		fz_free(rsrc);
		return fz_throw("syntaxerror: unknown XObject subtype");
	}
}

static fz_error *
preloadfont(pdf_xref *xref, fz_obj *ref)
{
	fz_error *error;
	pdf_font *font;
	pdf_rsrc *rsrc;
	fz_obj *obj = ref;

	if (pdf_findresource(xref->rfont, ref))
		return nil;

	if (!fz_isindirect(ref))
		pdf_logrsrc("inline font resource\n");

	rsrc = fz_malloc(sizeof(pdf_rsrc));
	if (!rsrc)
		return fz_outofmem;

	error = pdf_resolve(&obj, xref);
	if (error)
		return error;
	error = pdf_loadfont(&font, xref, obj);
	fz_dropobj(obj);
	if (error) {
		fz_free(rsrc);
		return error;
	}

	rsrc->key = fz_keepobj(ref);
	rsrc->val = font;
	rsrc->next = xref->rfont;
	xref->rfont = rsrc;
	return nil;
}

static fz_error *
scanfonts(pdf_xref *xref, fz_obj *rdb)
{
	fz_error *error;
	fz_obj *dict;
	fz_obj *obj;
	int i;

	dict = fz_dictgets(rdb, "ExtGState");
	if (dict)
	{
		for (i = 0; i < fz_dictlen(dict); i++)
		{
			obj = fz_dictgetval(dict, i);
			obj = fz_dictgets(obj, "Font");
			if (obj)
			{
				pdf_logrsrc("extgstate font\n");
				error = preloadfont(xref, fz_arrayget(obj, 0));
				if (error)
					return error;
			}
		}
	}

	dict = fz_dictgets(rdb, "Font");
	if (dict)
	{
		for (i = 0; i < fz_dictlen(dict); i++)
		{
			obj = fz_dictgetval(dict, i);
			error = preloadfont(xref, obj);
			if (error)
				return error;
		}
	}

	return nil;
}

static fz_error *
copyresolved(fz_obj **outp, pdf_xref *xref, fz_obj *dict)
{
	fz_error *error;
	fz_obj *key, *val, *obj;
	fz_obj *copy;
	int i;

	error = fz_newdict(&copy, fz_dictlen(dict));
	if (error)
		return error;

	for (i = 0; i < fz_dictlen(dict); i++)
	{
		key = fz_dictgetkey(dict, i);
		val = fz_dictgetval(dict, i);

		if (fz_isindirect(val))
		{
			error = pdf_loadindirect(&obj, xref, val);
			if (error)
				goto cleanup;
			error = fz_dictput(copy, key, obj);
			fz_dropobj(obj);
			if (error)
				goto cleanup;
		}
		else
		{
			error = fz_dictput(copy, key, val);
			if (error)
				goto cleanup;
		}
	}

	*outp = copy;
	return nil;

cleanup:
	fz_dropobj(copy);
	return error;
}

fz_error *
pdf_loadresources(fz_obj **rdbp, pdf_xref *xref, fz_obj *orig)
{
	fz_error *error;
	fz_obj *copy;
	fz_obj *old;
	fz_obj *new;
	fz_obj *dict;
	fz_obj *obj;
	int i;

	pdf_logrsrc("load resources {\n");

	/*
	 * Resolve indirect objects
	 */

	error = copyresolved(&copy, xref, orig);
	if (error)
		return error;

	old = fz_dictgets(copy, "ExtGState");
	if (old)
	{
		error = copyresolved(&new, xref, old);
		if (error)
			goto cleanup;
		error = fz_dictputs(copy, "ExtGState", new);
		fz_dropobj(new);
		if (error)
			goto cleanup;
	}

	/*
	 * Load ColorSpace objects
	 */

	dict = fz_dictgets(copy, "ColorSpace");
	if (dict)
	{
		for (i = 0; i < fz_dictlen(dict); i++)
		{
			obj = fz_dictgetval(dict, i);
				error = preloadcolorspace(xref, obj);
				if (error)
					return error;
		}
	}

	/*
	 * Load Patterns (and Shadings)
	 */

	dict = fz_dictgets(copy, "Pattern");
	if (dict)
	{
		for (i = 0; i < fz_dictlen(dict); i++)
		{
			obj = fz_dictgetval(dict, i);
				error = preloadpattern(xref, obj);
				if (error)
					return error;
		}
	}

	dict = fz_dictgets(copy, "Shading");
	if (dict)
	{
		for (i = 0; i < fz_dictlen(dict); i++)
		{
			obj = fz_dictgetval(dict, i);
				error = preloadshading(xref, obj);
				if (error)
					return error;
		}
	}

	/*
	 * Load XObjects and Images
	 */

	dict = fz_dictgets(copy, "XObject");
	if (dict)
	{
		for (i = 0; i < fz_dictlen(dict); i++)
		{
			obj = fz_dictgetval(dict, i);
				error = preloadxobject(xref, obj);
				if (error)
					return error;
		}
	}

	/*
	 * Load Font objects
	 */

	error = scanfonts(xref, copy);
	if (error)
		goto cleanup;

	pdf_logrsrc("}\n");

	*rdbp = copy;
	return nil;

cleanup:
	fz_dropobj(copy);
	return error;
}

