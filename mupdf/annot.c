#include <fitz.h>
#include <mupdf.h>

static fz_error *
loadcomment(pdf_comment **commentp, pdf_xref *xref, fz_obj *dict)
{
	return nil;
}

fz_error *
pdf_newlink(pdf_link **linkp, fz_rect bbox, int ismap, fz_obj *page, fz_obj *uri)
{
	pdf_link *link;

	link = fz_malloc(sizeof(pdf_link));
	if (!link)
		return fz_outofmem;

	link->rect = bbox;
	link->ismap = ismap;
	link->page = page ? fz_keepobj(page) : nil;
	link->uri = uri ? fz_keepobj(uri) : nil;
	link->next = nil;

	*linkp = link;
	return nil;
}

void
pdf_droplink(pdf_link *link)
{
	if (link->next)
		pdf_droplink(link->next);
	if (link->page)
		fz_dropobj(link->page);
	if (link->uri)
		fz_dropobj(link->uri);
	fz_free(link);
}

static fz_obj *
resolvedest(pdf_xref *xref, fz_obj *dest)
{
	if (fz_isname(dest) && xref->dests)
	{
		dest = pdf_lookupname(xref->dests, dest);
		pdf_resolve(&dest, xref); /* XXX */
		return resolvedest(xref, dest);
	}

	else if (fz_isstring(dest) && xref->dests)
	{
		dest = pdf_lookupname(xref->dests, dest);
		pdf_resolve(&dest, xref); /* XXX */
		return resolvedest(xref, dest);
	}

	else if (fz_isarray(dest))
	{
		return fz_arrayget(dest, 0);
	}

	else if (fz_isdict(dest))
	{
		dest = fz_dictgets(dest, "D");
		return resolvedest(xref, dest);
	}

	else if (fz_isindirect(dest))
		return dest;

	return nil;
}

static fz_error *
loadlink(pdf_link **linkp, pdf_xref *xref, fz_obj *dict)
{
	fz_error *error;
	pdf_link *link;
	fz_obj *page;
	fz_obj *uri;
	fz_obj *action;
	fz_obj *obj;
	fz_rect bbox;
	int ismap;

	pdf_logpage("load link {\n");

	link = nil;
	page = nil;
	uri = nil;
	ismap = 0;

	obj = fz_dictgets(dict, "Rect");
	bbox = pdf_torect(obj);
	pdf_logpage("rect [%g %g %g %g]\n",
		bbox.min.x, bbox.min.y,
		bbox.max.x, bbox.max.y);

	obj = fz_dictgets(dict, "Dest");
	if (obj)
	{
		error = pdf_resolve(&obj, xref);
		if (error)
			return error;
		page = resolvedest(xref, obj);
		pdf_logpage("dest %d %d R\n", fz_tonum(page), fz_togen(page));
		fz_dropobj(obj);
	}

	action = fz_dictgets(dict, "A");
	if (action)
	{
		error = pdf_resolve(&action, xref);
		if (error)
			return error;

		obj = fz_dictgets(action, "S");
		if (!strcmp(fz_toname(obj), "GoTo"))
		{
			page = resolvedest(xref, fz_dictgets(action, "D"));
			pdf_logpage("action goto %d %d R\n", fz_tonum(page), fz_togen(page));
		}
		else if (!strcmp(fz_toname(obj), "URI"))
		{
			uri = fz_dictgets(action, "URI");
			ismap = fz_tobool(fz_dictgets(action, "IsMap"));
			pdf_logpage("action uri ismap=%d\n", ismap);
		}
		else
			pdf_logpage("action ... ?\n");

		fz_dropobj(action);
	}

	pdf_logpage("}\n");

	if (page || uri)
	{
		error = pdf_newlink(&link, bbox, ismap, page, uri);
		if (error)
			return error;
		link->next = *linkp;
		*linkp = link;
	}

	return nil;
}

fz_error *
pdf_loadannots(pdf_comment **cp, pdf_link **lp, pdf_xref *xref, fz_obj *annots)
{
	fz_error *error;
	pdf_comment *comment;
	pdf_link *link;
	fz_obj *subtype;
	fz_obj *obj;
	int i;

	comment = nil;
	link = nil;

	pdf_logpage("load annotations {\n");

	for (i = 0; i < fz_arraylen(annots); i++)
	{
		obj = fz_arrayget(annots, i);
		error = pdf_resolve(&obj, xref);
		if (error)
			goto cleanup;

		subtype = fz_dictgets(obj, "Subtype");
		if (!strcmp(fz_toname(subtype), "Link"))
			error = loadlink(&link, xref, obj);
		else
			error = loadcomment(&comment, xref, obj);
			
		fz_dropobj(obj);

		if (error)
			goto cleanup;
	}

	pdf_logpage("}\n");

	*cp = comment;
	*lp = link;
	return nil;

cleanup:
	pdf_droplink(link);
	return error;
}

