#include <fitz.h>
#include <mupdf.h>

static fz_error *
loadoutlinetree(pdf_xref *xref, pdf_outline *outline, fz_obj *obj)
{
// please call this 'error'
	fz_error *err;
	fz_obj *first;
	fz_obj *next;
	fz_obj *ref;
	fz_obj *t;
	pdf_outline *o;
	int i;

	t = fz_dictgets(obj, "Title");
// check for failure after each malloc
	outline->title = fz_malloc(sizeof(char) * fz_tostringlen(t) + 1);
// use strlcpy instead. strncpy does not null terminate.
	strncpy(outline->title, fz_tostringbuf(t), fz_tostringlen(t));
	outline->title[fz_tostringlen(t)] = 0;

	t = fz_dictgets(obj, "Count");
	outline->count = fz_toint(t);

	outline->dest = fz_dictgets(obj, "Dest");
	if (outline->dest) fz_keepobj(outline->dest);
	outline->a = fz_dictgets(obj, "A");
	if (outline->a) fz_keepobj(outline->a);
	outline->se = fz_dictgets(obj, "SE");
	if (outline->se) fz_keepobj(outline->se);

	t = fz_dictgets(obj, "C");
	if (t) {
		for (i = 0; i < 3; i++)
			outline->c[i] = fz_toreal(fz_arrayget(t, i));
	} else {
		for (i = 0; i < 3; i++)
			outline->c[i] = 0.;
	}

	t = fz_dictgets(obj, "F");
	if (t)
		outline->f = fz_toint(t);

	first = fz_dictgets(obj, "First");
	if (first) {
		err = pdf_loadindirect(&ref, xref, first);
		if (err) return err;

		o = fz_malloc(sizeof(pdf_outline));
// you leak ref
		if (!o) { err = fz_outofmem; return err; }

		loadoutlinetree(xref, o, ref);
// check error return
		
		outline->first = o;

		fz_dropobj(ref);
	} else {
		outline->first = nil;
	}

	next = fz_dictgets(obj, "Next");
	if (next) {
		err = pdf_loadindirect(&ref, xref, next);
		if (err) return err;

		o = fz_malloc(sizeof(pdf_outline));
// you leak ref
		if (!o) { err = fz_outofmem; return err; }

		loadoutlinetree(xref, o, ref);
// check error return?
		
		outline->next = o;

		fz_dropobj(ref);
	} else {
		outline->next = nil;
	}

	return nil;
}

fz_error *
pdf_loadoutlinetree(pdf_outlinetree **oo, pdf_xref *xref)
{
// please rename to 'error'
	fz_error *err;
	pdf_outlinetree *o = nil;
	fz_obj *outline = nil;
	fz_obj *catalog = nil;
	fz_obj *outlines = nil;
	fz_obj *trailer;
	fz_obj *ref;
	int count;

	trailer = xref->trailer;

	ref = fz_dictgets(trailer, "Root");
	err = pdf_loadindirect(&catalog, xref, ref);
	if (err) goto error;

// create empty tree if no outlines exist instead of failing?
	ref = fz_dictgets(catalog, "Outlines");
	if (!ref) goto error;
	err = pdf_loadindirect(&outlines, xref, ref);
	if (err) goto error;

	ref = fz_dictgets(outlines, "Count");
	count = fz_toint(ref);

	o = *oo = fz_malloc(sizeof(pdf_outlinetree));
	if (!o) { err = fz_outofmem; goto error; }

	o->count = count;
	o->first = fz_malloc(sizeof(pdf_outline));
	if (!o->first) { err = fz_outofmem; goto error; }

	ref = fz_dictgets(outlines, "First");
	err = pdf_loadindirect(&outline, xref, ref);
// check error
	err = loadoutlinetree(xref, o->first, outline);
	if (err) goto error;

	fz_dropobj(outline);
	fz_dropobj(outlines);
	fz_dropobj(catalog);
	return nil;

error:
	if (outlines) fz_dropobj(outlines);
	if (catalog) fz_dropobj(catalog);
	if (o) fz_free(o);
	return nil;
}

void
pdf_dropoutline(pdf_outline *outline)
{
	if (outline->first)
		pdf_dropoutline(outline->first);
	if (outline->next)
		pdf_dropoutline(outline->next);

	fz_free(outline->title);
	if (outline->dest) fz_dropobj(outline->dest);
	if (outline->a) fz_dropobj(outline->a);
	if (outline->se) fz_dropobj(outline->se);

	fz_free(outline);
}

void
pdf_dropoutlinetree(pdf_outlinetree *outlinetree)
{
	if (outlinetree->first)
		pdf_dropoutline(outlinetree->first);
	fz_free(outlinetree);
}

static void
debugoutline(pdf_outline *outline, int level)
{
	int i;
	while (outline)
	{
		for (i = 0; i < level; i++) putchar(' ');
		printf("(%s) ", outline->title);
		if (outline->dest)
			fz_debugobj(outline->dest);
		if (outline->a)
			fz_debugobj(outline->a);
		printf("\n");
		if (outline->first)
			debugoutline(outline->first, level + 2);
		outline = outline->next;
	}
}

void
pdf_debugoutlinetree(pdf_outlinetree *outlinetree)
{
	debugoutline(outlinetree->first, 0);
}

