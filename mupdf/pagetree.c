#include <fitz.h>
#include <mupdf.h>

struct stuff
{
	fz_obj *resources;
	fz_obj *mediabox;
	fz_obj *cropbox;
	fz_obj *rotate;
};

static fz_error *
loadpagetree(pdf_xref *xref, pdf_pagetree *pages,
	struct stuff inherit, fz_obj *obj, fz_obj *ref)
{
	fz_error *err;
	fz_obj *type;
	fz_obj *kids;
	fz_obj *kref, *kobj;
	fz_obj *inh;
	int i;

	type = fz_dictgets(obj, "Type");

	if (strcmp(fz_toname(type), "Page") == 0)
	{
		if (inherit.resources && !fz_dictgets(obj, "Resources")) {
			err = fz_dictputs(obj, "Resources", inherit.resources);
			if (err) return err;
		}

		if (inherit.mediabox && !fz_dictgets(obj, "MediaBox")) {
			err = fz_dictputs(obj, "MediaBox", inherit.mediabox);
			if (err) return err;
		}

		if (inherit.cropbox && !fz_dictgets(obj, "CropBox")) {
			err = fz_dictputs(obj, "CropBox", inherit.cropbox);
			if (err) return err;
		}

		if (inherit.rotate && !fz_dictgets(obj, "Rotate")) {
			err = fz_dictputs(obj, "Rotate", inherit.rotate);
			if (err) return err;
		}

		pages->pref[pages->cursor] = fz_keepobj(ref);
		pages->pobj[pages->cursor] = fz_keepobj(obj);
		pages->cursor ++;
	}

	else if (strcmp(fz_toname(type), "Pages") == 0)
	{
		inh = fz_dictgets(obj, "Resources");
		if (inh) inherit.resources = inh;

		inh = fz_dictgets(obj, "MediaBox");
		if (inh) inherit.mediabox = inh;

		inh = fz_dictgets(obj, "CropBox");
		if (inh) inherit.cropbox = inh;

		inh = fz_dictgets(obj, "Rotate");
		if (inh) inherit.rotate = inh;

		kids = fz_dictgets(obj, "Kids");
		for (i = 0; i < fz_arraylen(kids); i++)
		{
			kref = fz_arrayget(kids, i);

			err = pdf_loadobject(&kobj, xref, kref, nil);
			if (err) return err;

			err = loadpagetree(xref, pages, inherit, kobj, kref);
			fz_dropobj(kobj);
			if (err) return err;
		}
	}

	return nil;
}

void
pdf_debugpagetree(pdf_pagetree *pages)
{
	int i;
	printf("<<\n  /Type /Pages\n  /Count %d\n  /Kids [\n", pages->count);
	for (i = 0; i < pages->count; i++) {
		printf("    ");
		fz_debugobj(pages->pref[i]);
		printf("\t%% page %d\n", i + 1);
		//fz_debugobj(stdout, pages->pobj[i]);
		//printf("\n");
	}
	printf("  ]\n>>\n");
}

fz_error *
pdf_loadpagetree(pdf_pagetree **pp, pdf_xref *xref)
{
	fz_error *err;
	struct stuff inherit;
	pdf_pagetree *p = nil;
	fz_obj *catalog = nil;
	fz_obj *pages = nil;
	fz_obj *trailer;
	fz_obj *ref;
	int count;

	inherit.resources = nil;
	inherit.mediabox = nil;
	inherit.cropbox = nil;
	inherit.rotate = nil;

	trailer = xref->trailer;

	ref = fz_dictgets(trailer, "Root");
	err = pdf_loadobject(&catalog, xref, ref, nil);
	if (err) goto error;

	ref = fz_dictgets(catalog, "Pages");
	err = pdf_loadobject(&pages, xref, ref, nil);
	if (err) goto error;

	ref = fz_dictgets(pages, "Count");
	count = fz_toint(ref);

	p = *pp = fz_malloc(sizeof(pdf_pagetree));
	if (!p) { err = fz_outofmem; goto error; }

	p->pref = nil;
	p->pobj = nil;
	p->count = count;
	p->cursor = 0;

	p->pref = fz_malloc(sizeof(fz_obj*) * count);
	if (!p->pref) { err = fz_outofmem; goto error; }

	p->pobj = fz_malloc(sizeof(fz_obj*) * count);
	if (!p->pobj) { err = fz_outofmem; goto error; }

	err = loadpagetree(xref, p, inherit, pages, ref);
	if (err) goto error;

	fz_dropobj(pages);
	fz_dropobj(catalog);
	return nil;

error:
	if (pages) fz_dropobj(pages);
	if (catalog) fz_dropobj(catalog);
	if (p) {
		fz_free(p->pref);
		fz_free(p->pobj);
		fz_free(p);
	}
	return nil;
}

void
pdf_freepagetree(pdf_pagetree *pages)
{
	int i;
	for (i = 0; i < pages->count; i++) {
		if (pages->pref[i])
			fz_dropobj(pages->pref[i]);
		if (pages->pobj[i])
			fz_dropobj(pages->pobj[i]);
	}
	fz_free(pages->pref);
	fz_free(pages->pobj);
	fz_free(pages);
}

