#include <fitz.h>
#include <mupdf.h>

static fz_error *
grownametree(pdf_nametree *tree, int amount)
{
	struct fz_keyval_s *newitems;
	int newcap;

	newcap = tree->cap + amount;
	newitems = fz_realloc(tree->items, sizeof(struct fz_keyval_s) * newcap);
	if (!newitems)
		return fz_outofmem;

	tree->items = newitems;
	tree->cap = newcap;

	return nil;
}

static fz_error *
loadnametreenode(pdf_nametree *tree, pdf_xref *xref, fz_obj *node)
{
	fz_error *error;
	fz_obj *names;
	fz_obj *kids;
	fz_obj *key;
	fz_obj *val;
	int i, len;

	error = pdf_resolve(&node, xref);
	if (error)
		return error;

	names = fz_dictgets(node, "Names");
	if (names)
	{
		error = pdf_resolve(&names, xref);
		if (error)
			goto cleanup;

		len = fz_arraylen(names) / 2;

		error = grownametree(tree, len);
		if (error)
		{
			fz_dropobj(names);
			goto cleanup;
		}

		for (i = 0; i < len; ++i)
		{
			key = fz_arrayget(names, i * 2 + 0);
			val = fz_arrayget(names, i * 2 + 1);

			tree->items[tree->len].k = fz_keepobj(key);
			tree->items[tree->len].v = fz_keepobj(val);
			tree->len ++;
		}

		fz_dropobj(names);
	}

	kids = fz_dictgets(node, "Kids");
	if (kids)
	{
		error = pdf_resolve(&kids, xref);
		if (error)
			goto cleanup;

		len = fz_arraylen(kids);
		for (i = 0; i < len; ++i)
		{
			error = loadnametreenode(tree, xref, fz_arrayget(kids, i));
			if (error)
			{
				fz_dropobj(kids);
				goto cleanup;
			}
		}

		fz_dropobj(kids);
	}

	fz_dropobj(node);
	return nil;

cleanup:
	fz_dropobj(node);
	return error;
}

void
pdf_dropnametree(pdf_nametree *tree)
{
	int i;
	for (i = 0; i < tree->len; i++)
	{
		fz_dropobj(tree->items[i].k);
		fz_dropobj(tree->items[i].v);
	}
	fz_free(tree->items);
	fz_free(tree);
}

fz_error *
pdf_loadnametree(pdf_nametree **treep, pdf_xref *xref, fz_obj *root)
{
	fz_error *error;
	pdf_nametree *tree;

	tree = fz_malloc(sizeof(pdf_nametree));
	if (!tree)
		return fz_outofmem;

	tree->len = 0;
	tree->cap = 0;
	tree->items = nil;

	error = loadnametreenode(tree, xref, root);
	if (error)
	{
		pdf_dropnametree(tree);
		return error;
	}

	*treep = tree;
	return nil;
}

void
pdf_debugnametree(pdf_nametree *tree)
{
	int i;
	for (i = 0; i < tree->len; i++) {
		printf("   ");
		fz_debugobj(tree->items[i].k);
		printf("   ");
		fz_debugobj(tree->items[i].v);
		printf("\n");
	}
}

static fz_obj *
lookup(pdf_nametree *tree, char *namestr, int namelen)
{
	int l = 0;
	int r = tree->len - 1;

	while (l <= r)
	{
		int m = (l + r) >> 1;
		char *keystr = fz_tostringbuf(tree->items[m].k);
		int keylen = fz_tostringlen(tree->items[m].k);
		int cmplen = MIN(namelen, keylen);
		int c = strncmp(namestr, keystr, cmplen);
		if (c < 0)
			r = m - 1;
		else if (c > 0)
			l = m + 1;
		else
			return tree->items[m].v;
	}

	return nil;
}

fz_obj *
pdf_lookupname(pdf_nametree *tree, fz_obj *name)
{
	return lookup(tree, fz_tostringbuf(name), fz_tostringlen(name));
}

fz_obj *
pdf_lookupnames(pdf_nametree *tree, char *name)
{
	return lookup(tree, name, strlen(name));
}

fz_error *
pdf_loadnametrees(pdf_xref *xref)
{
	fz_error *error;
	fz_obj *catalog;
	fz_obj *names;
	fz_obj *dests;

	catalog = fz_dictgets(xref->trailer, "Root");
	error = pdf_resolve(&catalog, xref);
	if (error)
		return error;

	names = fz_dictgets(catalog, "Names");
	if (names)
	{
		error = pdf_resolve(&names, xref);
		if (error)
		{
			fz_dropobj(names);
			fz_dropobj(catalog);
			return error;
		}

		dests = fz_dictgets(names, "Dests");
		error = pdf_loadnametree(&xref->dests, xref, dests);
		if (error)
		{
			fz_dropobj(names);
			fz_dropobj(catalog);
			return error;
		}

		fz_dropobj(names);
	}

	fz_dropobj(catalog);
	return nil;
}

