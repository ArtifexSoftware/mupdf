#include <fitz.h>
#include <mupdf.h>

#define GCMEM (4 * 1024)

extern pdf_font *pdf_newfont(char *name);

static void
t3dropfont(fz_font *font)
{
	int i;
	pdf_font *pfont = (pdf_font*)font;
	if (pfont->encoding)
		fz_dropcmap(pfont->encoding);
	for (i = 0; i < 256; i++)
		if (pfont->charprocs[i])
			fz_droptree(pfont->charprocs[i]);
}

static fz_error *
t3render(fz_glyph *glyph, fz_font *fzfont, int cid, fz_matrix trm)
{
	pdf_font *font = (pdf_font*)fzfont;
	fz_error *error;
	fz_renderer *gc;
	fz_tree *tree;
	fz_pixmap *pixmap;
	fz_matrix ctm;
	fz_irect bbox;
	int i;

	if (cid < 0 || cid > 255)
		return fz_throw("rangecheck: glyph out of range");

	tree = font->charprocs[cid];
	if (!tree)
	{
		glyph->w = 0;
		glyph->h = 0;
		return nil;
	}

	ctm = fz_concat(font->matrix, trm);
	bbox = fz_roundrect(fz_boundtree(tree, ctm));

	error = fz_newrenderer(&gc, nil, GCMEM);
	if (error)
		return error;
	error = fz_rendertree(&pixmap, gc, tree, ctm, bbox, 0);
	fz_droprenderer(gc);
	if (error)
		return error;

	assert(pixmap->n == 1);

	glyph->lsb = pixmap->x;
	glyph->top = pixmap->h + pixmap->y;
	glyph->w = pixmap->w;
	glyph->h = pixmap->h;
	glyph->bitmap = pixmap->samples;

	unsigned char tmp[pixmap->w * pixmap->h];
	memcpy(tmp, pixmap->samples, pixmap->w * pixmap->h);

	for (i = 0; i < pixmap->h; i++)
	{
		memcpy(	pixmap->samples + i * pixmap->w,
				tmp + (pixmap->h - i - 1) * pixmap->w,
				pixmap->w );
	}

	/* XXX flip bitmap in ftrender instead; free pixmap */

	return nil;
}

static fz_error *
loadcharproc(fz_tree **treep, pdf_xref *xref, fz_obj *rdb, fz_obj *stmref)
{
	fz_error *error;
	pdf_csi *csi;

	error = pdf_newcsi(&csi, 1);

	error = pdf_openstream(xref, fz_tonum(stmref), fz_togen(stmref));
	if (error)
		return error;

	error = pdf_runcsi(csi, xref, rdb, xref->stream);

	pdf_closestream(xref);

	*treep = csi->tree;
	csi->tree = nil;

	pdf_dropcsi(csi);

	return error;
}

fz_error *
pdf_loadtype3font(pdf_font **fontp, pdf_xref *xref, fz_obj *dict)
{
	fz_error *error;
	char buf[256];
	char *estrings[256];
	pdf_font *font;
	fz_obj *encoding;
	fz_obj *widths;
	fz_obj *resources;
	fz_obj *charprocs;
	fz_obj *obj;
	int first, last;
	int i, k, n;

	obj = fz_dictgets(dict, "Name");
	if (obj)
		strlcpy(buf, fz_toname(obj), sizeof buf);
	else
		sprintf(buf, "Unnamed-T3");

printf("loading type3 font %s\n", buf);

	font = pdf_newfont(buf);
	if (!font)
		return fz_outofmem;

	font->super.render = t3render;
	font->super.drop = (void(*)(fz_font*)) t3dropfont;

	obj = fz_dictgets(dict, "FontMatrix");
	font->matrix.a = fz_toreal(fz_arrayget(obj, 0));
	font->matrix.b = fz_toreal(fz_arrayget(obj, 1));
	font->matrix.c = fz_toreal(fz_arrayget(obj, 2));
	font->matrix.d = fz_toreal(fz_arrayget(obj, 3));
	font->matrix.e = fz_toreal(fz_arrayget(obj, 4));
	font->matrix.f = fz_toreal(fz_arrayget(obj, 5));

printf("  matrix [%g %g %g %g %g %g]\n",
	font->matrix.a, font->matrix.b,
	font->matrix.c, font->matrix.d,
	font->matrix.e, font->matrix.f);

	/* TODO: scale bbox by fontmatrix * 1000 */
	obj = fz_dictgets(dict, "FontBBox");
	fz_setfontbbox((fz_font*)font,
		fz_toreal(fz_arrayget(obj, 0)),
		fz_toreal(fz_arrayget(obj, 1)),
		fz_toreal(fz_arrayget(obj, 2)),
		fz_toreal(fz_arrayget(obj, 3)));

	/*
	 * Encoding
	 */

	for (i = 0; i < 256; i++)
		estrings[i] = nil;

	encoding = fz_dictgets(dict, "Encoding");
	if (!encoding) {
		error = fz_throw("syntaxerror: Type3 font missing Encoding");
		goto cleanup;
	}

	error = pdf_resolve(&encoding, xref);
	if (error)
		goto cleanup;

	if (fz_isname(obj))
		pdf_loadencoding(estrings, fz_toname(encoding));

	if (fz_isdict(encoding))
	{
		fz_obj *base, *diff, *item;

		base = fz_dictgets(encoding, "BaseEncoding");
		if (fz_isname(base))
			pdf_loadencoding(estrings, fz_toname(base));

		diff = fz_dictgets(encoding, "Differences");
		if (fz_isarray(diff))
		{
			n = fz_arraylen(diff);
			k = 0;
			for (i = 0; i < n; i++)
			{
				item = fz_arrayget(diff, i);
				if (fz_isint(item))
					k = fz_toint(item);
				if (fz_isname(item))
					estrings[k++] = fz_toname(item);
				if (k < 0) k = 0;
				if (k > 255) k = 255;
			}
		}
	}

	fz_dropobj(encoding);

	error = pdf_makeidentitycmap(&font->encoding, 0, 1);
	if (error)
		goto cleanup;

	error = pdf_loadtounicode(font, xref,
				estrings, nil, fz_dictgets(dict, "ToUnicode"));
	if (error)
		goto cleanup;

	/*
	 * Widths
	 */

	fz_setdefaulthmtx((fz_font*)font, 0);

	first = fz_toint(fz_dictgets(dict, "FirstChar"));
	last = fz_toint(fz_dictgets(dict, "LastChar"));

	widths = fz_dictgets(dict, "Widths");
	if (!widths) {
		error = fz_throw("syntaxerror: Type3 font missing Widths");
		goto cleanup;
	}

	error = pdf_resolve(&widths, xref);
	if (error)
		goto cleanup;

	for (i = first; i <= last; i++)
	{
		float w = fz_toreal(fz_arrayget(widths, i - first));
		w = font->matrix.a * w * 1000.0;
		error = fz_addhmtx((fz_font*)font, i, i, w);
		if (error) {
			fz_dropobj(widths);
			goto cleanup;
		}
	}

	fz_dropobj(widths);

	error = fz_endhmtx((fz_font*)font);
	if (error)
		goto cleanup;

	/*
	 * Resources
	 */

	resources = nil;

	obj = fz_dictgets(dict, "Resources");
	if (obj)
	{
		error = pdf_resolve(&obj, xref);
		if (error)
			goto cleanup;

		error = pdf_loadresources(&resources, xref, obj);

		fz_dropobj(obj);

		if (error)
			goto cleanup;
	}

	/*
	 * CharProcs
	 */

	charprocs = fz_dictgets(dict, "CharProcs");
	if (!charprocs)
	{
		error = fz_throw("syntaxerror: Type3 font missing CharProcs");
		goto cleanup2;
	}

	error = pdf_resolve(&charprocs, xref);
	if (error)
		goto cleanup2;

	for (i = 0; i < 256; i++)
	{
		if (estrings[i])
		{
			obj = fz_dictgets(charprocs, estrings[i]);
			if (obj)
			{
				error = loadcharproc(&font->charprocs[i], xref, resources, obj);
				if (error)
					goto cleanup2;
			}
		}
	}

	fz_dropobj(charprocs);
	if (resources)
		fz_dropobj(resources);

	*fontp = font;
	return nil;

cleanup2:
	fz_dropobj(resources);
cleanup:
	fz_dropfont((fz_font*)font);
	return error;
}

