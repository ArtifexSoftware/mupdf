#include <fitz.h>
#include <mupdf.h>

void
pdf_initgstate(pdf_gstate *gs)
{
	gs->linewidth = 1.0;
	gs->linecap = 0;
	gs->linejoin = 0;
	gs->miterlimit = 10;
	gs->dashphase = 0;
	gs->dashlen = 0;
	memset(gs->dashlist, 0, sizeof(gs->dashlist));

	gs->stroke.kind = PDF_MCOLOR;
	gs->stroke.cs = pdf_devicegray;
	gs->stroke.v[0] = 0;

	gs->fill.kind = PDF_MCOLOR;
	gs->fill.cs = pdf_devicegray;
	gs->fill.v[0] = 0;

	gs->charspace = 0;
	gs->wordspace = 0;
	gs->scale = 1;
	gs->leading = 0;
	gs->font = nil;
	gs->size = -1;
	gs->render = 0;
	gs->rise = 0;

	gs->head = nil;
}

fz_error *
pdf_setcolorspace(pdf_csi *csi, int what, fz_colorspace *cs)
{
	pdf_gstate *gs = csi->gstate + csi->gtop;
	fz_error *error;
	pdf_material *mat;

	error = pdf_flushtext(csi);
	if (error)
		return error;

	mat = what == PDF_MFILL ? &gs->fill : &gs->stroke;

	mat->kind = PDF_MCOLOR;
	mat->cs = cs;

	mat->v[0] = 0;	/* FIXME: default color */
	mat->v[1] = 0;	/* FIXME: default color */
	mat->v[2] = 0;	/* FIXME: default color */
	mat->v[3] = 1;	/* FIXME: default color */

	if (!strcmp(cs->name, "Indexed"))
	{
		mat->kind = PDF_MINDEXED;
		mat->indexed = (pdf_indexed*)cs;
		mat->cs = mat->indexed->base;
	}

	if (!strcmp(cs->name, "Lab"))
		mat->kind = PDF_MLAB;

	return nil;
}

fz_error *
pdf_setcolor(pdf_csi *csi, int what, float *v)
{
	pdf_gstate *gs = csi->gstate + csi->gtop;
	fz_error *error;
	pdf_indexed *ind;
	pdf_material *mat;
	int i, k;

	error = pdf_flushtext(csi);
	if (error)
		return error;

	mat = what == PDF_MFILL ? &gs->fill : &gs->stroke;

	switch (mat->kind)
	{
	case PDF_MPATTERN:
		if (!strcmp(mat->cs->name, "Lab"))
			goto Llab;
		if (!strcmp(mat->cs->name, "Indexed"))
			goto Lindexed;
		/* fall through */

	case PDF_MCOLOR:
		for (i = 0; i < mat->cs->n; i++)
			mat->v[i] = v[i];
		break;

	case PDF_MLAB:
Llab:
		mat->v[0] = v[0] / 100.0;
		mat->v[1] = (v[1] + 100) / 200.0;
		mat->v[2] = (v[2] + 100) / 200.0;
		break;

	case PDF_MINDEXED:
Lindexed:
		ind = mat->indexed;
		i = CLAMP(v[0], 0, ind->high);
		for (k = 0; k < ind->base->n; k++)
			mat->v[k] = ind->lookup[ind->base->n * i + k] / 255.0;
		break;

	default:
		return fz_throw("syntaxerror: color not compatible with material");
	}

	return nil;
}

fz_error *
pdf_setpattern(pdf_csi *csi, int what, pdf_pattern *pat, float *v)
{
	pdf_gstate *gs = csi->gstate + csi->gtop;
	fz_error *error;
	pdf_material *mat;

	error = pdf_flushtext(csi);
	if (error)
		return error;

	mat = what == PDF_MFILL ? &gs->fill : &gs->stroke;

	mat->kind = PDF_MPATTERN;
	mat->pattern = pat;

	if (v)
		return pdf_setcolor(csi, what, v);

	return nil;
}

fz_error *
pdf_buildstrokepath(pdf_gstate *gs, fz_pathnode *path)
{
	fz_error *error;
	fz_stroke stroke;
	fz_dash *dash;

	stroke.linecap = gs->linecap;
	stroke.linejoin = gs->linejoin;
	stroke.linewidth = gs->linewidth;
	stroke.miterlimit = gs->miterlimit;

	if (gs->dashlen)
	{
		error = fz_newdash(&dash, gs->dashphase, gs->dashlen, gs->dashlist);
		if (error)
			return error;
	}
	else
		dash = nil;

	error = fz_endpath(path, FZ_STROKE, &stroke, dash);
	if (error) {
		fz_dropdash(dash);
		return error;
	}

	return nil;
}

fz_error *
pdf_buildfillpath(pdf_gstate *gs, fz_pathnode *path, int eofill)
{
	return fz_endpath(path, eofill ? FZ_EOFILL : FZ_FILL, nil, nil);
}

static fz_error *
addcolorshape(pdf_gstate *gs, fz_node *shape, fz_colorspace *cs, float *v)
{
	fz_error *error;
	fz_node *mask;
	fz_node *solid;

	error = fz_newmasknode(&mask);
	if (error) return error;

	error = fz_newcolornode(&solid, cs, cs->n, v);
	if (error) return error;

	fz_insertnode(mask, shape);
	fz_insertnode(mask, solid);
	fz_insertnode(gs->head, mask);

	return nil;
}

static fz_error *
addinvisibleshape(pdf_gstate *gs, fz_node *shape)
{
	fz_error *error;
	fz_node *mask;
	fz_pathnode *path;

	error = fz_newmasknode(&mask);
	if (error) return error;

	error = fz_newpathnode(&path);
	if (error) return error;
	error = fz_endpath(path, FZ_FILL, nil, nil);
	if (error) return error;

	fz_insertnode(mask, (fz_node*)path);
	fz_insertnode(mask, shape);
	fz_insertnode(gs->head, mask);

	return nil;
}

static fz_matrix getmatrix(fz_node *node)
{
	if (node->parent)
	{
		fz_matrix ptm = getmatrix(node->parent);
		if (fz_istransformnode(node))
			return fz_concat(((fz_transformnode*)node)->m, ptm);
		return ptm;
	}
	if (fz_istransformnode(node))
		return ((fz_transformnode*)node)->m;
	return fz_identity();
}

static fz_error *
addpatternshape(pdf_gstate *gs, fz_node *shape,
	pdf_pattern *pat, fz_colorspace *cs, float *v)
{
	fz_error *error;
	fz_node *xform;
	fz_node *over;
	fz_node *mask;
	fz_node *link;
	fz_matrix ctm;
	fz_matrix inv;
	fz_matrix ptm;
	fz_rect bbox;
	int x, y, x0, y0, x1, y1;

	/* patterns are painted in user space */
	ctm = getmatrix(gs->head);
	inv = fz_invertmatrix(ctm);

	error = fz_newmasknode(&mask);
	if (error) return error;

	ptm = fz_concat(pat->matrix, fz_invertmatrix(ctm));
	error = fz_newtransformnode(&xform, ptm);
	if (error) return error;

	error = fz_newovernode(&over);
	if (error) return error;

	fz_insertnode(mask, shape);
	fz_insertnode(mask, xform);
	fz_insertnode(xform, over);

	/* get bbox of shape in pattern space for stamping */
	ptm = fz_concat(ctm, fz_invertmatrix(pat->matrix));
	bbox = fz_boundnode(shape, ptm);

	/* expand bbox by pattern bbox */
	bbox.min.x += pat->bbox.min.x;
	bbox.min.y += pat->bbox.min.y;
	bbox.max.x += pat->bbox.max.x;
	bbox.max.y += pat->bbox.max.y;

printf("stamping pattern [%g %g] over [%g %g %g %g]\n",
	pat->xstep, pat->ystep,
	bbox.min.x, bbox.min.y,
	bbox.max.x, bbox.max.y);

	x0 = fz_floor(bbox.min.x / pat->xstep);
	y0 = fz_floor(bbox.min.y / pat->ystep);
	x1 = fz_ceil(bbox.max.x / pat->xstep);
	y1 = fz_ceil(bbox.max.y / pat->ystep);

printf("  %d,%d to %d,%d\n", x0, y0, x1, y1);

	for (y = y0; y <= y1; y++)
	{
		for (x = x0; x <= x1; x++)
		{
			ptm = fz_translate(x * pat->xstep, y * pat->ystep);
			error = fz_newtransformnode(&xform, ptm);
			if (error) return error;
			error = fz_newlinknode(&link, pat->tree);
			if (error) return error;
			fz_insertnode(xform, link);
			fz_insertnode(over, xform);
		}
	}

	if (pat->ismask)
		return addcolorshape(gs, mask, cs, v);

	fz_insertnode(gs->head, mask);
	return nil;
}

fz_error *
pdf_addfillshape(pdf_gstate *gs, fz_node *shape)
{
	switch (gs->fill.kind)
	{
	case PDF_MNONE:
		fz_insertnode(gs->head, shape);
		return nil;
	case PDF_MCOLOR:
	case PDF_MLAB:
	case PDF_MINDEXED:
		return addcolorshape(gs, shape, gs->fill.cs, gs->fill.v);
	case PDF_MPATTERN:
		return addpatternshape(gs, shape, gs->fill.pattern, gs->fill.cs, gs->fill.v);
	default:
		return fz_throw("unimplemented material");
	}
}

fz_error *
pdf_addstrokeshape(pdf_gstate *gs, fz_node *shape)
{
	switch (gs->stroke.kind)
	{
	case PDF_MNONE:
		fz_insertnode(gs->head, shape);
		return nil;
	case PDF_MCOLOR:
	case PDF_MLAB:
	case PDF_MINDEXED:
		return addcolorshape(gs, shape, gs->stroke.cs, gs->stroke.v);
	case PDF_MPATTERN:
		return addpatternshape(gs, shape, gs->stroke.pattern, gs->stroke.cs, gs->stroke.v);
	default:
		return fz_throw("unimplemented material");
	}
}

fz_error *
pdf_addclipmask(pdf_gstate *gs, fz_node *shape)
{
	fz_error *error;
	fz_node *mask;
	fz_node *over;

	error = fz_newmasknode(&mask);
	if (error) return error;

	error = fz_newovernode(&over);
	if (error) return error;

	fz_insertnode(mask, shape);
	fz_insertnode(mask, over);
	fz_insertnode(gs->head, mask);
	gs->head = over;

	return nil;
}

fz_error *
pdf_addtransform(pdf_gstate *gs, fz_node *transform)
{
	fz_error *error;
	fz_node *over;

	error = fz_newovernode(&over);
	if (error) return error;

	fz_insertnode(gs->head, transform);
	fz_insertnode(transform, over);
	gs->head = over;

	return nil;
}

fz_error *
pdf_showimage(pdf_csi *csi, pdf_image *img)
{
	fz_error *error;
	fz_node *mask;
	fz_node *color;
	fz_node *shape;

	error = fz_newimagenode(&color, (fz_image*)img);
	if (error)
		return error;

	if (img->super.n == 0 && img->super.a == 1)
	{
		error = pdf_addfillshape(csi->gstate + csi->gtop, color);
		if (error) {
			fz_dropnode(color);
			return error;
		}
	}
	else
	{
		if (img->mask)
		{
			error = fz_newimagenode(&shape, (fz_image*)img->mask);
			if (error) return error;
			error = fz_newmasknode(&mask);
			if (error) return error;
			fz_insertnode(mask, shape);
			fz_insertnode(mask, color);
			fz_insertnode(csi->gstate[csi->gtop].head, mask);
		}
		else
		{
			fz_insertnode(csi->gstate[csi->gtop].head, color);
		}
	}

	return nil;
}

fz_error *
pdf_showpath(pdf_csi *csi,
	int doclose, int dofill, int dostroke, int evenodd)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	fz_error *error;
	fz_pathnode *spath;
	fz_pathnode *fpath;

	if (doclose)
	{
		error = fz_closepath(csi->path);
		if (error) return error;
	}

	if (dofill && dostroke)
	{
		fpath = csi->path;
		error = fz_clonepath(&spath, fpath);
		if (error) return error;
	}
	else
	{
		spath = fpath = csi->path;
	}

	if (dofill)
	{
		error = pdf_buildfillpath(gstate, fpath, evenodd);
		if (error) return error;
		error = pdf_addfillshape(gstate, (fz_node*)fpath);
		if (error) return error;
	}

	if (dostroke)
	{
		error = pdf_buildstrokepath(gstate, spath);
		if (error) return error;
		error = pdf_addstrokeshape(gstate, (fz_node*)spath);
		if (error) return error;
	}

	if (!dofill && !dostroke)
	{
		fz_free(csi->path);
	}

	if (csi->clip)
	{
		error = pdf_addclipmask(gstate, (fz_node*)csi->clip);
		if (error) return error;
		csi->clip = nil;
	}

	csi->path = nil;

	error = fz_newpathnode(&csi->path);
	if (error) return error;

	return nil;
}

fz_error *
pdf_flushtext(pdf_csi *csi)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	fz_error *error;

	if (csi->text)
	{

		/* invisible */
		switch (csi->textmode)
		{
		case 0:	/* fill */
		case 1:	/* stroke */
		case 2:	/* stroke + fill */
			error = pdf_addfillshape(gstate, (fz_node*)csi->text);
			if (error)
				return error;
			break;

		case 3:	/* invisible */
			error = addinvisibleshape(gstate, (fz_node*)csi->text);
			if (error)
				return error;
			break;

		case 4: /* fill + clip */
		case 5: /* stroke + clip */
		case 6: /* stroke + fill + clip */
		case 7: /* invisible clip */
			if (!csi->textclip)
			{
				error = fz_newovernode(&csi->textclip);
				if (error)
					return error;
			}
			fz_insertnode(csi->textclip, (fz_node*)csi->text);
			break;
		}

		csi->text = nil;
	}

	return nil;
}

fz_error *
showglyph(pdf_csi *csi, int cid)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	pdf_font *font = gstate->font;
	fz_error *error;
	fz_matrix tsm, trm;
	float w0, w1, tx, ty;
	fz_hmtx h;
	fz_vmtx v;

	tsm.a = gstate->size * gstate->scale;
	tsm.b = 0;
	tsm.c = 0;
	tsm.d = gstate->size;
	tsm.e = 0;
	tsm.f = gstate->rise;

	if (font->super.wmode == 1)
	{
		v = fz_getvmtx((fz_font*)font, cid);
		tsm.e -= v.x * gstate->size / 1000.0;
		tsm.f -= v.y * gstate->size / 1000.0;
	}

	trm = fz_concat(tsm, csi->tm);

	/* flush buffered text if face or matrix or rendermode has changed */
	if (!csi->text ||
		((fz_font*)font) != csi->text->font ||
		fabs(trm.a - csi->text->trm.a) > FLT_EPSILON ||
		fabs(trm.b - csi->text->trm.b) > FLT_EPSILON ||
		fabs(trm.c - csi->text->trm.c) > FLT_EPSILON ||
		fabs(trm.d - csi->text->trm.d) > FLT_EPSILON ||
		gstate->render != csi->textmode)
	{
		error = pdf_flushtext(csi);
		if (error) return error;

		error = fz_newtextnode(&csi->text, (fz_font*)font);
		if (error) return error;

		csi->text->trm = trm;
		csi->text->trm.e = 0;
		csi->text->trm.f = 0;
		csi->textmode = gstate->render;
	}

	/* add glyph to textobject */
	error = fz_addtext(csi->text, cid, trm.e, trm.f);
	if (error)
		return error;

	if (font->super.wmode == 0)
	{
		h = fz_gethmtx((fz_font*)font, cid);
		w0 = h.w / 1000.0;
		tx = (w0 * gstate->size + gstate->charspace) * gstate->scale;
		csi->tm = fz_concat(fz_translate(tx, 0), csi->tm);
	}
	else
	{
		w1 = v.w / 1000.0;
		ty = w1 * gstate->size + gstate->charspace;
		csi->tm = fz_concat(fz_translate(0, ty), csi->tm);
	}

	return nil;
}

void
showspace(pdf_csi *csi, float tadj)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	pdf_font *font = gstate->font;
	if (font->super.wmode == 0)
		csi->tm = fz_concat(fz_translate(tadj * gstate->scale, 0), csi->tm);
	else
		csi->tm = fz_concat(fz_translate(0, tadj), csi->tm);
}

fz_error *
pdf_showtext(pdf_csi *csi, fz_obj *text)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	pdf_font *font = gstate->font;
	fz_error *error;
	unsigned char *buf;
	unsigned char *end;
	int i, len;
	int cpt, cid;

	if (fz_isarray(text))
	{
		for (i = 0; i < fz_arraylen(text); i++)
		{
			fz_obj *item = fz_arrayget(text, i);
			if (fz_isstring(item))
			{
				error = pdf_showtext(csi, item);
				if (error) return error;
			}
			else
			{
				showspace(csi, - fz_toreal(item) * gstate->size / 1000.0);
			}
		}
		return nil;
	}

	buf = fz_tostringbuf(text);
	len = fz_tostringlen(text);
	end = buf + len;

	while (buf < end)
	{
		buf = fz_decodecpt(font->encoding, buf, &cpt);

		cid = fz_lookupcid(font->encoding, cpt);

		error = showglyph(csi, cid);
		if (error)
			return error;

		if (cpt == 32)
			showspace(csi, gstate->wordspace);
	}

	return nil;
}

