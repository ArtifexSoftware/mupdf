#include <fitz.h>
#include <mupdf.h>

extern int FT_Get_Char_Index(void*, int);

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

	gs->stroke.r = 0;
	gs->stroke.g = 0;
	gs->stroke.b = 0;

	gs->fill.r = 0;
	gs->fill.g = 0;
	gs->fill.b = 0;

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
pdf_buildstrokepath(pdf_gstate *gs, fz_path *path)
{
	fz_error *error;
	fz_stroke *stroke;
	fz_dash *dash;

	stroke = fz_malloc(sizeof(fz_stroke));
	if (!stroke)
		return fz_outofmem;
	stroke->linecap = gs->linecap;
	stroke->linejoin = gs->linejoin;
	stroke->linewidth = gs->linewidth;
	stroke->miterlimit = gs->miterlimit;

	if (gs->dashlen)
	{
		error = fz_newdash(&dash, gs->dashphase, gs->dashlen, gs->dashlist);
		if (error) {
			fz_free(stroke);
			return error;
		}
	}
	else
	{
		dash = nil;
	}

	error = fz_endpath(path, FZ_STROKE, stroke, dash);
	if (error) {
		fz_freedash(dash);
		fz_free(stroke);
		return error;
	}

	return nil;
}

fz_error *
pdf_buildfillpath(pdf_gstate *gs, fz_path *path, int eofill)
{
	return fz_endpath(path, eofill ? FZ_EOFILL : FZ_FILL, nil, nil);
}

static fz_error *
addcolorshape(pdf_gstate *gs, fz_node *shape, float r, float g, float b)
{
	fz_error *error;
	fz_node *mask;
	fz_node *solid;

	error = fz_newmask(&mask);
	if (error) return error;

	error = fz_newsolid(&solid, r, g, b);
	if (error) return error;

	fz_insertnode(mask, shape);
	fz_insertnode(mask, solid);
	fz_insertnode(gs->head, mask);

	return nil;
}

fz_error *
pdf_addfillshape(pdf_gstate *gs, fz_node *shape)
{
	return addcolorshape(gs, shape, gs->fill.r, gs->fill.g, gs->fill.b);
}

fz_error *
pdf_addstrokeshape(pdf_gstate *gs, fz_node *shape)
{
	return addcolorshape(gs, shape, gs->stroke.r, gs->stroke.g, gs->stroke.b);
}

fz_error *
pdf_addclipmask(pdf_gstate *gs, fz_node *shape)
{
	fz_error *error;
	fz_node *mask;
	fz_node *over;

	error = fz_newmask(&mask);
	if (error) return error;

	error = fz_newover(&over);
	if (error) return error;

	fz_insertnode(mask, shape);
	fz_insertnode(mask, over);
	fz_insertnode(gs->head, mask);
	gs->head = over;

	return nil;
}

fz_error *
pdf_addtransform(pdf_gstate *gs, fz_node *affine)
{
	fz_error *error;
	fz_node *over;

	error = fz_newover(&over);
	if (error) return error;

	fz_insertnode(gs->head, affine);
	fz_insertnode(affine, over);
	gs->head = over;

	return nil;
}

fz_error *
pdf_showpath(pdf_csi *csi,
	int doclose, int dofill, int dostroke, int evenodd)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	fz_error *error;
	fz_path *spath;
	fz_path *fpath;

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

	error = fz_newpath(&csi->path);
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
		error = pdf_addfillshape(gstate, (fz_node*)csi->text);
		if (error)
			return error;
		csi->text = nil;
	}

	return nil;
}

fz_error *
showglyph(pdf_csi *csi, int g)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	pdf_font *font = gstate->font;
	fz_error *error;
	fz_matrix tsm, trm, tm;
	float w0, w1, tx, ty;
	fz_hmtx h;
	fz_vmtx v;

	tsm.a = gstate->size * gstate->scale;
	tsm.b = 0;
	tsm.c = 0;
	tsm.d = gstate->size;
	tsm.e = 0;
	tsm.f = gstate->rise;

	tm = csi->tm;

	if (font->super.wmode == 1)
	{
		v = fz_getvmtx((fz_font*)font, g);
		tm.e -= v.x * gstate->size / 1000.0;
		tm.f += v.y * gstate->size / 1000.0;
	}

	trm = fz_concat(tsm, tm);

	/* flush buffered text if face or matrix has changed */
	if (!csi->text ||
		((fz_font*)font) != csi->text->font ||
		fabs(trm.a - csi->text->trm.a) > FLT_EPSILON ||
		fabs(trm.b - csi->text->trm.b) > FLT_EPSILON ||
		fabs(trm.c - csi->text->trm.c) > FLT_EPSILON ||
		fabs(trm.d - csi->text->trm.d) > FLT_EPSILON)
	{
		error = pdf_flushtext(csi);
		if (error) return error;

		error = fz_newtext(&csi->text, (fz_font*)font);
		if (error) return error;

		csi->text->trm = trm;
		csi->text->trm.e = 0;
		csi->text->trm.f = 0;
	}

	/* add glyph to textobject */
	error = fz_addtext(csi->text, g, trm.e, trm.f);
	if (error)
		return error;

	if (font->super.wmode == 0)
	{
		h = fz_gethmtx((fz_font*)font, g);
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
	int cpt, cid, gid;

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

		if (font->cidtogidmap)
		{
			if (cid >= 0 && cid < font->cidtogidlen)
				gid = font->cidtogidmap[cid];
			else
				gid = 0;
		}
		else
		{
			gid = cid;
		}

//printf("gl %s %g [%g %g %g %g %g %g] cpt<%02x> cid %d gid %d h %d\n",
//	font->super.name, size,
//	csi->tm.a, csi->tm.b, csi->tm.c, csi->tm.d, csi->tm.e, csi->tm.f,
//	cpt, cid, gid, font->super.hadv[gid]);

		error = showglyph(csi, gid);
		if (error)
			return error;

		if (cpt == 32)
			showspace(csi, gstate->wordspace);
	}

	return nil;
}

