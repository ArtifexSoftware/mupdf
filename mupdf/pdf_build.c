#include "fitz.h"
#include "mupdf.h"

void
pdf_initgstate(pdf_gstate *gs, fz_matrix ctm)
{
	gs->ctm = ctm;
	gs->clipdepth = 0;

	gs->linewidth = 1.0;
	gs->linecap = 0;
	gs->linejoin = 0;
	gs->miterlimit = 10;
	gs->dashphase = 0;
	gs->dashlen = 0;
	memset(gs->dashlist, 0, sizeof(gs->dashlist));

	gs->stroke.kind = PDF_MCOLOR;
	gs->stroke.cs = fz_keepcolorspace(pdf_devicegray);
	gs->stroke.v[0] = 0;
	gs->stroke.indexed = nil;
	gs->stroke.pattern = nil;
	gs->stroke.shade = nil;
	gs->stroke.parentalpha = 1.0;
	gs->stroke.alpha = 1.0;

	gs->fill.kind = PDF_MCOLOR;
	gs->fill.cs = fz_keepcolorspace(pdf_devicegray);
	gs->fill.v[0] = 0;
	gs->fill.indexed = nil;
	gs->fill.pattern = nil;
	gs->fill.shade = nil;
	gs->fill.parentalpha = 1.0;
	gs->fill.alpha = 1.0;

	gs->blendmode = FZ_BNORMAL;

	gs->charspace = 0;
	gs->wordspace = 0;
	gs->scale = 1;
	gs->leading = 0;
	gs->font = nil;
	gs->size = -1;
	gs->render = 0;
	gs->rise = 0;
}

void
pdf_setcolorspace(pdf_csi *csi, int what, fz_colorspace *cs)
{
	pdf_gstate *gs = csi->gstate + csi->gtop;
	pdf_material *mat;

	pdf_flushtext(csi);

	mat = what == PDF_MFILL ? &gs->fill : &gs->stroke;

	fz_dropcolorspace(mat->cs);

	mat->kind = PDF_MCOLOR;
	mat->cs = fz_keepcolorspace(cs);

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
}

void
pdf_setcolor(pdf_csi *csi, int what, float *v)
{
	pdf_gstate *gs = csi->gstate + csi->gtop;
	pdf_indexed *ind;
	pdf_material *mat;
	int i, k;

	pdf_flushtext(csi);

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
		fz_warn("color incompatible with material");
	}
}

void
pdf_setpattern(pdf_csi *csi, int what, pdf_pattern *pat, float *v)
{
	pdf_gstate *gs = csi->gstate + csi->gtop;
	pdf_material *mat;

	pdf_flushtext(csi);

	mat = what == PDF_MFILL ? &gs->fill : &gs->stroke;

	if (mat->pattern)
		pdf_droppattern(mat->pattern);

	mat->kind = PDF_MPATTERN;
	if (pat)
		mat->pattern = pdf_keeppattern(pat);
	else
		mat->pattern = nil;

	if (v)
		pdf_setcolor(csi, what, v);
}

void
pdf_setshade(pdf_csi *csi, int what, fz_shade *shade)
{
	pdf_gstate *gs = csi->gstate + csi->gtop;
	pdf_material *mat;

	pdf_flushtext(csi);

	mat = what == PDF_MFILL ? &gs->fill : &gs->stroke;

	if (mat->shade)
		fz_dropshade(mat->shade);

	mat->kind = PDF_MSHADE;
	mat->shade = fz_keepshade(shade);
}

void
pdf_showpattern(pdf_gstate *gs, pdf_pattern *pat, fz_colorspace *cs, float *v)
{
	fz_matrix ctm;
	fz_matrix ptm;
	fz_rect bbox;
	int x, y, x0, y0, x1, y1;

	/* patterns are painted in user space */
	ctm = gs->ctm;
	ptm = fz_concat(pat->matrix, fz_invertmatrix(ctm));

	/* get bbox of shape in pattern space for stamping */
	ptm = fz_concat(ctm, fz_invertmatrix(pat->matrix));
	//XXX	bbox = fz_boundnode(shape, ptm);

	/* expand bbox by pattern bbox */
	bbox.x0 += pat->bbox.x0;
	bbox.y0 += pat->bbox.y0;
	bbox.x1 += pat->bbox.x1;
	bbox.y1 += pat->bbox.y1;

	x0 = fz_floor(bbox.x0 / pat->xstep);
	y0 = fz_floor(bbox.y0 / pat->ystep);
	x1 = fz_ceil(bbox.x1 / pat->xstep);
	y1 = fz_ceil(bbox.y1 / pat->ystep);

	for (y = y0; y <= y1; y++)
	{
		for (x = x0; x <= x1; x++)
		{
			ptm = fz_translate(x * pat->xstep, y * pat->ystep);
			// TODO paint the pattern contents with the ptm
		}
	}

	if (pat->ismask)
	{
		// TODO clip
	}
}

void
pdf_showshade(pdf_csi *csi, fz_shade *shd)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	csi->dev->drawshade(csi->dev->user, shd, gstate->ctm);
}

void
pdf_showimage(pdf_csi *csi, pdf_image *img)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	csi->dev->drawimage(csi->dev->user, (fz_image*)img, gstate->ctm);
}

void
pdf_showpath(pdf_csi *csi, int doclose, int dofill, int dostroke, int evenodd)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	int i;

	if (doclose)
		fz_closepath(csi->path);

	csi->path->ctm = gstate->ctm;
	csi->path->winding = evenodd ? FZ_EVENODD : FZ_NONZERO;
	csi->path->linewidth = gstate->linewidth;
	csi->path->linecap = gstate->linecap;
	csi->path->linejoin = gstate->linejoin;
	csi->path->miterlimit = gstate->miterlimit;
	csi->path->dashlen = gstate->dashlen;
	csi->path->dashphase = gstate->dashphase;
	for (i = 0; i < csi->path->dashlen; i++)
		csi->path->dashlist[i] = gstate->dashlist[i];

	if (csi->clip)
	{
		gstate->clipdepth++;
		csi->dev->clippath(csi->dev->user, csi->path);
		csi->clip = 0;
	}

	if (dofill)
	{
		switch (gstate->fill.kind)
		{
		case PDF_MNONE:
			break;
		case PDF_MCOLOR:
		case PDF_MINDEXED:
		case PDF_MLAB:
			csi->dev->fillpath(csi->dev->user, csi->path,
				gstate->fill.cs, gstate->fill.v, gstate->fill.alpha);
			break;
		case PDF_MPATTERN:
			printf("pattern fills not supported yet\n");
			break;
		case PDF_MSHADE:
			csi->dev->clippath(csi->dev->user, csi->path);
			csi->dev->drawshade(csi->dev->user, gstate->fill.shade, gstate->ctm);
			csi->dev->popclip(csi->dev->user);
			break;
		}
	}

	if (dostroke)
	{
		// TODO: indexed, pattern, shade materials
		csi->dev->strokepath(csi->dev->user, csi->path,
			gstate->stroke.cs, gstate->stroke.v, gstate->stroke.alpha);
	}

	fz_resetpath(csi->path);
}

/*
 * Text
 */

void
pdf_flushtext(pdf_csi *csi)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	int dofill = 0;
	int dostroke = 0;
	int doclip = 0;
	int doinvisible = 0;

	if (!csi->text)
		return;

	csi->text->ctm = gstate->ctm;

	switch (csi->textmode)
	{
	case 0:
		dofill = 1;
		break;
	case 1:
		dostroke = 1;
		break;
	case 2:
		dofill = 1;
		dostroke = 1;
		break;
	case 3:
		doinvisible = 1;
		break;
	case 4:
		dofill = 1;
		doclip = 1;
		break;
	case 5:
		dostroke = 1;
		doclip = 1;
		break;
	case 6:
		dofill = 1;
		dostroke = 1;
		doclip = 1;
		break;
	case 7:
		doclip = 1;
		break;
	}

	if (doinvisible)
		csi->dev->ignoretext(csi->dev->user, csi->text);

	if (doclip)
	{
		gstate->clipdepth++;
		csi->dev->cliptext(csi->dev->user, csi->text);
	}

	if (dofill)
	{
		// TODO: indexed, pattern, shade materials
		csi->dev->filltext(csi->dev->user, csi->text,
			gstate->fill.cs, gstate->fill.v, gstate->fill.alpha);
	}

	if (dostroke)
	{
		// TODO: indexed, pattern, shade materials
		csi->dev->stroketext(csi->dev->user, csi->text,
			gstate->stroke.cs, gstate->stroke.v, gstate->stroke.alpha);
	}

	fz_freetext(csi->text);
	csi->text = nil;
}

static void
pdf_showglyph(pdf_csi *csi, int cid)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	pdf_fontdesc *fontdesc = gstate->font;
	fz_matrix tsm, trm;
	float w0, w1, tx, ty;
	pdf_hmtx h;
	pdf_vmtx v;
	int gid;
	int ucs;

	tsm.a = gstate->size * gstate->scale;
	tsm.b = 0;
	tsm.c = 0;
	tsm.d = gstate->size;
	tsm.e = 0;
	tsm.f = gstate->rise;

	if (fontdesc->tounicode)
		ucs = pdf_lookupcmap(fontdesc->tounicode, cid);
	else if (cid < fontdesc->ncidtoucs)
		ucs = fontdesc->cidtoucs[cid];
	else
		ucs = '?';

	gid = pdf_fontcidtogid(fontdesc, cid);

	if (fontdesc->wmode == 1)
	{
		v = pdf_getvmtx(fontdesc, cid);
		tsm.e -= v.x * gstate->size / 1000.0;
		tsm.f -= v.y * gstate->size / 1000.0;
	}

	trm = fz_concat(tsm, csi->tm);

	/* flush buffered text if face or matrix or rendermode has changed */
	if (!csi->text ||
		(fontdesc->font) != csi->text->font ||
		fabs(trm.a - csi->text->trm.a) > FLT_EPSILON ||
		fabs(trm.b - csi->text->trm.b) > FLT_EPSILON ||
		fabs(trm.c - csi->text->trm.c) > FLT_EPSILON ||
		fabs(trm.d - csi->text->trm.d) > FLT_EPSILON ||
		gstate->render != csi->textmode)
	{
		pdf_flushtext(csi);

		csi->text = fz_newtext(fontdesc->font);
		csi->text->trm = trm;
		csi->text->trm.e = 0;
		csi->text->trm.f = 0;
		csi->textmode = gstate->render;
	}

	/* add glyph to textobject */
	fz_addtext(csi->text, gid, ucs, trm.e, trm.f);

	if (fontdesc->wmode == 0)
	{
		h = pdf_gethmtx(fontdesc, cid);
		w0 = h.w / 1000.0;
		tx = (w0 * gstate->size + gstate->charspace) * gstate->scale;
		csi->tm = fz_concat(fz_translate(tx, 0), csi->tm);
	}

	if (fontdesc->wmode == 1)
	{
		w1 = v.w / 1000.0;
		ty = w1 * gstate->size + gstate->charspace;
		csi->tm = fz_concat(fz_translate(0, ty), csi->tm);
	}
}

static void
pdf_showspace(pdf_csi *csi, float tadj)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	pdf_fontdesc *fontdesc = gstate->font;
	if (fontdesc->wmode == 0)
		csi->tm = fz_concat(fz_translate(tadj * gstate->scale, 0), csi->tm);
	else
		csi->tm = fz_concat(fz_translate(0, tadj), csi->tm);
}

void
pdf_showtext(pdf_csi *csi, fz_obj *text)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	pdf_fontdesc *fontdesc = gstate->font;
	unsigned char *buf;
	unsigned char *end;
	int i, len;
	int cpt, cid;

	if (!fontdesc)
	{
		fz_warn("cannot draw text since font and size not set");
		return;
	}

	if (fz_isarray(text))
	{
		for (i = 0; i < fz_arraylen(text); i++)
		{
			fz_obj *item = fz_arrayget(text, i);
			if (fz_isstring(item))
				pdf_showtext(csi, item);
			else
				pdf_showspace(csi, - fz_toreal(item) * gstate->size / 1000.0);
		}
	}

	if (fz_isstring(text))
	{
		buf = (unsigned char *)fz_tostrbuf(text);
		len = fz_tostrlen(text);
		end = buf + len;

		while (buf < end)
		{
			buf = pdf_decodecmap(fontdesc->encoding, buf, &cpt);
			cid = pdf_lookupcmap(fontdesc->encoding, cpt);
			if (cid == -1)
				cid = 0;

			pdf_showglyph(csi, cid);

			if (cpt == 32)
				pdf_showspace(csi, gstate->wordspace);
		}
	}
}
