#include <fitz.h>
#include <mupdf.h>

fz_error *
pdf_newcsi(pdf_csi **csip)
{
	fz_error *error;
	pdf_csi *csi;
	fz_node *node;
	float white = 1.0;

	csi = *csip = fz_malloc(sizeof(pdf_csi));
	if (!csi)
		return fz_outofmem;

	pdf_initgstate(&csi->gstate[0]);

	csi->gtop = 0;
	csi->top = 0;

	csi->xbalance = 0;

	error = fz_newpathnode(&csi->path);
	if (error) {
		fz_free(csi);
		return error;
	}

	error = fz_newtree(&csi->tree);
	if (error) {
		fz_freenode((fz_node*)csi->path);
		fz_free(csi);
		return error;
	}

	error = fz_newovernode(&node);
	csi->tree->root = node;
	csi->gstate[0].head = node;

	error = fz_newcolornode(&node, pdf_devicegray, 1, &white);
	fz_insertnode(csi->tree->root, node);

	csi->clip = nil;

	csi->text = nil;
	csi->tm = fz_identity();
	csi->tlm = fz_identity();

	return nil;
}

static void
clearstack(pdf_csi *csi)
{
	int i;
	for (i = 0; i < csi->top; i++)
		fz_dropobj(csi->stack[i]);
	csi->top = 0;
}

void
pdf_freecsi(pdf_csi *csi)
{
	if (csi->path) fz_freenode((fz_node*)csi->path);
	if (csi->clip) fz_freenode((fz_node*)csi->clip);
	if (csi->text) fz_freenode((fz_node*)csi->text);
	clearstack(csi);
	fz_free(csi);
}

static fz_error *
runextgstate(pdf_gstate *gstate, pdf_xref *xref, fz_obj *extgstate)
{
	int i, k;

	for (i = 0; i < fz_dictlen(extgstate); i++)
	{
		fz_obj *key = fz_dictgetkey(extgstate, i);
		fz_obj *val = fz_dictgetval(extgstate, i);
		char *s = fz_toname(key);

		if (!strcmp(s, "Font"))
		{
			if (fz_isarray(val) && fz_arraylen(val) == 2)
			{
				gstate->font = pdf_findresource(xref->rfont, fz_arrayget(val, 0));
				if (!gstate->font)
					return fz_throw("syntaxerror: missing font resource");
				gstate->size = fz_toreal(fz_arrayget(val, 1));
			}
			else
				return fz_throw("syntaxerror in ExtGState/Font");
		}

		else if (!strcmp(s, "LW"))
			gstate->linewidth = fz_toreal(val);
		else if (!strcmp(s, "LC"))
			gstate->linecap = fz_toint(val);
		else if (!strcmp(s, "LJ"))
			gstate->linejoin = fz_toint(val);
		else if (!strcmp(s, "ML"))
			gstate->miterlimit = fz_toreal(val);
	
		else if (!strcmp(s, "D"))
		{
			if (fz_isarray(val) && fz_arraylen(val) == 2)
			{
				fz_obj *dashes = fz_arrayget(val, 0);
				gstate->dashlen = MAX(fz_arraylen(dashes), 32);
				for (k = 0; k < gstate->dashlen; k++)
					gstate->dashlist[k] = fz_toreal(fz_arrayget(dashes, k));
				gstate->dashphase = fz_toreal(fz_arrayget(val, 1));
			}
			else
				return fz_throw("syntaxerror in ExtGState/D");
		}
	}

	return nil;
}

static fz_error *
runkeyword(pdf_csi *csi, pdf_xref *xref, fz_obj *rdb, char *buf)
{
	pdf_gstate *gstate = csi->gstate + csi->gtop;
	fz_error *error;
	float a, b, c, d, e, f;
	float x, y, w, h;
	fz_matrix m;
	int i;

	if (strlen(buf) > 1)
	{
		if (!strcmp(buf, "BX"))
		{
			if (csi->top != 0)
				goto syntaxerror;
			csi->xbalance ++;
		}

		else if (!strcmp(buf, "EX"))
		{
			if (csi->top != 0)
				goto syntaxerror;
			csi->xbalance --;
		}

		else if (!strcmp(buf, "MP"))
		{
			fz_node *meta;
			if (csi->top != 1)
				goto syntaxerror;
			error = fz_newmetanode(&meta, csi->stack[0], nil);
			if (error) return error;
			fz_insertnode(gstate->head, meta);
		}

		else if (!strcmp(buf, "DP"))
		{
			fz_node *meta;
			if (csi->top != 2)
				goto syntaxerror;
			error = fz_newmetanode(&meta, csi->stack[0], csi->stack[1]);
			if (error) return error;
			fz_insertnode(gstate->head, meta);
		}

		else if (!strcmp(buf, "BMC"))
		{
			fz_node *meta;
			if (csi->top != 1)
				goto syntaxerror;
			error = fz_newmetanode(&meta, csi->stack[0], nil);
			if (error) return error;
			// error = pdf_beginmarkedcontent(gstate, meta);
			// if (error) { fz_freenode(meta); return error; };
			fz_insertnode(gstate->head, meta);
		}

		else if (!strcmp(buf, "BDC"))
		{
			fz_node *meta;
			if (csi->top != 2)
				goto syntaxerror;
			error = fz_newmetanode(&meta, csi->stack[0], csi->stack[1]);
			if (error) return error;
			// error = pdf_beginmarkedcontent(gstate, meta);
			// if (error) { fz_freenode(meta); return error; };
			fz_insertnode(gstate->head, meta);
		}

		else if (!strcmp(buf, "EMC"))
		{
			// error = pdf_endmarkedcontent(gstate);
			// if (error) return error;
		}

		else if (!strcmp(buf, "cm"))
		{
			fz_matrix m;
			fz_node *transform;

			if (csi->top != 6)
				goto syntaxerror;

			m.a = fz_toreal(csi->stack[0]);
			m.b = fz_toreal(csi->stack[1]);
			m.c = fz_toreal(csi->stack[2]);
			m.d = fz_toreal(csi->stack[3]);
			m.e = fz_toreal(csi->stack[4]);
			m.f = fz_toreal(csi->stack[5]);

			error = fz_newtransformnode(&transform, m);
			if (error) return error;
			error = pdf_addtransform(gstate, transform);
			if (error) return error;
		}

		else if (!strcmp(buf, "ri"))
		{
			if (csi->top != 1)
				goto syntaxerror;
		}

		else if (!strcmp(buf, "gs"))
		{
			fz_obj *dict;
			fz_obj *obj;

			if (csi->top != 1)
				goto syntaxerror;

			dict = fz_dictgets(rdb, "ExtGState");
			if (!dict)
				return fz_throw("syntaxerror: missing extgstate resource");

			obj = fz_dictget(dict, csi->stack[0]);
			if (!obj)
				return fz_throw("syntaxerror: missing extgstate resource");

			runextgstate(gstate, xref, obj);
		}

		else if (!strcmp(buf, "re"))
		{
			if (csi->top != 4)
				goto syntaxerror;
			x = fz_toreal(csi->stack[0]);
			y = fz_toreal(csi->stack[1]);
			w = fz_toreal(csi->stack[2]);
			h = fz_toreal(csi->stack[3]);
			error = fz_moveto(csi->path, x, y);
			if (error) return error;
			error = fz_lineto(csi->path, x + w, y);
			if (error) return error;
			error = fz_lineto(csi->path, x + w, y + h);
			if (error) return error;
			error = fz_lineto(csi->path, x, y + h);
			if (error) return error;
			error = fz_closepath(csi->path);
			if (error) return error;
		}

		else if (!strcmp(buf, "f*"))
		{
			if (csi->top != 0)
				goto syntaxerror;
			error = pdf_showpath(csi, 0, 1, 0, 1);
			if (error) return error;
		}

		else if (!strcmp(buf, "B*"))
		{
			if (csi->top != 0)
				goto syntaxerror;
			error = pdf_showpath(csi, 0, 1, 1, 1);
			if (error) return error;
		}

		else if (!strcmp(buf, "b*"))
		{
			if (csi->top != 0)
				goto syntaxerror;
			error = pdf_showpath(csi, 1, 1, 1, 1);
			if (error) return error;
		}

		else if (!strcmp(buf, "W*"))
		{
			if (csi->top != 0)
				goto syntaxerror;
			error = fz_clonepath(&csi->clip, csi->path);
			if (error) return error;
			error = fz_endpath(csi->clip, FZ_EOFILL, nil, nil);
			if (error) return error;
		}

		else if (!strcmp(buf, "cs"))
		{
			fz_obj *dict;
			fz_obj *obj;

			if (csi->top != 1)
				goto syntaxerror;

			error = pdf_flushtext(csi);
			if (error) return error;

			obj = csi->stack[0];

			if (!strcmp(fz_toname(obj), "DeviceGray"))
				gstate->fillcs = pdf_devicegray;
			else if (!strcmp(fz_toname(obj), "DeviceRGB"))
				gstate->fillcs = pdf_devicergb;
			else if (!strcmp(fz_toname(obj), "DeviceCMYK"))
				gstate->fillcs = pdf_devicecmyk;
			else
			{
				dict = fz_dictgets(rdb, "ColorSpace");
				if (!dict)
					return fz_throw("syntaxerror: missing colorspace resource");
				obj = fz_dictget(dict, obj);
				if (!obj)
					return fz_throw("syntaxerror: missing colorspace resource");
				if (fz_isindirect(obj))
					gstate->fillcs = pdf_findresource(xref->rcolorspace, obj);
				else
					return fz_throw("syntaxerror: inline colorspace in dict");
				if (!gstate->fillcs)
					return fz_throw("syntaxerror: missing colorspace resource");
			}

			// FIXME set default color
		}

		else if (!strcmp(buf, "CS"))
		{
			fz_obj *dict;
			fz_obj *obj;

			if (csi->top != 1)
				goto syntaxerror;

			error = pdf_flushtext(csi);
			if (error) return error;

			obj = csi->stack[0];

			if (!strcmp(fz_toname(obj), "DeviceGray"))
				gstate->strokecs = pdf_devicegray;
			else if (!strcmp(fz_toname(obj), "DeviceRGB"))
				gstate->strokecs = pdf_devicergb;
			else if (!strcmp(fz_toname(obj), "DeviceCMYK"))
				gstate->strokecs = pdf_devicecmyk;
			else
			{
				dict = fz_dictgets(rdb, "ColorSpace");
				if (!dict)
					return fz_throw("syntaxerror: missing colorspace resource");
				obj = fz_dictget(dict, obj);
				if (!obj)
					return fz_throw("syntaxerror: missing colorspace resource");
				if (fz_isindirect(obj))
					gstate->strokecs = pdf_findresource(xref->rcolorspace, obj);
				else
					return fz_throw("syntaxerror: inline colorspace in dict");
				if (!gstate->strokecs)
					return fz_throw("syntaxerror: missing colorspace resource");
			}

			// FIXME set default color
		}

		else if (!strcmp(buf, "sc") || !strcmp(buf, "scn"))
		{
			if (csi->top != gstate->fillcs->n)
				goto syntaxerror;

			error = pdf_flushtext(csi);
			if (error) return error;

			for (i = 0; i < csi->top; i++)
				gstate->fill[i] = fz_toreal(csi->stack[i]);
		}

		else if (!strcmp(buf, "SC") || !strcmp(buf, "SCN"))
		{
			if (csi->top != gstate->strokecs->n)
				goto syntaxerror;

			error = pdf_flushtext(csi);
			if (error) return error;

			for (i = 0; i < csi->top; i++)
				gstate->stroke[i] = fz_toreal(csi->stack[i]);
		}

		else if (!strcmp(buf, "rg"))
		{
			if (csi->top != 3)
				goto syntaxerror;

			error = pdf_flushtext(csi);
			if (error) return error;

			gstate->fillcs = pdf_devicergb;
			gstate->fill[0] = fz_toreal(csi->stack[0]);
			gstate->fill[1] = fz_toreal(csi->stack[1]);
			gstate->fill[2] = fz_toreal(csi->stack[2]);
		}

		else if (!strcmp(buf, "RG"))
		{
			if (csi->top != 3)
				goto syntaxerror;

			error = pdf_flushtext(csi);
			if (error) return error;

			gstate->strokecs = pdf_devicergb;
			gstate->stroke[0] = fz_toreal(csi->stack[0]);
			gstate->stroke[1] = fz_toreal(csi->stack[1]);
			gstate->stroke[2] = fz_toreal(csi->stack[2]);
		}

		else if (!strcmp(buf, "BT"))
		{
			if (csi->top != 0)
				goto syntaxerror;
			csi->tm = fz_identity();
			csi->tlm = fz_identity();
		}

		else if (!strcmp(buf, "ET"))
		{
			if (csi->top != 0)
				goto syntaxerror;
			error = pdf_flushtext(csi);
			if (error)
				return error;
		}

		else if (!strcmp(buf, "Tc"))
		{
			if (csi->top != 1)
				goto syntaxerror;
			gstate->charspace = fz_toreal(csi->stack[0]);
		}

		else if (!strcmp(buf, "Tw"))
		{
			if (csi->top != 1)
				goto syntaxerror;
			gstate->wordspace = fz_toreal(csi->stack[0]);
		}

		else if (!strcmp(buf, "Tz"))
		{
			if (csi->top != 1)
				goto syntaxerror;

			error = pdf_flushtext(csi);
			if (error) return error;

			gstate->scale = fz_toreal(csi->stack[0]) / 100.0;
		}

		else if (!strcmp(buf, "TL"))
		{
			if (csi->top != 1)
				goto syntaxerror;
			gstate->leading = fz_toreal(csi->stack[0]);
		}

		else if (!strcmp(buf, "Tf"))
		{
			fz_obj *dict;
			fz_obj *obj;

			if (csi->top != 2)
				goto syntaxerror;

			dict = fz_dictgets(rdb, "Font");
			if (!dict)
				return fz_throw("syntaxerror: missing font resource");

			obj = fz_dictget(dict, csi->stack[0]);
			if (!obj)
				return fz_throw("syntaxerror: missing font resource");

			gstate->font = pdf_findresource(xref->rfont, obj);
			if (!gstate->font)
				return fz_throw("syntaxerror: missing font resource");

			gstate->size = fz_toreal(csi->stack[1]);
		}

		else if (!strcmp(buf, "Tr"))
		{
			if (csi->top != 1)
				goto syntaxerror;
			gstate->render = fz_toint(csi->stack[0]);
		}

		else if (!strcmp(buf, "Ts"))
		{
			if (csi->top != 1)
				goto syntaxerror;
			gstate->rise = fz_toreal(csi->stack[0]);
		}

		else if (!strcmp(buf, "Td"))
		{
			if (csi->top != 2)
				goto syntaxerror;
			m = fz_translate(fz_toreal(csi->stack[0]), fz_toreal(csi->stack[1]));
			csi->tlm = fz_concat(m, csi->tlm);
			csi->tm = csi->tlm;
		}

		else if (!strcmp(buf, "TD"))
		{
			if (csi->top != 2)
				goto syntaxerror;
			gstate->leading = -fz_toreal(csi->stack[1]);
			m = fz_translate(fz_toreal(csi->stack[0]), fz_toreal(csi->stack[1]));
			csi->tlm = fz_concat(m, csi->tlm);
			csi->tm = csi->tlm;
		}

		else if (!strcmp(buf, "Tm"))
		{
			if (csi->top != 6)
				goto syntaxerror;

			error = pdf_flushtext(csi);
			if (error) return error;

			csi->tm.a = fz_toreal(csi->stack[0]);
			csi->tm.b = fz_toreal(csi->stack[1]);
			csi->tm.c = fz_toreal(csi->stack[2]);
			csi->tm.d = fz_toreal(csi->stack[3]);
			csi->tm.e = fz_toreal(csi->stack[4]);
			csi->tm.f = fz_toreal(csi->stack[5]);
			csi->tlm = csi->tm;
		}

		else if (!strcmp(buf, "T*"))
		{
			if (csi->top != 0)
				goto syntaxerror;
			m = fz_translate(0, -gstate->leading);
			csi->tlm = fz_concat(m, csi->tlm);
			csi->tm = csi->tlm;
		}

		else if (!strcmp(buf, "Tj"))
		{
			if (csi->top != 1)
				goto syntaxerror;
			error = pdf_showtext(csi, csi->stack[0]);
			if (error) return error;
		}

		else if (!strcmp(buf, "TJ"))
		{
			if (csi->top != 1)
				goto syntaxerror;
			error = pdf_showtext(csi, csi->stack[0]);
			if (error) return error;
		}

		else if (!strcmp(buf, "Do"))
		{
			fz_obj *dict;
			fz_obj *obj;
			pdf_image *img;

			if (csi->top != 1)
				goto syntaxerror;

			dict = fz_dictgets(rdb, "XObject");
			if (!dict)
				return fz_throw("syntaxerror: missing xobject resource");

			obj = fz_dictget(dict, csi->stack[0]);
			if (!obj)
				return fz_throw("syntaxerror: missing xobject resource");

			img = pdf_findresource(xref->rimage, obj);
			if (!img)
			{
fprintf(stderr, "syntaxerror: missing image resource");
return nil;
			}

			error = pdf_showimage(csi, img);
			if (error)
				return error;
		}

		else
fprintf(stderr, "syntaxerror: unknown keyword '%s'\n", buf);
			//return fz_throw("syntaxerror: unknown keyword '%s'", buf);
			//if (!csi->xbalance) goto syntaxerror;
	}

	else switch (buf[0])
	{

	case 'q':
		if (csi->top != 0)
			goto syntaxerror;
		if (csi->gtop == 31)
			return fz_throw("gstate overflow in content stream");
		memcpy(&csi->gstate[csi->gtop + 1],
				&csi->gstate[csi->gtop],
				sizeof (pdf_gstate));
		csi->gtop ++;
		break;

	case 'Q':
		if (csi->top != 0)
			goto syntaxerror;
		if (csi->gtop == 0)
			return fz_throw("gstate underflow in content stream");
		csi->gtop --;
		break;

	case 'w':
		if (csi->top != 1)
			goto syntaxerror;
		gstate->linewidth = fz_toreal(csi->stack[0]);
		break;

	case 'J':
		if (csi->top != 1)
			goto syntaxerror;
		gstate->linecap = fz_toint(csi->stack[0]);
		break;

	case 'j':
		if (csi->top != 1)
			goto syntaxerror;
		gstate->linejoin = fz_toint(csi->stack[0]);
		break;

	case 'M':
		if (csi->top != 1)
			goto syntaxerror;
		gstate->miterlimit = fz_toreal(csi->stack[0]);
		break;

	case 'd':
		if (csi->top != 2)
			goto syntaxerror;
		{
			int i;
			fz_obj *array = csi->stack[0];
			gstate->dashlen = fz_arraylen(array);
			if (gstate->dashlen > 32)
				return fz_throw("rangecheck: too large dash pattern");
			for (i = 0; i < gstate->dashlen; i++)
				gstate->dashlist[i] = fz_toreal(fz_arrayget(array, i));
			gstate->dashphase = fz_toreal(csi->stack[1]);
		}
		break;

	case 'i':
		if (csi->top != 1)
			goto syntaxerror;
		/* flatness */
		break;

	case 'm':
		if (csi->top != 2)
			goto syntaxerror;
		a = fz_toreal(csi->stack[0]);
		b = fz_toreal(csi->stack[1]);
		return fz_moveto(csi->path, a, b);

	case 'l':
		if (csi->top != 2)
			goto syntaxerror;
		a = fz_toreal(csi->stack[0]);
		b = fz_toreal(csi->stack[1]);
		return fz_lineto(csi->path, a, b);

	case 'c':
		if (csi->top != 6)
			goto syntaxerror;
		a = fz_toreal(csi->stack[0]);
		b = fz_toreal(csi->stack[1]);
		c = fz_toreal(csi->stack[2]);
		d = fz_toreal(csi->stack[3]);
		e = fz_toreal(csi->stack[4]);
		f = fz_toreal(csi->stack[5]);
		return fz_curveto(csi->path, a, b, c, d, e, f);

	case 'v':
		if (csi->top != 4)
			goto syntaxerror;
		a = fz_toreal(csi->stack[0]);
		b = fz_toreal(csi->stack[1]);
		c = fz_toreal(csi->stack[2]);
		d = fz_toreal(csi->stack[3]);
		return fz_curvetov(csi->path, a, b, c, d);

	case 'y':
		if (csi->top != 4)
			goto syntaxerror;
		a = fz_toreal(csi->stack[0]);
		b = fz_toreal(csi->stack[1]);
		c = fz_toreal(csi->stack[2]);
		d = fz_toreal(csi->stack[3]);
		return fz_curvetoy(csi->path, a, b, c, d);

	case 'h':
		if (csi->top != 0)
			goto syntaxerror;
		return fz_closepath(csi->path);

	case 'S':
		if (csi->top != 0)
			goto syntaxerror;
		error = pdf_showpath(csi, 0, 0, 1, 0);
		if (error) return error;
		break;

	case 's':
		if (csi->top != 0)
			goto syntaxerror;
		error = pdf_showpath(csi, 1, 0, 1, 0);
		if (error) return error;
		break;

	case 'F':
	case 'f':
		if (csi->top != 0)
			goto syntaxerror;
		error = pdf_showpath(csi, 0, 1, 0, 0);
		if (error) return error;
		break;

	case 'B':
		if (csi->top != 0)
			goto syntaxerror;
		error = pdf_showpath(csi, 0, 1, 1, 0);
		if (error) return error;
		break;

	case 'b':
		if (csi->top != 0)
			goto syntaxerror;
		error = pdf_showpath(csi, 1, 1, 1, 0);
		if (error) return error;
		break;

	case 'n':
		if (csi->top != 0)
			goto syntaxerror;
		error = pdf_showpath(csi, 0, 0, 0, 0);
		if (error) return error;
		break;

	case 'W':
		if (csi->top != 0)
			goto syntaxerror;
		error = fz_clonepath(&csi->clip, csi->path);
		if (error) return error;
		error = fz_endpath(csi->clip, FZ_FILL, nil, nil);
		if (error) return error;
		break;

	case 'g':	
		if (csi->top != 1)
			goto syntaxerror;

		error = pdf_flushtext(csi);
		if (error) return error;

		gstate->fillcs = pdf_devicegray;
		gstate->fill[0] = fz_toreal(csi->stack[0]);
		break;
		
	case 'G':
		if (csi->top != 1)
			goto syntaxerror;

		error = pdf_flushtext(csi);
		if (error) return error;

		gstate->strokecs = pdf_devicegray;
		gstate->stroke[0] = fz_toreal(csi->stack[0]);
		break;

	case 'k':
		if (csi->top != 4)
			goto syntaxerror;

		error = pdf_flushtext(csi);
		if (error) return error;

		gstate->fillcs = pdf_devicecmyk;
		gstate->fill[0] = fz_toreal(csi->stack[0]);
		gstate->fill[1] = fz_toreal(csi->stack[1]);
		gstate->fill[2] = fz_toreal(csi->stack[2]);
		gstate->fill[3] = fz_toreal(csi->stack[3]);
		break;

	case 'K':
		if (csi->top != 4)
			goto syntaxerror;

		error = pdf_flushtext(csi);
		if (error) return error;

		gstate->strokecs = pdf_devicecmyk;
		gstate->stroke[0] = fz_toreal(csi->stack[0]);
		gstate->stroke[1] = fz_toreal(csi->stack[1]);
		gstate->stroke[2] = fz_toreal(csi->stack[2]);
		gstate->stroke[3] = fz_toreal(csi->stack[3]);
		break;

	case '\'':
		if (csi->top != 1)
			goto syntaxerror;

		m = fz_translate(0, -gstate->leading);
		csi->tlm = fz_concat(m, csi->tlm);
		csi->tm = csi->tlm;

		error = pdf_showtext(csi, csi->stack[0]);
		if (error) return error;
		break;

	case '"':
		if (csi->top != 3)
			goto syntaxerror;

		gstate->wordspace = fz_toreal(csi->stack[0]);
		gstate->charspace = fz_toreal(csi->stack[1]);

		m = fz_translate(0, -gstate->leading);
		csi->tlm = fz_concat(m, csi->tlm);
		csi->tm = csi->tlm;

		error = pdf_showtext(csi, csi->stack[2]);
		if (error) return error;
		break;

	default:
fprintf(stderr, "syntaxerror: unknown keyword '%s'\n", buf);
		//return fz_throw("syntaxerror: unknown keyword '%s'", buf);
		//if (!csi->xbalance) goto syntaxerror;
	}

	return nil;

syntaxerror:
	return fz_throw("syntaxerror in content stream: '%s'", buf);
}

fz_error *
pdf_runcsi(pdf_csi *csi, pdf_xref *xref, fz_obj *rdb, fz_file *file)
{
	fz_error *error;
	unsigned char buf[65536];
	int token, len;

	while (1)
	{
		if (csi->top == 31)
			return fz_throw("stack overflow in content stream");

		token = pdf_lex(file, buf, sizeof buf, &len);

		switch (token)
		{
		case PDF_TEOF:
			return nil;

		/* FIXME: need to make array parsing be able to span files for
		   those stupid pdf files that split TJ arrays across content
		   streams...
		*/
		case PDF_TOARRAY:
			error = pdf_parsearray(&csi->stack[csi->top], file, buf, sizeof buf);
			if (error) return error;
			csi->top ++;
			break;

		/* drop down to normal pdf object parsing for dictionaries,
		   and pray that they are not split in the middle with the beginning
		   and end in different streams
		*/
		case PDF_TODICT:
			error = pdf_parsedict(&csi->stack[csi->top], file, buf, sizeof buf);
			if (error) return error;
			csi->top ++;
			break;

		case PDF_TNAME:
			error = fz_newname(&csi->stack[csi->top], buf);
			if (error) return error;
			csi->top ++;
			break;

		case PDF_TINT:
			error = fz_newint(&csi->stack[csi->top], atoi(buf));
			if (error) return error;
			csi->top ++;
			break;

		case PDF_TREAL:
			error = fz_newreal(&csi->stack[csi->top], atof(buf));
			if (error) return error;
			csi->top ++;
			break;

		case PDF_TSTRING:
			error = fz_newstring(&csi->stack[csi->top], buf, len);
			if (error) return error;
			csi->top ++;
			break;

		case PDF_TTRUE:
			error = fz_newbool(&csi->stack[csi->top], 1);
			if (error) return error;
			csi->top ++;
			break;

		case PDF_TFALSE:
			error = fz_newbool(&csi->stack[csi->top], 0);
			if (error) return error;
			csi->top ++;
			break;

		case PDF_TNULL:
			error = fz_newnull(&csi->stack[csi->top]);
			if (error) return error;
			csi->top ++;
			break;

		case PDF_TKEYWORD:
			error = runkeyword(csi, xref, rdb, buf);
			if (error) return error;
			clearstack(csi);
			break;

		default:
			clearstack(csi);
			return fz_throw("syntaxerror in content stream");
		}
	}
}

