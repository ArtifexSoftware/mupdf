#include <fitz.h>

static inline void
addspan(short *list, int x0, int x1, int xofs, int hs)
{
	int x0pix, x0sub;
	int x1pix, x1sub;

	if (x0 == x1)
		return;

	/* x between 0 and width of bbox */
	x0 -= xofs;
	x1 -= xofs;

	x0pix = x0 / hs;
	x0sub = x0 % hs;
	x1pix = x1 / hs;
	x1sub = x1 % hs;

	if (x0pix == x1pix)
	{
		list[x0pix] += x1sub - x0sub;
		list[x0pix+1] += x0sub - x1sub;
	}

	else
	{
		list[x0pix] += hs - x0sub;
		list[x0pix+1] += x0sub;
		list[x1pix] += x1sub - hs;
		list[x1pix+1] += -x1sub;
	}
}

static inline void
nonzerowinding(fz_ael *ael, short *list, int xofs, int hs)
{
	int winding = 0;
	int x = 0;
	int i;
	for (i = 0; i < ael->len; i++)
	{
		if (!winding && (winding + ael->edges[i]->ydir))
			x = ael->edges[i]->x;
		if (winding && !(winding + ael->edges[i]->ydir))
			addspan(list, x, ael->edges[i]->x, xofs, hs);
		winding += ael->edges[i]->ydir;
	}
}

static inline void
evenodd(fz_ael *ael, short *list, int xofs, int hs)
{
	int even = 0;
	int x = 0;
	int i;
	for (i = 0; i < ael->len; i++)
	{
		if (!even)
			x = ael->edges[i]->x;
		else
			addspan(list, x, ael->edges[i]->x, xofs, hs);
		even = !even;
	}
}

/*
void
fz_emitdeltas(short *list, int y, int xofs, int n)
{
	int d = 0;
	while (n--)
		d += *list++;
}
*/

fz_error *
fz_scanconvert(fz_gel *gel, fz_ael *ael, int eofill,
	void (*blitfunc)(int,int,int,short*,void*), void *blitdata)
{
	fz_error *error;
	short *deltas;
	int y, e;
	int yd, yc;

	int xmin = fz_idiv(gel->xmin, gel->hs);
	int xmax = fz_idiv(gel->xmax, gel->hs) + 1;
	int ymin = fz_idiv(gel->ymin, gel->vs);
	int ymax = fz_idiv(gel->ymax, gel->vs) + 1;

	int xofs = xmin * gel->hs;
	int hs = gel->hs;
	int vs = gel->vs;

	if (gel->len == 0)
		return nil;

	deltas = fz_malloc(sizeof(short) * (xmax - xmin));
	if (!deltas)
		return fz_outofmem;
	memset(deltas, 0, sizeof(short) * (xmax - xmin));

	e = 0;
	y = gel->edges[0].y;
	yc = fz_idiv(y, vs);
	yd = yc;

	while (ael->len > 0 || e < gel->len)
	{
		yc = fz_idiv(y, vs);
		if (yc != yd) {
			blitfunc(yd, xmin, xmax - xmin, deltas, blitdata);
			memset(deltas, 0, sizeof(short) * (xmax - xmin));
		}
		yd = yc;

		error = fz_insertael(ael, gel, y, &e);
		if (error) {
			fz_free(deltas);
			return error;
		}

		if (eofill)
			evenodd(ael, deltas, xofs, hs);
		else
			nonzerowinding(ael, deltas, xofs, hs);

		fz_advanceael(ael);

		if (ael->len > 0)
			y ++;
		else if (e < gel->len)
			y = gel->edges[e].y;
	}

	blitfunc(yd, xmin, xmax - xmin, deltas, blitdata);

	return nil;
}

