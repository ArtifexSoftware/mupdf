#include <fitz.h>

/*
 * Global Edge List -- list of straight path segments for scan conversion
 *
 * Stepping along the edges is with bresenham's line algorithm.
 *
 * See Mike Abrash -- Graphics Programming Black Book (notably chapter 40)
 */

fz_error *
fz_newgel(fz_gel **gelp)
{
	fz_gel *gel;

	gel = *gelp = fz_malloc(sizeof(fz_gel));
	if (!gel)
		return fz_outofmem;

	gel->edges = nil;

	gel->cap = 512;
	gel->len = 0;
	gel->edges = fz_malloc(sizeof(fz_edge) * gel->cap);
	if (!gel->edges) {
		fz_free(gel);
		return fz_outofmem;
	}

	gel->xmin = gel->ymin = INT_MAX;
	gel->xmax = gel->ymax = INT_MIN;
	gel->hs = 1;
	gel->vs = 1;

	return nil;
}

void
fz_resetgel(fz_gel *gel, int hs, int vs)
{
	gel->xmin = gel->ymin = INT_MAX;
	gel->xmax = gel->ymax = INT_MIN;
	gel->hs = hs;
	gel->vs = vs;
	gel->len = 0;
}

void
fz_dropgel(fz_gel *gel)
{
	fz_free(gel->edges);
	fz_free(gel);
}

fz_irect
fz_boundgel(fz_gel *gel)
{
	fz_irect bbox;
	bbox.min.x = fz_idiv(gel->xmin, gel->hs);
	bbox.min.y = fz_idiv(gel->ymin, gel->vs);
	bbox.max.x = fz_idiv(gel->xmax, gel->hs) + 1;
	bbox.max.y = fz_idiv(gel->ymax, gel->vs) + 1;
	return bbox;
}

fz_error *
fz_insertgel(fz_gel *gel, float fx0, float fy0, float fx1, float fy1)
{
	fz_edge *edge;
	int x0, y0, x1, y1;
	int dx, dy;
	int winding;
	int width;
	int tmp;

	fx0 *= gel->hs;
	fy0 *= gel->vs;
	fx1 *= gel->hs;
	fy1 *= gel->vs;

	/* TODO: should we round or truncate? */
	x0 = fx0 < 0 ? fx0 - 0.5 : fx0 + 0.5;
	y0 = fy0 < 0 ? fy0 - 0.5 : fy0 + 0.5;
	x1 = fx1 < 0 ? fx1 - 0.5 : fx1 + 0.5;
	y1 = fy1 < 0 ? fy1 - 0.5 : fy1 + 0.5;

	if (y0 == y1)
		return nil;

	if (y0 > y1) {
		winding = -1;
		tmp = x0; x0 = x1; x1 = tmp;
		tmp = y0; y0 = y1; y1 = tmp;
	}
	else
		winding = 1;

	if (x0 < gel->xmin) gel->xmin = x0;
	if (x0 > gel->xmax) gel->xmax = x0;
	if (x1 < gel->xmin) gel->xmin = x1;
	if (x1 > gel->xmax) gel->xmax = x1;

	if (y0 < gel->ymin) gel->ymin = y0;
	if (y1 > gel->ymax) gel->ymax = y1;

	if (gel->len + 1 == gel->cap) {
		int newcap = gel->cap + 512;
		fz_edge *newedges = fz_realloc(gel->edges, sizeof(fz_edge) * newcap);
		if (!newedges)
			return fz_outofmem;
		gel->cap = newcap;
		gel->edges = newedges;
	}

	edge = &gel->edges[gel->len++];

	dy = y1 - y0;
	dx = x1 - x0;
	width = dx < 0 ? -dx : dx;

	edge->xdir = dx > 0 ? 1 : -1;
	edge->ydir = winding;
	edge->x = x0;
	edge->y = y0;
	edge->h = dy;
	edge->adjdown = dy;

	/* initial error term going l->r and r->l */
	if (dx >= 0)
		edge->e = 0;
	else
		edge->e = -dy + 1;

	/* y-major edge */
	if (dy >= width) {
		edge->xmove = 0;
		edge->adjup = width;
	}

	/* x-major edge */
	else {
		edge->xmove = (width / dy) * edge->xdir;
		edge->adjup = width % dy;
	}

	return nil;
}

void
fz_sortgel(fz_gel *gel)
{
	fz_edge *a = gel->edges;
	int n = gel->len;

	int h, i, k;
	fz_edge t;

	h = 1;
	if (n < 14) {
		h = 1;
	}
	else {
		while (h < n)
			h = 3 * h + 1;
		h /= 3;
		h /= 3;
	}

	while (h > 0)
	{
		for (i = 0; i < n; i++) {
			t = a[i];
			k = i - h;
			/* TODO: sort on y major, x minor */
			while (k >= 0 && a[k].y > t.y) {
				a[k + h] = a[k];
				k -= h;
			}
			a[k + h] = t;
		}

		h /= 3;
	}
}

/*
 * Active Edge List -- keep track of active edges while sweeping
 */

fz_error *
fz_newael(fz_ael **aelp)
{
	fz_ael *ael;

	ael = *aelp = fz_malloc(sizeof(fz_ael));
	if (!ael)
		return fz_outofmem;

	ael->cap = 64;
	ael->len = 0;
	ael->edges = fz_malloc(sizeof(fz_edge*) * ael->cap);
	if (!ael->edges) {
		fz_free(ael);
		return fz_outofmem;
	}

	return nil;
}

void
fz_dropael(fz_ael *ael)
{
	fz_free(ael->edges);
	fz_free(ael);
}

static inline void
sortael(fz_edge **a, int n)
{
	int h, i, k;
	fz_edge *t;

	h = 1;
	if (n < 14) {
		h = 1;
	}
	else {
		while (h < n)
			h = 3 * h + 1;
		h /= 3;
		h /= 3;
	}

	while (h > 0)
	{
		for (i = 0; i < n; i++) {
			t = a[i];
			k = i - h;
			while (k >= 0 && a[k]->x > t->x) {
				a[k + h] = a[k];
				k -= h;
			}
			a[k + h] = t;
		}

		h /= 3;
	}
}

fz_error *
fz_insertael(fz_ael *ael, fz_gel *gel, int y, int *e)
{
	/* insert edges that start here */
	while (*e < gel->len && gel->edges[*e].y == y) {
		if (ael->len + 1 == ael->cap) {
			int newcap = ael->cap + 64;
			fz_edge **newedges = fz_realloc(ael->edges, sizeof(fz_edge*) * newcap);
			if (!newedges)
				return fz_outofmem;
			ael->edges = newedges;
			ael->cap = newcap;
		}
		ael->edges[ael->len++] = &gel->edges[(*e)++];
	}

	/* shell-sort the edges by increasing x */
	sortael(ael->edges, ael->len);

	return nil;
}

void
fz_advanceael(fz_ael *ael)
{
	fz_edge *edge;
	int i = 0;

	while (i < ael->len)
	{
		edge = ael->edges[i];

		edge->h --;

		/* terminator! */
		if (edge->h == 0) {
			ael->edges[i] = ael->edges[--ael->len];
		}

		else {
			edge->x += edge->xmove;
			edge->e += edge->adjup;
			if (edge->e > 0) {
				edge->x += edge->xdir;
				edge->e -= edge->adjdown;
			}
			i ++;
		}
	}
}

