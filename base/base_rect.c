#include <fitz.h>

fz_rect fz_infiniterect = { { 1, 1}, {-1, -1} };
fz_rect fz_emptyrect = { { 0, 0}, {0, 0} };

static fz_irect infinite = { { 1, 1}, {-1, -1} };
static fz_irect empty = { { 0, 0}, {0, 0} };

fz_irect
fz_roundrect(fz_rect f)
{
	fz_irect i;
	i.min.x = fz_floor(f.min.x);
	i.min.y = fz_floor(f.min.y);
	i.max.x = fz_ceil(f.max.x);
	i.max.y = fz_ceil(f.max.y);
	return i;
}

fz_rect
fz_intersectrects(fz_rect a, fz_rect b)
{
	fz_rect r;
	if (fz_isinfiniterect(a)) return b;
	if (fz_isinfiniterect(b)) return a;
	r.min.x = MAX(a.min.x, b.min.x);
	r.min.y = MAX(a.min.y, b.min.y);
	r.max.x = MIN(a.max.x, b.max.x);
	r.max.y = MIN(a.max.y, b.max.y);
	return (r.max.x < r.min.x || r.max.y < r.min.y) ? fz_emptyrect : r;
}

fz_rect
fz_mergerects(fz_rect a, fz_rect b)
{
	fz_rect r;
	if (fz_isinfiniterect(a) || fz_isinfiniterect(b))
		return fz_infiniterect;
	if (fz_isemptyrect(a)) return b;
	if (fz_isemptyrect(b)) return a;
	r.min.x = MIN(a.min.x, b.min.x);
	r.min.y = MIN(a.min.y, b.min.y);
	r.max.x = MAX(a.max.x, b.max.x);
	r.max.y = MAX(a.max.y, b.max.y);
	return r;
}

fz_irect
fz_intersectirects(fz_irect a, fz_irect b)
{
	fz_irect r;
	if (fz_isinfiniterect(a)) return b;
	if (fz_isinfiniterect(b)) return a;
	r.min.x = MAX(a.min.x, b.min.x);
	r.min.y = MAX(a.min.y, b.min.y);
	r.max.x = MIN(a.max.x, b.max.x);
	r.max.y = MIN(a.max.y, b.max.y);
	return (r.max.x < r.min.x || r.max.y < r.min.y) ? empty : r;
}

fz_irect
fz_mergeirects(fz_irect a, fz_irect b)
{
	fz_irect r;
	if (fz_isinfiniterect(a) || fz_isinfiniterect(b))
		return infinite;
	if (fz_isemptyrect(a)) return b;
	if (fz_isemptyrect(b)) return a;
	r.min.x = MIN(a.min.x, b.min.x);
	r.min.y = MIN(a.min.y, b.min.y);
	r.max.x = MAX(a.max.x, b.max.x);
	r.max.y = MAX(a.max.y, b.max.y);
	return r;
}

