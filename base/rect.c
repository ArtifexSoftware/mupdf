#include <fitz.h>

static fz_rect none = { { 0, 0}, {0, 0} };
static fz_irect inone = { { 0, 0}, {0, 0} };

fz_rect
fz_infiniterect(void)
{
	fz_rect r;
	r.min.x = 1;
	r.min.y = 1;
	r.max.x = -1;
	r.max.y = -1;
	return r;
}

fz_rect
fz_intersectrects(fz_rect a, fz_rect b)
{
	fz_rect r;
	if (a.max.x < a.min.x)
		return (b.max.x < b.min.x) ? none : b;
	r.min.x = MAX(a.min.x, b.min.x);
	r.min.y = MAX(a.min.y, b.min.y);
	r.max.x = MIN(a.max.x, b.max.x);
	r.max.y = MIN(a.max.y, b.max.y);
	return (r.max.x < r.min.x || r.max.y < r.min.y) ? none : r;
}

fz_rect
fz_mergerects(fz_rect a, fz_rect b)
{
	fz_rect r;
	if (a.max.x < a.min.x)
		return (b.max.x < b.min.x) ? none : b;
	r.min.x = MIN(a.min.x, b.min.x);
	r.min.y = MIN(a.min.y, b.min.y);
	r.max.x = MAX(a.max.x, b.max.x);
	r.max.y = MAX(a.max.y, b.max.y);
	return r;
}

fz_irect
fz_roundrect(fz_rect f)
{
	fz_irect i;
	i.min.x = fz_floor(f.min.x);// - 1;
	i.min.y = fz_floor(f.min.y);// - 1;
	i.max.x = fz_ceil(f.max.x);// + 1;
	i.max.y = fz_ceil(f.max.y);// + 1;
	return i;
}

fz_irect
fz_intersectirects(fz_irect a, fz_irect b)
{
	fz_irect r;
	if (a.max.x < a.min.x)
		return (b.max.x < b.min.x) ? inone : b;
	r.min.x = MAX(a.min.x, b.min.x);
	r.min.y = MAX(a.min.y, b.min.y);
	r.max.x = MIN(a.max.x, b.max.x);
	r.max.y = MIN(a.max.y, b.max.y);
	return (r.max.x < r.min.x || r.max.y < r.min.y) ? inone : r;
}

fz_irect
fz_mergeirects(fz_irect a, fz_irect b)
{
	fz_irect r;
	if (a.max.x < a.min.x)
		return (b.max.x < b.min.x) ? inone : b;
	r.min.x = MIN(a.min.x, b.min.x);
	r.min.y = MIN(a.min.y, b.min.y);
	r.max.x = MAX(a.max.x, b.max.x);
	r.max.y = MAX(a.max.y, b.max.y);
	return r;
}

