#include <fitz.h>

fz_rect
fz_intersectrects(fz_rect a, fz_rect b)
{
	fz_rect r;
	r.min.x = MAX(a.min.x, b.min.x);
	r.min.y = MAX(a.min.y, b.min.y);
	r.max.x = MIN(a.max.x, b.max.x);
	r.max.y = MIN(a.max.y, b.max.y);
	return r;
}

fz_rect
fz_mergerects(fz_rect a, fz_rect b)
{
	fz_rect r;
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
	r.min.x = MAX(a.min.x, b.min.x);
	r.min.y = MAX(a.min.y, b.min.y);
	r.max.x = MIN(a.max.x, b.max.x);
	r.max.y = MIN(a.max.y, b.max.y);
	return r;
}

fz_irect
fz_mergeirects(fz_irect a, fz_irect b)
{
	fz_irect r;
	r.min.x = MIN(a.min.x, b.min.x);
	r.min.y = MIN(a.min.y, b.min.y);
	r.max.x = MAX(a.max.x, b.max.x);
	r.max.y = MAX(a.max.y, b.max.y);
	return r;
}

