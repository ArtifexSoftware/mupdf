#include <fitz.h>

void
fz_initfont(fz_font *font, char *name)
{
	strlcpy(font->name, name, sizeof font->name);

	font->wmode = 0;

	font->bbox.min.x = 0;
	font->bbox.min.y = 0;
	font->bbox.max.x = 1000;
	font->bbox.max.y = 1000;

	font->hmtxcap = 0;
	font->vmtxcap = 0;
	font->nhmtx = 0;
	font->nvmtx = 0;
	font->hmtx = nil;
	font->vmtx = nil;

	font->dhmtx.lo = 0x0000;
	font->dhmtx.hi = 0xFFFF;
	font->dhmtx.w = 0;

	font->dvmtx.lo = 0x0000;
	font->dvmtx.hi = 0xFFFF;
	font->dvmtx.x = 0;
	font->dvmtx.y = 880;
	font->dvmtx.w = -1000;
}

void
fz_setfontwmode(fz_font *font, int wmode)
{
	font->wmode = wmode;
}

void
fz_setfontbbox(fz_font *font, int xmin, int ymin, int xmax, int ymax)
{
    font->bbox.min.x = xmin;
    font->bbox.min.y = ymin;
    font->bbox.max.x = xmax;
    font->bbox.max.y = ymax;
}

void
fz_setdefaulthmtx(fz_font *font, int w)
{
	font->dhmtx.w = w;
}

void
fz_setdefaultvmtx(fz_font *font, int y, int w)
{
	font->dvmtx.y = y;
	font->dvmtx.w = w;
}

fz_error *
fz_addhmtx(fz_font *font, int lo, int hi, int w)
{
	int newcap;
	fz_hmtx *newmtx;

	if (font->nhmtx + 1 >= font->hmtxcap)
	{
		newcap = font->hmtxcap + 16;
		newmtx = fz_realloc(font->hmtx, sizeof(fz_hmtx) * newcap);
		if (!newmtx)
			return fz_outofmem;
		font->hmtxcap = newcap;
		font->hmtx = newmtx;
	}

	font->hmtx[font->nhmtx].lo = lo;
	font->hmtx[font->nhmtx].hi = hi;
	font->hmtx[font->nhmtx].w = w;
	font->nhmtx++;

	return nil;
}

fz_error *
fz_addvmtx(fz_font *font, int lo, int hi, int x, int y, int w)
{
	int newcap;
	fz_vmtx *newmtx;

	if (font->nvmtx + 1 >= font->vmtxcap)
	{
		newcap = font->vmtxcap + 16;
		newmtx = fz_realloc(font->vmtx, sizeof(fz_vmtx) * newcap);
		if (!newmtx)
			return fz_outofmem;
		font->vmtxcap = newcap;
		font->vmtx = newmtx;
	}

	font->vmtx[font->nvmtx].lo = lo;
	font->vmtx[font->nvmtx].hi = hi;
	font->vmtx[font->nvmtx].x = x;
	font->vmtx[font->nvmtx].y = y;
	font->vmtx[font->nvmtx].w = w;
	font->nvmtx++;

	return nil;
}

static int cmph(const void *a0, const void *b0)
{
	fz_hmtx *a = (fz_hmtx*)a0;
	fz_hmtx *b = (fz_hmtx*)b0;
	return a->lo - b->lo;
}

static int cmpv(const void *a0, const void *b0)
{
	fz_vmtx *a = (fz_vmtx*)a0;
	fz_vmtx *b = (fz_vmtx*)b0;
	return a->lo - b->lo;
}

static int uniq(void *ptr, int count, int size)
{
	char *a = ptr;
	char *b = ((char*)ptr) + size;

	while (count--)
	{
		if (memcmp(a, b, sizeof(short)) != 0)
		{
			a += size;
			if (a != b)
				memcpy(a, b, size);
		}
		b += size;
	}

	return (a - ((char*)ptr)) / size;
}

fz_error *
fz_endhmtx(fz_font *font)
{
	fz_hmtx *newmtx;

	if (!font->hmtx)
		return nil;

	qsort(font->hmtx, font->nhmtx, sizeof(fz_hmtx), cmph);
	font->nhmtx = uniq(font->hmtx, font->nhmtx, sizeof(fz_hmtx));

	newmtx = fz_realloc(font->hmtx, sizeof(fz_hmtx) * font->nhmtx);
	if (!newmtx)
		return fz_outofmem;
	font->hmtxcap = font->nhmtx;
	font->hmtx = newmtx;

	return nil;
}

fz_error *
fz_endvmtx(fz_font *font)
{
	fz_vmtx *newmtx;

	if (!font->vmtx)
		return nil;

	qsort(font->vmtx, font->nvmtx, sizeof(fz_vmtx), cmpv);
	font->nvmtx = uniq(font->vmtx, font->nvmtx, sizeof(fz_vmtx));

	newmtx = fz_realloc(font->vmtx, sizeof(fz_vmtx) * font->nvmtx);
	if (!newmtx)
		return fz_outofmem;
	font->vmtxcap = font->nvmtx;
	font->vmtx = newmtx;

	return nil;
}

fz_hmtx
fz_gethmtx(fz_font *font, int cid)
{
	int l = 0;
	int r = font->nhmtx;
	int m;

	if (!font->hmtx)
		goto notfound;

	while (l <= r)
	{
		m = (l + r) >> 1;
		if (cid < font->hmtx[m].lo)
			r = m - 1;
		else if (cid > font->hmtx[m].hi)
			l = m + 1;
		else
			return font->hmtx[m];
	}

notfound:
	return font->dhmtx;
}

fz_vmtx
fz_getvmtx(fz_font *font, int cid)
{
	fz_hmtx h;
	fz_vmtx v;
	int l = 0;
	int r = font->nvmtx;
	int m;

	if (!font->vmtx)
		goto notfound;

	while (l <= r)
	{
		m = (l + r) >> 1;
		if (cid < font->vmtx[m].lo)
			r = m - 1;
		else if (cid > font->vmtx[m].hi)
			l = m + 1;
		else
			return font->vmtx[m];
	}

notfound:
	h = fz_gethmtx(font, cid);
	v = font->dvmtx;
	v.x = h.w / 2;
	return v;
}

void
fz_freefont(fz_font *font)
{
	if (font->free)
		font->free(font);
	fz_free(font->hmtx);
	fz_free(font->vmtx);
	fz_free(font);
}

void
fz_debugfont(fz_font *font)
{
	int i;

	printf("font '%s' {\n", font->name);
	printf("  wmode %d\n", font->wmode);
	printf("  bbox [%d %d %d %d]\n",
		font->bbox.min.x, font->bbox.min.y,
		font->bbox.max.x, font->bbox.max.y);
	printf("  DW %d\n", font->dhmtx.w);

	printf("  W {\n");
	for (i = 0; i < font->nhmtx; i++)
		printf("    <%04x> <%04x> %d\n",
			font->hmtx[i].lo, font->hmtx[i].hi, font->hmtx[i].w);
	printf("  }\n");

	if (font->wmode)
	{
		printf("  DW2 [%d %d]\n", font->dvmtx.y, font->dvmtx.w);
		printf("  W2 {\n");
		for (i = 0; i < font->nvmtx; i++)
			printf("    <%04x> <%04x> %d %d %d\n", font->vmtx[i].lo, font->vmtx[i].hi,
				font->vmtx[i].x, font->vmtx[i].y, font->vmtx[i].w);
		printf("  }\n");
	}

	printf("}\n");
}

