#include <fitz.h>

typedef struct fz_range_s fz_range;

enum { MAXCODESPACE = 10 };
enum { SINGLE, RANGE, LOOKUP };

struct fz_range_s
{
	int low;
	int high;
	int flag;
	int offset;
};

struct fz_cmap_s
{
	int nrefs;
	char cmapname[32];

	char usecmapname[32];
	fz_cmap *usecmap;

	int wmode;

	int ncspace;
	struct {
		int n;
		unsigned char lo[4];
		unsigned char hi[4];
	} cspace[MAXCODESPACE];

	int rlen, rcap;
	fz_range *ranges;

	int tlen, tcap;
	int *lookup;
};

fz_error *
fz_newcmap(fz_cmap **cmapp)
{
	fz_cmap *cmap;

	cmap = *cmapp = fz_malloc(sizeof(fz_cmap));
	if (!cmap)
		return fz_outofmem;

	cmap->nrefs = 1;
	strcpy(cmap->cmapname, "");

	strcpy(cmap->usecmapname, "");
	cmap->usecmap = nil;

	cmap->wmode = 0;

	cmap->ncspace = 0;

	cmap->rlen = 0;
	cmap->rcap = 0;
	cmap->ranges = nil;

	cmap->tlen = 0;
	cmap->tcap = 0;
	cmap->lookup = nil;

	return nil;
}

fz_cmap *
fz_keepcmap(fz_cmap *cmap)
{
	cmap->nrefs ++;
	return cmap;
}

void
fz_dropcmap(fz_cmap *cmap)
{
	if (--cmap->nrefs == 0)
	{
		if (cmap->usecmap)
			fz_dropcmap(cmap->usecmap);
		fz_free(cmap->ranges);
		fz_free(cmap->lookup);
		fz_free(cmap);
	}
}

char *
fz_getcmapname(fz_cmap *cmap)
{
	if (cmap->cmapname[0])
		return cmap->cmapname;
	return nil;
}

void
fz_setcmapname(fz_cmap *cmap, char *cmapname)
{
	strlcpy(cmap->cmapname, cmapname, sizeof cmap->cmapname);
}

char *
fz_getusecmapname(fz_cmap *cmap)
{
	if (cmap->usecmapname[0])
		return cmap->usecmapname;
	return nil;
}

void
fz_setusecmapname(fz_cmap *cmap, char *usecmap)
{
	strlcpy(cmap->usecmapname, usecmap, sizeof cmap->usecmapname);
}

fz_cmap *
fz_getusecmap(fz_cmap *cmap)
{
	return cmap->usecmap;
}

void
fz_setusecmap(fz_cmap *cmap, fz_cmap *usecmap)
{
	int i;

	if (cmap->usecmap)
		fz_dropcmap(cmap->usecmap);
	cmap->usecmap = fz_keepcmap(usecmap);

	if (cmap->ncspace == 0)
	{
		cmap->ncspace = usecmap->ncspace;
		for (i = 0; i < usecmap->ncspace; i++)
			cmap->cspace[i] = usecmap->cspace[i];
	}
}

void
fz_setwmode(fz_cmap *cmap, int wmode)
{
	cmap->wmode = wmode;
}

int
fz_getwmode(fz_cmap *cmap)
{
	return cmap->wmode;
}

fz_error *
fz_addcodespacerange(fz_cmap *cmap, unsigned lo, unsigned hi, int n)
{
	int i;

	if (cmap->ncspace + 1 == MAXCODESPACE)
		return fz_throw("rangelimit: too many code space ranges");

	cmap->cspace[cmap->ncspace].n = n;

	for (i = 0; i < n; i++)
	{
		int o = (n - i - 1) * 8;
		cmap->cspace[cmap->ncspace].lo[i] = (lo >> o) & 0xFF;
		cmap->cspace[cmap->ncspace].hi[i] = (hi >> o) & 0xFF;
	}

	cmap->ncspace ++;

	return nil;
}

fz_error *
fz_addcidrange(fz_cmap *cmap, int low, int high, int offset)
{
	if (cmap->rlen + 1 > cmap->rcap)
	{
		fz_range *newranges;
		int newcap = cmap->rcap == 0 ? 256 : cmap->rcap * 2;
		newranges = fz_realloc(cmap->ranges, newcap * sizeof(fz_range));
		if (!newranges)
			return fz_outofmem;
		cmap->rcap = newcap;
		cmap->ranges = newranges;
	}

	cmap->ranges[cmap->rlen].low = low;
	cmap->ranges[cmap->rlen].high = high;
	cmap->ranges[cmap->rlen].flag = high - low == 0 ? SINGLE : RANGE;
	cmap->ranges[cmap->rlen].offset = offset;
	cmap->rlen ++;

	return nil;
}

static fz_error *
addlookup(fz_cmap *cmap, int value)
{
	if (cmap->tlen + 1 > cmap->tcap)
	{
		int newcap = cmap->tcap == 0 ? 256 : cmap->tcap * 2;
		int *newlookup = fz_realloc(cmap->lookup, newcap * sizeof(int));
		if (!newlookup)
			return fz_outofmem;
		cmap->tcap = newcap;
		cmap->lookup = newlookup;
	}

	cmap->lookup[cmap->tlen++] = value;

	return nil;
}

static int compare(const void *va, const void *vb)
{
	return ((const fz_range*)va)->low - ((const fz_range*)vb)->low;
}

fz_error *
fz_endcidrange(fz_cmap *cmap)
{
	fz_error *err;
	fz_range *newranges;
	int *newlookup;
	fz_range *a;			/* last written range on output */
	fz_range *b;			/* current range examined on input */

	qsort(cmap->ranges, cmap->rlen, sizeof(fz_range), compare);

	a = cmap->ranges;
	b = cmap->ranges + 1;

	while (b < cmap->ranges + cmap->rlen)
	{
		/* input contiguous */
		if (a->high + 1 == b->low)
		{
			/* output contiguous */
			if (a->high - a->low + a->offset + 1 == b->offset)
			{
				/* SR -> R and SS -> R and RR -> R and RS -> R */
				if (a->flag == SINGLE || a->flag == RANGE)
				{
					a->flag = RANGE;
					a->high = b->high;
				}

				/* LS -> L */
				else if (a->flag == LOOKUP && b->flag == SINGLE)
				{
					a->high = b->high;
					err = addlookup(cmap, b->offset);
					if (err)
						return err;
				}

				/* LR -> LR */
				else if (a->flag == LOOKUP && b->flag == RANGE)
				{
					*(++a) = *b;
				}
			}

			/* output separated */
			else
			{
				/* SS -> L */
				if (a->flag == SINGLE && b->flag == SINGLE)
				{
					a->flag = LOOKUP;
					a->high = b->high;

					err = addlookup(cmap, a->offset);
					if (err)
						return err;

					err = addlookup(cmap, b->offset);
					if (err)
						return err;

					a->offset = cmap->tlen - 2;
				}

				/* LS -> L */
				else if (a->flag == LOOKUP && b->flag == SINGLE)
				{
					a->high = b->high;
					err = addlookup(cmap, b->offset);
					if (err)
						return err;
				}

				/* XX -> XX */
				else
				{
					*(++a) = *b;
				}
			}
		}

		/* input separated: XX -> XX */
		else
		{
			*(++a) = *b;
		}

		b ++;
	}

	cmap->rlen = a - cmap->ranges + 1;

	assert(cmap->rlen > 0);

	newranges = fz_realloc(cmap->ranges, cmap->rlen * sizeof(fz_range));
	if (!newranges)
		return fz_outofmem;
	cmap->rcap = cmap->rlen;
	cmap->ranges = newranges;

	if (cmap->tlen)
	{
		newlookup = fz_realloc(cmap->lookup, cmap->tlen * sizeof(int));
		if (!newlookup)
			return fz_outofmem;
		cmap->tcap = cmap->tlen;
		cmap->lookup = newlookup;
	}

	return nil;
}

fz_error *
fz_setcidlookup(fz_cmap *cmap, int map[256])
{
	int i;

	cmap->rlen = cmap->rcap = 1;
	cmap->ranges = fz_malloc(sizeof (fz_range));
	if (!cmap->ranges) {
		return fz_outofmem;
	}

	cmap->tlen = cmap->tcap = 256;
	cmap->lookup = fz_malloc(sizeof (int) * 256);
	if (!cmap->lookup) {
		fz_free(cmap->ranges);
		return fz_outofmem;
	}

	cmap->ranges[0].low = 0;
	cmap->ranges[0].high = 255;
	cmap->ranges[0].flag = LOOKUP;
	cmap->ranges[0].offset = 0;

	for (i = 0; i < 256; i++)
		cmap->lookup[i] = map[i];

	return nil;
}

int
fz_lookupcid(fz_cmap *cmap, int cpt)
{
	int l = 0;
	int r = cmap->rlen - 1;
	int m;

	while (l <= r)
	{
		m = (l + r) >> 1;
		if (cpt < cmap->ranges[m].low)
			r = m - 1;
		else if (cpt > cmap->ranges[m].high)
			l = m + 1;
		else
		{
			int i = cpt - cmap->ranges[m].low + cmap->ranges[m].offset;
			if (cmap->ranges[m].flag == LOOKUP)
				return cmap->lookup[i];
			return i;
		}
	}

	if (cmap->usecmap)
		return fz_lookupcid(cmap->usecmap, cpt);

	return -1;
}

char *
fz_decodecpt(fz_cmap *cmap, unsigned char *buf, int *cpt)
{
	int i, k;

	for (k = 0; k < cmap->ncspace; k++)
	{
		unsigned char *lo = cmap->cspace[k].lo;
		unsigned char *hi = cmap->cspace[k].hi;
		int n = cmap->cspace[k].n;
		int c = 0;

		for (i = 0; i < n; i++)
		{
			if (lo[i] <= buf[i] && buf[i] <= hi[i])
				c = (c << 8) | buf[i];
			else
				break;
		}

		if (i == n) {
			*cpt = c;
			return buf + n;
		}
	}

	*cpt = 0;
	return buf + 1;
}

void
fz_debugcmap(fz_cmap *cmap)
{
	int i, k;

	printf("cmap $%p /%s {\n", cmap, cmap->cmapname);

	if (cmap->usecmapname[0])
		printf("  usecmap /%s\n", cmap->usecmapname);
	if (cmap->usecmap)
		printf("  usecmap $%p\n", cmap->usecmap);

	printf("  wmode %d\n", cmap->wmode);

	printf("  codespaces {\n");
	for (i = 0; i < cmap->ncspace; i++)
	{
		printf("    <");
		for (k = 0; k < cmap->cspace[i].n; k++)
			printf("%02x", cmap->cspace[i].lo[k]);
		printf("> <");
		for (k = 0; k < cmap->cspace[i].n; k++)
			printf("%02x", cmap->cspace[i].hi[k]);
		printf(">\n");
	}
	printf("  }\n");

	printf("  ranges (%d,%d) {\n", cmap->rlen, cmap->tlen);
	for (i = 0; i < cmap->rlen; i++)
	{
		fz_range *r = &cmap->ranges[i];
		printf("    <%04x> <%04x> ", r->low, r->high);
		if (r->flag == LOOKUP)
		{
			printf("[ ");
			for (k = 0; k < r->high - r->low + 1; k++)
				printf("%d ", cmap->lookup[r->offset + k]);
			printf("]\n");
		}
		else
			printf("%d\n", r->offset);
	}
	printf("  }\n}\n");
}

