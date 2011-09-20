/*
 * Information tool.
 * Print information about the input pdf.
 */

#include "fitz.h"
#include "mupdf.h"

pdf_xref *xref;
fz_context *ctx;
int pagecount;

void closexref(void);

void die(fz_error error)
{
	fz_error_handle(error, "aborting");
	closexref();
	exit(1);
}

void openxref(char *filename, char *password, int dieonbadpass, int loadpages);

enum
{
	DIMENSIONS = 0x01,
	FONTS = 0x02,
	IMAGES = 0x04,
	SHADINGS = 0x08,
	PATTERNS = 0x10,
	XOBJS = 0x20,
	ALL = DIMENSIONS | FONTS | IMAGES | SHADINGS | PATTERNS | XOBJS
};

struct info
{
	int page;
	fz_obj *pageref;
	fz_obj *pageobj;
	union {
		struct {
			fz_obj *obj;
		} info;
		struct {
			fz_obj *obj;
		} crypt;
		struct {
			fz_obj *obj;
			fz_rect *bbox;
		} dim;
		struct {
			fz_obj *obj;
			fz_obj *subtype;
			fz_obj *name;
		} font;
		struct {
			fz_obj *obj;
			fz_obj *width;
			fz_obj *height;
			fz_obj *bpc;
			fz_obj *filter;
			fz_obj *cs;
			fz_obj *altcs;
		} image;
		struct {
			fz_obj *obj;
			fz_obj *type;
		} shading;
		struct {
			fz_obj *obj;
			fz_obj *type;
			fz_obj *paint;
			fz_obj *tiling;
			fz_obj *shading;
		} pattern;
		struct {
			fz_obj *obj;
			fz_obj *groupsubtype;
			fz_obj *reference;
		} form;
	} u;
};

static struct info *dim = NULL;
static int dims = 0;
static struct info *font = NULL;
static int fonts = 0;
static struct info *image = NULL;
static int images = 0;
static struct info *shading = NULL;
static int shadings = 0;
static struct info *pattern = NULL;
static int patterns = 0;
static struct info *form = NULL;
static int forms = 0;
static struct info *psobj = NULL;
static int psobjs = 0;

void closexref(void)
{
	int i;
	if (xref)
	{
		pdf_free_xref(xref);
		xref = NULL;
	}

	if (dim)
	{
		for (i = 0; i < dims; i++)
			fz_free(ctx, dim[i].u.dim.bbox);
		fz_free(ctx, dim);
		dim = NULL;
		dims = 0;
	}

	if (font)
	{
		fz_free(ctx, font);
		font = NULL;
		fonts = 0;
	}

	if (image)
	{
		fz_free(ctx, image);
		image = NULL;
		images = 0;
	}

	if (shading)
	{
		fz_free(ctx, shading);
		shading = NULL;
		shadings = 0;
	}

	if (pattern)
	{
		fz_free(ctx, pattern);
		pattern = NULL;
		patterns = 0;
	}

	if (form)
	{
		fz_free(ctx, form);
		form = NULL;
		forms = 0;
	}

	if (psobj)
	{
		fz_free(ctx, psobj);
		psobj = NULL;
		psobjs = 0;
	}

	if (xref && xref->store)
	{
		pdf_free_store(ctx, xref->store);
		xref->store = NULL;
	}
}

static void
infousage(void)
{
	fprintf(stderr,
		"usage: pdfinfo [options] [file.pdf ... ]\n"
		"\t-d -\tpassword for decryption\n"
		"\t-f\tlist fonts\n"
		"\t-i\tlist images\n"
		"\t-m\tlist dimensions\n"
		"\t-p\tlist patterns\n"
		"\t-s\tlist shadings\n"
		"\t-x\tlist form and postscript xobjects\n");
	exit(1);
}

static void
showglobalinfo(void)
{
	fz_obj *obj;

	printf("\nPDF-%d.%d\n", xref->version / 10, xref->version % 10);

	obj = fz_dict_gets(ctx, xref->trailer, "Info");
	if (obj)
	{
		printf("Info object (%d %d R):\n", fz_to_num(obj), fz_to_gen(obj));
		fz_debug_obj(ctx, fz_resolve_indirect(xref->ctx, obj));
	}

	obj = fz_dict_gets(ctx, xref->trailer, "Encrypt");
	if (obj)
	{
		printf("\nEncryption object (%d %d R):\n", fz_to_num(obj), fz_to_gen(obj));
		fz_debug_obj(ctx, fz_resolve_indirect(xref->ctx, obj));
	}

	printf("\nPages: %d\n\n", pagecount);
}

static void
gatherdimensions(int page, fz_obj *pageref, fz_obj *pageobj)
{
	fz_rect bbox;
	fz_obj *obj;
	int j;

	obj = fz_dict_gets(ctx, pageobj, "MediaBox");
	if (!fz_is_array(ctx, obj))
		return;

	bbox = pdf_to_rect(ctx, obj);

	for (j = 0; j < dims; j++)
		if (!memcmp(dim[j].u.dim.bbox, &bbox, sizeof (fz_rect)))
			break;

	if (j < dims)
		return;

	dims++;

	dim = fz_realloc(ctx, dim, dims * sizeof(struct info));
	dim[dims - 1].page = page;
	dim[dims - 1].pageref = pageref;
	dim[dims - 1].pageobj = pageobj;
	dim[dims - 1].u.dim.bbox = fz_malloc(ctx, sizeof(fz_rect));
	memcpy(dim[dims - 1].u.dim.bbox, &bbox, sizeof (fz_rect));

	return;
}

static void
gatherfonts(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	int i, n;

	n = fz_dict_len(ctx, dict);
	for (i = 0; i < n; i++)
	{
		fz_obj *fontdict = NULL;
		fz_obj *subtype = NULL;
		fz_obj *basefont = NULL;
		fz_obj *name = NULL;
		int k;

		fontdict = fz_dict_get_val(ctx, dict, i);
		if (!fz_is_dict(ctx, fontdict))
		{
			fz_warn("not a font dict (%d %d R)", fz_to_num(fontdict), fz_to_gen(fontdict));
			continue;
		}

		subtype = fz_dict_gets(ctx, fontdict, "Subtype");
		basefont = fz_dict_gets(ctx, fontdict, "BaseFont");
		if (!basefont || fz_is_null(ctx, basefont))
			name = fz_dict_gets(ctx, fontdict, "Name");

		for (k = 0; k < fonts; k++)
			if (!fz_objcmp(font[k].u.font.obj, fontdict))
				break;

		if (k < fonts)
			continue;

		fonts++;

		font = fz_realloc(ctx, font, fonts * sizeof(struct info));
		font[fonts - 1].page = page;
		font[fonts - 1].pageref = pageref;
		font[fonts - 1].pageobj = pageobj;
		font[fonts - 1].u.font.obj = fontdict;
		font[fonts - 1].u.font.subtype = subtype;
		font[fonts - 1].u.font.name = basefont ? basefont : name;
	}
}

static void
gatherimages(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	int i, n;

	n = fz_dict_len(ctx, dict);
	for (i = 0; i < n; i++)
	{
		fz_obj *imagedict;
		fz_obj *type;
		fz_obj *width;
		fz_obj *height;
		fz_obj *bpc = NULL;
		fz_obj *filter = NULL;
		fz_obj *cs = NULL;
		fz_obj *altcs;
		int k;

		imagedict = fz_dict_get_val(ctx, dict, i);
		if (!fz_is_dict(ctx, imagedict))
		{
			fz_warn("not an image dict (%d %d R)", fz_to_num(imagedict), fz_to_gen(imagedict));
			continue;
		}

		type = fz_dict_gets(ctx, imagedict, "Subtype");
		if (strcmp(fz_to_name(ctx, type), "Image"))
			continue;

		filter = fz_dict_gets(ctx, imagedict, "Filter");

		altcs = NULL;
		cs = fz_dict_gets(ctx, imagedict, "ColorSpace");
		if (fz_is_array(ctx, cs))
		{
			fz_obj *cses = cs;

			cs = fz_array_get(ctx, cses, 0);
			if (fz_is_name(ctx, cs) && (!strcmp(fz_to_name(ctx, cs), "DeviceN") || !strcmp(fz_to_name(ctx, cs), "Separation")))
			{
				altcs = fz_array_get(ctx, cses, 2);
				if (fz_is_array(ctx, altcs))
					altcs = fz_array_get(ctx, altcs, 0);
			}
		}

		width = fz_dict_gets(ctx, imagedict, "Width");
		height = fz_dict_gets(ctx, imagedict, "Height");
		bpc = fz_dict_gets(ctx, imagedict, "BitsPerComponent");

		for (k = 0; k < images; k++)
			if (!fz_objcmp(image[k].u.image.obj, imagedict))
				break;

		if (k < images)
			continue;

		images++;

		image = fz_realloc(ctx, image, images * sizeof(struct info));
		image[images - 1].page = page;
		image[images - 1].pageref = pageref;
		image[images - 1].pageobj = pageobj;
		image[images - 1].u.image.obj = imagedict;
		image[images - 1].u.image.width = width;
		image[images - 1].u.image.height = height;
		image[images - 1].u.image.bpc = bpc;
		image[images - 1].u.image.filter = filter;
		image[images - 1].u.image.cs = cs;
		image[images - 1].u.image.altcs = altcs;
	}
}

static void
gatherforms(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	int i, n;

	n = fz_dict_len(ctx, dict);
	for (i = 0; i < n; i++)
	{
		fz_obj *xobjdict;
		fz_obj *type;
		fz_obj *subtype;
		fz_obj *group;
		fz_obj *groupsubtype;
		fz_obj *reference;
		int k;

		xobjdict = fz_dict_get_val(ctx, dict, i);
		if (!fz_is_dict(ctx, xobjdict))
		{
			fz_warn("not a xobject dict (%d %d R)", fz_to_num(xobjdict), fz_to_gen(xobjdict));
			continue;
		}

		type = fz_dict_gets(ctx, xobjdict, "Subtype");
		if (strcmp(fz_to_name(ctx, type), "Form"))
			continue;

		subtype = fz_dict_gets(ctx, xobjdict, "Subtype2");
		if (!strcmp(fz_to_name(ctx, subtype), "PS"))
			continue;

		group = fz_dict_gets(ctx, xobjdict, "Group");
		groupsubtype = fz_dict_gets(ctx, group, "S");
		reference = fz_dict_gets(ctx, xobjdict, "Ref");

		for (k = 0; k < forms; k++)
			if (!fz_objcmp(form[k].u.form.obj, xobjdict))
				break;

		if (k < forms)
			continue;

		forms++;

		form = fz_realloc(ctx, form, forms * sizeof(struct info));
		form[forms - 1].page = page;
		form[forms - 1].pageref = pageref;
		form[forms - 1].pageobj = pageobj;
		form[forms - 1].u.form.obj = xobjdict;
		form[forms - 1].u.form.groupsubtype = groupsubtype;
		form[forms - 1].u.form.reference = reference;
	}
}

static void
gatherpsobjs(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	int i, n;

	n = fz_dict_len(ctx, dict);
	for (i = 0; i < n; i++)
	{
		fz_obj *xobjdict;
		fz_obj *type;
		fz_obj *subtype;
		int k;

		xobjdict = fz_dict_get_val(ctx, dict, i);
		if (!fz_is_dict(ctx, xobjdict))
		{
			fz_warn("not a xobject dict (%d %d R)", fz_to_num(xobjdict), fz_to_gen(xobjdict));
			continue;
		}

		type = fz_dict_gets(ctx, xobjdict, "Subtype");
		subtype = fz_dict_gets(ctx, xobjdict, "Subtype2");
		if (strcmp(fz_to_name(ctx, type), "PS") &&
			(strcmp(fz_to_name(ctx, type), "Form") || strcmp(fz_to_name(ctx, subtype), "PS")))
			continue;

		for (k = 0; k < psobjs; k++)
			if (!fz_objcmp(psobj[k].u.form.obj, xobjdict))
				break;

		if (k < psobjs)
			continue;

		psobjs++;

		psobj = fz_realloc(ctx, psobj, psobjs * sizeof(struct info));
		psobj[psobjs - 1].page = page;
		psobj[psobjs - 1].pageref = pageref;
		psobj[psobjs - 1].pageobj = pageobj;
		psobj[psobjs - 1].u.form.obj = xobjdict;
	}
}

static void
gathershadings(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	int i, n;

	n = fz_dict_len(ctx, dict);
	for (i = 0; i < n; i++)
	{
		fz_obj *shade;
		fz_obj *type;
		int k;

		shade = fz_dict_get_val(ctx, dict, i);
		if (!fz_is_dict(ctx, shade))
		{
			fz_warn("not a shading dict (%d %d R)", fz_to_num(shade), fz_to_gen(shade));
			continue;
		}

		type = fz_dict_gets(ctx, shade, "ShadingType");
		if (!fz_is_int(ctx, type) || fz_to_int(ctx, type) < 1 || fz_to_int(ctx, type) > 7)
		{
			fz_warn("not a shading type (%d %d R)", fz_to_num(shade), fz_to_gen(shade));
			type = NULL;
		}

		for (k = 0; k < shadings; k++)
			if (!fz_objcmp(shading[k].u.shading.obj, shade))
				break;

		if (k < shadings)
			continue;

		shadings++;

		shading = fz_realloc(ctx, shading, shadings * sizeof(struct info));
		shading[shadings - 1].page = page;
		shading[shadings - 1].pageref = pageref;
		shading[shadings - 1].pageobj = pageobj;
		shading[shadings - 1].u.shading.obj = shade;
		shading[shadings - 1].u.shading.type = type;
	}
}

static void
gatherpatterns(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	int i, n;

	n = fz_dict_len(ctx, dict);
	for (i = 0; i < n; i++)
	{
		fz_obj *patterndict;
		fz_obj *type;
		fz_obj *paint = NULL;
		fz_obj *tiling = NULL;
		fz_obj *shading = NULL;
		int k;

		patterndict = fz_dict_get_val(ctx, dict, i);
		if (!fz_is_dict(ctx, patterndict))
		{
			fz_warn("not a pattern dict (%d %d R)", fz_to_num(patterndict), fz_to_gen(patterndict));
			continue;
		}

		type = fz_dict_gets(ctx, patterndict, "PatternType");
		if (!fz_is_int(ctx, type) || fz_to_int(ctx, type) < 1 || fz_to_int(ctx, type) > 2)
		{
			fz_warn("not a pattern type (%d %d R)", fz_to_num(patterndict), fz_to_gen(patterndict));
			type = NULL;
		}

		if (fz_to_int(ctx, type) == 1)
		{
			paint = fz_dict_gets(ctx, patterndict, "PaintType");
			if (!fz_is_int(ctx, paint) || fz_to_int(ctx, paint) < 1 || fz_to_int(ctx, paint) > 2)
			{
				fz_warn("not a pattern paint type (%d %d R)", fz_to_num(patterndict), fz_to_gen(patterndict));
				paint = NULL;
			}

			tiling = fz_dict_gets(ctx, patterndict, "TilingType");
			if (!fz_is_int(ctx, tiling) || fz_to_int(ctx, tiling) < 1 || fz_to_int(ctx, tiling) > 3)
			{
				fz_warn("not a pattern tiling type (%d %d R)", fz_to_num(patterndict), fz_to_gen(patterndict));
				tiling = NULL;
			}
		}
		else
		{
			shading = fz_dict_gets(ctx, patterndict, "Shading");
		}

		for (k = 0; k < patterns; k++)
			if (!fz_objcmp(pattern[k].u.pattern.obj, patterndict))
				break;

		if (k < patterns)
			continue;

		patterns++;

		pattern = fz_realloc(ctx, pattern, patterns * sizeof(struct info));
		pattern[patterns - 1].page = page;
		pattern[patterns - 1].pageref = pageref;
		pattern[patterns - 1].pageobj = pageobj;
		pattern[patterns - 1].u.pattern.obj = patterndict;
		pattern[patterns - 1].u.pattern.type = type;
		pattern[patterns - 1].u.pattern.paint = paint;
		pattern[patterns - 1].u.pattern.tiling = tiling;
		pattern[patterns - 1].u.pattern.shading = shading;
	}
}

static void
gatherresourceinfo(int page, fz_obj *rsrc)
{
	fz_obj *pageobj;
	fz_obj *pageref;
	fz_obj *font;
	fz_obj *xobj;
	fz_obj *shade;
	fz_obj *pattern;
	fz_obj *subrsrc;
	int i;

	pageobj = xref->page_objs[page-1];
	pageref = xref->page_refs[page-1];

	if (!pageobj)
		die(fz_error_make("cannot retrieve info from page %d", page));

	font = fz_dict_gets(ctx, rsrc, "Font");
	if (font)
	{
		int n;

		gatherfonts(page, pageref, pageobj, font);
		n = fz_dict_len(ctx, font);
		for (i = 0; i < n; i++)
		{
			fz_obj *obj = fz_dict_get_val(ctx, font, i);

			subrsrc = fz_dict_gets(ctx, obj, "Resources");
			if (subrsrc && fz_objcmp(rsrc, subrsrc))
				gatherresourceinfo(page, subrsrc);
		}
	}

	xobj = fz_dict_gets(ctx, rsrc, "XObject");
	if (xobj)
	{
		int n;

		gatherimages(page, pageref, pageobj, xobj);
		gatherforms(page, pageref, pageobj, xobj);
		gatherpsobjs(page, pageref, pageobj, xobj);
		n = fz_dict_len(ctx, xobj);
		for (i = 0; i < n; i++)
		{
			fz_obj *obj = fz_dict_get_val(ctx, xobj, i);
			subrsrc = fz_dict_gets(ctx, obj, "Resources");
			if (subrsrc && fz_objcmp(rsrc, subrsrc))
				gatherresourceinfo(page, subrsrc);
		}
	}

	shade = fz_dict_gets(ctx, rsrc, "Shading");
	if (shade)
		gathershadings(page, pageref, pageobj, shade);

	pattern = fz_dict_gets(ctx, rsrc, "Pattern");
	if (pattern)
	{
		int n;
		gatherpatterns(page, pageref, pageobj, pattern);
		n = fz_dict_len(ctx, pattern);
		for (i = 0; i < n; i++)
		{
			fz_obj *obj = fz_dict_get_val(ctx, pattern, i);
			subrsrc = fz_dict_gets(ctx, obj, "Resources");
			if (subrsrc && fz_objcmp(rsrc, subrsrc))
				gatherresourceinfo(page, subrsrc);
		}
	}
}

static void
gatherpageinfo(int page)
{
	fz_obj *pageobj;
	fz_obj *pageref;
	fz_obj *rsrc;

	pageobj = xref->page_objs[page-1];
	pageref = xref->page_refs[page-1];

	if (!pageobj)
		die(fz_error_make("cannot retrieve info from page %d", page));

	gatherdimensions(page, pageref, pageobj);

	rsrc = fz_dict_gets(ctx, pageobj, "Resources");
	gatherresourceinfo(page, rsrc);
}

static void
printinfo(char *filename, int show, int page)
{
	int i;
	int j;

#define PAGE_FMT "\t% 5d (% 7d %1d R): "

	if (show & DIMENSIONS && dims > 0)
	{
		printf("Mediaboxes (%d):\n", dims);
		for (i = 0; i < dims; i++)
		{
			printf(PAGE_FMT "[ %g %g %g %g ]\n",
				dim[i].page,
				fz_to_num(dim[i].pageref), fz_to_gen(dim[i].pageref),
				dim[i].u.dim.bbox->x0,
				dim[i].u.dim.bbox->y0,
				dim[i].u.dim.bbox->x1,
				dim[i].u.dim.bbox->y1);
		}
		printf("\n");
	}

	if (show & FONTS && fonts > 0)
	{
		printf("Fonts (%d):\n", fonts);
		for (i = 0; i < fonts; i++)
		{
			printf(PAGE_FMT "%s '%s' (%d %d R)\n",
				font[i].page,
				fz_to_num(font[i].pageref), fz_to_gen(font[i].pageref),
				fz_to_name(ctx, font[i].u.font.subtype),
				fz_to_name(ctx, font[i].u.font.name),
				fz_to_num(font[i].u.font.obj), fz_to_gen(font[i].u.font.obj));
		}
		printf("\n");
	}

	if (show & IMAGES && images > 0)
	{
		printf("Images (%d):\n", images);
		for (i = 0; i < images; i++)
		{
			char *cs = NULL;
			char *altcs = NULL;

			printf(PAGE_FMT "[ ",
				image[i].page,
				fz_to_num(image[i].pageref), fz_to_gen(image[i].pageref));

			if (fz_is_array(ctx, image[i].u.image.filter))
			{
				int n = fz_array_len(ctx, image[i].u.image.filter);
				for (j = 0; j < n; j++)
				{
					fz_obj *obj = fz_array_get(ctx, image[i].u.image.filter, j);
					char *filter = fz_strdup(ctx, fz_to_name(ctx, obj));

					if (strstr(filter, "Decode"))
						*(strstr(filter, "Decode")) = '\0';

					printf("%s%s",
							filter,
							j == fz_array_len(ctx, image[i].u.image.filter) - 1 ? "" : " ");
					fz_free(ctx, filter);
				}
			}
			else if (image[i].u.image.filter)
			{
				fz_obj *obj = image[i].u.image.filter;
				char *filter = fz_strdup(ctx, fz_to_name(ctx, obj));

				if (strstr(filter, "Decode"))
					*(strstr(filter, "Decode")) = '\0';

				printf("%s", filter);
				fz_free(ctx, filter);
			}
			else
				printf("Raw");

			if (image[i].u.image.cs)
			{
				cs = fz_strdup(ctx, fz_to_name(ctx, image[i].u.image.cs));

				if (!strncmp(cs, "Device", 6))
				{
					int len = strlen(cs + 6);
					memmove(cs + 3, cs + 6, len + 1);
					cs[3 + len + 1] = '\0';
				}
				if (strstr(cs, "ICC"))
					fz_strlcpy(cs, "ICC", 4);
				if (strstr(cs, "Indexed"))
					fz_strlcpy(cs, "Idx", 4);
				if (strstr(cs, "Pattern"))
					fz_strlcpy(cs, "Pat", 4);
				if (strstr(cs, "Separation"))
					fz_strlcpy(cs, "Sep", 4);
			}
			if (image[i].u.image.altcs)
			{
				altcs = fz_strdup(ctx, fz_to_name(ctx, image[i].u.image.altcs));

				if (!strncmp(altcs, "Device", 6))
				{
					int len = strlen(altcs + 6);
					memmove(altcs + 3, altcs + 6, len + 1);
					altcs[3 + len + 1] = '\0';
				}
				if (strstr(altcs, "ICC"))
					fz_strlcpy(altcs, "ICC", 4);
				if (strstr(altcs, "Indexed"))
					fz_strlcpy(altcs, "Idx", 4);
				if (strstr(altcs, "Pattern"))
					fz_strlcpy(altcs, "Pat", 4);
				if (strstr(altcs, "Separation"))
					fz_strlcpy(altcs, "Sep", 4);
			}

			printf(" ] %dx%d %dbpc %s%s%s (%d %d R)\n",
				fz_to_int(ctx, image[i].u.image.width),
				fz_to_int(ctx, image[i].u.image.height),
				image[i].u.image.bpc ? fz_to_int(ctx, image[i].u.image.bpc) : 1,
				image[i].u.image.cs ? cs : "ImageMask",
				image[i].u.image.altcs ? " " : "",
				image[i].u.image.altcs ? altcs : "",
				fz_to_num(image[i].u.image.obj), fz_to_gen(image[i].u.image.obj));

			fz_free(ctx, cs);
			fz_free(ctx, altcs);
		}
		printf("\n");
	}

	if (show & SHADINGS && shadings > 0)
	{
		printf("Shading patterns (%d):\n", shadings);
		for (i = 0; i < shadings; i++)
		{
			char *shadingtype[] =
			{
				"",
				"Function",
				"Axial",
				"Radial",
				"Triangle mesh",
				"Lattice",
				"Coons patch",
				"Tensor patch",
			};

			printf(PAGE_FMT "%s (%d %d R)\n",
				shading[i].page,
				fz_to_num(shading[i].pageref), fz_to_gen(shading[i].pageref),
				shadingtype[fz_to_int(ctx, shading[i].u.shading.type)],
				fz_to_num(shading[i].u.shading.obj), fz_to_gen(shading[i].u.shading.obj));
		}
		printf("\n");
	}

	if (show & PATTERNS && patterns > 0)
	{
		printf("Patterns (%d):\n", patterns);
		for (i = 0; i < patterns; i++)
		{
			if (fz_to_int(ctx, pattern[i].u.pattern.type) == 1)
			{
				char *painttype[] =
				{
					"",
					"Colored",
					"Uncolored",
				};
				char *tilingtype[] =
				{
					"",
					"Constant",
					"No distortion",
					"Constant/fast tiling",
				};

				printf(PAGE_FMT "Tiling %s %s (%d %d R)\n",
						pattern[i].page,
						fz_to_num(pattern[i].pageref), fz_to_gen(pattern[i].pageref),
						painttype[fz_to_int(ctx, pattern[i].u.pattern.paint)],
						tilingtype[fz_to_int(ctx, pattern[i].u.pattern.tiling)],
						fz_to_num(pattern[i].u.pattern.obj), fz_to_gen(pattern[i].u.pattern.obj));
			}
			else
			{
				printf(PAGE_FMT "Shading %d %d R (%d %d R)\n",
						pattern[i].page,
						fz_to_num(pattern[i].pageref), fz_to_gen(pattern[i].pageref),
						fz_to_num(pattern[i].u.pattern.shading), fz_to_gen(pattern[i].u.pattern.shading),
						fz_to_num(pattern[i].u.pattern.obj), fz_to_gen(pattern[i].u.pattern.obj));
			}
		}
		printf("\n");
	}

	if (show & XOBJS && forms > 0)
	{
		printf("Form xobjects (%d):\n", forms);
		for (i = 0; i < forms; i++)
		{
			printf(PAGE_FMT "Form%s%s%s%s (%d %d R)\n",
				form[i].page,
				fz_to_num(form[i].pageref), fz_to_gen(form[i].pageref),
				form[i].u.form.groupsubtype ? " " : "",
				form[i].u.form.groupsubtype ? fz_to_name(ctx, form[i].u.form.groupsubtype) : "",
				form[i].u.form.groupsubtype ? " Group" : "",
				form[i].u.form.reference ? " Reference" : "",
				fz_to_num(form[i].u.form.obj), fz_to_gen(form[i].u.form.obj));
		}
		printf("\n");
	}

	if (show & XOBJS && psobjs > 0)
	{
		printf("Postscript xobjects (%d):\n", psobjs);
		for (i = 0; i < psobjs; i++)
		{
			printf(PAGE_FMT "(%d %d R)\n",
				psobj[i].page,
				fz_to_num(psobj[i].pageref), fz_to_gen(psobj[i].pageref),
				fz_to_num(psobj[i].u.form.obj), fz_to_gen(psobj[i].u.form.obj));
		}
		printf("\n");
	}
}

static void
showinfo(char *filename, int show, char *pagelist)
{
	int page, spage, epage;
	char *spec, *dash;
	int allpages;

	if (!xref)
		infousage();

	allpages = !strcmp(pagelist, "1-");

	spec = fz_strsep(&pagelist, ",");
	while (spec)
	{
		dash = strchr(spec, '-');

		if (dash == spec)
			spage = epage = pagecount;
		else
			spage = epage = atoi(spec);

		if (dash)
		{
			if (strlen(dash) > 1)
				epage = atoi(dash + 1);
			else
				epage = pagecount;
		}

		if (spage > epage)
			page = spage, spage = epage, epage = page;

		if (spage < 1)
			spage = 1;
		if (epage > pagecount)
			epage = pagecount;
		if (spage > pagecount)
			spage = pagecount;

		if (allpages)
			printf("Retrieving info from pages %d-%d...\n", spage, epage);
		if (spage >= 1)
		{
			for (page = spage; page <= epage; page++)
			{
				gatherpageinfo(page);
				if (!allpages)
				{
					printf("Page %d:\n", page);
					printinfo(filename, show, page);
					printf("\n");
				}
			}
		}

		spec = fz_strsep(&pagelist, ",");
	}

	if (allpages)
		printinfo(filename, show, -1);
}

int main(int argc, char **argv)
{
	enum { NO_FILE_OPENED, NO_INFO_GATHERED, INFO_SHOWN } state;
	fz_error error;
	char *filename = "";
	char *password = "";
	int show = ALL;
	int c;

	while ((c = fz_getopt(argc, argv, "mfispxd:")) != -1)
	{
		switch (c)
		{
		case 'm': if (show == ALL) show = DIMENSIONS; else show |= DIMENSIONS; break;
		case 'f': if (show == ALL) show = FONTS; else show |= FONTS; break;
		case 'i': if (show == ALL) show = IMAGES; else show |= IMAGES; break;
		case 's': if (show == ALL) show = SHADINGS; else show |= SHADINGS; break;
		case 'p': if (show == ALL) show = PATTERNS; else show |= PATTERNS; break;
		case 'x': if (show == ALL) show = XOBJS; else show |= XOBJS; break;
		case 'd': password = fz_optarg; break;
		default:
			infousage();
			break;
		}
	}

	if (fz_optind == argc)
		infousage();

	ctx = fz_new_context(&fz_alloc_default);
	if (ctx == NULL)
		die(fz_error_make("failed to initialise context"));

	state = NO_FILE_OPENED;
	while (fz_optind < argc)
	{
		if (strstr(argv[fz_optind], ".pdf") || strstr(argv[fz_optind], ".PDF"))
		{
			if (state == NO_INFO_GATHERED)
			{
				showinfo(filename, show, "1-");
				closexref();
			}

			closexref();

			filename = argv[fz_optind];
			printf("%s:\n", filename);
			error = pdf_open_xref(ctx, &xref, filename, password);
			if (error)
				die(fz_error_note(error, "cannot open input file '%s'", filename));

			error = pdf_load_page_tree(xref);
			if (error)
				die(fz_error_note(error, "cannot load page tree: %s", filename));
			pagecount = pdf_count_pages(xref);

			showglobalinfo();
			state = NO_INFO_GATHERED;
		}
		else
		{
			showinfo(filename, show, argv[fz_optind]);
			state = INFO_SHOWN;
		}

		fz_optind++;
	}

	if (state == NO_INFO_GATHERED)
		showinfo(filename, show, "1-");

	closexref();
	fz_free_context(ctx);
	return 0;
}
