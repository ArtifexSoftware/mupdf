#include <fitz.h>
#include <mupdf.h>

static char *password = "";
static int dodecode = 0;
static int dorepair = 0;
static int doprintxref = 0;
static int doprintpages = 0;

void usage()
{
	fprintf(stderr, "usage: mupdf [-drxp] [-u password] file.pdf\n");
	exit(1);
}

/*
 * Debug-print stream contents
 */

static int safecol = 0;

void printsafe(unsigned char *buf, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (buf[i] == '\r' || buf[i] == '\n') {
			printf("\n");
			safecol = 0;
		}
		else if (buf[i] < 32 || buf[i] > 126) {
			printf(".");
			safecol ++;
		}
		else {
			printf("%c", buf[i]);
			safecol ++;
		}
		if (safecol == 79) {
			printf("\n");
			safecol = 0;
		}
	}
}

void decodestream(pdf_xref *xref, fz_obj *stream, int oid, int gid, int ofs)
{
	fz_error *error;
	unsigned char buf[512];

	safecol = 0;

	error = pdf_openstream0(xref, stream, oid, gid, ofs);
	if (error) fz_abort(error);

	while (1)
	{
		int n = fz_read(xref->file, buf, sizeof buf);
		if (n == 0)
			break;
		if (n < 0)
			fz_abort(fz_ferror(xref->file));
		printsafe(buf, n);
	}

	pdf_closestream(xref);
}

void copystream(pdf_xref *xref, fz_obj *stream, int ofs)
{
	fz_error *error;
	unsigned char buf[512];
	fz_filter *filter;
	fz_obj *obj;
	int len;

	safecol = 0;

	obj = fz_dictgets(stream, "Length");
	error = pdf_resolve(&obj, xref);
	if (error) fz_abort(error);
	len = fz_toint(obj);
	fz_dropobj(obj);

	error = fz_newnullfilter(&filter, len);
	if (error) fz_abort(error);

	fz_seek(xref->file, ofs);

	error = fz_pushfilter(xref->file, filter);
	if (error) fz_abort(error);

	while (1)
	{
		int n = fz_read(xref->file, buf, sizeof buf);
		if (n == 0)
			break;
		if (n < 0)
			fz_abort(fz_ferror(xref->file));
		printsafe(buf, n);
	}

	fz_popfilter(xref->file);
}

void printobject(pdf_xref *xref, int oid, int gid)
{
	fz_error *error;
	int stmofs;
	fz_obj *obj;

	error = pdf_loadobject0(&obj, xref, oid, gid, &stmofs);
	if (error) fz_abort(error);

	printf("%d %d obj\n", oid, gid);
	fz_fprintobj(stdout, obj);
	printf("\n");
	if (stmofs != -1) {
		printf("stream\n");
		if (dodecode)
			decodestream(xref, obj, oid, gid, stmofs);
		else
			copystream(xref, obj, stmofs);
		printf("endstream\n");
	}
	printf("endobj\n");

	fz_dropobj(obj);
}

/*
 * Draw page
 */

void runcsi(pdf_xref *xref, pdf_csi *csi, pdf_resources *rdb, fz_obj *stmref)
{
	fz_error *error;

	error = pdf_openstream(xref, stmref);
	if (error) fz_abort(error);

	error = pdf_runcsi(csi, rdb, xref->file);
	if (error) fz_abort(error);

	pdf_closestream(xref);
}

void showpage(pdf_xref *xref, fz_obj *page)
{
	fz_error *error;
	pdf_csi *csi;
	pdf_resources *rdb = nil;
	fz_obj *resources;
	fz_obj *contents;
	int i;

	fz_fprintobj(stdout, page);
	printf("\n");

	resources = fz_dictgets(page, "Resources");
	if (resources)
	{
		error = pdf_resolve(&resources, xref);
		if (error) fz_abort(error);

		error = pdf_loadresources(&rdb, xref, resources);
		if (error) fz_abort(error);

		// parse resources into native res dict
		fz_dropobj(resources);
	}
	else
		fz_abort(fz_throw("syntaxerror: missing resource dictionary"));

printf("resources:\n");
printf("  font:\n");
fz_fprintobj(stdout, rdb->font);
printf("\n  extgstate:\n");
fz_fprintobj(stdout, rdb->extgstate);
printf("\nfitz tree:\n");

	error = pdf_newcsi(&csi);
	if (error) fz_abort(error);

	contents = fz_dictgets(page, "Contents");
	if (contents)
	{
		if (fz_isarray(contents))
		{
			for (i = 0; i < fz_arraylen(contents); i++)
			{
				runcsi(xref, csi, rdb, fz_arrayget(contents, i));
			}
		}
		else
		{
			// XXX resolve and check if it is an array
			runcsi(xref, csi, rdb, contents);
		}
	}

	fz_debugtree(csi->tree);

	{
		fz_pixmap *pix;
		fz_renderer *gc;
		fz_matrix ctm;

#define W 612
#define H 792

#define xW 1106
#define xH 1548

		fz_newrenderer(&gc);
		fz_newpixmap(&pix, 0, 0, W, H, 1, 0);
		ctm = fz_concat(fz_translate(0, -H), fz_scale(1,-1));

		memset(pix->samples, 0x00, pix->stride * pix->h * 2);

printf("rendering!\n");
		fz_rendernode(gc, csi->tree->root, ctm, pix);
printf("done!\n");
		fz_debugpixmap(pix);

		fz_freepixmap(pix);
		fz_freerenderer(gc);
	}

	pdf_freecsi(csi);
}

int main(int argc, char **argv)
{
	fz_error *error;
	char *filename;
	pdf_xref *xref;
	pdf_pagetree *pages;
	int c;

	while ((c = getopt(argc, argv, "drxopu:")) != -1)
	{
		switch (c)
		{
		case 'd':
			dodecode ++;
			break;
		case 'r':
			dorepair ++;
			break;
		case 'x':
			doprintxref ++;
			break;
		case 'p':
			doprintpages ++;
			break;
		case 'u':
			password = optarg;
			break;
		default:
			usage();
		}
	}

	if (argc - optind == 0)
		usage();

	filename = argv[optind++];

	error = pdf_newxref(&xref);
	if (error)
		fz_abort(error);

	if (dorepair)
		error = pdf_repairxref(xref, filename);
	else
		error = pdf_openxref(xref, filename);
	if (error)
		fz_abort(error);

	error = pdf_decryptxref(xref);
	if (error)
		fz_abort(error);

	if (xref->crypt)
	{
		error = pdf_setpassword(xref->crypt, password);
		if (error) fz_abort(error);
	}

	if (doprintxref)
		pdf_debugxref(xref);

	if (doprintpages)
	{
		error = pdf_loadpagetree(&pages, xref);
		if (error) fz_abort(error);

		if (optind == argc)
		{
			printf("pagetree\n");
			pdf_debugpagetree(pages);
			printf("\n");
		}
		else
		{
			for ( ; optind < argc; optind++)
			{
				int page = atoi(argv[optind]);
				if (page < 1 || page > pages->count)
					fprintf(stderr, "page out of bounds: %d\n", page);
				printf("page %d\n", page);
				showpage(xref, pages->pobj[page - 1]);
			}
		}
	}

	else
	{
		if (optind == argc)
		{
			printf("trailer\n");
			fz_fprintobj(stdout, xref->trailer);
			printf("\n");
		}

		for ( ; optind < argc; optind++)
		{
			printobject(xref, atoi(argv[optind]), 0);
			printf("\n");
		}
	}

	pdf_closexref(xref);

	return 0;
}

