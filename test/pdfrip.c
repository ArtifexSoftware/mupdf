#include <fitz.h>
#include <mupdf.h>

void usage()
{
	fprintf(stderr, "usage: pdfrip [-r] [-p password] file.pdf [pages...]\n");
	exit(1);
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

	fz_debugobj(page);
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
fz_debugobj(rdb->font);
printf("\n  extgstate:\n");
fz_debugobj(rdb->extgstate);
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

	char *password = "";
	int dorepair = 0;

	while ((c = getopt(argc, argv, "rp:")) != -1)
	{
		switch (c)
		{
		case 'r': dorepair ++; break;
		case 'p': password = optarg; break;
		default: usage();
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

	error = pdf_loadpagetree(&pages, xref);
	if (error) fz_abort(error);

	if (optind == argc)
	{
		printf("pagetree\n");
		pdf_debugpagetree(pages);
		printf("\n");
	}

	for ( ; optind < argc; optind++)
	{
		int page = atoi(argv[optind]);
		if (page < 1 || page > pages->count)
			fprintf(stderr, "page out of bounds: %d\n", page);
		printf("page %d\n", page);
		showpage(xref, pages->pobj[page - 1]);
	}

	pdf_closexref(xref);

	return 0;
}

