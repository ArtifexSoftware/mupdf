#include <fitz.h>
#include <mupdf.h>

int showtree = 0;
float zoom = 1.0;
char *namefmt = "out-%02d.ppm";
fz_renderer *gc;
int nbands = 1;

void usage()
{
	fprintf(stderr, "usage: pdfrip [-d] [-b bands] [-o out-%%02d.ppm] [-p password] [-z zoom] file.pdf pages...\n");
	exit(1);
}

/*
 * Draw page
 */

void showpage(pdf_xref *xref, fz_obj *pageobj, int pagenum)
{
	fz_error *error;
	pdf_page *page;
	char namebuf[256];
	fz_pixmap *pix;
	fz_matrix ctm;
	fz_irect bbox;
	fz_irect band;
	FILE *f;
	int x, y;
	int w, h;
	int b;

	sprintf(namebuf, namefmt, pagenum);

	error = pdf_loadpage(&page, xref, pageobj);
	if (error)
		fz_abort(error);

	if (showtree)
	{
		fz_debugobj(pageobj);
		printf("\n");

		printf("page\n");
		printf("  mediabox [ %g %g %g %g ]\n",
			page->mediabox.min.x, page->mediabox.min.y,
			page->mediabox.max.x, page->mediabox.max.y);
		printf("  rotate %d\n", page->rotate);

		printf("  resources\n");
		fz_debugobj(page->resources);
		printf("\n");

		printf("tree\n");
		fz_debugtree(page->tree);
		printf("endtree\n");
	}

	ctm = fz_concat(fz_translate(0, -page->mediabox.max.y),
					fz_scale(zoom, -zoom));

	bbox = fz_roundrect(page->mediabox);
	bbox.min.x = bbox.min.x * zoom;
	bbox.min.y = bbox.min.y * zoom;
	bbox.max.x = bbox.max.x * zoom;
	bbox.max.y = bbox.max.y * zoom;
	w = bbox.max.x - bbox.min.x;
	h = bbox.max.y - bbox.min.y;

	f = fopen(namebuf, "wb");
	fprintf(f, "P6\n%d %d\n255\n", w, h);

	for (b = 0; b < nbands; b++)
	{
		printf("band %d / %d\n", b, nbands);

		band.min.x = bbox.min.x;
		band.max.x = bbox.max.x;
		band.min.y = bbox.min.y + (h * b) / nbands;
		band.max.y = bbox.min.y + (h * (b + 1)) / nbands;

		error = fz_rendertree(&pix, gc, page->tree, ctm, band, 1);
		if (error)
			fz_abort(error);

		for (y = 0; y < pix->h; y++)
		{
			for (x = 0; x < pix->w; x++)
			{
				putc(pix->samples[y * pix->w * 4 + x * 4 + 1], f);
				putc(pix->samples[y * pix->w * 4 + x * 4 + 2], f);
				putc(pix->samples[y * pix->w * 4 + x * 4 + 3], f);
			}
		}

		fz_droppixmap(pix);
	}

	fclose(f);

}

int main(int argc, char **argv)
{
	fz_error *error;
	char *filename;
	pdf_xref *xref;
	pdf_pagetree *pages;
	int c;

	char *password = "";

	fz_cpudetect();
	fz_accelerate();

	while ((c = getopt(argc, argv, "dz:p:o:b:")) != -1)
	{
		switch (c)
		{
		case 'p': password = optarg; break;
		case 'z': zoom = atof(optarg); break;
		case 'd': ++showtree; break;
		case 'o': namefmt = optarg; break;
		case 'b': nbands = atoi(optarg); break;
		default: usage();
		}
	}

	if (argc - optind == 0)
		usage();

	filename = argv[optind++];
	
	error = pdf_newxref(&xref);
	if (error)
		fz_abort(error);

	error = pdf_loadxref(xref, filename);
	if (error)
		fz_abort(error);

	error = pdf_decryptxref(xref);
	if (error)
		fz_abort(error);

	if (xref->crypt)
	{
		error = pdf_setpassword(xref->crypt, password);
		if (error)
			fz_abort(error);
	}

	error = pdf_loadpagetree(&pages, xref);
	if (error)
		fz_abort(error);

	if (optind == argc)
	{
		printf("number of pages: %d\n", pdf_getpagecount(pages));
	}

	error = fz_newrenderer(&gc, pdf_devicergb, 0, 1024 * 512);
	if (error)
		fz_abort(error);

	for ( ; optind < argc; optind++)
	{
		int page = atoi(argv[optind]);
		if (page < 1 || page > pdf_getpagecount(pages))
			fprintf(stderr, "page out of bounds: %d\n", page);
		printf("page %d\n", page);
		showpage(xref, pdf_getpageobject(pages, page - 1), page);
	}

	fz_droprenderer(gc);

	pdf_closexref(xref);

	return 0;
}

