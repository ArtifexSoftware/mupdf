#include <fitz.h>
#include <mupdf.h>

int showtree = 0;
int showtext = 0;
float zoom = 1.0;

void usage()
{
	fprintf(stderr, "usage: pdfrip [-dt] [-p password] [-z zoom] file.pdf [pages...]\n");
	exit(1);
}

enum
{
        Bit1    = 7,
        Bitx    = 6,
        Bit2    = 5,
        Bit3    = 4,
        Bit4    = 3,

        T1      = ((1<<(Bit1+1))-1) ^ 0xFF,     /* 0000 0000 */
        Tx      = ((1<<(Bitx+1))-1) ^ 0xFF,     /* 1000 0000 */
        T2      = ((1<<(Bit2+1))-1) ^ 0xFF,     /* 1100 0000 */
        T3      = ((1<<(Bit3+1))-1) ^ 0xFF,     /* 1110 0000 */
        T4      = ((1<<(Bit4+1))-1) ^ 0xFF,     /* 1111 0000 */

        Rune1   = (1<<(Bit1+0*Bitx))-1,         /* 0000 0000 0111 1111 */
        Rune2   = (1<<(Bit2+1*Bitx))-1,         /* 0000 0111 1111 1111 */
        Rune3   = (1<<(Bit3+2*Bitx))-1,         /* 1111 1111 1111 1111 */

        Maskx   = (1<<Bitx)-1,                  /* 0011 1111 */
        Testx   = Maskx ^ 0xFF,                 /* 1100 0000 */
};

void putrune(int c)
{
	if (c <= Rune1)
	{
		putchar(c);
		return;
	}

	if (c <= Rune2)
	{
		putchar(T2 | (c >> 1*Bitx));
		putchar(Tx | (c & Maskx));
		return;
	}
		
	putchar(T3 | (c >> 2*Bitx));
	putchar(Tx | ((c >> 1*Bitx) & Maskx));
	putchar(Tx | (c & Maskx));
}

/*
 * Dump text nodes as unicode
 */
void dumptext(fz_node *node)
{
	int i, cid, ucs;
	static fz_point old = { 0, 0 };
	fz_point p;
	float dx, dy;
	fz_vmtx v;
	fz_hmtx h;

	if (fz_istextnode(node))
	{
		fz_textnode *text = (fz_textnode*)node;
		pdf_font *font = (pdf_font*)text->font;
		fz_matrix invtrm = fz_invertmatrix(text->trm);

		for (i = 0; i < text->len; i++)
		{
			cid = text->els[i].cid;
			p.x = text->els[i].x;
			p.y = text->els[i].y;
			p = fz_transformpoint(invtrm, p);
			dx = old.x - p.x;
			dy = old.y - p.y;
			old = p;

			if (fabs(dy) > 1.3)
				puts("\n");
			else if (fabs(dy) > 0.1)
				putchar('\n');
			else if (fabs(dx) > 0.1)
				putchar(' ');

			h = fz_gethmtx(text->font, cid);
			old.x += h.w / 1000.0;

			if (font->ncidtoucs)
				ucs = font->cidtoucs[cid];
			else
				ucs = cid;

			putrune(ucs);
		}
	}

	for (node = node->child; node; node = node->next)
		dumptext(node);
}

/*
 * Draw page
 */

void showpage(pdf_xref *xref, fz_obj *pageobj)
{
	fz_error *error;
	pdf_page *page;

	fz_debugobj(pageobj);
	printf("\n");

	error = pdf_loadpage(&page, xref, pageobj);
	if (error)
		fz_abort(error);

	if (showtree)
	{
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

	if (showtext)
	{
		printf("---begin text dump---\n");
		dumptext(page->tree->root);
		printf("\n---end text dump---\n");
	}

	else
	{
		fz_pixmap *pix;
		fz_renderer *gc;
		fz_matrix ctm;
		fz_rect bbox;

		error = fz_newrenderer(&gc, pdf_devicergb, 1024 * 512);
		if (error) fz_abort(error);

		ctm = fz_concat(fz_translate(0, -page->mediabox.max.y), fz_scale(zoom, -zoom));
printf("ctm %g %g %g %g %g %g\n",
	ctm.a, ctm.b, ctm.c, ctm.d, ctm.e, ctm.f);

printf("bounding!\n");
		bbox = fz_boundtree(page->tree, ctm);
printf("  [%g %g %g %g]\n", bbox.min.x, bbox.min.y, bbox.max.x, bbox.max.y);
printf("rendering!\n");
		bbox = page->mediabox;
		bbox.min.x = bbox.min.x * zoom;
		bbox.min.y = bbox.min.y * zoom;
		bbox.max.x = bbox.max.x * zoom;
		bbox.max.y = bbox.max.y * zoom;
		error = fz_rendertree(&pix, gc, page->tree, ctm, bbox);
		if (error) fz_abort(error);
printf("done!\n");

		fz_debugpixmap(pix);
		fz_droppixmap(pix);

		fz_droprenderer(gc);
	}
}

int main(int argc, char **argv)
{
	fz_error *error;
	char *filename;
	pdf_xref *xref;
	pdf_pagetree *pages;
	pdf_outlinetree *outlines;
	int c;

	char *password = "";

	while ((c = getopt(argc, argv, "dtz:p:")) != -1)
	{
		switch (c)
		{
		case 'p': password = optarg; break;
		case 'z': zoom = atof(optarg); break;
		case 'd': ++showtree; break;
		case 't': ++showtext; break;
		default: usage();
		}
	}

	if (argc - optind == 0)
		usage();

	filename = argv[optind++];

	error = pdf_openpdf(&xref, filename);
	if (error)
		fz_abort(error);

	error = pdf_decryptpdf(xref);
	if (error)
		fz_abort(error);

	if (xref->crypt)
	{
		error = pdf_setpassword(xref->crypt, password);
		if (error) fz_abort(error);
	}

	error = pdf_loadpagetree(&pages, xref);
	if (error) fz_abort(error);

	outlines = nil;
	error = pdf_loadoutlinetree(&outlines, xref);
	if (error) { fz_warn(error->msg); fz_droperror(error); }

	if (optind == argc)
	{
		printf("pagetree\n");
		pdf_debugpagetree(pages);
		printf("\n");

		if (outlines)
		{
			printf("outlines\n");
			pdf_debugoutlinetree(outlines);
			printf("\n");
		}
	}

	for ( ; optind < argc; optind++)
	{
		int page = atoi(argv[optind]);
		if (page < 1 || page > pdf_getpagecount(pages))
			fprintf(stderr, "page out of bounds: %d\n", page);
		printf("page %d\n", page);
		showpage(xref, pdf_getpageobject(pages, page - 1));
	}

	pdf_closepdf(xref);

	return 0;
}

