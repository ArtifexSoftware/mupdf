/*
 * pdfdraw -- command line tool for drawing pdf documents
 */

#include "fitz.h"
#include "mupdf.h"

#define MAXBANDSIZE (3 * 1024 * 1024)

char *output = NULL;
float resolution = 72;

int showxml = 0;
int showtext = 0;
int showtime = 0;
int savealpha = 0;

fz_glyphcache *glyphcache;
char *filename;

static void die(fz_error error)
{
	fz_catch(error, "aborting");
	exit(1);
}

static void usage(void)
{
	fprintf(stderr,
		"usage: pdfdraw [options] input.pdf [pages]\n"
		"\t-o -\toutput filename (%%d for page number)\n"
		"\t\tsupported formats: pgm, ppm, pam, png\n"
		"\t-p -\tpassword\n"
		"\t-r -\tresolution in dpi (default: 72)\n"
		"\t-x\tshow display list as xml\n"
		"\t-t\textract text (-tt for xml)\n"
		"\t-a\tsave alpha channel (only pam and png)\n"
		"\tpages\tcomma separated list of ranges\n");
	exit(1);
}

static int isrange(char *s)
{
	while (*s)
	{
		if ((*s < '0' || *s > '9') && *s != '-' && *s != ',')
			return 0;
		s++;
	}
	return 1;
}

static void drawpage(pdf_xref *xref, int pagenum)
{
	fz_error error;
	fz_obj *pageobj;
	pdf_page *page;
	fz_displaylist *list;
	fz_device *dev;
	fz_matrix ctm;
	fz_bbox bbox;
	fz_colorspace *colorspace;
	fz_pixmap *pix;
	char buf[512];
	float zoom;

	pageobj = pdf_getpageobject(xref, pagenum);
	error = pdf_loadpage(&page, xref, pageobj);
	if (error)
		die(fz_rethrow(error, "cannot load page %d in file '%s'", pagenum, filename));

	list = fz_newdisplaylist();

	dev = fz_newlistdevice(list);
	error = pdf_runpage(xref, page, dev, fz_identity);
	if (error)
		die(fz_rethrow(error, "cannot draw page %d in file '%s'", pagenum, filename));
	fz_freedevice(dev);

	if (showxml)
	{
		dev = fz_newtracedevice();
		printf("<page number=\"%d\">\n", pagenum);
		fz_executedisplaylist(list, dev, fz_identity);
		printf("</page>\n");
		fz_freedevice(dev);
	}

	if (showtext)
	{
		fz_textspan *text = fz_newtextspan();
		dev = fz_newtextdevice(text);
		fz_executedisplaylist(list, dev, fz_identity);
		fz_freedevice(dev);
		printf("[Page %d]\n", pagenum);
		if (showtext > 1)
			fz_debugtextspanxml(text);
		else
			fz_debugtextspan(text);
		printf("\n");
		fz_freetextspan(text);
	}

	if (output || showtime)
	{
		sprintf(buf, output, pagenum);

		zoom = resolution / 72;
		ctm = fz_translate(0, -page->mediabox.y1);
		ctm = fz_concat(ctm, fz_scale(zoom, -zoom));
		ctm = fz_concat(ctm, fz_rotate(page->rotate));
		bbox = fz_roundrect(fz_transformrect(ctm, page->mediabox));

		colorspace = pdf_devicergb;
		if (strstr(output, ".pgm"))
			colorspace = pdf_devicegray;

		/* TODO: banded rendering and multi-page ppm */

		pix = fz_newpixmap(colorspace, bbox.x0, bbox.y0, bbox.x1, bbox.y1);

		if (savealpha)
			fz_clearpixmap(pix, 0x00);
		else
			fz_clearpixmap(pix, 0xff);

		dev = fz_newdrawdevice(glyphcache, pix);
		fz_executedisplaylist(list, dev, ctm);
		fz_freedevice(dev);

		if (strstr(output, ".pgm") || strstr(output, ".ppm") || strstr(output, ".pnm"))
			fz_writepnm(pix, buf);
		else if (strstr(output, ".pam"))
			fz_writepam(pix, buf, savealpha);
		else if (strstr(output, ".png"))
			fz_writepng(pix, buf, savealpha);

		fz_droppixmap(pix);
	}

	fz_freedisplaylist(list);
	pdf_freepage(page);

	pdf_agestoreditems(xref->store);
	pdf_evictageditems(xref->store);
}

static void drawrange(pdf_xref *xref, char *range)
{
	int page, spage, epage;
	char *spec, *dash;

	spec = fz_strsep(&range, ",");
	while (spec)
	{
		dash = strchr(spec, '-');

		if (dash == spec)
			spage = epage = 1;
		else
			spage = epage = atoi(spec);

		if (dash)
		{
			if (strlen(dash) > 1)
				epage = atoi(dash + 1);
			else
				epage = pdf_getpagecount(xref);
		}

		spage = CLAMP(spage, 1, pdf_getpagecount(xref));
		epage = CLAMP(epage, 1, pdf_getpagecount(xref));

		if (spage < epage)
			for (page = spage; page <= epage; page++)
				drawpage(xref, page);
		else
			for (page = spage; page >= epage; page--)
				drawpage(xref, page);

		spec = fz_strsep(&range, ",");
	}
}

int main(int argc, char **argv)
{
	char *password = "";
	pdf_xref *xref;
	fz_error error;
	int c;

	fz_accelerate();

	while ((c = fz_getopt(argc, argv, "o:p:r:amtx")) != -1)
	{
		switch (c)
		{
		case 'o': output = fz_optarg; break;
		case 'p': password = fz_optarg; break;
		case 'r': resolution = atof(fz_optarg) / 72; break;
		case 'a': savealpha = 1; break;
		case 'm': showtime++; break;
		case 't': showtext++; break;
		case 'x': showxml++; break;
		default: usage(); break;
		}
	}

	if (fz_optind == argc)
		usage();

	if (showxml)
		printf("<?xml version=\"1.0\"?>\n");

	glyphcache = fz_newglyphcache();

	while (fz_optind < argc)
	{
		filename = argv[fz_optind++];

		error = pdf_openxref(&xref, filename, password);
		if (error)
			die(fz_rethrow(error, "cannot open document: %s", filename));

		if (showxml)
			printf("<document name=\"%s\">\n", filename);

		if (fz_optind == argc || !isrange(argv[fz_optind]))
			drawrange(xref, "1-");
		if (fz_optind < argc && isrange(argv[fz_optind]))
			drawrange(xref, argv[fz_optind++]);

		if (showxml)
			printf("</document>\n");

		pdf_freexref(xref);
	}

	fz_freeglyphcache(glyphcache);

	return 0;
}
