/*
 * Swiss army knife for manipulating and debugging PDFs.
 *
 * There are a few major modes of operation:
 *
 *   show -- pretty-print objects and streams
 *   draw -- render pages to bitmap
 *   clean -- simple rewrite of pdf file
 *   edit -- edit pages (impose and copy operations)
 */

#include "fitz.h"
#include "mupdf.h"

#ifdef _MSC_VER
#include <winsock2.h>
#else
#include <sys/time.h>
#endif

/* put these up here so we can clean up in die() */
fz_renderer *drawgc = nil;
void closesrc(void);

/*
 * Common operations.
 * Parse page selectors.
 * Load and decrypt a PDF file.
 * Select pages.
 */

char *srcname = "(null)";
pdf_xref *src = nil;
pdf_outline *srcoutline = nil;
pdf_pagetree *srcpages = nil;

void die(fz_error *eo)
{
	fflush(stdout);
	fz_printerror(eo);
	fz_droperror(eo);
	fflush(stderr);
	if (drawgc)
		fz_droprenderer(drawgc);
	closesrc();
	abort();
}

void closesrc(void)
{
	if (srcpages)
	{
		pdf_droppagetree(srcpages);
		srcpages = nil;
	}

	if (src)
	{
		if (src->store)
		{
			pdf_dropstore(src->store);
			src->store = nil;
		}
		pdf_closexref(src);
		src = nil;
	}

	srcname = nil;
}

void opensrc(char *filename, char *password, int loadpages)
{
	fz_error *error;
	fz_obj *obj;

	closesrc();

	srcname = filename;

	error = pdf_newxref(&src);
	if (error)
		die(error);

	error = pdf_loadxref(src, filename);
	if (error)
	{
		fz_printerror(error);
		fz_droperror(error);
		fz_warn("trying to repair");
		error = pdf_repairxref(src, filename);
		if (error)
			die(error);
	}

	error = pdf_decryptxref(src);
	if (error)
		die(error);

	if (src->crypt)
	{
		int okay = pdf_setpassword(src->crypt, password);
		if (!okay)
			die(fz_throw("invalid password"));
	}

	if (loadpages)
	{
		error = pdf_loadpagetree(&srcpages, src);
		if (error)
			die(error);
	}

	/* TODO: move into mupdf lib, see pdfapp_open in pdfapp.c */
	obj = fz_dictgets(src->trailer, "Root");
	if (!obj)
		die(error);

	error = pdf_loadindirect(&src->root, src, obj);
	if (error)
		die(error);

	obj = fz_dictgets(src->trailer, "Info");
	if (obj)
	{
		error = pdf_loadindirect(&src->info, src, obj);
		if (error)
			die(error);
	}

	error = pdf_loadnametrees(src);
	if (error)
		die(error);

	error = pdf_loadoutline(&srcoutline, src);
	if (error)
		die(error);
}

void preloadobjstms(void)
{
	fz_error *error;
	fz_obj *obj;
	int i;

	for (i = 0; i < src->len; i++)
	{
		if (src->table[i].type == 'o')
		{
			error = pdf_loadobject(&obj, src, i, 0);
			if (error) die(error);
			fz_dropobj(obj);
		}
	}
}

/* --------------------------------------------------------------------- */

/*
 * Debug print parts of the PDF.
 */

int showbinary = 0;
int showdecode = 0;
int showcolumn;

void showusage(void)
{
	fprintf(stderr, "usage: mupdftool show [-bd] <file> [xref] [trailer] [object numbers]\n");
	fprintf(stderr, "  -b  \tprint streams as raw binary data\n");
	fprintf(stderr, "  -d  \tdecode streams\n");
	exit(1);
}

void showtrailer(void)
{
	if (!src)
		die(fz_throw("no file specified"));
	printf("trailer\n");
	fz_debugobj(src->trailer);
	printf("\n");
}

void showxref(void)
{
	if (!src)
		die(fz_throw("no file specified"));
	pdf_debugxref(src);
	printf("\n");
}

void showsafe(unsigned char *buf, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (buf[i] == '\r' || buf[i] == '\n') {
			putchar('\n');
			showcolumn = 0;
		}
		else if (buf[i] < 32 || buf[i] > 126) {
			putchar('.');
			showcolumn ++;
		}
		else {
			putchar(buf[i]);
			showcolumn ++;
		}
		if (showcolumn == 79) {
			putchar('\n');
			showcolumn = 0;
		}
	}
}

void showstream(int num, int gen)
{
	fz_error *error;
	fz_stream *stm;
	unsigned char buf[2048];
	int n;

	showcolumn = 0;

	if (showdecode)
		error = pdf_openstream(&stm, src, num, gen);
	else
		error = pdf_openrawstream(&stm, src, num, gen);
	if (error)
		die(error);

	while (1)
	{
		error = fz_read(&n, stm, buf, sizeof buf);
		if (error)
			die(error);
		if (n == 0)
			break;
		if (showbinary)
			fwrite(buf, 1, n, stdout);
		else
			showsafe(buf, n);
	}

	fz_dropstream(stm);
}

void showobject(int num, int gen)
{
	fz_error *error;
	fz_obj *obj;

	if (!src)
		die(fz_throw("no file specified"));

	error = pdf_loadobject(&obj, src, num, gen);
	if (error)
		die(error);

	printf("%d %d obj\n", num, gen);
	fz_debugobj(obj);

	if (pdf_isstream(src, num, gen))
	{
		printf("stream\n");
		showstream(num, gen);
		printf("endstream\n");
	}

	printf("endobj\n\n");

	fz_dropobj(obj);
}

void
showmain(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "bd")) != -1)
	{
		switch (c)
		{
		case 'b': showbinary ++; break;
		case 'd': showdecode ++; break;
		default:
			  showusage();
			  break;
		}
	}

	if (optind == argc)
		showusage();

	opensrc(argv[optind++], "", 0);

	if (optind == argc)
		showtrailer();

	while (optind < argc)
	{
		if (!strcmp(argv[optind], "trailer"))
			showtrailer();
		else if (!strcmp(argv[optind], "xref"))
			showxref();
		else
			showobject(atoi(argv[optind]), 0);
		optind++;
	}
}

/* --------------------------------------------------------------------- */

/*
 * Clean tool.
 * Rewrite PDF.
 * Garbage collect.
 * Decompress streams.
 * Encrypt or decrypt.
 */

void
cleanusage(void)
{
	fprintf(stderr,
			"usage: mupdftool clean [options] input.pdf [outfile.pdf]\n"
			"  -d -\tpassword for decryption\n"
			"  -g  \tgarbage collect unused objects\n"
			"  -x  \texpand compressed streams\n"
			"  -e  \tencrypt output\n"
			"    -u -\tset user password for encryption\n"
			"    -o -\tset owner password\n"
			"    -p -\tset permissions (combine letters 'pmca')\n"
			"    -n -\tkey length in bits: 40 <= n <= 128\n");
	exit(1);
}

void
cleanexpand(void)
{
	fz_error *error;
	fz_obj *stmobj;
	fz_buffer *buf;
	fz_obj *stmlen;
	int i, gen;

	for (i = 0; i < src->len; i++)
	{
		if (src->table[i].type == 'n')
		{
			gen = src->table[i].gen;

			if (pdf_isstream(src, i, gen))
			{
				error = pdf_loadobject(&stmobj, src, i, gen);
				if (error) die(error);

				error = pdf_loadstream(&buf, src, i, gen);
				if (error) die(error);

				fz_dictdels(stmobj, "Filter");
				fz_dictdels(stmobj, "DecodeParms");

				error = fz_newint(&stmlen, buf->wp - buf->rp);
				if (error) die(error);
				error = fz_dictputs(stmobj, "Length", stmlen);
				if (error) die(error);
				fz_dropobj(stmlen);

				pdf_updateobject(src, i, gen, stmobj);
				pdf_updatestream(src, i, gen, buf);

				fz_dropobj(stmobj);
			}
		}
	}
}

void
cleanmain(int argc, char **argv)
{
	int doencrypt = 0;
	int dogarbage = 0;
	int doexpand = 0;
	pdf_crypt *encrypt = nil;
	char *infile;
	char *outfile = "out.pdf";
	char *userpw = "";
	char *ownerpw = "";
	unsigned perms = 0xfffff0c0;	/* nothing allowed */
	int keylen = 40;
	char *password = "";
	fz_error *error;
	int c;

	while ((c = getopt(argc, argv, "d:egn:o:p:u:x")) != -1)
	{
		switch (c)
		{
		case 'p':
			/* see TABLE 3.15 User access permissions */
			perms = 0xfffff0c0;
			if (strchr(optarg, 'p')) /* print */
				perms |= (1 << 2) | (1 << 11);
			if (strchr(optarg, 'm')) /* modify */
				perms |= (1 << 3) | (1 << 10);
			if (strchr(optarg, 'c')) /* copy */
				perms |= (1 << 4) | (1 << 9);
			if (strchr(optarg, 'a')) /* annotate / forms */
				perms |= (1 << 5) | (1 << 8);
			break;
		case 'd': password = optarg; break;
		case 'e': doencrypt ++; break;
		case 'g': dogarbage ++; break;
		case 'n': keylen = atoi(optarg); break;
		case 'o': ownerpw = optarg; break;
		case 'u': userpw = optarg; break;
		case 'x': doexpand ++; break;
		default: cleanusage(); break;
		}
	}

	if (argc - optind < 1)
		cleanusage();

	infile = argv[optind++];
	if (argc - optind > 0)
		outfile = argv[optind++];

	opensrc(infile, password, 0);

	if (doencrypt)
	{
		fz_obj *id = fz_dictgets(src->trailer, "ID");
		if (!id)
		{
			error = fz_packobj(&id, "[(ABCDEFGHIJKLMNOP)(ABCDEFGHIJKLMNOP)]");
			if (error)
				die(error);
		}
		else
			fz_keepobj(id);

		error = pdf_newencrypt(&encrypt, userpw, ownerpw, perms, keylen, id);
		if (error)
			die(error);

		fz_dropobj(id);
	}

	if (doexpand)
		cleanexpand();

	if (dogarbage)
	{
		preloadobjstms();
		pdf_garbagecollect(src);
	}

	error = pdf_savexref(src, outfile, encrypt);
	if (error)
		die(error);

	if (encrypt)
		pdf_dropcrypt(encrypt);

	pdf_closexref(src);
}


/* --------------------------------------------------------------------- */

/*
 * Draw pages to PPM bitmaps.
 */

enum { DRAWPNM, DRAWTXT, DRAWXML };

struct benchmark
{
    int pages;
    long min;
    int minpage;
    long avg;
    long max;
    int maxpage;
};

int drawmode = DRAWPNM;
char *drawpattern = nil;
pdf_page *drawpage = nil;
float drawzoom = 1.0;
int drawrotate = 0;
int drawbands = 1;
int drawcount = 0;
int benchmark = 0;

void
drawusage(void)
{
	fprintf(stderr,
			"usage: mupdftool draw [options] [file.pdf pages ... ]\n"
			"  -b -\tdraw page in N bands\n"
			"  -d -\tpassword for decryption\n"
			"  -o -\tpattern (%%d for page number) for output file\n"
			"  -r -\tresolution in dpi\n"
			"  -t  \tutf-8 text output instead of graphics\n"
			"  -x  \txml dump of display tree\n"
			"  -m  \tprint benchmark results\n"
			"  example:\n"
			"    mupdftool draw -o out%%03d.pnm a.pdf 1-3,5,9-\n");
	exit(1);
}

void
gettime(long *time_)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) < 0)
	    abort();

    *time_ = tv.tv_sec * 1000000 + tv.tv_usec;
}

void
drawloadpage(int pagenum, struct benchmark *loadtimes)
{
	fz_error *error;
	fz_obj *pageobj;
	long start;
	long end;
	long elapsed;

	char *basename;

	basename = strrchr(srcname, '/');
	if (!basename)
	    basename = srcname;
	else
	    basename ++;

	fprintf(stderr, "draw %s:%03d ", basename, pagenum);
	if (benchmark && loadtimes)
	{
		fflush(stderr);
		gettime(&start);
	}

	pageobj = pdf_getpageobject(srcpages, pagenum - 1);
	error = pdf_loadpage(&drawpage, src, pageobj);
	if (error)
		die(error);

	if (benchmark && loadtimes)
	{
	    gettime(&end);
	    elapsed = end - start;

	    if (elapsed < loadtimes->min)
	    {
		loadtimes->min = elapsed;
		loadtimes->minpage = pagenum;
	    }
	    if (elapsed > loadtimes->max)
	    {
		loadtimes->max = elapsed;
		loadtimes->maxpage = pagenum;
	    }
	    loadtimes->avg += elapsed;
	    loadtimes->pages++;
	}

	if (benchmark)
		fflush(stderr);
}

void
drawfreepage(void)
{
	pdf_droppage(drawpage);
	drawpage = nil;

	/* Flush resources between pages.
	 * TODO: should check memory usage before deciding to do this.
	 */
	if (src && src->store)
	{
		fflush(stderr);
		/* pdf_debugstore(src->store); */
		pdf_emptystore(src->store);
	}
}

void
drawpnm(int pagenum, struct benchmark *loadtimes, struct benchmark *drawtimes)
{
	fz_error *error;
	fz_matrix ctm;
	fz_irect bbox;
	fz_pixmap *pix;
	char name[256];
	char pnmhdr[256];
	int i, x, y, w, h, b, bh;
	int fd = -1;
	long start;
	long end;
	long elapsed;

	fz_md5 digest;

	fz_md5init(&digest);

	drawloadpage(pagenum, loadtimes);

	if (benchmark)
		gettime(&start);

	ctm = fz_identity();
	ctm = fz_concat(ctm, fz_translate(0, -drawpage->mediabox.y1));
	ctm = fz_concat(ctm, fz_scale(drawzoom, -drawzoom));
	ctm = fz_concat(ctm, fz_rotate(drawrotate + drawpage->rotate));

	bbox = fz_roundrect(fz_transformaabb(ctm, drawpage->mediabox));
	w = bbox.x1 - bbox.x0;
	h = bbox.y1 - bbox.y0;
	bh = h / drawbands;

	if (drawpattern)
	{
		sprintf(name, drawpattern, drawcount++);
		fd = open(name, O_BINARY|O_WRONLY|O_CREAT|O_TRUNC, 0666);
		if (fd < 0)
			die(fz_throw("ioerror: could not open file '%s'", name));

		sprintf(pnmhdr, "P6\n%d %d\n255\n", w, h);
		write(fd, pnmhdr, strlen(pnmhdr));
	}

	error = fz_newpixmap(&pix, bbox.x0, bbox.y0, w, bh, 4);
	if (error)
		die(error);

	memset(pix->samples, 0xff, pix->h * pix->w * pix->n);

	for (b = 0; b < drawbands; b++)
	{
		if (drawbands > 1)
			fprintf(stderr, "drawing band %d / %d\n", b + 1, drawbands);

		error = fz_rendertreeover(drawgc, pix, drawpage->tree, ctm);
		if (error)
			die(error);

		if (drawpattern)
		{
			for (y = 0; y < pix->h; y++)
			{
				unsigned char *src = pix->samples + y * pix->w * 4;
				unsigned char *dst = src;

				for (x = 0; x < pix->w; x++)
				{
					dst[x * 3 + 0] = src[x * 4 + 1];
					dst[x * 3 + 1] = src[x * 4 + 2];
					dst[x * 3 + 2] = src[x * 4 + 3];
				}

				write(fd, dst, pix->w * 3);

				memset(src, 0xff, pix->w * 4);
			}
		}

		fz_md5update(&digest, pix->samples, pix->h * pix->w * 4);

		pix->y += bh;
		if (pix->y + pix->h > bbox.y1)
			pix->h = bbox.y1 - pix->y;
	}

	fz_droppixmap(pix);

	{
	    unsigned char buf[16];
	    fz_md5final(&digest, buf);
	    for (i = 0; i < 16; i++)
		fprintf(stderr, "%02x", buf[i]);
	}

	if (drawpattern)
		close(fd);

	drawfreepage();

	if (benchmark)
	{
	    gettime(&end);
	    elapsed = end - start;

	    if (elapsed < drawtimes->min)
	    {
		drawtimes->min = elapsed;
		drawtimes->minpage = pagenum;
	    }
	    if (elapsed > drawtimes->max)
	    {
		drawtimes->max = elapsed;
		drawtimes->maxpage = pagenum;
	    }
	    drawtimes->avg += elapsed;
	    drawtimes->pages++;

	    fprintf(stderr, " time %.3fs",
		    elapsed / 1000000.0);
	}

	fprintf(stderr, "\n");
}

void
drawtxt(int pagenum)
{
#if 0 /* removed temporarily pending rewrite of pdf_loadtextfromtree */
	fz_error *error;
	pdf_textline *line;
	fz_matrix ctm;

	drawloadpage(pagenum, NULL);

	ctm = fz_concat(
			fz_translate(0, -drawpage->mediabox.y1),
			fz_scale(drawzoom, -drawzoom));

	error = pdf_loadtextfromtree(&line, drawpage->tree, ctm);
	if (error)
		die(error);

	pdf_debugtextline(line);
	pdf_droptextline(line);

	drawfreepage();
#endif
}

void
drawxml(int pagenum)
{
	drawloadpage(pagenum, NULL);
	fz_debugtree(drawpage->tree);
	drawfreepage();
}

void
drawpages(char *pagelist)
{
	int page, spage, epage;
	char *spec, *dash;
	struct benchmark loadtimes, drawtimes;

	if (!src)
		drawusage();

	if (benchmark)
	{
		memset(&loadtimes, 0x00, sizeof (loadtimes));
		loadtimes.min = LONG_MAX;
		memset(&drawtimes, 0x00, sizeof (drawtimes));
		drawtimes.min = LONG_MAX;
	}

	spec = strsep(&pagelist, ",");
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
				epage = pdf_getpagecount(srcpages);
		}

		if (spage > epage)
			page = spage, spage = epage, epage = page;

		if (spage < 1)
			spage = 1;
		if (epage > pdf_getpagecount(srcpages))
			epage = pdf_getpagecount(srcpages);

		printf("Drawing pages %d-%d...\n", spage, epage);
		for (page = spage; page <= epage; page++)
		{
			switch (drawmode)
			{
			case DRAWPNM: drawpnm(page, &loadtimes, &drawtimes); break;
			case DRAWTXT: drawtxt(page); break;
			case DRAWXML: drawxml(page); break;
			}
		}

		spec = strsep(&pagelist, ",");
	}

	if (benchmark)
	{
		if (loadtimes.pages > 0)
		{
			loadtimes.avg /= loadtimes.pages;
			drawtimes.avg /= drawtimes.pages;

			printf("benchmark[load]: min: %6.3fs (page % 4d), avg: %6.3fs, max: %6.3fs (page % 4d)\n",
				loadtimes.min / 1000000.0, loadtimes.minpage,
				loadtimes.avg / 1000000.0,
				loadtimes.max / 1000000.0, loadtimes.maxpage);
			printf("benchmark[draw]: min: %6.3fs (page % 4d), avg: %6.3fs, max: %6.3fs (page % 4d)\n",
				drawtimes.min / 1000000.0, drawtimes.minpage,
				drawtimes.avg / 1000000.0,
				drawtimes.max / 1000000.0, drawtimes.maxpage);
		}
	}
}

void
drawmain(int argc, char **argv)
{
	fz_error *error;
	char *password = "";
	int c;
	enum { NO_FILE_OPENED, NO_PAGES_DRAWN, DREW_PAGES } state;

	while ((c = getopt(argc, argv, "b:d:o:r:txm")) != -1)
	{
		switch (c)
		{
		case 'b': drawbands = atoi(optarg); break;
		case 'd': password = optarg; break;
		case 'o': drawpattern = optarg; break;
		case 'r': drawzoom = atof(optarg) / 72.0; break;
		case 't': drawmode = DRAWTXT; break;
		case 'x': drawmode = DRAWXML; break;
		case 'm': benchmark = 1; break;
		default:
			  drawusage();
			  break;
		}
	}

	if (optind == argc)
		drawusage();

	error = fz_newrenderer(&drawgc, pdf_devicergb, 0, 1024 * 512);
	if (error)
		die(error);

	state = NO_FILE_OPENED;
	while (optind < argc)
	{
		if (strstr(argv[optind], ".pdf") ||
		    strstr(argv[optind], ".PDF"))
		{
			if (state == NO_PAGES_DRAWN)
				drawpages("1-");

			opensrc(argv[optind], password, 1);
			state = NO_PAGES_DRAWN;
		}
		else
		{
			drawpages(argv[optind]);
			state = DREW_PAGES;
		}
		optind++;
	}

	if (state == NO_PAGES_DRAWN)
		drawpages("1-");

	closesrc();

	fz_droprenderer(drawgc);
}

/* --------------------------------------------------------------------- */

/*
 * Information tool.
 * Print some information on input pdf.
 */

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
	fz_obj *ref;
	union {
		struct {
			fz_obj *obj;
		} info;
		struct {
			fz_rect *bbox;
		} dim;
		struct {
			fz_obj *subtype;
			fz_obj *name;
		} font;
		struct {
			fz_obj *width;
			fz_obj *height;
			fz_obj *bpc;
			fz_obj *filter;
			fz_obj *cs;
			fz_obj *altcs;
		} image;
		struct {
			fz_obj *type;
		} shading;
		struct {
			fz_obj *pattern;
			fz_obj *paint;
			fz_obj *tiling;
		} pattern;
		struct {
			fz_obj *group;
			fz_obj *reference;
		} form;
	} u;
};

struct info *info = nil;
struct info **dim = nil;
int dims = 0;
struct info **font = nil;
int fonts = 0;
struct info **image = nil;
int images = 0;
struct info **shading = nil;
int shadings = 0;
struct info **pattern = nil;
int patterns = 0;
struct info **form = nil;
int forms = 0;
struct info **psobj = nil;
int psobjs = 0;

void
infousage(void)
{
	fprintf(stderr,
			"usage: mupdftool info [options] [file.pdf ... ]\n"
			"  -d -\tpassword for decryption\n"
			"  -f -\tlist fonts\n"
			"  -i -\tlist images\n"
			"  -m -\tlist dimensions\n"
			"  -p -\tlist pattners\n"
			"  -s -\tlist shadings\n"
			"  -x -\tlist form and postscript xobjects\n"
			"  example:\n"
			"    mupdftool info -p mypassword a.pdf\n");
	exit(1);
}

void
gatherglobalinfo()
{
	info = malloc(sizeof (struct info));
	if (!info)
		die(fz_throw("out of memory"));

	info->page = -1;
	info->pageref = nil;
	info->ref = fz_dictgets(src->trailer, "Info");

	info->u.info.obj = nil;

	if (!info->ref)
		return;

	if (!fz_isdict(info->ref) && !fz_isindirect(info->ref))
		die(fz_throw("not an indirect info object"));

	info->u.info.obj = src->info;
}

fz_error *
gatherdimensions(int page, fz_obj *pageref, fz_obj *pageobj)
{
	fz_error *error;
	fz_obj *ref;
	fz_rect bbox;
	fz_obj *obj;
	int j;

	obj = ref = fz_dictgets(pageobj, "MediaBox");
	if (obj)
	{
		error = pdf_resolve(&obj, src);
		if (error)
			return error;
	}
	if (!fz_isarray(obj))
		return fz_throw("cannot find page bounds (%d %d R)", fz_tonum(ref), fz_togen(ref));

	bbox = pdf_torect(obj);

	for (j = 0; j < dims; j++)
		if (!memcmp(dim[j]->u.dim.bbox, &bbox, sizeof (fz_rect)))
			break;

	if (j < dims)
		return fz_okay;

	dims++;

	dim = realloc(dim, dims * sizeof (struct info *));
	if (!dim)
		return fz_throw("out of memory");

	dim[dims - 1] = malloc(sizeof (struct info));
	if (!dim[dims - 1])
		return fz_throw("out of memory");

	dim[dims - 1]->u.dim.bbox = malloc(sizeof (fz_rect));
	if (!dim[dims - 1]->u.dim.bbox)
		return fz_throw("out of memory");

	dim[dims - 1]->page = page;
	dim[dims - 1]->pageref = pageref;
	dim[dims - 1]->ref = nil;
	memcpy(dim[dims - 1]->u.dim.bbox, &bbox, sizeof (fz_rect));

	return fz_okay;
}

fz_error *
gatherfonts(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	fz_error *error;
	int i;

	for (i = 0; i < fz_dictlen(dict); i++)
	{
		fz_obj *ref;
		fz_obj *fontdict;
		fz_obj *subtype;
		fz_obj *basefont;
		fz_obj *name;
		int k;

		fontdict = ref = fz_dictgetval(dict, i);
		if (fontdict)
		{
			error = pdf_resolve(&fontdict, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect font dict (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isdict(fontdict))
			return fz_throw("not a font dict (%d %d R)", fz_tonum(ref), fz_togen(ref));

		subtype = fz_dictgets(fontdict, "Subtype");
		if (subtype)
		{
			error = pdf_resolve(&subtype, src);
			if (error)
				return fz_rethrow(error, "cannot find font dict subtype (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isname(subtype))
			return fz_throw("not a font dict subtype (%d %d R)", fz_tonum(ref), fz_togen(ref));

		basefont = fz_dictgets(fontdict, "BaseFont");
		if (basefont)
		{
		    error = pdf_resolve(&basefont, src);
		    if (error)
			return fz_rethrow(error, "cannot find font dict basefont (%d %d R)", fz_tonum(ref), fz_togen(ref));
		    if (!fz_isname(basefont))
			return fz_throw("not a font dict basefont (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		else
		{
		    name = fz_dictgets(fontdict, "Name");
		    if (name)
			error = pdf_resolve(&name, src);
		    else
			error = fz_newnull(&name);
		    if (error)
			return fz_rethrow(error, "cannot find font dict name (%d %d R)", fz_tonum(ref), fz_togen(ref));
		    if (!fz_isnull(name) && !fz_isname(name))
			return fz_throw("not a font dict name (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}

		for (k = 0; k < fonts; k++)
			if (fz_tonum(font[k]->ref) == fz_tonum(ref) &&
					fz_togen(font[k]->ref) == fz_togen(ref))
				break;

		if (k < fonts)
			return fz_okay;

		fonts++;

		font = realloc(font, fonts * sizeof (struct info *));
		if (!font)
			return fz_throw("out of memory");

		font[fonts - 1] = malloc(sizeof (struct info));
		if (!font[fonts - 1])
			return fz_throw("out of memory");

		font[fonts - 1]->page = page;
		font[fonts - 1]->pageref = pageref;
		font[fonts - 1]->ref = ref;
		font[fonts - 1]->u.font.subtype = subtype;
		font[fonts - 1]->u.font.name = basefont ? basefont : name;
	}

	return fz_okay;
}

fz_error *
gatherimages(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	fz_error *error;
	int i;

	for (i = 0; i < fz_dictlen(dict); i++)
	{
		fz_obj *ref;
		fz_obj *imagedict;
		fz_obj *type;
		fz_obj *width;
		fz_obj *height;
		fz_obj *bpc;
		fz_obj *filter;
		fz_obj *mask;
		fz_obj *cs;
		fz_obj *altcs;
		int k;

		imagedict = ref = fz_dictgetval(dict, i);
		if (imagedict)
		{
			error = pdf_resolve(&imagedict, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect image dict (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isdict(imagedict))
			return fz_throw("not an image dict (%d %d R)", fz_tonum(ref), fz_togen(ref));

		type = fz_dictgets(imagedict, "Subtype");
		if (type)
		{
			error = pdf_resolve(&type, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect image subtype (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isname(type))
			return fz_throw("not an image subtype (%d %d R)", fz_tonum(ref), fz_togen(ref));
		if (strcmp(fz_toname(type), "Image"))
			continue;

		filter = fz_dictgets(imagedict, "Filter");
		if (filter)
		{
			error = pdf_resolve(&filter, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect image filter (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		else
		{
			error = fz_newname(&filter, "Raw");
			if (error)
				return fz_rethrow(error, "cannot create fake raw image filter (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isname(filter) && !fz_isarray(filter))
			return fz_throw("not an image filter (%d %d R)", fz_tonum(ref), fz_togen(ref));

		mask = fz_dictgets(imagedict, "ImageMask");
		if (mask)
		{
			error = pdf_resolve(&mask, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect image mask (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}

		altcs = nil;
		cs = fz_dictgets(imagedict, "ColorSpace");
		if (cs)
		{
			error = pdf_resolve(&cs, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect image colorspace (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (fz_isarray(cs))
		{
			fz_obj *cses = cs;

			cs = fz_arrayget(cses, 0);
			if (cs)
			{
				error = pdf_resolve(&cs, src);
				if (error)
					return fz_rethrow(error, "cannot resolve indirect image colorspace name (%d %d R)", fz_tonum(ref), fz_togen(ref));
			}

			if (fz_isname(cs) && (!strcmp(fz_toname(cs), "DeviceN") || !strcmp(fz_toname(cs), "Separation")))
			{
				altcs = fz_arrayget(cses, 2);
				if (altcs)
				{
					error = pdf_resolve(&altcs, src);
					if (error)
						return fz_rethrow(error, "cannot resolve indirect image alternate colorspace name (%d %d R)", fz_tonum(ref), fz_togen(ref));
				}

				if (fz_isarray(altcs))
				{
					altcs = fz_arrayget(altcs, 0);
					if (altcs)
					{
						error = pdf_resolve(&altcs, src);
						if (error)
							return fz_rethrow(error, "cannot resolve indirect image alternate colorspace name (%d %d R)", fz_tonum(ref), fz_togen(ref));
					}
				}
			}
		}

		if (fz_isbool(mask) && fz_tobool(mask))
		{
			if (cs)
				fz_warn("image mask (%d %d R) may not have colorspace", fz_tonum(ref), fz_togen(ref));
			error = fz_newname(&cs, "ImageMask");
			if (error)
				return fz_rethrow(error, "cannot create fake image mask colorspace (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isname(cs))
			return fz_throw("not an image colorspace (%d %d R)", fz_tonum(ref), fz_togen(ref));
		if (altcs && !fz_isname(altcs))
			return fz_throw("not an image alternate colorspace (%d %d R)", fz_tonum(ref), fz_togen(ref));

		width = fz_dictgets(imagedict, "Width");
		if (width)
		{
			error = pdf_resolve(&type, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect image width (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isint(width))
			return fz_throw("not an image width (%d %d R)", fz_tonum(ref), fz_togen(ref));

		height = fz_dictgets(imagedict, "Height");
		if (height)
		{
			error = pdf_resolve(&height, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect image height (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isint(height))
			return fz_throw("not an image height (%d %d R)", fz_tonum(ref), fz_togen(ref));

		bpc = fz_dictgets(imagedict, "BitsPerComponent");
		if (bpc)
		{
			error = pdf_resolve(&bpc, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect image bits per component (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_tobool(mask) && !fz_isint(bpc))
			return fz_throw("not an image bits per component (%d %d R)", fz_tonum(ref), fz_togen(ref));
		if (fz_tobool(mask) && fz_isint(bpc) && fz_toint(bpc) != 1)
			return fz_throw("not an image mask bits per component (%d %d R)", fz_tonum(ref), fz_togen(ref));
		if (fz_tobool(mask) && !bpc)
		{
			error = fz_newint(&bpc, 1);
			if (error)
				return fz_rethrow(error, "cannot create fake image mask bits per components (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}

		for (k = 0; k < images; k++)
			if (fz_tonum(image[k]->ref) == fz_tonum(ref) &&
					fz_togen(image[k]->ref) == fz_togen(ref))
				break;

		if (k < images)
			continue;

		images++;

		image = realloc(image, images * sizeof (struct info *));
		if (!image)
			return fz_throw("out of memory");

		image[images - 1] = malloc(sizeof (struct info));
		if (!image[images - 1])
			return fz_throw("out of memory");

		image[images - 1]->page = page;
		image[images - 1]->pageref = pageref;
		image[images - 1]->ref = ref;
		image[images - 1]->u.image.width = width;
		image[images - 1]->u.image.height = height;
		image[images - 1]->u.image.bpc = bpc;
		image[images - 1]->u.image.filter = filter;
		image[images - 1]->u.image.cs = cs;
		image[images - 1]->u.image.altcs = altcs;
	}

	return fz_okay;
}

fz_error *
gatherforms(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	fz_error *error;
	int i;

	for (i = 0; i < fz_dictlen(dict); i++)
	{
		fz_obj *ref;
		fz_obj *xobjdict;
		fz_obj *type;
		fz_obj *subtype;
		fz_obj *group;
		fz_obj *reference;
		int k;

		xobjdict = ref = fz_dictgetval(dict, i);
		if (xobjdict)
		{
			error = pdf_resolve(&xobjdict, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect image dict (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isdict(xobjdict))
			return fz_throw("not a xobject dict (%d %d R)", fz_tonum(ref), fz_togen(ref));

		type = fz_dictgets(xobjdict, "Subtype");
		if (type)
		{
			error = pdf_resolve(&type, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect xobject type (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isname(type))
			return fz_throw("not a xobject type (%d %d R)", fz_tonum(ref), fz_togen(ref));
		if (strcmp(fz_toname(type), "Form"))
			return fz_okay;

		subtype = fz_dictgets(xobjdict, "Subtype2");
		if (subtype)
		{
			error = pdf_resolve(&subtype, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect xobject subtype (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (subtype && !fz_isname(subtype))
			return fz_throw("not a xobject subtype (%d %d R)", fz_tonum(ref), fz_togen(ref));
		if (strcmp(fz_toname(subtype), "PS"))
			return fz_okay;

		group = fz_dictgets(xobjdict, "Group");
		if (group)
		{
			error = pdf_resolve(&group, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect form xobject group dict (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (group && !fz_isdict(group))
			return fz_throw("not a form xobject group dict (%d %d R)", fz_tonum(ref), fz_togen(ref));

		reference = fz_dictgets(xobjdict, "Ref");
		if (reference)
		{
			error = pdf_resolve(&reference, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect form xobject reference dict (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (reference && !fz_isdict(reference))
			return fz_throw("not a form xobject reference dict (%d %d R)", fz_tonum(ref), fz_togen(ref));

		for (k = 0; k < forms; k++)
			if (fz_tonum(form[k]->ref) == fz_tonum(ref) &&
					fz_togen(form[k]->ref) == fz_togen(ref))
				break;

		if (k < forms)
			return fz_okay;

		forms++;

		form = realloc(form, forms * sizeof (struct info *));
		if (!form)
			return fz_throw("out of memory");

		form[forms - 1] = malloc(sizeof (struct info));
		if (!form[forms - 1])
			return fz_throw("out of memory");

		form[forms - 1]->page = page;
		form[forms - 1]->pageref = pageref;
		form[forms - 1]->ref = ref;
		form[forms - 1]->u.form.group = group;
		form[forms - 1]->u.form.reference = reference;
	}

	return fz_okay;
}

fz_error *
gatherpsobjs(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	fz_error *error;
	int i;

	for (i = 0; i < fz_dictlen(dict); i++)
	{
		fz_obj *ref;
		fz_obj *xobjdict;
		fz_obj *type;
		fz_obj *subtype;
		int k;

		xobjdict = ref = fz_dictgetval(dict, i);
		if (xobjdict)
		{
			error = pdf_resolve(&xobjdict, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect image dict (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isdict(xobjdict))
			return fz_throw("not a xobject dict (%d %d R)", fz_tonum(ref), fz_togen(ref));

		type = fz_dictgets(xobjdict, "Subtype");
		if (type)
		{
			error = pdf_resolve(&type, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect xobject type (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isname(type))
			return fz_throw("not a xobject type (%d %d R)", fz_tonum(ref), fz_togen(ref));
		if (strcmp(fz_toname(type), "Form"))
			return fz_okay;

		subtype = fz_dictgets(xobjdict, "Subtype2");
		if (subtype)
		{
			error = pdf_resolve(&subtype, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect xobject subtype (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (subtype && !fz_isname(subtype))
			return fz_throw("not a xobject subtype (%d %d R)", fz_tonum(ref), fz_togen(ref));
		if (strcmp(fz_toname(type), "PS") &&
				(strcmp(fz_toname(type), "Form") || strcmp(fz_toname(subtype), "PS")))
			return fz_okay;

		for (k = 0; k < psobjs; k++)
			if (fz_tonum(psobj[k]->ref) == fz_tonum(ref) &&
					fz_togen(psobj[k]->ref) == fz_togen(ref))
				break;

		if (k < psobjs)
			return fz_okay;

		psobjs++;

		psobj = realloc(psobj, psobjs * sizeof (struct info *));
		if (!psobj)
			return fz_throw("out of memory");

		psobj[psobjs - 1] = malloc(sizeof (struct info));
		if (!psobj[psobjs - 1])
			return fz_throw("out of memory");

		psobj[psobjs - 1]->page = page;
		psobj[psobjs - 1]->pageref = pageref;
		psobj[psobjs - 1]->ref = ref;
	}

	return fz_okay;
}

fz_error *
gathershadings(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	fz_error *error;
	int i;

	for (i = 0; i < fz_dictlen(dict); i++)
	{
		fz_obj *ref;
		fz_obj *shade;
		fz_obj *type;
		int k;

		shade = ref = fz_dictgetval(dict, i);
		if (shade)
		{
			error = pdf_resolve(&shade, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect shading dict (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isdict(shade))
			return fz_throw("not a shading dict (%d %d R)", fz_tonum(ref), fz_togen(ref));

		type = fz_dictgets(shade, "ShadingType");
		if (type)
		{
			error = pdf_resolve(&type, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect shading type (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isint(type) || fz_toint(type) < 1 || fz_toint(type) > 7)
			return fz_throw("not a shading type (%d %d R)", fz_tonum(ref), fz_togen(ref));

		for (k = 0; k < shadings; k++)
			if (fz_tonum(shading[k]->ref) == fz_tonum(ref) &&
					fz_togen(shading[k]->ref) == fz_togen(ref))
				break;

		if (k < shadings)
			return fz_okay;

		shadings++;

		shading = realloc(shading, shadings * sizeof (struct info *));
		if (!shading)
			return fz_throw("out of memory");

		shading[shadings - 1] = malloc(sizeof (struct info));
		if (!shading[shadings - 1])
			return fz_throw("out of memory");

		shading[shadings - 1]->page = page;
		shading[shadings - 1]->pageref = pageref;
		shading[shadings - 1]->ref = ref;
		shading[shadings - 1]->u.shading.type = type;
	}

	return fz_okay;
}

fz_error *
gatherpatterns(int page, fz_obj *pageref, fz_obj *pageobj, fz_obj *dict)
{
	fz_error *error;
	int i;

	for (i = 0; i < fz_dictlen(dict); i++)
	{
		fz_obj *ref;
		fz_obj *patterndict;
		fz_obj *type;
		fz_obj *paint;
		fz_obj *tiling;
		int k;

		patterndict = ref = fz_dictgetval(dict, i);
		if (patterndict)
		{
			error = pdf_resolve(&patterndict, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect pattern dict (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isdict(patterndict))
			return fz_throw("not a pattern dict (%d %d R)", fz_tonum(ref), fz_togen(ref));

		type = fz_dictgets(patterndict, "PatternType");
		if (type)
		{
			error = pdf_resolve(&type, src);
			if (error)
				return fz_rethrow(error, "cannot resolve indirect pattern type (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		if (!fz_isint(type) || fz_toint(type) < 1 || fz_toint(type) > 2)
			return fz_throw("not a pattern type (%d %d R)", fz_tonum(ref), fz_togen(ref));

		if (fz_toint(type) == 1)
		{
			paint = fz_dictgets(patterndict, "PaintType");
			if (paint)
			{
				error = pdf_resolve(&paint, src);
				if (error)
					return fz_rethrow(error, "cannot resolve indirect pattern paint type (%d %d R)", fz_tonum(ref), fz_togen(ref));
			}
			if (!fz_isint(paint) || fz_toint(paint) < 1 || fz_toint(paint) > 2)
				return fz_throw("not a pattern paint type (%d %d R)", fz_tonum(ref), fz_togen(ref));

			tiling = fz_dictgets(patterndict, "TilingType");
			if (tiling)
			{
				error = pdf_resolve(&tiling, src);
				if (error)
					return fz_rethrow(error, "cannot resolve indirect pattern tiling type (%d %d R)", fz_tonum(ref), fz_togen(ref));
			}
			if (!fz_isint(tiling) || fz_toint(tiling) < 1 || fz_toint(tiling) > 3)
				return fz_throw("not a pattern tiling type (%d %d R)", fz_tonum(ref), fz_togen(ref));
		}
		else
		{
			error = fz_newint(&paint, 0);
			if (error)
				return fz_throw("cannot create fake pattern paint type");
			error = fz_newint(&tiling, 0);
			if (error)
				return fz_throw("cannot create fake pattern tiling type");
		}

		for (k = 0; k < patterns; k++)
			if (fz_tonum(pattern[k]->ref) == fz_tonum(ref) &&
					fz_togen(pattern[k]->ref) == fz_togen(ref))
				break;

		if (k < patterns)
			return fz_okay;

		patterns++;

		pattern = realloc(pattern, patterns * sizeof (struct info *));
		if (!pattern)
			return fz_throw("out of memory");

		pattern[patterns - 1] = malloc(sizeof (struct info));
		if (!pattern[patterns - 1])
			return fz_throw("out of memory");

		pattern[patterns - 1]->page = page;
		pattern[patterns - 1]->pageref = pageref;
		pattern[patterns - 1]->ref = ref;
		pattern[patterns - 1]->u.pattern.pattern = type;
		pattern[patterns - 1]->u.pattern.paint = paint;
		pattern[patterns - 1]->u.pattern.tiling = tiling;
	}

	return fz_okay;
}

void
gatherinfo(int show, int page)
{
	fz_error *error;
	fz_obj *pageref;
	fz_obj *pageobj;
	fz_obj *rsrc;
	fz_obj *font;
	fz_obj *xobj;
	fz_obj *shade;
	fz_obj *pattern;

	pageref = pdf_getpagereference(srcpages, page - 1);
	pageobj = pdf_getpageobject(srcpages, page - 1);

	if (!pageref || !pageobj)
		die(fz_throw("cannot retrieve info from page %d", page));

	if (show & DIMENSIONS)
	{
		error = gatherdimensions(page, pageref, pageobj);
		if (error)
			die(fz_rethrow(error, "gathering dimensions at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));
	}

	rsrc = fz_dictgets(pageobj, "Resources");
	if (rsrc)
	{
		error = pdf_resolve(&rsrc, src);
		if (error)
			die(fz_rethrow(error, "retrieving resources at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));
	}

	if (show & FONTS)
	{
		font = fz_dictgets(rsrc, "Font");
		if (font)
		{
			error = pdf_resolve(&font, src);
			if (error)
				die(fz_rethrow(error, "resolving font dict at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));

			error = gatherfonts(page, pageref, pageobj, font);
			if (error)
				die(fz_rethrow(error, "gathering fonts at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));
		}
	}

	if (show & IMAGES || show & XOBJS)
	{
		xobj = fz_dictgets(rsrc, "XObject");
		if (xobj)
		{
			error = pdf_resolve(&xobj, src);
			if (error)
				die(fz_rethrow(error, "resolving xobject dict at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));

			error = gatherimages(page, pageref, pageobj, xobj);
			if (error)
				die(fz_rethrow(error, "gathering images at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));
			error = gatherforms(page, pageref, pageobj, xobj);
			if (error)
				die(fz_rethrow(error, "gathering forms at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));
			error = gatherpsobjs(page, pageref, pageobj, xobj);
			if (error)
				die(fz_rethrow(error, "gathering postscript objects at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));
		}
	}

	if (show & SHADINGS)
	{
		shade = fz_dictgets(rsrc, "Shading");
		if (shade)
		{
			error = pdf_resolve(&shade, src);
			if (error)
				die(fz_rethrow(error, "resolving shading dict at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));

			error = gathershadings(page, pageref, pageobj, shade);
			if (error)
				die(fz_rethrow(error, "gathering shadings at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));
		}
	}

	if (show & PATTERNS)
	{
		pattern = fz_dictgets(rsrc, "Pattern");
		if (pattern)
		{
			error = pdf_resolve(&pattern, src);
			if (error)
				die(fz_rethrow(error, "resolving pattern dict at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));

			error = gathershadings(page, pageref, pageobj, shade);
			if (error)
				die(fz_rethrow(error, "gathering shadings at page %d (%d %d R)", page, fz_tonum(pageref), fz_togen(pageref)));
		}
	}
}

void
printglobalinfo(char *filename)
{
	printf("%s:\n\n", filename);
	printf("PDF-%d.%d\n\n", src->version / 10, src->version % 10);

	if (info->u.info.obj)
	{
		printf("Info object (%d %d R):\n", fz_tonum(info->ref), fz_togen(info->ref));
		fz_debugobj(info->u.info.obj);
	}

	printf("\nPages: %d\n\n", pdf_getpagecount(srcpages));
}

void
printinfo(char *filename, int show, int page)
{
	int i;
	int j;

#define PAGE_FMT "\t% 6d (% 6d %1d R): "

	if (show & DIMENSIONS && dims > 0)
	{
		printf("MediaBox: ");
		printf("\n");
		for (i = 0; i < dims; i++)
			printf(PAGE_FMT "[ %g %g %g %g ]\n",
					dim[i]->page,
					fz_tonum(dim[i]->pageref), fz_togen(dim[i]->pageref),
					dim[i]->u.dim.bbox->x0,
					dim[i]->u.dim.bbox->y0,
					dim[i]->u.dim.bbox->x1,
					dim[i]->u.dim.bbox->y1);
		printf("\n");

		for (i = 0; i < dims; i++)
		{
			free(dim[i]->u.dim.bbox);
			free(dim[i]);
		}
		free(dim);
		dim = nil;
		dims = 0;
	}

	if (show & FONTS && fonts > 0)
	{
		printf("Fonts (%d):\n", fonts);
		for (i = 0; i < fonts; i++)
		{
			printf(PAGE_FMT "%s %s (%d %d R)\n",
					font[i]->page,
					fz_tonum(font[i]->pageref), fz_togen(font[i]->pageref),
					fz_toname(font[i]->u.font.subtype),
					fz_toname(font[i]->u.font.name),
					fz_tonum(font[i]->ref), fz_togen(font[i]->ref));
		}
		printf("\n");

		for (i = 0; i < fonts; i++)
			free(font[i]);
		free(font);
		font = nil;
		fonts = 0;
	}

	if (show & IMAGES && images > 0)
	{
		printf("Images (%d):\n", images);
		for (i = 0; i < images; i++)
		{
			printf(PAGE_FMT "[ ",
					image[i]->page,
					fz_tonum(image[i]->pageref), fz_togen(image[i]->pageref));

			if (fz_isarray(image[i]->u.image.filter))
				for (j = 0; j < fz_arraylen(image[i]->u.image.filter); j++)
				{
					printf("%s%s",
							fz_toname(fz_arrayget(image[i]->u.image.filter, j)),
							j == fz_arraylen(image[i]->u.image.filter) - 1 ? "" : " ");
				}
			else
				printf("%s", fz_toname(image[i]->u.image.filter));

			printf(" ] %dx%d %dbpc %s%s%s (%d %d R)\n",
					fz_toint(image[i]->u.image.width),
					fz_toint(image[i]->u.image.height),
					fz_toint(image[i]->u.image.bpc),
					fz_toname(image[i]->u.image.cs),
					image[i]->u.image.altcs ? " " : "",
					image[i]->u.image.altcs ? fz_toname(image[i]->u.image.altcs) : "",
					fz_tonum(image[i]->ref), fz_togen(image[i]->ref));
		}
		printf("\n");

		for (i = 0; i < images; i++)
			free(image[i]);
		free(image);
		image = nil;
		images = 0;
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
				"Free-form triangle mesh",
				"Lattice-form triangle mesh",
				"Coons patch mesh",
				"Tendor-product patch mesh",
			};

			printf(PAGE_FMT "%s (%d %d R)\n",
					shading[i]->page,
					fz_tonum(shading[i]->pageref), fz_togen(shading[i]->pageref),
					shadingtype[fz_toint(shading[i]->u.shading.type)],
					fz_tonum(shading[i]->ref), fz_togen(shading[i]->ref));
		}
		printf("\n");

		for (i = 0; i < shadings; i++)
			free(shading[i]);
		free(shading);
		shading = nil;
		shadings = 0;
	}

	if (show & PATTERNS && patterns > 0)
	{
		printf("Patterns (%d):\n", patterns);
		for (i = 0; i < patterns; i++)
		{
			char *patterntype[] =
			{
				"",
				"Tiling",
				"Shading",
			};
			char *painttype[] =
			{
				"",
				"Colored",
				"Uncolored",
			};
			char *tilingtype[] =
			{
				"",
				"Constant spacing",
				"No distortion",
				"Constant space/fast tiling",
			};

			printf(PAGE_FMT "%s %s %s (%d %d R)\n",
					pattern[i]->page,
					fz_tonum(pattern[i]->pageref), fz_togen(pattern[i]->pageref),
					patterntype[fz_toint(pattern[i]->u.pattern.pattern)],
					painttype[fz_toint(pattern[i]->u.pattern.paint)],
					tilingtype[fz_toint(pattern[i]->u.pattern.tiling)],
					fz_tonum(pattern[i]->ref), fz_togen(pattern[i]->ref));
		}
		printf("\n");

		for (i = 0; i < patterns; i++)
			free(pattern[i]);
		free(pattern);
		pattern = nil;
		patterns = 0;
	}

	if (show & XOBJS && forms > 0)
	{
		printf("Form xobjects (%d):\n", forms);
		for (i = 0; i < forms; i++)
		{
			printf(PAGE_FMT "%s%s (%d %d R)\n",
					form[i]->page,
					fz_tonum(form[i]->pageref), fz_togen(form[i]->pageref),
					form[i]->u.form.group ? "Group" : "",
					form[i]->u.form.reference ? "Reference" : "",
					fz_tonum(form[i]->ref), fz_togen(form[i]->ref));
		}
		printf("\n");

		for (i = 0; i < forms; i++)
			free(form[i]);
		free(form);
		form = nil;
		forms = 0;
	}

	if (show & XOBJS && psobjs > 0)
	{
		printf("Postscript xobjects (%d):\n", psobjs);
		for (i = 0; i < psobjs; i++)
		{
			printf(PAGE_FMT "(%d %d R)\n",
					psobj[i]->page,
					fz_tonum(psobj[i]->pageref), fz_togen(psobj[i]->pageref),
					fz_tonum(psobj[i]->ref), fz_togen(psobj[i]->ref));
		}
		printf("\n");

		for (i = 0; i < psobjs; i++)
			free(psobj[i]);
		free(psobj);
		psobj = nil;
		psobjs = 0;
	}
}

void
showinfo(char *filename, int show, char *pagelist)
{
	int page, spage, epage;
	char *spec, *dash;
	int allpages;

	if (!src)
		infousage();

	allpages = !strcmp(pagelist, "1-");

	spec = strsep(&pagelist, ",");
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
				epage = pdf_getpagecount(srcpages);
		}

		if (spage > epage)
			page = spage, spage = epage, epage = page;

		if (spage < 1)
			spage = 1;
		if (epage > pdf_getpagecount(srcpages))
			epage = pdf_getpagecount(srcpages);
		if (spage > pdf_getpagecount(srcpages))
			spage = pdf_getpagecount(srcpages);

		if (allpages)
			printf("Retrieving info from pages %d-%d...\n", spage, epage);
		if (spage >= 1)
		{
		    for (page = spage; page <= epage; page++)
		    {
			gatherinfo(show, page);
			if (!allpages)
			{
			    printf("Page %05d:\n", page);
			    printinfo(filename, show, page);
			    printf("\n");
			}
		    }
		}

		spec = strsep(&pagelist, ",");
	}

	if (allpages)
		printinfo(filename, show, -1);
}

void
infomain(int argc, char **argv)
{
	enum { NO_FILE_OPENED, NO_INFO_GATHERED, INFO_SHOWN } state;
	char *filename = "";
	char *password = "";
	int show = ALL;
	int c;

	while ((c = getopt(argc, argv, "mfispxd:")) != -1)
	{
		switch (c)
		{
			case 'm': if (show == ALL) show = DIMENSIONS; else show |= DIMENSIONS; break;
			case 'f': if (show == ALL) show = FONTS; else show |= FONTS; break;
			case 'i': if (show == ALL) show = IMAGES; else show |= IMAGES; break;
			case 's': if (show == ALL) show = SHADINGS; else show |= SHADINGS; break;
			case 'p': if (show == ALL) show = PATTERNS; else show |= PATTERNS; break;
			case 'x': if (show == ALL) show = XOBJS; else show |= XOBJS; break;
			case 'd': password = optarg; break;
			default:
				  infousage();
				  break;
		}
	}

	if (optind == argc)
		infousage();

	state = NO_FILE_OPENED;
	while (optind < argc)
	{
		if (strstr(argv[optind], ".pdf") || strstr(argv[optind], ".PDF"))
		{
			if (state == NO_INFO_GATHERED)
			{
				printglobalinfo(filename);
				showinfo(filename, show, "1-");
			}

			filename = argv[optind];
			opensrc(filename, password, 1);
			gatherglobalinfo();
			state = NO_INFO_GATHERED;
		}
		else
		{
			if (state == NO_INFO_GATHERED)
			printglobalinfo(filename);
			showinfo(filename, show, argv[optind]);
			state = INFO_SHOWN;
		}

		optind++;
	}

	if (state == NO_INFO_GATHERED)
	{
		printglobalinfo(filename);
		showinfo(filename, show, "1-");
	}

	closesrc();
}

/* --------------------------------------------------------------------- */

/*
 * Edit tool.
 * Copy or impose pages from other pdf files into output pdf.
 */

/* for each source pdf, build a list of objects to transplant.
 * for each source pdf, do the transplants at the end of object collecting.
 * build a new page tree structure for output.
 * change page nodes into xobjects for over and n-up modes.
 * create new page nodes.
 * create new page tree.
 */

enum { COPY, OVER, NUP2, NUP4, NUP8 };

pdf_xref *editxref = nil;
fz_obj *editpagelist = nil;
fz_obj *editmodelist = nil;
fz_obj *editobjects = nil;
int editmode = COPY;

void
editusage(void)
{
	fprintf(stderr, "usage: mupdftool edit [-o file.pdf] [mode file.pdf pages ... ]\n");
	fprintf(stderr, "  mode is one of: copy over 2up 4up 8up\n");
	fprintf(stderr, "  pages is a comma separated list of ranges\n");
	fprintf(stderr, "  example:\n");
	fprintf(stderr, "    mupdftool edit -o output.pdf copy one.pdf 1-3,5,9 two.pdf 1-\n");
	exit(1);
}

void
editcopy(int pagenum)
{
	fz_error *error;
	fz_obj *obj;
	fz_obj *ref;
	fz_obj *num;

	printf("copy %s page %d\n", srcname, pagenum);

	ref = srcpages->pref[pagenum - 1];
	obj = pdf_getpageobject(srcpages, pagenum - 1);

	fz_dictdels(obj, "Parent");
	/*
	fz_dictdels(obj, "B");
	fz_dictdels(obj, "PieceInfo");
	fz_dictdels(obj, "Metadata");
	fz_dictdels(obj, "Annots");
	fz_dictdels(obj, "Tabs");
	*/

	pdf_updateobject(src, fz_tonum(ref), fz_togen(ref), obj);

	error = fz_arraypush(editobjects, ref);
	if (error)
		die(error);

	error = fz_newint(&num, editmode);
	if (error)
		die(error);

	error = fz_arraypush(editmodelist, num);
	if (error)
		die(error);

	fz_dropobj(num);
}

void
editflushobjects(void)
{
	fz_error *error;
	fz_obj *results;
	int i;

	error = pdf_transplant(editxref, src, &results, editobjects);
	if (error)
		die(error);

	for (i = 0; i < fz_arraylen(results); i++)
	{
		error = fz_arraypush(editpagelist, fz_arrayget(results, i));
		if (error)
			die(error);
	}

	fz_dropobj(results);
}

void
editflushpagetree(void)
{

	/* TODO: merge pages where editmode != COPY by turning them into XObjects
	   and creating a new page object with resource dictionary and content
	   stream placing the xobjects on the page. */
}

void
editflushcatalog(void)
{
	fz_error *error;
	int rootnum, rootgen;
	int listnum, listgen;
	fz_obj *listref;
	fz_obj *obj;
	int i;

	/* Create page tree and add back-links */

	error = pdf_allocobject(editxref, &listnum, &listgen);
	if (error)
		die(error);

	error = fz_packobj(&obj, "<</Type/Pages/Count %i/Kids %o>>",
			fz_arraylen(editpagelist),
			editpagelist);
	if (error)
		die(error);

	pdf_updateobject(editxref, listnum, listgen, obj);

	fz_dropobj(obj);

	error = fz_newindirect(&listref, listnum, listgen);
	if (error)
		die(error);

	for (i = 0; i < fz_arraylen(editpagelist); i++)
	{
		int num = fz_tonum(fz_arrayget(editpagelist, i));
		int gen = fz_togen(fz_arrayget(editpagelist, i));

		error = pdf_loadobject(&obj, editxref, num, gen);
		if (error)
			die(error);

		error = fz_dictputs(obj, "Parent", listref);
		if (error)
			die(error);

		pdf_updateobject(editxref, num, gen, obj);

		fz_dropobj(obj);
	}

	/* Create catalog */

	error = pdf_allocobject(editxref, &rootnum, &rootgen);
	if (error)
		die(error);

	error = fz_packobj(&obj, "<</Type/Catalog/Pages %r>>", listnum, listgen);
	if (error)
		die(error);

	pdf_updateobject(editxref, rootnum, rootgen, obj);

	fz_dropobj(obj);

	/* Create trailer */

	error = fz_packobj(&editxref->trailer, "<</Root %r>>", rootnum, rootgen);
	if (error)
		die(error);
}

void
editpages(char *pagelist)
{
	int page, spage, epage;
	char *spec, *dash;

	if (!src)
		editusage();

	spec = strsep(&pagelist, ",");
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
				epage = pdf_getpagecount(srcpages);
		}

		if (spage > epage)
			page = spage, spage = epage, epage = page;

		for (page = spage; page <= epage; page++)
		{
			if (page < 1 || page > pdf_getpagecount(srcpages))
				continue;
			editcopy(page);
		}

		spec = strsep(&pagelist, ",");
	}
}

void
editmain(int argc, char **argv)
{
	char *outfile = "out.pdf";
	fz_error *error;
	int c;

	while ((c = getopt(argc, argv, "o:")) != -1)
	{
		switch (c)
		{
		case 'o':
			outfile = optarg;
			break;
		default:
			editusage();
			break;
		}
	}

	if (optind == argc)
		editusage();

	error = pdf_newxref(&editxref);
	if (error)
		die(error);

	error = pdf_initxref(editxref);
	if (error)
		die(error);

	error = fz_newarray(&editpagelist, 100);
	if (error)
		die(error);

	error = fz_newarray(&editmodelist, 100);
	if (error)
		die(error);

	while (optind < argc)
	{
		if (strstr(argv[optind], ".pdf"))
		{
			if (editobjects)
				editflushobjects();

			opensrc(argv[optind], "", 1);

			error = fz_newarray(&editobjects, 100);
			if (error)
				die(error);
		}
		else if (!strcmp(argv[optind], "copy"))
			editmode = COPY;
		else if (!strcmp(argv[optind], "over"))
			editmode = OVER;
		else if (!strcmp(argv[optind], "2up"))
			editmode = NUP2;
		else if (!strcmp(argv[optind], "4up"))
			editmode = NUP4;
		else if (!strcmp(argv[optind], "8up"))
			editmode = NUP8;
		else
			editpages(argv[optind]);
		optind++;
	}

	if (editobjects)
		editflushobjects();

	closesrc();

	editflushpagetree();
	editflushcatalog();

	error = pdf_savexref(editxref, outfile, nil);
	if (error)
		die(error);

	pdf_closexref(editxref);
}

/* --------------------------------------------------------------------- */

/*
 * Main!
 */

void
mainusage(void)
{
	fprintf(stderr, "usage: mupdftool <command> [options...]\n");
	fprintf(stderr, "  command is one of: show, draw, clean, edit, info\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	if (argc >= 2)
	{
		optind = 2;
		if (!strcmp(argv[1], "show"))
			showmain(argc, argv);
		else if (!strcmp(argv[1], "draw"))
			drawmain(argc, argv);
		else if (!strcmp(argv[1], "clean"))
			cleanmain(argc, argv);
		else if (!strcmp(argv[1], "edit"))
			editmain(argc, argv);
		else if (!strcmp(argv[1], "info"))
			infomain(argc, argv);
		else
			mainusage();
	}
	else
		mainusage();
	return 0;
}

