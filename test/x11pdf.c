#include <fitz.h>
#include <mupdf.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/Intrinsic.h>
#include <X11/cursorfont.h>
#include <X11/keysym.h>

extern int ximage_init(Display *display, int screen, Visual *visual);
extern int ximage_get_depth(void);
extern Visual *ximage_get_visual(void);
extern Colormap ximage_get_colormap(void);
extern void ximage_blit(Drawable d, GC gc, int dstx, int dsty,
	unsigned char *srcdata,
	int srcx, int srcy, int srcw, int srch, int srcstride);

static Display *xdpy;
static int xscr;
static Window xwin;
static GC xgc;
static XEvent xevt;
static int mapped = 0;
static Cursor xcarrow, xchand, xcwait;

static float zoom = 1.0;
static int rotate = 0;
static int pageno = 1;
static int count = 0;

static int hist[256];
static int histlen = 0;

/* for 123G commands */
static unsigned char pagebuf[256];
static int pagebufidx = 0;

static pdf_xref *xref;
static pdf_pagetree *pages;
static fz_renderer *rast;
static fz_pixmap *image;

void usage()
{
	fprintf(stderr, "usage: x11pdf [-u password] file.pdf\n");
	exit(1);
}

/*
 * X11 magic
 */

static void xopen(void)
{
	xdpy = XOpenDisplay(nil);
    assert(xdpy != nil);

    xscr = DefaultScreen(xdpy);

    ximage_init(xdpy, xscr, DefaultVisual(xdpy, xscr));

    xcarrow = XCreateFontCursor(xdpy, XC_left_ptr);
    xchand = XCreateFontCursor(xdpy, XC_hand2);
    xcwait = XCreateFontCursor(xdpy, XC_watch);

    xwin = XCreateWindow(xdpy, DefaultRootWindow(xdpy),
            10, 10, 200, 100, 1,
            ximage_get_depth(),
            InputOutput,
            ximage_get_visual(),
            0,
            nil);

    XSetWindowColormap(xdpy, xwin, ximage_get_colormap());
    XSelectInput(xdpy, xwin,
            StructureNotifyMask | ExposureMask | KeyPressMask |
            PointerMotionMask | ButtonPressMask);

    mapped = 0;

    xgc = XCreateGC(xdpy, xwin, 0, nil);
}

static void xresize(void)
{
	XWindowChanges values;
	int mask;

	mask = CWWidth | CWHeight;
	values.width = image->w;
	values.height = image->h;
	XConfigureWindow(xdpy, xwin, mask, &values);

	if (!mapped)
	{
		XMapWindow(xdpy, xwin);
		XFlush(xdpy);

		while (1)
		{
			XNextEvent(xdpy, &xevt);
			if (xevt.type == MapNotify)
				break;
		}

		XSetForeground(xdpy, xgc, WhitePixel(xdpy, xscr));
		XFillRectangle(xdpy, xwin, xgc, 0, 0, image->w, image->h);
		XFlush(xdpy);

		mapped = 1;
	}
}

static void xblit(void)
{
	ximage_blit(xwin, xgc, 0, 0, image->samples, 0, 0,
		image->w, image->h, image->w * image->n);
}

static void xtitle(char *s)
{
	XmbSetWMProperties(xdpy, xwin, s, s, 0, 0, 0, 0, 0);
}

static void showpage(void)
{
	fz_error *error;
	pdf_page *page;
	fz_matrix ctm;
	fz_rect bbox;
	char s[256];
	fz_obj *pageobj;

	assert(pageno > 0 && pageno <= pdf_getpagecount(pages));

	pageobj = pdf_getpageobject(pages, pageno - 1);

	XDefineCursor(xdpy, xwin, xcwait);
	XFlush(xdpy);

	if (image)
		fz_droppixmap(image);
	image = nil;

	sprintf(s, "Loading page %d", pageno);
	XSetForeground(xdpy, xgc, BlackPixel(xdpy, xscr));
	XDrawString(xdpy, xwin, xgc, 10, 20, s, strlen(s));
	XFlush(xdpy);

	error = pdf_loadpage(&page, xref, pageobj);
	if (error)
		fz_abort(error);

	sprintf(s, "Rendering...");
	XSetForeground(xdpy, xgc, BlackPixel(xdpy, xscr));
	XDrawString(xdpy, xwin, xgc, 10, 30, s, strlen(s));
	XFlush(xdpy);

	ctm = fz_concat(fz_translate(0, -page->mediabox.max.y),
					fz_scale(zoom, -zoom));

	bbox = page->mediabox;
	bbox.min.x = bbox.min.x * zoom;
	bbox.min.y = bbox.min.y * zoom;
	bbox.max.x = bbox.max.x * zoom;
	bbox.max.y = bbox.max.y * zoom;

	error = fz_rendertree(&image, rast, page->tree, ctm, bbox);
	if (error)
		fz_abort(error);

	pdf_droppage(page);

	XDefineCursor(xdpy, xwin, xcarrow);
	XFlush(xdpy);

	xresize();
	xblit();
}

static void pdfopen(char *filename, char *password)
{
	fz_error *error;

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

	count = pdf_getpagecount(pages);

	error = fz_newrenderer(&rast, pdf_devicergb);
	if (error) fz_abort(error);

	image = nil;
}

static void handlekey(int c)
{
    int oldpage = pageno;
    float oldzoom = zoom;
    int oldrotate = rotate;

    if (c >= '0' && c <= '9')
		pagebuf[pagebufidx++] = c;
    else
		if (c != 'g' && c != 'G')
		    pagebufidx = 0;

    switch (c)
    {
    case 'b':
		pageno--;
		if (pageno < 1)
		    pageno = 1;
		break;
    case 'B':
		pageno -= 10;
		if (pageno < 1)
		    pageno = 1;
		break;
    case ' ':
    case 'f':
		pageno++;
		if (pageno > count)
		    pageno = count;
		break;
    case 'F':
		pageno += 10;
		if (pageno > count)
		    pageno = count;
		break;
    case 't':
    case 'T':
		if (histlen > 0)
		    pageno = hist[--histlen];
		break;
    case '-':
		zoom -= 0.1;
		if (zoom < 0.1)
		    zoom = 0.1;
		break;
    case '+':
		zoom += 0.1;
		if (zoom > 3.0)
		    zoom = 3.0;
		break;
    case '<':
		rotate -= 90;
		break;
    case '>':
		rotate += 90;
		break;
    case 'q':
		exit(0);
    case 'g':
    case 'G':
		if (pagebufidx > 0)
		{
		    pagebuf[pagebufidx] = '\0';
		    pageno = atoi(pagebuf);
		    pagebufidx = 0;
		    if (pageno < 1)
				pageno = 1;
		    if (pageno > count)
				pageno = count;
		}
		else
		{
		    if (c == 'G')
		    {
				pageno = count;
		    }
		}
		break;
    }

	if (pageno != oldpage || zoom != oldzoom || rotate != oldrotate)
		showpage();
}

int main(int argc, char **argv)
{
	char *filename;
	fz_obj *obj;
	char buf[256];
	int c;

	char *password = "";

	while ((c = getopt(argc, argv, "z:r:p:u:")) != -1)
	{
		switch (c)
		{
		case 'u': password = optarg; break;
		case 'p': pageno = atoi(optarg); break;
		case 'z': zoom = atof(optarg); break;
		case 'r': rotate = atoi(optarg); break;
		default: usage();
		}
	}

	if (argc - optind == 0)
		usage();

	filename = argv[optind++];

	xopen();
	pdfopen(filename, password);
	showpage();

	strlcpy(buf, filename, sizeof buf);
	obj = fz_dictgets(xref->trailer, "Info");
	if (fz_isindirect(obj))
	{
		pdf_resolve(&obj, xref);
		obj = fz_dictgets(obj, "Title");
		if (obj)
		{
			int n = MIN(fz_tostringlen(obj) + 1, sizeof buf);
			if (obj)
				strlcpy(buf, fz_tostringbuf(obj), n);
			printf("Title: %s\n", buf);
		}
	}
	xtitle(buf);

	while (1)
	{
		int len;
		unsigned char buf[128];
		KeySym keysym;

		XNextEvent(xdpy, &xevt);
		switch (xevt.type)
		{
		case Expose:
			if (xevt.xexpose.count == 0)
				xblit();
			break;

		case KeyPress:
			len = XLookupString(&xevt.xkey, buf, sizeof buf, &keysym, 0);
			if (len)
				handlekey(buf[0]);
			break;
		}
	}

	pdf_closepdf(xref);

	return 0;
}

