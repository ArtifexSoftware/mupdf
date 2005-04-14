#include "fitz.h"
#include "mupdf.h"
#include "pdfapp.h"

#include "gs_l.xbm"

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
static int justcopied = 0;
static int dirty = 0;
static char *password = "";
static XColor xbgcolor;
static XColor xshcolor;

static pdfapp_t gapp;

/*
 * Dialog boxes
 */

void winwarn(pdfapp_t *app, char *msg)
{
	fprintf(stderr, "ghostpdf: %s\n", msg);
}

void winerror(pdfapp_t *app, char *msg)
{
	fprintf(stderr, "ghostpdf: %s\n", msg);
	exit(1);
}

char *winpassword(pdfapp_t *app, char *filename)
{
	char *r = password;
	password = NULL;
	return r;
}

/*
 * X11 magic
 */

void winopen(void)
{
	XWMHints *hints;

	xdpy = XOpenDisplay(nil);
	assert(xdpy != nil);

	xscr = DefaultScreen(xdpy);

	ximage_init(xdpy, xscr, DefaultVisual(xdpy, xscr));

	xcarrow = XCreateFontCursor(xdpy, XC_left_ptr);
	xchand = XCreateFontCursor(xdpy, XC_hand2);
	xcwait = XCreateFontCursor(xdpy, XC_watch);

	xbgcolor.red = 0x7000;
	xbgcolor.green = 0x7000;
	xbgcolor.blue = 0x7000;

	xshcolor.red = 0x4000;
	xshcolor.green = 0x4000;
	xshcolor.blue = 0x4000;

	XAllocColor(xdpy, DefaultColormap(xdpy, xscr), &xbgcolor);
	XAllocColor(xdpy, DefaultColormap(xdpy, xscr), &xshcolor);

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
			PointerMotionMask | ButtonPressMask | ButtonReleaseMask);

	mapped = 0;

	xgc = XCreateGC(xdpy, xwin, 0, nil);

	XDefineCursor(xdpy, xwin, xcarrow);

	hints = XAllocWMHints();
	if (hints)
	{
		hints->flags = IconPixmapHint;
		hints->icon_pixmap = XCreateBitmapFromData(xdpy, xwin,
				gs_l_xbm_bits, gs_l_xbm_width, gs_l_xbm_height);
		if (hints->icon_pixmap)
		{
			XSetWMHints(xdpy, xwin, hints);
		}
		XFree(hints);
	}
}

void wincursor(pdfapp_t *app, int curs)
{
	if (curs == ARROW)
		XDefineCursor(xdpy, xwin, xcarrow);
	if (curs == HAND)
		XDefineCursor(xdpy, xwin, xchand);
	if (curs == WAIT)
		XDefineCursor(xdpy, xwin, xcwait);
}

void wintitle(pdfapp_t *app, char *s)
{
	XmbSetWMProperties(xdpy, xwin, s, s, 0, 0, 0, 0, 0);
}

void winconvert(pdfapp_t *app, fz_pixmap *image)
{
	// never mind
}

void winresize(pdfapp_t *app, int w, int h)
{
	XWindowChanges values;
	int mask;

	mask = CWWidth | CWHeight;
	values.width = w;
	values.height = h;
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
		XFillRectangle(xdpy, xwin, xgc, 0, 0, gapp.image->w, gapp.image->h);
		XFlush(xdpy);

		mapped = 1;
	}
}

void winblit(pdfapp_t *app)
{
	int x0 = gapp.panx;
	int y0 = gapp.pany;
	int x1 = gapp.panx + gapp.image->w;
	int y1 = gapp.pany + gapp.image->h;

	XSetForeground(xdpy, xgc, xbgcolor.pixel);
	XFillRectangle(xdpy, xwin, xgc, 0, 0, x0, gapp.winh);
	XFillRectangle(xdpy, xwin, xgc, x1, 0, gapp.winw - x1, gapp.winh);
	XFillRectangle(xdpy, xwin, xgc, 0, 0, gapp.winw, y0);
	XFillRectangle(xdpy, xwin, xgc, 0, y1, gapp.winw, gapp.winh - y1);

	XSetForeground(xdpy, xgc, xshcolor.pixel);
	XFillRectangle(xdpy, xwin, xgc, x0+2, y1, gapp.image->w, 2);
	XFillRectangle(xdpy, xwin, xgc, x1, y0+2, 2, gapp.image->h);

	if (0)
	{
		ximage_blit(xwin, xgc,
				x0, y0,
				gapp.image->samples,
				0, 0,
				gapp.image->w,
				gapp.image->h,
				gapp.image->w * gapp.image->n);
	}
	else
	{
		XSetForeground(xdpy, xgc, WhitePixel(xdpy, xscr));
		XFillRectangle(xdpy, xwin, xgc,
				x0, y0, x1 - x0, y1 - y0);
	}

}

void winrepaint(pdfapp_t *app)
{
	dirty = 1;
}

void windocopy(pdfapp_t *app)
{
	/* yeah, right. not right now. */
}

void winopenuri(pdfapp_t *app, char *buf)
{
	char cmd[2048];
	if (getenv("BROWSER"))
		sprintf(cmd, "$BROWSER %s &", buf);
	else
		sprintf(cmd, "open %s", buf);
	system(cmd);
}

void onkey(int c)
{
	if (justcopied)
	{
		justcopied = 0;
		winrepaint(&gapp);
	}

	if (c == 'q')
		exit(0);

	pdfapp_onkey(&gapp, c);
}

void onmouse(int x, int y, int btn, int state)
{
	if (state != 0 && justcopied)
	{
		justcopied = 0;
		winrepaint(&gapp);
	}

	pdfapp_onmouse(&gapp, x, y, btn, state);
}

void usage(void)
{
	fprintf(stderr, "usage: ghostpdf [-d password] file.pdf\n");
	exit(1);
}

int main(int argc, char **argv)
{
	char *filename;
	int c;
	int len;
	unsigned char buf[128];
	KeySym keysym;

	while ((c = getopt(argc, argv, "d:")) != -1)
	{
		switch (c)
		{
		case 'd': password = optarg; break;
		default: usage();
		}
	}

	if (argc - optind == 0)
		usage();

	filename = argv[optind++];

	fz_cpudetect();
	fz_accelerate();

	winopen();

	pdfapp_init(&gapp);
	gapp.scrw = DisplayWidth(xdpy, xscr);
	gapp.scrh = DisplayHeight(xdpy, xscr);

	pdfapp_open(&gapp, filename);

	while (1)
	{
		do
		{
			XNextEvent(xdpy, &xevt);

			switch (xevt.type)
			{
			case Expose:
				dirty = 1;
				break;

			case ConfigureNotify:
				if (gapp.image)
				{
					if (xevt.xconfigure.width != gapp.image->w ||
						xevt.xconfigure.height != gapp.image->h)
						gapp.shrinkwrap = 0;
				}
				pdfapp_onresize(&gapp,
						xevt.xconfigure.width,
						xevt.xconfigure.height);
				break;

			case KeyPress:
				len = XLookupString(&xevt.xkey, buf, sizeof buf, &keysym, 0);
				if (len)
					onkey(buf[0]);
				break;

			case MotionNotify:
				onmouse(xevt.xbutton.x, xevt.xbutton.y, xevt.xbutton.button, 0);
				break;

			case ButtonPress:
				onmouse(xevt.xbutton.x, xevt.xbutton.y, xevt.xbutton.button, 1);
				break;

			case ButtonRelease:
				onmouse(xevt.xbutton.x, xevt.xbutton.y, xevt.xbutton.button, -1);
				break;
			}
		}
		while (XPending(xdpy));

		if (dirty)
		{
			winblit(&gapp);
			dirty = 0;
		}
	}

	pdfapp_close(&gapp);

	return 0;
}

