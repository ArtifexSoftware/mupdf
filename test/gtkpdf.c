/*

TODO:
	- threaded pdf/page loading
	- info dialog
	- resource dialog
	- password dialog
	- outline tree
	- magnifying glass
	- text selection
	- text search

*/

#include <fitz.h>
#include <mupdf.h>

#include <gtk/gtk.h>
#include <glib.h>
#include <pthread.h>

typedef struct PDFApp PDFApp;

enum { ZOOM, FITWIDTH, FITPAGE };

struct PDFApp
{
	GtkWidget *canvas;
	GtkWidget *status;
	GtkWidget *scroll;
	int statusid;
	int viewmode;

	char *filename;
	int pageno;
	int rotate;
	float zoom;

	fz_renderer *gc;
	pdf_xref *xref;
	pdf_pagetree *pagetree;
	fz_obj *pageobj;
	pdf_page *page;
	fz_pixmap *image;
};

static volatile int busy = 0;

PDFApp *gapp;

static void showstatus(char *fmt, ...)
{
	char msg[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, 256, fmt, ap);
	va_end(ap);

	gtk_statusbar_pop(GTK_STATUSBAR(gapp->status), gapp->statusid);
	gtk_statusbar_push(GTK_STATUSBAR(gapp->status), gapp->statusid, msg);
}

static void panic(fz_error *error)
{
	gapp->filename = "";
	gapp->pageno = 1;
	gapp->rotate = 0;
	gapp->zoom = 1.0;

	gapp->gc = nil;
	gapp->xref = nil;
	gapp->pagetree = nil;
	gapp->page = nil;
	gapp->image = nil;

	fz_abort(error);
}

static void forkwork(void*(*func)(void*))
{
	pthread_t tid;
	if (busy) return;
	pthread_create(&tid, NULL, func, nil);
}

static void* drawpage(void*args)
{
	char msg[256];
	fz_error *error;
	float scalex, scaley, scale;
	fz_matrix ctm;
	fz_irect bbox;
	fz_obj *obj;

	if (!gapp->xref)
		return nil;

	busy = 1;

	while (gapp->rotate < 0)
		gapp->rotate += 360;
	gapp->rotate = gapp->rotate % 360;

	obj = pdf_getpageobject(gapp->pagetree, gapp->pageno - 1);
	if (obj == gapp->pageobj)
		goto Lskipload;
	gapp->pageobj = obj;

	if (gapp->page)
		pdf_droppage(gapp->page);

	gdk_threads_enter();
	sprintf(msg, " loading page %d ... ", gapp->pageno);
	showstatus(msg);
	gdk_threads_leave();

	error = pdf_loadpage(&gapp->page, gapp->xref, gapp->pageobj);
	if (error)
		panic(error);

Lskipload:

	gdk_threads_enter();
	showstatus(" drawing ... ");

	ctm = fz_identity();
	ctm = fz_concat(ctm, fz_translate(0, -gapp->page->mediabox.max.y));
	ctm = fz_concat(ctm, fz_rotate(gapp->rotate + gapp->page->rotate));
	bbox = fz_roundrect(fz_transformaabb(ctm, gapp->page->mediabox));

	scale = gapp->zoom;
	scalex = scaley = 1.0;

	if (gapp->viewmode == FITWIDTH || gapp->viewmode == FITPAGE)
	{
		GtkAdjustment *hadj;
		int w;
		hadj = gtk_scrolled_window_get_hadjustment(GTK_SCROLLED_WINDOW(gapp->scroll));
		w = bbox.max.x - bbox.min.x;
		if (w != 0)
			scalex = hadj->page_size / (float)w;
		scale = scalex;
	}

	if (gapp->viewmode == FITPAGE)
	{
		GtkAdjustment *vadj;
		int h;
		vadj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(gapp->scroll));
		h = bbox.max.y - bbox.min.y;
		if (h != 0)
			scaley = vadj->page_size / (float)h;
		scale = MIN(scale, scaley);
	}

	gapp->zoom = scale;

	gdk_threads_leave();

	if (gapp->image)
		fz_droppixmap(gapp->image);
	gapp->image = nil;

	ctm = fz_identity();
	ctm = fz_concat(ctm, fz_translate(0, -gapp->page->mediabox.max.y));
	ctm = fz_concat(ctm, fz_scale(gapp->zoom, -gapp->zoom));
	ctm = fz_concat(ctm, fz_rotate(gapp->rotate + gapp->page->rotate));
	bbox = fz_roundrect(fz_transformaabb(ctm, gapp->page->mediabox));

	error = fz_rendertree(&gapp->image, gapp->gc, gapp->page->tree, ctm, bbox, 1);
	if (error)
		panic(error);

	gdk_threads_enter();
	sprintf(msg, " page %d of %d  zoom %g  rotate %d ",
		gapp->pageno, pdf_getpagecount(gapp->pagetree),
		gapp->zoom, gapp->rotate);
	showstatus(msg);
	gtk_widget_set_usize(gapp->canvas, gapp->image->w, gapp->image->h);
	gtk_widget_queue_draw(gapp->canvas);
	gdk_threads_leave();

	busy = 0;

	return nil;
}

static void* openpdf(void*args)
{
	fz_error *error;
	char msg[256];

	busy = 1;

	gdk_threads_enter();
	sprintf(msg, " Loading %s...", gapp->filename);
	showstatus(msg);
	gdk_threads_leave();

	if (gapp->xref)
	{
		pdf_droppage(gapp->page);
		pdf_droppagetree(gapp->pagetree);
		pdf_closepdf(gapp->xref);
		gapp->page = nil;
		gapp->pagetree = nil;
		gapp->xref = nil;
	}

	error = pdf_openpdf(&gapp->xref, gapp->filename);
	if (error) panic(error);

	error = pdf_decryptpdf(gapp->xref);
	if (error) panic(error);

	/* TODO: ask for password */
	if (gapp->xref->crypt)
	{
		error = pdf_setpassword(gapp->xref->crypt, "");
		if (error) panic(error);
	}

	error = pdf_loadpagetree(&gapp->pagetree, gapp->xref);
	if (error) panic(error);

	gdk_threads_enter();
	showstatus("");
	gdk_threads_leave();

	gapp->pageno = 1;
	drawpage(nil);

	busy = 0;

	return nil;
}

/*
 * Handle event callbacks
 */

static void onquit(GtkWidget *widget, void *data)
{
	exit(0);
}

static void onopenokay(GtkWidget *w, GtkFileSelection *fs)
{
	gapp->filename = strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
	gtk_widget_destroy(GTK_WIDGET(fs));
	forkwork(openpdf);
}

static void onopen(GtkWidget *widget, void *data)
{
	GtkWidget *filew;
	if (busy) return;
	filew = gtk_file_selection_new ("Open PDF file");
	gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(filew)->ok_button),
						"clicked", (GtkSignalFunc)onopenokay, filew);
	gtk_signal_connect_object(GTK_OBJECT(GTK_FILE_SELECTION(filew)->cancel_button),
						"clicked", (GtkSignalFunc)gtk_widget_destroy, GTK_OBJECT(filew));
	gtk_widget_show(filew);
}

static void oninfo(GtkWidget *widget, void *data)
{
}

static void onback10(GtkWidget *widget, void *data)
{
	if (busy) return;
	if (!gapp->xref) return;
	gapp->pageno -= 10;
	if (gapp->pageno < 1)
		gapp->pageno = 1;
	forkwork(drawpage);
}

static void onnext10(GtkWidget *widget, void *data)
{
	if (busy) return;
	if (!gapp->xref) return;
	gapp->pageno += 10;
	if (gapp->pageno > pdf_getpagecount(gapp->pagetree))
		gapp->pageno = pdf_getpagecount(gapp->pagetree);
	forkwork(drawpage);
}

static void onback(GtkWidget *widget, void *data)
{
	if (busy) return;
	if (!gapp->xref) return;
	if (gapp->pageno > 1)
	{
		gapp->pageno --;
		forkwork(drawpage);
	}
}

static void onnext(GtkWidget *widget, void *data)
{
	if (busy) return;
	if (!gapp->xref) return;
	if (gapp->pageno < pdf_getpagecount(gapp->pagetree))
	{
		gapp->pageno ++;
		forkwork(drawpage);
	}
}

static void onfirst(GtkWidget *widget, void *data)
{
	if (busy) return;
	if (!gapp->xref) return;
	gapp->pageno = 1;
	forkwork(drawpage);
}

static void onlast(GtkWidget *widget, void *data)
{
	if (busy) return;
	if (!gapp->xref) return;
	gapp->pageno = pdf_getpagecount(gapp->pagetree);
	forkwork(drawpage);
}

static void onzoomin(GtkWidget * widget, void *data)
{
    gapp->viewmode = ZOOM;
    gapp->zoom *= 1.25;
    forkwork(drawpage);
}

static void onzoomout(GtkWidget * widget, void *data)
{
    gapp->viewmode = ZOOM;
    gapp->zoom *= 0.8;
    forkwork(drawpage);
}

static void onzoom100(GtkWidget * widget, void *data)
{
    gapp->viewmode = ZOOM;
    gapp->zoom = 1.0;
    forkwork(drawpage);
}

static void onrotl(GtkWidget *widget, void *data) { gapp->rotate -= 90; forkwork(drawpage); }
static void onrotr(GtkWidget *widget, void *data) { gapp->rotate += 90; forkwork(drawpage); }

static void onfitwidth(GtkWidget *widget, void *data)
{
	gapp->viewmode = FITWIDTH;
	forkwork(drawpage);
}

static void onfitpage(GtkWidget *widget, void *data)
{
	gapp->viewmode = FITPAGE;
	forkwork(drawpage);
}

static int startxpos;
static int startypos;
static int dopan = 0;
guint32 pangrabtime = 0;

static void mousedown(GtkWidget *widget, GdkEventMotion *event, void *data)
{
	GdkModifierType mods;
	gtk_widget_grab_focus(gapp->scroll);

	gdk_window_get_pointer(gapp->scroll->window, &startxpos, &startypos, &mods);
	if (mods & GDK_BUTTON2_MASK) {
		GtkAdjustment *adj;
		adj = gtk_scrolled_window_get_hadjustment(GTK_SCROLLED_WINDOW(gapp->scroll));
		startxpos += adj->value;

		adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(gapp->scroll));
		startypos += adj->value;

		gdk_pointer_grab(gapp->scroll->window, TRUE, GDK_POINTER_MOTION_MASK | GDK_BUTTON_RELEASE_MASK, NULL, NULL /* TODO: pan cursor */, event->time);

		dopan = 1;
	}
	else {
		dopan = 0;
	}
}

static void mouseup(GtkWidget *widget, GdkEventMotion *event, void *data)
{
	dopan = 0;
	gdk_pointer_ungrab(event->time);
}

static void mousemove(GtkWidget *widget, GdkEventMotion *event, void *data)
{
	int xpos, ypos;
	GdkModifierType mods;
	GtkAdjustment *adj;

	if (!dopan) return;

	gdk_window_get_pointer(gapp->scroll->window, &xpos, &ypos, &mods);

	if (mods & GDK_BUTTON2_MASK) {
		adj = gtk_scrolled_window_get_hadjustment(GTK_SCROLLED_WINDOW(gapp->scroll));
		adj->value = startxpos - xpos;
		adj->value = CLAMP(adj->value, adj->lower, adj->upper - adj->page_size);

		gtk_adjustment_value_changed(adj);

		adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(gapp->scroll));
		adj->value = startypos - ypos;
		adj->value = CLAMP(adj->value, adj->lower, adj->upper - adj->page_size);

		/* clamp to viewport... */

		gtk_adjustment_value_changed(adj);
	}
	else
		mouseup(widget, event, data); // XXX
}

static void keypress(GtkWidget *widget, GdkEventKey *event, void *data)
{
	if (busy) return;
	switch (event->string[0])
	{
	case 'q': onquit(widget, data); break;
	case 'g': onlast(widget, data); break;
	case '0': onfirst(widget, data); break;
	case 'b': onback(widget, data); break;
	case 'B': onback10(widget, data); break;
	case ' ': onnext(widget, data); break;
	case 'f': onnext(widget, data); break;
	case 'F': onnext10(widget, data); break;
	case '+': onzoomin(widget, data); break;
	case '-': onzoomout(widget, data); break;
	case '1': onzoom100(widget, data); break;
	case 'l': onrotl(widget, data); break;
	case 'r': onrotr(widget, data); break;
	case 'L': gapp->rotate -= 15; forkwork(drawpage); break;
	case 'R': gapp->rotate += 15; forkwork(drawpage); break;
	}
}

static void onexpose(GtkWidget *widget, GdkEventExpose *event, void *data)
{
	PDFApp *app = data;
	if (app->image)
	{
		int x0 = event->area.x;
		int y0 = event->area.y;
		int w = event->area.width;
		int h = event->area.height;
		int x1, y1;
		int x, y;

		unsigned char *rgb = fz_malloc(w * h * 3);
		unsigned char *s, *d;

		x1 = MIN(x0 + w, app->image->w);
		y1 = MIN(y0 + h, app->image->h);

		if (x0 + w > x1 || y0 + h > y1)
			memset(rgb, 200, w * h * 3);

		for (y = y0; y < y1; y++)
		{
			s = app->image->samples + (y * app->image->w + x0) * 4;
			d = rgb + (y - y0) * w * 3;
			for (x = x0; x < x1; x++)
			{
				d[0] = s[1];
				d[1] = s[2];
				d[2] = s[3];
				s += 4;
				d += 3;
			}
		}

		gdk_draw_rgb_image(widget->window,
						   widget->style->black_gc,
						   x0, y0, w, h,
						   GDK_RGB_DITHER_NONE, rgb,
						   w * 3);

		fz_free(rgb);
	}
}

/*
 * Construct widgets
 */

static GtkWidget *
addmenuitem(GtkWidget *menu, const char *name, GtkSignalFunc callback,
			void *callback_data, GtkAccelGroup *ag, const char *accel)
{
	GtkWidget *menuitem;
	menuitem = gtk_menu_item_new_with_label(name);
	gtk_menu_append(GTK_MENU(menu), menuitem);
	gtk_widget_show(menuitem);
	if (accel != NULL)
	{
		guint accel_key, accel_mods;
		gtk_accelerator_parse(accel, &accel_key, &accel_mods);
		gtk_widget_add_accelerator(menuitem, "activate", ag,
								   accel_key, accel_mods, GTK_ACCEL_VISIBLE);
	}
	gtk_signal_connect(GTK_OBJECT(menuitem), "activate",
				   (GtkSignalFunc)callback, callback_data);
	return menuitem;
}

static void
addmenuseparator(GtkWidget *menu)
{
	GtkWidget *menuitem;
	menuitem = gtk_menu_item_new();
	gtk_menu_append(GTK_MENU(menu), menuitem);
	gtk_widget_show(menuitem);
}

void makeapp(PDFApp *app)
{
	GtkWidget *frame;
	GtkWidget *menubar;
	GtkWidget *menu;
	GtkWidget *menuitem;
	GtkWidget *da;
	GtkWidget *sb;
	GtkWidget *sv;
	GtkWidget *vbox;
	GtkAccelGroup *ag;
	void *data = app;

	frame = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_signal_connect(GTK_OBJECT(frame), "destroy", (GtkSignalFunc)onquit, "WM destroy");
	gtk_window_set_title(GTK_WINDOW(frame), "MuPDF");
	gtk_widget_set_usize(GTK_WIDGET(frame), 300, 200);

	vbox = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	gtk_widget_show(vbox);

	menubar = gtk_menu_bar_new();
	ag = gtk_accel_group_new();
	gtk_window_add_accel_group(GTK_WINDOW(frame), ag);
	gtk_box_pack_start(GTK_BOX(vbox), menubar, FALSE, FALSE, 0);
	gtk_widget_show(menubar);

	menu = gtk_menu_new();
	menuitem = gtk_menu_item_new_with_label("File");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(menuitem), menu);
	gtk_menu_bar_append(GTK_MENU_BAR(menubar), menuitem);
	gtk_widget_show(menuitem);
	gtk_menu_set_accel_group(GTK_MENU(menu), ag);
	addmenuitem(menu, "Info...", (GtkSignalFunc)oninfo, data, ag, "<ctrl>I");
	addmenuitem(menu, "Open...", (GtkSignalFunc)onopen, data, ag, "<ctrl>O");
	addmenuseparator(menu);
	addmenuitem(menu, "Quit", (GtkSignalFunc)onquit, data, ag, "<ctrl>Q");

	menu = gtk_menu_new();
	menuitem = gtk_menu_item_new_with_label("Go");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(menuitem), menu);
	gtk_menu_bar_append(GTK_MENU_BAR(menubar), menuitem);
	gtk_widget_show(menuitem);
	gtk_menu_set_accel_group(GTK_MENU(menu), ag);
	addmenuitem(menu, "Back", (GtkSignalFunc)onback10, data, ag, "<ctrl>B");
	addmenuitem(menu, "Next", (GtkSignalFunc)onnext10, data, ag, "<ctrl>F");
	addmenuitem(menu, "Back 10", (GtkSignalFunc)onback10, data, ag, nil);
	addmenuitem(menu, "Next 10", (GtkSignalFunc)onnext10, data, ag, nil);
	addmenuseparator(menu);
	addmenuitem(menu, "First", (GtkSignalFunc)onfirst, data, ag, nil);
	addmenuitem(menu, "Last", (GtkSignalFunc)onlast, data, ag, "<ctrl>G");

	menu = gtk_menu_new();
	menuitem = gtk_menu_item_new_with_label("View");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(menuitem), menu);
	gtk_menu_bar_append(GTK_MENU_BAR(menubar), menuitem);
	gtk_widget_show(menuitem);
	gtk_menu_set_accel_group(GTK_MENU(menu), ag);
	addmenuitem(menu, "Zoom in", (GtkSignalFunc)onzoomin, data, ag, "<ctrl>'+'");
	addmenuitem(menu, "Zoom out", (GtkSignalFunc)onzoomout, data, ag, "<ctrl>'-'");
	addmenuitem(menu, "Zoom 100%", (GtkSignalFunc)onzoom100, data, ag, "<ctrl>1");
	addmenuitem(menu, "Fit width", (GtkSignalFunc)onfitwidth, data, ag, nil);
	addmenuitem(menu, "Fit page", (GtkSignalFunc)onfitpage, data, ag, nil);
	addmenuseparator(menu);
	addmenuitem(menu, "Rotate left", (GtkSignalFunc)onrotl, data, ag, "<ctrl>L");
	addmenuitem(menu, "Rotate right", (GtkSignalFunc)onrotr, data, ag, "<ctrl>R");

	sv = gtk_scrolled_window_new(NULL, NULL);
	app->scroll = sv;
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sv), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	GTK_WIDGET_SET_FLAGS(sv, GTK_CAN_FOCUS);
	gtk_widget_set_extension_events(sv, GDK_EXTENSION_EVENTS_ALL);
	gtk_signal_connect(GTK_OBJECT(sv), "button_press_event", (GtkSignalFunc)mousedown, data);
	gtk_signal_connect(GTK_OBJECT(sv), "motion_notify_event", (GtkSignalFunc)mousemove, data);
	gtk_signal_connect(GTK_OBJECT(sv), "button_release_event", (GtkSignalFunc)mouseup, data);
	gtk_signal_connect(GTK_OBJECT(sv), "key_press_event", (GtkSignalFunc)keypress, data);
	gtk_box_pack_start(GTK_BOX(vbox), sv, TRUE, TRUE, 0);
	gtk_widget_show(sv);

	da = gtk_drawing_area_new();
	app->canvas = da;
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(sv), da);
	gtk_signal_connect(GTK_OBJECT(da), "expose_event", (GtkSignalFunc)onexpose, data);
	gtk_widget_set_events (da,
		GDK_BUTTON_PRESS_MASK
		| GDK_BUTTON_RELEASE_MASK
		| GDK_POINTER_MOTION_MASK);
	gtk_widget_show(da);

	sb = gtk_statusbar_new();
	app->status = sb;
	app->statusid = gtk_statusbar_get_context_id(GTK_STATUSBAR(sb), "mupdf");
	gtk_box_pack_start(GTK_BOX(vbox), sb, FALSE, FALSE, 0);
	gtk_widget_show(sb);

	gtk_window_set_default_size(GTK_WINDOW(frame), 512, 512);
	gtk_widget_grab_focus(sv);
	gtk_widget_show(frame);
}

int main(int argc, char **argv)
{
	fz_error *error;
	PDFApp theapp;

	g_thread_init(NULL);
	gtk_init(&argc, &argv);
	gtk_widget_set_default_colormap(gdk_rgb_get_cmap());
	gtk_widget_set_default_visual(gdk_rgb_get_visual());

	makeapp(&theapp);
	gapp = &theapp;

	gapp->pageno = 1;
	gapp->rotate = 0;
	gapp->zoom = 1.0;

	gapp->image = nil;
	gapp->xref = nil;
	gapp->pagetree = nil;
	gapp->page = nil;

	fz_cpudetect();
	fz_accelerate();

	error = fz_newrenderer(&gapp->gc, pdf_devicergb, 0, 1024 * 512);
	if (error)
		fz_abort(error);

	if (argc > 1)
	{
		gapp->filename = argv[1];
		forkwork(openpdf);
	}

	gdk_threads_enter();
	gtk_main();
	gdk_threads_leave();
	return 0;
}

