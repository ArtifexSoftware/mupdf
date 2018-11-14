#include "gl-app.h"

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mujs.h"

#ifndef PATH_MAX
#define PATH_MAX 2048
#endif

#ifndef _WIN32
#include <unistd.h> /* for fork, exec, and getcwd */
#else
char *realpath(const char *path, char *resolved_path); /* in gl-file.c */
#endif

#ifdef __APPLE__
static void cleanup(void);
void glutLeaveMainLoop(void)
{
	cleanup();
	exit(0);
}
#endif

fz_context *ctx = NULL;
pdf_document *pdf = NULL;
pdf_page *page = NULL;
pdf_annot *selected_annot = NULL;
fz_stext_page *page_text = NULL;
fz_matrix draw_page_ctm, view_page_ctm, view_page_inv_ctm;
fz_rect page_bounds, draw_page_bounds, view_page_bounds;
fz_irect view_page_area;
char filename[PATH_MAX];

enum
{
	/* Screen furniture: aggregate size of unusable space from title bars, task bars, window borders, etc */
	SCREEN_FURNITURE_W = 20,
	SCREEN_FURNITURE_H = 40,

	/* Default EPUB/HTML layout dimensions */
	DEFAULT_LAYOUT_W = 450,
	DEFAULT_LAYOUT_H = 600,
	DEFAULT_LAYOUT_EM = 12,
};

static void open_browser(const char *uri)
{
	char buf[PATH_MAX];

	/* Relative file:// URI, make it absolute! */
	if (!strncmp(uri, "file://", 7) && uri[7] != '/')
	{
		char buf_base[PATH_MAX];
		char buf_cwd[PATH_MAX];
		fz_dirname(buf_base, filename, sizeof buf_base);
		getcwd(buf_cwd, sizeof buf_cwd);
		fz_snprintf(buf, sizeof buf, "file://%s/%s/%s", buf_cwd, buf_base, uri+7);
		fz_cleanname(buf+7);
		uri = buf;
	}

#ifdef _WIN32
	ShellExecuteA(NULL, "open", uri, 0, 0, SW_SHOWNORMAL);
#else
	const char *browser = getenv("BROWSER");
	if (!browser)
	{
#ifdef __APPLE__
		browser = "open";
#else
		browser = "xdg-open";
#endif
	}
	if (fork() == 0)
	{
		execlp(browser, browser, uri, (char*)0);
		fprintf(stderr, "cannot exec '%s'\n", browser);
		exit(0);
	}
#endif
}

static const int zoom_list[] = {
	24, 36, 48, 60, 72, 84, 96, 108,
	120, 144, 168, 192, 228, 264,
	300, 350, 400, 450, 500, 550, 600
};

static int zoom_in(int oldres)
{
	int i;
	for (i = 0; i < nelem(zoom_list) - 1; ++i)
		if (zoom_list[i] <= oldres && zoom_list[i+1] > oldres)
			return zoom_list[i+1];
	return zoom_list[i];
}

static int zoom_out(int oldres)
{
	int i;
	for (i = 0; i < nelem(zoom_list) - 1; ++i)
		if (zoom_list[i] < oldres && zoom_list[i+1] >= oldres)
			return zoom_list[i];
	return zoom_list[0];
}

#define MINRES (zoom_list[0])
#define MAXRES (zoom_list[nelem(zoom_list)-1])
#define DEFRES 96

static char *password = "";
static char *anchor = NULL;
static float layout_w = DEFAULT_LAYOUT_W;
static float layout_h = DEFAULT_LAYOUT_H;
static float layout_em = DEFAULT_LAYOUT_EM;
static char *layout_css = NULL;
static int layout_use_doc_css = 1;
static int enable_js = 1;

static fz_document *doc = NULL;
static fz_page *fzpage = NULL;
static fz_outline *outline = NULL;
static fz_link *links = NULL;

static int number = 0;

static struct texture page_tex = { 0 };
static int screen_w = 0, screen_h = 0;
static int scroll_x = 0, scroll_y = 0;
static int canvas_x = 0, canvas_w = 100;
static int canvas_y = 0, canvas_h = 100;

static int outline_w = 14; /* to be scaled by lineheight */
static int annotate_w = 12; /* to be scaled by lineheight */

static int oldinvert = 0, currentinvert = 0;
static int oldpage = 0, currentpage = 0;
static float oldzoom = DEFRES, currentzoom = DEFRES;
static float oldrotate = 0, currentrotate = 0;

static int isfullscreen = 0;
static int showoutline = 0;
static int showannotate = 0;
static int showlinks = 0;
static int showsearch = 0;
static int showinfo = 0;
static int showhelp = 0;
int showform = 0;

struct mark
{
	int page;
	fz_point scroll;
};

static int history_count = 0;
static struct mark history[256];
static int future_count = 0;
static struct mark future[256];
static struct mark marks[10];

static char *get_history_filename(void)
{
	static char history_path[PATH_MAX];
	static int once = 0;
	if (!once)
	{
		char *home = getenv("HOME");
		if (!home)
			home = getenv("USERPROFILE");
		if (!home)
			home = "/tmp";
		fz_snprintf(history_path, sizeof history_path, "%s/.mupdf.history", home);
		fz_cleanname(history_path);
		once = 1;
	}
	return history_path;
}

static void read_history_file_as_json(js_State *J)
{
	fz_buffer *buf = NULL;
	const char *json = "{}";

	fz_var(buf);

	if (fz_file_exists(ctx, get_history_filename()))
	{
		fz_try(ctx)
		{
			buf = fz_read_file(ctx, get_history_filename());
			json = fz_string_from_buffer(ctx, buf);
		}
		fz_catch(ctx)
			;
	}

	js_getglobal(J, "JSON");
	js_getproperty(J, -1, "parse");
	js_pushnull(J);
	js_pushstring(J, json);
	if (js_pcall(J, 1))
	{
		fz_warn(ctx, "Can't parse history file: %s", js_trystring(J, -1, "error"));
		js_pop(J, 1);
		js_newobject(J);
	}
	else
	{
		js_rot2pop1(J);
	}

	fz_drop_buffer(ctx, buf);
}

static void load_history(void)
{
	js_State *J;
	char absname[PATH_MAX];
	int i, n;

	if (!realpath(filename, absname))
		return;

	J = js_newstate(NULL, NULL, 0);

	read_history_file_as_json(J);

	if (js_hasproperty(J, -1, absname))
	{
		if (js_hasproperty(J, -1, "current"))
		{
			currentpage = js_tryinteger(J, -1, 1) - 1;
			js_pop(J, 1);
		}

		if (js_hasproperty(J, -1, "history"))
		{
			if (js_isarray(J, -1))
			{
				history_count = fz_clampi(js_getlength(J, -1), 0, nelem(history));
				for (i = 0; i < history_count; ++i)
				{
					js_getindex(J, -1, i);
					history[i].page = js_tryinteger(J, -1, 1) - 1;
					js_pop(J, 1);
				}
			}
			js_pop(J, 1);
		}

		if (js_hasproperty(J, -1, "future"))
		{
			if (js_isarray(J, -1))
			{
				future_count = fz_clampi(js_getlength(J, -1), 0, nelem(future));
				for (i = 0; i < future_count; ++i)
				{
					js_getindex(J, -1, i);
					future[i].page = js_tryinteger(J, -1, 1) - 1;
					js_pop(J, 1);
				}
			}
			js_pop(J, 1);
		}

		if (js_hasproperty(J, -1, "marks"))
		{
			if (js_isarray(J, -1))
			{
				n = fz_clampi(js_getlength(J, -1), 0, nelem(marks));
				for (i = 0; i < n; ++i)
				{
					js_getindex(J, -1, i);
					marks[i].page = js_tryinteger(J, -1, 1) - 1;
					js_pop(J, 1);
				}
			}
			js_pop(J, 1);
		}
	}

	js_freestate(J);
}

static void save_history(void)
{
	js_State *J;
	char absname[PATH_MAX];
	fz_output *out = NULL;
	const char *json;
	int i;

	fz_var(out);

	if (!doc)
		return;

	if (!realpath(filename, absname))
		return;

	J = js_newstate(NULL, NULL, 0);

	read_history_file_as_json(J);

	js_newobject(J);
	{
		js_pushnumber(J, currentpage+1);
		js_setproperty(J, -2, "current");

		js_newarray(J);
		for (i = 0; i < history_count; ++i)
		{
			js_pushnumber(J, history[i].page+1);
			js_setindex(J, -2, i);
		}
		js_setproperty(J, -2, "history");

		js_newarray(J);
		for (i = 0; i < future_count; ++i)
		{
			js_pushnumber(J, future[i].page+1);
			js_setindex(J, -2, i);
		}
		js_setproperty(J, -2, "future");

		js_newarray(J);
		for (i = 0; i < nelem(marks); ++i)
		{
			js_pushnumber(J, marks[i].page+1);
			js_setindex(J, -2, i);
		}
		js_setproperty(J, -2, "marks");
	}
	js_setproperty(J, -2, absname);

	js_getglobal(J, "JSON");
	js_getproperty(J, -1, "stringify");
	js_pushnull(J);
	js_copy(J, -4);
	js_pushnull(J);
	js_pushnumber(J, 0);
	js_call(J, 3);
	js_rot2pop1(J);
	json = js_tostring(J, -1);

	fz_try(ctx)
	{
		out = fz_new_output_with_path(ctx, get_history_filename(), 0);
		fz_write_string(ctx, out, json);
		fz_write_byte(ctx, out, '\n');
		fz_close_output(ctx, out);
	}
	fz_always(ctx)
		fz_drop_output(ctx, out);
	fz_catch(ctx)
		fz_warn(ctx, "Can't write history file.");

	js_freestate(J);
}

static int search_active = 0;
static struct input search_input = { { 0 }, 0 };
static char *search_needle = 0;
static int search_dir = 1;
static int search_page = -1;
static int search_hit_page = -1;
static int search_hit_count = 0;
static fz_quad search_hit_quads[5000];

static char error_message[256];
static void error_dialog(void)
{
	ui_dialog_begin(500, (ui.gridsize+4)*4);
	ui_layout(T, NONE, NW, 2, 2);
	ui_label("%C %s", 0x1f4a3, error_message); /* BOMB */
	ui_layout(B, NONE, S, 2, 2);
	if (ui_button("Quit") || ui.key == KEY_ENTER || ui.key == KEY_ESCAPE || ui.key == 'q')
		glutLeaveMainLoop();
	ui_dialog_end();
}
void ui_show_error_dialog(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fz_vsnprintf(error_message, sizeof error_message, fmt, ap);
	va_end(ap);
	ui.dialog = error_dialog;
}

static char warning_message[256];
static void warning_dialog(void)
{
	ui_dialog_begin(500, (ui.gridsize+4)*4);
	ui_layout(T, NONE, NW, 2, 2);
	ui_label("%C %s", 0x26a0, warning_message); /* WARNING SIGN */
	ui_layout(B, NONE, S, 2, 2);
	if (ui_button("Okay") || ui.key == KEY_ENTER || ui.key == KEY_ESCAPE)
		ui.dialog = NULL;
	ui_dialog_end();
}
void ui_show_warning_dialog(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fz_vsnprintf(warning_message, sizeof warning_message, fmt, ap);
	va_end(ap);
	ui.dialog = warning_dialog;
}

void update_title(void)
{
	char buf[256];
	char *title = "MuPDF/GL";
	char *extra = "";
	size_t n;

	title = strrchr(filename, '/');
	if (!title)
		title = strrchr(filename, '\\');
	if (title)
		++title;
	else
		title = filename;

	if (pdf && pdf->dirty)
		extra = "*";

	n = strlen(title);
	if (n > 50)
		sprintf(buf, "...%s%s - %d / %d", title + n - 50, extra, currentpage + 1, fz_count_pages(ctx, doc));
	else
		sprintf(buf, "%s%s - %d / %d", title, extra, currentpage + 1, fz_count_pages(ctx, doc));
	glutSetWindowTitle(buf);
	glutSetIconTitle(buf);
}

void transform_page(void)
{
	draw_page_ctm = fz_transform_page(page_bounds, currentzoom, currentrotate);
	draw_page_bounds = fz_transform_rect(page_bounds, draw_page_ctm);
}

void load_page(void)
{
	fz_irect area;

	/* clear all editor selections */
	selected_annot = NULL;

	fz_drop_stext_page(ctx, page_text);
	page_text = NULL;
	fz_drop_link(ctx, links);
	links = NULL;
	fz_drop_page(ctx, fzpage);
	fzpage = NULL;

	fzpage = fz_load_page(ctx, doc, currentpage);
	if (pdf)
		page = (pdf_page*)fzpage;

	links = fz_load_links(ctx, fzpage);
	page_text = fz_new_stext_page_from_page(ctx, fzpage, NULL);

	/* compute bounds here for initial window size */
	page_bounds = fz_bound_page(ctx, fzpage);
	transform_page();

	area = fz_irect_from_rect(draw_page_bounds);
	page_tex.w = area.x1 - area.x0;
	page_tex.h = area.y1 - area.y0;
}

void render_page(void)
{
	fz_pixmap *pix;

	transform_page();

	pix = fz_new_pixmap_from_page(ctx, fzpage, draw_page_ctm, fz_device_rgb(ctx), 0);
	if (currentinvert)
	{
		fz_invert_pixmap(ctx, pix);
		fz_gamma_pixmap(ctx, pix, 1 / 1.4f);
	}

	ui_texture_from_pixmap(&page_tex, pix);
	fz_drop_pixmap(ctx, pix);
}

static struct mark save_mark()
{
	struct mark mark;
	mark.page = currentpage;
	mark.scroll = fz_transform_point_xy(scroll_x, scroll_y, view_page_inv_ctm);
	return mark;
}

static void restore_mark(struct mark mark)
{
	currentpage = mark.page;
	mark.scroll = fz_transform_point(mark.scroll, draw_page_ctm);
	scroll_x = mark.scroll.x;
	scroll_y = mark.scroll.y;
}

static void push_history(void)
{
	if (history_count > 0 && history[history_count-1].page == currentpage)
		return;
	if (history_count + 1 >= nelem(history))
	{
		memmove(history, history + 1, sizeof *history * (nelem(history) - 1));
		history[history_count] = save_mark();
	}
	else
	{
		history[history_count++] = save_mark();
	}
}

static void push_future(void)
{
	if (future_count + 1 >= nelem(future))
	{
		memmove(future, future + 1, sizeof *future * (nelem(future) - 1));
		future[future_count] = save_mark();
	}
	else
	{
		future[future_count++] = save_mark();
	}
}

static void clear_future(void)
{
	future_count = 0;
}

static void jump_to_page(int newpage)
{
	newpage = fz_clampi(newpage, 0, fz_count_pages(ctx, doc) - 1);
	clear_future();
	push_history();
	currentpage = newpage;
	push_history();
}

static void jump_to_page_xy(int newpage, float x, float y)
{
	fz_point p = fz_transform_point_xy(x, y, draw_page_ctm);
	newpage = fz_clampi(newpage, 0, fz_count_pages(ctx, doc) - 1);
	clear_future();
	push_history();
	currentpage = newpage;
	scroll_x = p.x;
	scroll_y = p.y;
	push_history();
}

static void pop_history(void)
{
	int here = currentpage;
	push_future();
	while (history_count > 0 && currentpage == here)
		restore_mark(history[--history_count]);
}

static void pop_future(void)
{
	int here = currentpage;
	push_history();
	while (future_count > 0 && currentpage == here)
		restore_mark(future[--future_count]);
	push_history();
}

static int count_outline(fz_outline *node)
{
	int n = 0;
	while (node)
	{
		if (node->page >= 0)
		{
			n += 1;
			if (node->down && node->is_open)
				n += count_outline(node->down);
		}
		node = node->next;
	}
	return n;
}

static void do_outline_imp(struct list *list, int end, fz_outline *node, int depth)
{
	int selected, was_open, n;

	while (node)
	{
		int p = node->page;
		if (p >= 0)
		{
			n = end;
			if (node->next && node->next->page >= 0)
				n = node->next->page;

			was_open = node->is_open;
			selected = (currentpage == p || (currentpage > p && currentpage < n));
			if (ui_tree_item(list, node, node->title, selected, depth, !!node->down, &node->is_open))
				jump_to_page_xy(p, node->x, node->y);

			if (node->down && was_open)
				do_outline_imp(list, n, node->down, depth + 1);
		}
		node = node->next;
	}
}

static void do_outline(fz_outline *node)
{
	static struct list list;
	ui_layout(L, BOTH, NW, 0, 0);
	ui_tree_begin(&list, count_outline(node), outline_w, 0, 1);
	do_outline_imp(&list, fz_count_pages(ctx, doc), node, 0);
	ui_tree_end(&list);
	ui_splitter(&outline_w, 150, 500, R);
}

static void do_links(fz_link *link)
{
	fz_rect bounds;
	fz_irect area;
	float link_x, link_y;

	glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_BLEND);

	while (link)
	{
		bounds = link->rect;
		bounds = fz_transform_rect(link->rect, view_page_ctm);
		area = fz_irect_from_rect(bounds);

		if (ui_mouse_inside(&area))
		{
			ui.hot = link;
			if (!ui.active && ui.down)
				ui.active = link;
		}

		if (ui.hot == link || showlinks)
		{
			if (ui.active == link && ui.hot == link)
				glColor4f(0, 0, 1, 0.4f);
			else if (ui.hot == link)
				glColor4f(0, 0, 1, 0.2f);
			else
				glColor4f(0, 0, 1, 0.1f);
			glRectf(area.x0, area.y0, area.x1, area.y1);
		}

		if (ui.active == link && !ui.down)
		{
			if (ui.hot == link)
			{
				if (fz_is_external_link(ctx, link->uri))
					open_browser(link->uri);
				else
				{
					int p = fz_resolve_link(ctx, doc, link->uri, &link_x, &link_y);
					if (p >= 0)
						jump_to_page_xy(p, link_x, link_y);
					else
						fz_warn(ctx, "cannot find link destination '%s'", link->uri);
				}
			}
		}

		link = link->next;
	}

	glDisable(GL_BLEND);
}

static void do_page_selection(void)
{
	static fz_point pt = { 0, 0 };
	fz_quad hits[1000];
	int i, n;

	if (ui_mouse_inside(&view_page_area))
	{
		ui.hot = &pt;
		if (!ui.active && ui.right)
		{
			ui.active = &pt;
			pt.x = ui.x;
			pt.y = ui.y;
		}
	}

	if (ui.active == &pt)
	{
		fz_point page_a = { pt.x, pt.y };
		fz_point page_b = { ui.x, ui.y };

		page_a = fz_transform_point(page_a, view_page_inv_ctm);
		page_b = fz_transform_point(page_b, view_page_inv_ctm);

		if (ui.mod == GLUT_ACTIVE_CTRL)
			fz_snap_selection(ctx, page_text, &page_a, &page_b, FZ_SELECT_WORDS);
		else if (ui.mod == GLUT_ACTIVE_CTRL + GLUT_ACTIVE_SHIFT)
			fz_snap_selection(ctx, page_text, &page_a, &page_b, FZ_SELECT_LINES);

		n = fz_highlight_selection(ctx, page_text, page_a, page_b, hits, nelem(hits));

		glBlendFunc(GL_ONE_MINUS_DST_COLOR, GL_ZERO); /* invert destination color */
		glEnable(GL_BLEND);

		glColor4f(1, 1, 1, 1);
		glBegin(GL_QUADS);
		for (i = 0; i < n; ++i)
		{
			fz_quad thit = fz_transform_quad(hits[i], view_page_ctm);
			glVertex2f(thit.ul.x, thit.ul.y);
			glVertex2f(thit.ur.x, thit.ur.y);
			glVertex2f(thit.lr.x, thit.lr.y);
			glVertex2f(thit.ll.x, thit.ll.y);
		}
		glEnd();

		glDisable(GL_BLEND);

		if (!ui.right)
		{
			char *s;
#ifdef _WIN32
			s = fz_copy_selection(ctx, page_text, page_a, page_b, 1);
#else
			s = fz_copy_selection(ctx, page_text, page_a, page_b, 0);
#endif
			ui_set_clipboard(s);
			fz_free(ctx, s);
		}
	}
}

static void do_search_hits(void)
{
	int i;

	glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_BLEND);

	glColor4f(1, 0, 0, 0.4f);
	glBegin(GL_QUADS);
	for (i = 0; i < search_hit_count; ++i)
	{
		fz_quad thit = fz_transform_quad(search_hit_quads[i], view_page_ctm);
		glVertex2f(thit.ul.x, thit.ul.y);
		glVertex2f(thit.ur.x, thit.ur.y);
		glVertex2f(thit.lr.x, thit.lr.y);
		glVertex2f(thit.ll.x, thit.ll.y);
	}

	glEnd();
	glDisable(GL_BLEND);
}

static void toggle_fullscreen(void)
{
	static int win_x = 0, win_y = 0;
	static int win_w = 100, win_h = 100;
	if (!isfullscreen)
	{
		win_w = glutGet(GLUT_WINDOW_WIDTH);
		win_h = glutGet(GLUT_WINDOW_HEIGHT);
		win_x = glutGet(GLUT_WINDOW_X);
		win_y = glutGet(GLUT_WINDOW_Y);
		glutFullScreen();
		isfullscreen = 1;
	}
	else
	{
		glutPositionWindow(win_x, win_y);
		glutReshapeWindow(win_w, win_h);
		isfullscreen = 0;
	}
}

static void shrinkwrap(void)
{
	int w = page_tex.w + (showoutline ? outline_w + 4 : 0) + (showannotate ? annotate_w : 0);
	int h = page_tex.h;
	if (screen_w > 0 && w > screen_w)
		w = screen_w;
	if (screen_h > 0 && h > screen_h)
		h = screen_h;
	if (isfullscreen)
		toggle_fullscreen();
	glutReshapeWindow(w, h);
}

static struct input input_password;
static void password_dialog(void)
{
	int is;
	ui_dialog_begin(400, (ui.gridsize+4)*3);
	{
		ui_layout(T, X, NW, 2, 2);
		ui_label("Password:");
		is = ui_input(&input_password, 200, 1);

		ui_layout(B, X, NW, 2, 2);
		ui_panel_begin(0, ui.gridsize, 0, 0, 0);
		{
			ui_layout(R, NONE, S, 0, 0);
			if (ui_button("Cancel") || (!ui.focus && ui.key == KEY_ESCAPE))
				glutLeaveMainLoop();
			ui_spacer();
			if (ui_button("Okay") || is == UI_INPUT_ACCEPT)
			{
				password = input_password.text;
				ui.dialog = NULL;
				reload();
				shrinkwrap();
			}
		}
		ui_panel_end();
	}
	ui_dialog_end();
}

static void load_document(void)
{
	fz_drop_outline(ctx, outline);
	fz_drop_document(ctx, doc);

	doc = fz_open_document(ctx, filename);
	if (fz_needs_password(ctx, doc))
	{
		if (!fz_authenticate_password(ctx, doc, password))
		{
			fz_drop_document(ctx, doc);
			doc = NULL;
			fprintf(stderr, "Invalid password.\n");
			ui_input_init(&input_password, "");
			ui.focus = &input_password;
			ui.dialog = password_dialog;
			return;
		}
	}

	fz_layout_document(ctx, doc, layout_w, layout_h, layout_em);

	fz_try(ctx)
		outline = fz_load_outline(ctx, doc);
	fz_catch(ctx)
		outline = NULL;

	load_history();

	pdf = pdf_specifics(ctx, doc);
	if (pdf)
	{
		if (enable_js)
			pdf_enable_js(ctx, pdf);
		if (anchor)
			jump_to_page(pdf_lookup_anchor(ctx, pdf, anchor, NULL, NULL));
	}
	else
	{
		if (anchor)
			jump_to_page(fz_atoi(anchor) - 1);
	}
	anchor = NULL;

	currentpage = fz_clampi(currentpage, 0, fz_count_pages(ctx, doc) - 1);
}

void reload(void)
{
	save_history();
	load_document();
	if (doc)
	{
		load_page();
		render_page();
		update_title();
	}
}

static void toggle_outline(void)
{
	if (outline)
	{
		showoutline = !showoutline;
		if (canvas_w == page_tex.w && canvas_h == page_tex.h)
			shrinkwrap();
	}
}

static void toggle_annotate(void)
{
	if (pdf)
	{
		showannotate = !showannotate;
		if (canvas_w == page_tex.w && canvas_h == page_tex.h)
			shrinkwrap();
	}
}

static void set_zoom(int z, int cx, int cy)
{
	z = fz_clamp(z, MINRES, MAXRES);
	scroll_x = (scroll_x + cx - canvas_x) * z / currentzoom - cx + canvas_x;
	scroll_y = (scroll_y + cy - canvas_y) * z / currentzoom - cy + canvas_y;
	currentzoom = z;
}

static void auto_zoom_w(void)
{
	currentzoom = fz_clamp(currentzoom * canvas_w / page_tex.w, MINRES, MAXRES);
}

static void auto_zoom_h(void)
{
	currentzoom = fz_clamp(currentzoom * canvas_h / page_tex.h, MINRES, MAXRES);
}

static void auto_zoom(void)
{
	float page_a = (float) page_tex.w / page_tex.h;
	float screen_a = (float) canvas_w / canvas_h;
	if (page_a > screen_a)
		auto_zoom_w();
	else
		auto_zoom_h();
}

static void smart_move_backward(void)
{
	if (scroll_y <= 0)
	{
		if (scroll_x <= 0)
		{
			if (currentpage - 1 >= 0)
			{
				scroll_x = page_tex.w;
				scroll_y = page_tex.h;
				currentpage -= 1;
			}
		}
		else
		{
			scroll_y = page_tex.h;
			scroll_x -= canvas_w * 9 / 10;
		}
	}
	else
	{
		scroll_y -= canvas_h * 9 / 10;
	}
}

static void smart_move_forward(void)
{
	if (scroll_y + canvas_h >= page_tex.h)
	{
		if (scroll_x + canvas_w >= page_tex.w)
		{
			if (currentpage + 1 < fz_count_pages(ctx, doc))
			{
				scroll_x = 0;
				scroll_y = 0;
				currentpage += 1;
			}
		}
		else
		{
			scroll_y = 0;
			scroll_x += canvas_w * 9 / 10;
		}
	}
	else
	{
		scroll_y += canvas_h * 9 / 10;
	}
}

static void clear_search(void)
{
	showsearch = 0;
	search_hit_page = -1;
	search_hit_count = 0;
}

static void do_app(void)
{
	if (ui.key == KEY_F4 && ui.mod == GLUT_ACTIVE_ALT)
		glutLeaveMainLoop();

	if (ui.down || ui.middle || ui.right || ui.key)
		showinfo = showhelp = 0;

	if (!ui.focus && ui.key && ui.plain)
	{
		switch (ui.key)
		{
		case KEY_ESCAPE: clear_search(); selected_annot = NULL; break;
		case KEY_F1: showhelp = !showhelp; break;
		case 'a': toggle_annotate(); break;
		case 'o': toggle_outline(); break;
		case 'L': showlinks = !showlinks; break;
		case 'F': showform = !showform; break;
		case 'i': showinfo = !showinfo; break;
		case 'r': reload(); break;
		case 'q': glutLeaveMainLoop(); break;

		case 'I': currentinvert = !currentinvert; break;
		case 'f': toggle_fullscreen(); break;
		case 'w': shrinkwrap(); break;
		case 'W': auto_zoom_w(); break;
		case 'H': auto_zoom_h(); break;
		case 'Z': auto_zoom(); break;
		case 'z': set_zoom(number > 0 ? number : DEFRES, canvas_w/2, canvas_h/2); break;
		case '+': set_zoom(zoom_in(currentzoom), ui.x, ui.y); break;
		case '-': set_zoom(zoom_out(currentzoom), ui.x, ui.y); break;
		case '[': currentrotate -= 90; break;
		case ']': currentrotate += 90; break;
		case 'k': case KEY_UP: scroll_y -= 10; break;
		case 'j': case KEY_DOWN: scroll_y += 10; break;
		case 'h': case KEY_LEFT: scroll_x -= 10; break;
		case 'l': case KEY_RIGHT: scroll_x += 10; break;

		case 'b': number = fz_maxi(number, 1); while (number--) smart_move_backward(); break;
		case ' ': number = fz_maxi(number, 1); while (number--) smart_move_forward(); break;
		case ',': case KEY_PAGE_UP: currentpage -= fz_maxi(number, 1); break;
		case '.': case KEY_PAGE_DOWN: currentpage += fz_maxi(number, 1); break;
		case '<': currentpage -= 10 * fz_maxi(number, 1); break;
		case '>': currentpage += 10 * fz_maxi(number, 1); break;
		case 'g': jump_to_page(number - 1); break;
		case 'G': jump_to_page(fz_count_pages(ctx, doc) - 1); break;

		case 'm':
			if (number == 0)
				push_history();
			else if (number > 0 && number < nelem(marks))
				marks[number] = save_mark();
			break;
		case 't':
			if (number == 0)
			{
				if (history_count > 0)
					pop_history();
			}
			else if (number > 0 && number < nelem(marks))
			{
				struct mark mark = marks[number];
				restore_mark(mark);
				jump_to_page(mark.page);
			}
			break;
		case 'T':
			if (number == 0)
			{
				if (future_count > 0)
					pop_future();
			}
			break;

		case '/':
			clear_search();
			search_dir = 1;
			showsearch = 1;
			ui.focus = &search_input;
			search_input.p = search_input.text;
			search_input.q = search_input.end;
			break;
		case '?':
			clear_search();
			search_dir = -1;
			showsearch = 1;
			ui.focus = &search_input;
			search_input.p = search_input.text;
			search_input.q = search_input.end;
			break;
		case 'N':
			search_dir = -1;
			if (search_hit_page == currentpage)
				search_page = currentpage + search_dir;
			else
				search_page = currentpage;
			if (search_page >= 0 && search_page < fz_count_pages(ctx, doc))
			{
				search_hit_page = -1;
				if (search_needle)
					search_active = 1;
			}
			break;
		case 'n':
			search_dir = 1;
			if (search_hit_page == currentpage)
				search_page = currentpage + search_dir;
			else
				search_page = currentpage;
			if (search_page >= 0 && search_page < fz_count_pages(ctx, doc))
			{
				search_hit_page = -1;
				if (search_needle)
					search_active = 1;
			}
			break;
		}

		if (ui.key >= '0' && ui.key <= '9')
			number = number * 10 + ui.key - '0';
		else
			number = 0;

		currentpage = fz_clampi(currentpage, 0, fz_count_pages(ctx, doc) - 1);
		while (currentrotate < 0) currentrotate += 360;
		while (currentrotate >= 360) currentrotate -= 360;

		if (search_hit_page != currentpage)
			search_hit_page = -1; /* clear highlights when navigating */

		ui.key = 0; /* we ate the key event, so zap it */
	}
}

static void do_info(void)
{
	char buf[100];

	ui_dialog_begin(500, 10 * ui.lineheight);
	ui_layout(T, X, W, 0, 0);

	if (fz_lookup_metadata(ctx, doc, FZ_META_INFO_TITLE, buf, sizeof buf) > 0)
		ui_label("Title: %s", buf);
	if (fz_lookup_metadata(ctx, doc, FZ_META_INFO_AUTHOR, buf, sizeof buf) > 0)
		ui_label("Author: %s", buf);
	if (fz_lookup_metadata(ctx, doc, FZ_META_FORMAT, buf, sizeof buf) > 0)
		ui_label("Format: %s", buf);
	if (fz_lookup_metadata(ctx, doc, FZ_META_ENCRYPTION, buf, sizeof buf) > 0)
		ui_label("Encryption: %s", buf);
	if (pdf_specifics(ctx, doc))
	{
		if (fz_lookup_metadata(ctx, doc, "info:Creator", buf, sizeof buf) > 0)
			ui_label("PDF Creator: %s", buf);
		if (fz_lookup_metadata(ctx, doc, "info:Producer", buf, sizeof buf) > 0)
			ui_label("PDF Producer: %s", buf);
		buf[0] = 0;
		if (fz_has_permission(ctx, doc, FZ_PERMISSION_PRINT))
			fz_strlcat(buf, "print, ", sizeof buf);
		if (fz_has_permission(ctx, doc, FZ_PERMISSION_COPY))
			fz_strlcat(buf, "copy, ", sizeof buf);
		if (fz_has_permission(ctx, doc, FZ_PERMISSION_EDIT))
			fz_strlcat(buf, "edit, ", sizeof buf);
		if (fz_has_permission(ctx, doc, FZ_PERMISSION_ANNOTATE))
			fz_strlcat(buf, "annotate, ", sizeof buf);
		if (strlen(buf) > 2)
			buf[strlen(buf)-2] = 0;
		else
			fz_strlcat(buf, "none", sizeof buf);
		ui_label("Permissions: %s", buf);
	}

	ui_dialog_end();
}

static void do_help_line(char *label, char *text)
{
	ui_panel_begin(0, ui.lineheight, 0, 0, 0);
	{
		ui_layout(L, NONE, W, 0, 0);
		ui_panel_begin(150, ui.lineheight, 0, 0, 0);
		ui_layout(R, NONE, W, 20, 0);
		ui_label("%s", label);
		ui_panel_end();

		ui_layout(ALL, X, W, 0, 0);
		ui_panel_begin(0, ui.lineheight, 0, 0, 0);
		ui_label("%s", text);
		ui_panel_end();
	}
	ui_panel_end();
}

static void do_help(void)
{
	ui_dialog_begin(500, 36 * ui.lineheight);
	ui_layout(T, X, W, 0, 0);

	do_help_line("MuPDF", FZ_VERSION);
	ui_spacer();
	do_help_line("F1", "show this message");
	do_help_line("i", "show document information");
	do_help_line("o", "show/hide outline");
	do_help_line("a", "show/hide annotation editor");
	do_help_line("L", "show/hide links");
	do_help_line("F", "show/hide form fields");
	do_help_line("r", "reload file");
	do_help_line("q", "quit");
	ui_spacer();
	do_help_line("I", "toggle inverted color mode");
	do_help_line("f", "fullscreen window");
	do_help_line("w", "shrink wrap window");
	do_help_line("W or H", "fit to width or height");
	do_help_line("Z", "fit to page");
	do_help_line("z", "reset zoom");
	do_help_line("N z", "set zoom to N");
	do_help_line("+ or -", "zoom in or out");
	do_help_line("[ or ]", "rotate left or right");
	do_help_line("arrow keys", "pan in small increments");
	ui_spacer();
	do_help_line("b", "smart move backward");
	do_help_line("Space", "smart move forward");
	do_help_line(", or PgUp", "go backward");
	do_help_line(". or PgDn", "go forward");
	do_help_line("<", "go backward 10 pages");
	do_help_line(">", "go forward 10 pages");
	do_help_line("N g", "go to page N");
	do_help_line("G", "go to last page");
	ui_spacer();
	do_help_line("t", "go backward in history");
	do_help_line("T", "go forward in history");
	do_help_line("N m", "save location in bookmark N");
	do_help_line("N t", "go to bookmark N");
	ui_spacer();
	do_help_line("/ or ?", "search for text");
	do_help_line("n or N", "repeat search");

	ui_dialog_end();
}

static void do_canvas(void)
{
	static int saved_scroll_x = 0;
	static int saved_scroll_y = 0;
	static int saved_ui_x = 0;
	static int saved_ui_y = 0;
	fz_irect area;
	int page_x, page_y;

	ui_layout(ALL, BOTH, NW, 0, 0);
	ui_pack_push(area = ui_pack(0, 0));
	glScissor(area.x0, ui.window_h-area.y1, area.x1-area.x0, area.y1-area.y0);
	glEnable(GL_SCISSOR_TEST);

	canvas_x = area.x0;
	canvas_y = area.y0;
	canvas_w = area.x1 - area.x0;
	canvas_h = area.y1 - area.y0;

	if (ui_mouse_inside(&area))
	{
		ui.hot = doc;
		if (!ui.active && ui.middle)
		{
			ui.active = doc;
			saved_scroll_x = scroll_x;
			saved_scroll_y = scroll_y;
			saved_ui_x = ui.x;
			saved_ui_y = ui.y;
		}
	}

	if (ui.hot == doc)
	{
		scroll_x -= ui.scroll_x * ui.lineheight * 3;
		scroll_y -= ui.scroll_y * ui.lineheight * 3;
	}

	if (ui.active == doc)
	{
		scroll_x = saved_scroll_x + saved_ui_x - ui.x;
		scroll_y = saved_scroll_y + saved_ui_y - ui.y;
	}

	if (page_tex.w <= canvas_w)
	{
		scroll_x = 0;
		page_x = canvas_x + (canvas_w - page_tex.w) / 2;
	}
	else
	{
		scroll_x = fz_clamp(scroll_x, 0, page_tex.w - canvas_w);
		page_x = canvas_x - scroll_x;
	}

	if (page_tex.h <= canvas_h)
	{
		scroll_y = 0;
		page_y = canvas_y + (canvas_h - page_tex.h) / 2;
	}
	else
	{
		scroll_y = fz_clamp(scroll_y, 0, page_tex.h - canvas_h);
		page_y = canvas_y - scroll_y;
	}

	view_page_ctm = draw_page_ctm;
	view_page_ctm.e += page_x;
	view_page_ctm.f += page_y;
	view_page_inv_ctm = fz_invert_matrix(view_page_ctm);
	view_page_bounds = fz_transform_rect(page_bounds, view_page_ctm);
	view_page_area = fz_irect_from_rect(view_page_bounds);

	ui_draw_image(&page_tex, page_x, page_y);

	if (search_active)
	{
		ui_layout(T, X, NW, 0, 0);
		ui_panel_begin(0, ui.gridsize+8, 4, 4, 1);
		ui_layout(L, NONE, W, 2, 0);
		ui_label("Searching page %d of %d.", search_page + 1, fz_count_pages(ctx, doc));
		ui_panel_end();
	}
	else
	{
		if (showannotate)
		{
			do_annotate_canvas(area);
		}
		else
		{
			do_widget_canvas(area);
			do_links(links);
			do_page_selection();
		}

		if (search_hit_page == currentpage && search_hit_count > 0)
			do_search_hits();
	}

	if (showsearch)
	{
		ui_layout(T, X, NW, 0, 0);
		ui_panel_begin(0, ui.gridsize+8, 4, 4, 1);
		ui_layout(L, NONE, W, 2, 0);
		ui_label("Search:");
		ui_layout(ALL, X, E, 2, 0);
		if (ui_input(&search_input, 0, 1) == UI_INPUT_ACCEPT)
		{
			showsearch = 0;
			search_page = -1;
			if (search_needle)
			{
				fz_free(ctx, search_needle);
				search_needle = NULL;
			}
			if (search_input.end > search_input.text)
			{
				search_needle = fz_strdup(ctx, search_input.text);
				search_active = 1;
				search_page = currentpage;
			}
		}
		if (ui.focus != &search_input)
			showsearch = 0;
		ui_panel_end();
	}

	ui_pack_pop();
	glDisable(GL_SCISSOR_TEST);
}

void do_main(void)
{
	if (search_active)
	{
		int start_time = glutGet(GLUT_ELAPSED_TIME);

		if (ui.key == KEY_ESCAPE)
			search_active = 0;

		/* ignore events during search */
		ui.key = ui.mod = ui.plain = 0;
		ui.down = ui.middle = ui.right = 0;

		while (glutGet(GLUT_ELAPSED_TIME) < start_time + 200)
		{
			search_hit_count = fz_search_page_number(ctx, doc, search_page, search_needle,
					search_hit_quads, nelem(search_hit_quads));
			if (search_hit_count)
			{
				search_active = 0;
				search_hit_page = search_page;
				jump_to_page(search_hit_page);
				break;
			}
			else
			{
				search_page += search_dir;
				if (search_page < 0 || search_page == fz_count_pages(ctx, doc))
				{
					search_active = 0;
					break;
				}
			}
		}

		/* keep searching later */
		if (search_active)
			glutPostRedisplay();
	}

	do_app();

	if (oldpage != currentpage)
	{
		load_page();
		update_title();
	}
	if (oldpage != currentpage || oldzoom != currentzoom || oldrotate != currentrotate || oldinvert != currentinvert)
	{
		render_page();
		oldpage = currentpage;
		oldzoom = currentzoom;
		oldrotate = currentrotate;
		oldinvert = currentinvert;
	}

	if (showoutline)
		do_outline(outline);

	if (showannotate)
	{
		ui_layout(R, BOTH, NW, 0, 0);
		ui_panel_begin(annotate_w, 0, 4, 4, 1);
		do_annotate_panel();
		ui_panel_end();
	}

	do_canvas();

	if (showinfo)
		do_info();
	else if (showhelp)
		do_help();
}

void run_main_loop(void)
{
	if (currentinvert)
		glClearColor(0, 0, 0, 1);
	else
		glClearColor(0.3f, 0.3f, 0.3f, 1);
	ui_begin();
	fz_try(ctx)
	{
		if (ui.dialog)
			ui.dialog();
		else
			do_main();
	}
	fz_catch(ctx)
		ui_show_error_dialog("%s", fz_caught_message(ctx));
	ui_end();
}

static void usage(const char *argv0)
{
	fprintf(stderr, "mupdf-gl version %s\n", FZ_VERSION);
	fprintf(stderr, "usage: %s [options] document [page]\n", argv0);
	fprintf(stderr, "\t-p -\tpassword\n");
	fprintf(stderr, "\t-r -\tresolution\n");
	fprintf(stderr, "\t-I\tinvert colors\n");
	fprintf(stderr, "\t-W -\tpage width for EPUB layout\n");
	fprintf(stderr, "\t-H -\tpage height for EPUB layout\n");
	fprintf(stderr, "\t-S -\tfont size for EPUB layout\n");
	fprintf(stderr, "\t-U -\tuser style sheet for EPUB layout\n");
	fprintf(stderr, "\t-X\tdisable document styles for EPUB layout\n");
	fprintf(stderr, "\t-J\tdisable javascript in PDF forms\n");
	exit(1);
}

static int document_filter(const char *filename)
{
	return !!fz_recognize_document(ctx, filename);
}

static void do_open_document_dialog(void)
{
	if (ui_open_file(filename))
	{
		ui.dialog = NULL;
		if (filename[0] == 0)
			glutLeaveMainLoop();
		else
			load_document();
		if (doc)
		{
			load_page();
			render_page();
			shrinkwrap();
			update_title();
		}
	}
}

static void cleanup(void)
{
	save_history();

	ui_finish();

#ifndef NDEBUG
	if (fz_atoi(getenv("FZ_DEBUG_STORE")))
		fz_debug_store(ctx);
#endif

	fz_drop_stext_page(ctx, page_text);
	fz_drop_link(ctx, links);
	fz_drop_page(ctx, fzpage);
	fz_drop_outline(ctx, outline);
	fz_drop_document(ctx, doc);
	fz_drop_context(ctx);
}

#ifdef _MSC_VER
int main_utf8(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	int c;

	glutInit(&argc, argv);

	screen_w = glutGet(GLUT_SCREEN_WIDTH) - SCREEN_FURNITURE_W;
	screen_h = glutGet(GLUT_SCREEN_HEIGHT) - SCREEN_FURNITURE_H;

	while ((c = fz_getopt(argc, argv, "p:r:IW:H:S:U:XJ")) != -1)
	{
		switch (c)
		{
		default: usage(argv[0]); break;
		case 'p': password = fz_optarg; break;
		case 'r': currentzoom = fz_atof(fz_optarg); break;
		case 'I': currentinvert = !currentinvert; break;
		case 'W': layout_w = fz_atof(fz_optarg); break;
		case 'H': layout_h = fz_atof(fz_optarg); break;
		case 'S': layout_em = fz_atof(fz_optarg); break;
		case 'U': layout_css = fz_optarg; break;
		case 'X': layout_use_doc_css = 0; break;
		case 'J': enable_js = !enable_js; break;
		}
	}

	ctx = fz_new_context(NULL, NULL, 0);
	fz_register_document_handlers(ctx);
	if (layout_css)
	{
		fz_buffer *buf = fz_read_file(ctx, layout_css);
		fz_set_user_css(ctx, fz_string_from_buffer(ctx, buf));
		fz_drop_buffer(ctx, buf);
	}
	fz_set_use_document_css(ctx, layout_use_doc_css);

	if (fz_optind < argc)
	{
		fz_strlcpy(filename, argv[fz_optind++], sizeof filename);
		if (fz_optind < argc)
			anchor = argv[fz_optind++];

		fz_try(ctx)
		{
			page_tex.w = 600;
			page_tex.h = 700;
			load_document();
			if (doc) load_page();
		}
		fz_always(ctx)
		{
			float sx = 1, sy = 1;
			if (screen_w > 0 && page_tex.w > screen_w)
				sx = (float)screen_w / page_tex.w;
			if (screen_h > 0 && page_tex.h > screen_h)
				sy = (float)screen_h / page_tex.h;
			if (sy < sx)
				sx = sy;
			if (sx < 1)
			{
				fz_irect area;

				currentzoom *= sx;

				/* compute bounds here for initial window size */
				page_bounds = fz_bound_page(ctx, fzpage);
				transform_page();

				area = fz_irect_from_rect(draw_page_bounds);
				page_tex.w = area.x1 - area.x0;
				page_tex.h = area.y1 - area.y0;
			}

			ui_init(page_tex.w, page_tex.h, "MuPDF: Loading...");
			ui_input_init(&search_input, "");
		}
		fz_catch(ctx)
		{
			ui_show_error_dialog("%s", fz_caught_message(ctx));
		}

		fz_try(ctx)
		{
			if (doc)
			{
				render_page();
				update_title();
			}
		}
		fz_catch(ctx)
		{
			ui_show_error_dialog("%s", fz_caught_message(ctx));
		}
	}
	else
	{
#ifdef _WIN32
		win_install();
#endif
		ui_init(640, 700, "MuPDF: Open document");
		ui_input_init(&search_input, "");
		ui_init_open_file(".", document_filter);
		ui.dialog = do_open_document_dialog;
	}

	annotate_w *= ui.lineheight;
	outline_w *= ui.lineheight;

	glutMainLoop();

	cleanup();

	return 0;
}

#ifdef _MSC_VER
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	int argc;
	LPWSTR *wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
	char **argv = fz_argv_from_wargv(argc, wargv);
	int ret = main_utf8(argc, argv);
	fz_free_argv(argc, argv);
	return ret;
}
#endif
