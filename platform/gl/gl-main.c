#include "gl-app.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _WIN32
#include <unistd.h> /* for fork and exec */
#endif

fz_context *ctx = NULL;
pdf_document *pdf = NULL;
pdf_page *page = NULL;
int page_x_ofs = 0;
int page_y_ofs = 0;
fz_matrix page_ctm, page_inv_ctm;

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

static const int zoom_list[] = { 18, 24, 36, 54, 72, 96, 120, 144, 180, 216, 288 };

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

static char filename[2048];
static char *password = "";
static char *anchor = NULL;
static float layout_w = DEFAULT_LAYOUT_W;
static float layout_h = DEFAULT_LAYOUT_H;
static float layout_em = DEFAULT_LAYOUT_EM;
static char *layout_css = NULL;
static int layout_use_doc_css = 1;

static const char *title = "MuPDF/GL";
static fz_document *doc = NULL;
static fz_page *fzpage = NULL;
static fz_stext_page *text = NULL;
static fz_outline *outline = NULL;
static fz_link *links = NULL;

static int number = 0;

static struct texture page_tex = { 0 };
static int scroll_x = 0, scroll_y = 0;
static int canvas_x = 0, canvas_w = 100;
static int canvas_y = 0, canvas_h = 100;

static int outline_w = 260;

static int oldinvert = 0, currentinvert = 0;
static int oldpage = 0, currentpage = 0;
static float oldzoom = DEFRES, currentzoom = DEFRES;
static float oldrotate = 0, currentrotate = 0;

static int isfullscreen = 0;
static int showoutline = 0;
static int showlinks = 0;
static int showsearch = 0;
static int showinfo = 0;
static int showhelp = 0;

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

static int search_active = 0;
static struct input search_input = { { 0 }, 0 };
static char *search_needle = 0;
static int search_dir = 1;
static int search_page = -1;
static int search_hit_page = -1;
static int search_hit_count = 0;
static fz_rect search_hit_bbox[5000];

static void update_title(void)
{
	static char buf[256];
	size_t n = strlen(title);
	if (n > 50)
		sprintf(buf, "...%s - %d / %d", title + n - 50, currentpage + 1, fz_count_pages(ctx, doc));
	else
		sprintf(buf, "%s - %d / %d", title, currentpage + 1, fz_count_pages(ctx, doc));
	glutSetWindowTitle(buf);
	glutSetIconTitle(buf);
}

void load_page(void)
{
	fz_rect rect;
	fz_irect irect;

	fz_scale(&page_ctm, currentzoom / 72, currentzoom / 72);
	fz_pre_rotate(&page_ctm, -currentrotate);
	fz_invert_matrix(&page_inv_ctm, &page_ctm);

	fz_drop_stext_page(ctx, text);
	text = NULL;
	fz_drop_link(ctx, links);
	links = NULL;
	fz_drop_page(ctx, fzpage);
	fzpage = NULL;

	fzpage = fz_load_page(ctx, doc, currentpage);
	if (pdf)
		page = (pdf_page*)fzpage;

	links = fz_load_links(ctx, fzpage);
	text = fz_new_stext_page_from_page(ctx, fzpage, NULL);


	/* compute bounds here for initial window size */
	fz_bound_page(ctx, fzpage, &rect);
	fz_transform_rect(&rect, &page_ctm);
	fz_irect_from_rect(&irect, &rect);
	page_tex.w = irect.x1 - irect.x0;
	page_tex.h = irect.y1 - irect.y0;
}

void render_page(void)
{
	fz_pixmap *pix;

	fz_scale(&page_ctm, currentzoom / 72, currentzoom / 72);
	fz_pre_rotate(&page_ctm, -currentrotate);
	fz_invert_matrix(&page_inv_ctm, &page_ctm);

	pix = fz_new_pixmap_from_page(ctx, fzpage, &page_ctm, fz_device_rgb(ctx), 0);
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
	mark.scroll.x = scroll_x;
	mark.scroll.y = scroll_y;
	fz_transform_point(&mark.scroll, &page_inv_ctm);
	return mark;
}

static void restore_mark(struct mark mark)
{
	currentpage = mark.page;
	fz_transform_point(&mark.scroll, &page_ctm);
	scroll_x = mark.scroll.x;
	scroll_y = mark.scroll.y;
}

static void push_history(void)
{
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
	fz_point p = { x, y };
	newpage = fz_clampi(newpage, 0, fz_count_pages(ctx, doc) - 1);
	fz_transform_point(&p, &page_ctm);
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
			if (node->down)
				n += count_outline(node->down);
		}
		node = node->next;
	}
	return n;
}

static void do_outline_imp(struct list *list, int end, fz_outline *node, int depth)
{
	int selected;

	while (node)
	{
		int p = node->page;
		if (p >= 0)
		{
			int n = end;
			if (node->next && node->next->page >= 0)
				n = node->next->page;

			selected = (currentpage == p || (currentpage > p && currentpage < n));
			if (ui_list_item(list, node, depth * ui.lineheight, node->title, selected))
				jump_to_page_xy(p, node->x, node->y);

			if (node->down)
				do_outline_imp(list, n, node->down, depth + 1);
		}
		node = node->next;
	}
}

static void do_outline(fz_outline *node)
{
	static struct list list = {};
	ui_layout(L, BOTH, NW, 0, 0);
	ui_list_begin(&list, count_outline(node), outline_w, 0);
	do_outline_imp(&list, fz_count_pages(ctx, doc), node, 1);
	ui_list_end(&list);
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
		fz_transform_rect(&bounds, &page_ctm);
		fz_irect_from_rect(&area, &bounds);
		fz_translate_irect(&area, page_x_ofs, page_y_ofs);

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

static void do_page_selection(int x0, int y0, int x1, int y1)
{
	static fz_point pt = { 0, 0 };
	fz_rect hits[1000];
	int i, n;

	if (ui.x >= x0 && ui.x < x1 && ui.y >= y0 && ui.y < y1)
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
		int xofs = x0 - page_tex.x;
		int yofs = y0 - page_tex.y;

		fz_point page_a = { pt.x - xofs, pt.y - yofs };
		fz_point page_b = { ui.x - xofs, ui.y - yofs };

		fz_transform_point(&page_a, &page_inv_ctm);
		fz_transform_point(&page_b, &page_inv_ctm);

		n = fz_highlight_selection(ctx, text, page_a, page_b, hits, nelem(hits));

		glBlendFunc(GL_ONE_MINUS_DST_COLOR, GL_ZERO); /* invert destination color */
		glEnable(GL_BLEND);

		glColor4f(1, 1, 1, 1);
		for (i = 0; i < n; ++i)
		{
			fz_transform_rect(&hits[i], &page_ctm);
			glRectf(hits[i].x0+xofs, hits[i].y0+yofs, hits[i].x1 + 1 + xofs, hits[i].y1 + 1 + yofs);
		}

		glDisable(GL_BLEND);

		if (!ui.right)
		{
			char *s;
#ifdef _WIN32
			s = fz_copy_selection(ctx, text, page_a, page_b, 1);
#else
			s = fz_copy_selection(ctx, text, page_a, page_b, 0);
#endif
			ui_set_clipboard(s);
			fz_free(ctx, s);
		}
	}
}

static void do_search_hits(void)
{
	fz_rect bounds;
	fz_irect area;
	int i;

	glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_BLEND);

	for (i = 0; i < search_hit_count; ++i)
	{
		bounds = search_hit_bbox[i];
		fz_transform_rect(&bounds, &page_ctm);
		fz_irect_from_rect(&area, &bounds);
		fz_translate_irect(&area, page_x_ofs, page_y_ofs);

		glColor4f(1, 0, 0, 0.4f);
		glRectf(area.x0, area.y0, area.x1, area.y1);
	}

	glDisable(GL_BLEND);
}

static void do_forms(void)
{
	static int do_forms_tag = 0;
	pdf_ui_event event;
	fz_point p;

	if (!pdf || search_active)
		return;

	p.x = page_x_ofs + ui.x;
	p.y = page_y_ofs + ui.y;
	fz_transform_point(&p, &page_inv_ctm);

	if (ui.down && !ui.active)
	{
		event.etype = PDF_EVENT_TYPE_POINTER;
		event.event.pointer.pt = p;
		event.event.pointer.ptype = PDF_POINTER_DOWN;
		if (pdf_pass_event(ctx, pdf, (pdf_page*)page, &event))
		{
			if (pdf->focus)
				ui.active = &do_forms_tag;
			pdf_update_page(ctx, (pdf_page*)page);
			render_page();
		}
	}
	else if (ui.active == &do_forms_tag && !ui.down)
	{
		ui.active = NULL;
		event.etype = PDF_EVENT_TYPE_POINTER;
		event.event.pointer.pt = p;
		event.event.pointer.ptype = PDF_POINTER_UP;
		if (pdf_pass_event(ctx, pdf, (pdf_page*)page, &event))
		{
			pdf_update_page(ctx, (pdf_page*)page);
			render_page();
		}
	}
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
	int screen_w = glutGet(GLUT_SCREEN_WIDTH) - SCREEN_FURNITURE_W;
	int screen_h = glutGet(GLUT_SCREEN_HEIGHT) - SCREEN_FURNITURE_H;
	int w = page_tex.w + (showoutline ? outline_w : 0);
	int h = page_tex.h;
	if (screen_w > 0 && w > screen_w)
		w = screen_w;
	if (screen_h > 0 && h > screen_h)
		h = screen_h;
	if (isfullscreen)
		toggle_fullscreen();
	glutReshapeWindow(w, h);
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
			fprintf(stderr, "Invalid password.\n");
			exit(1);
		}
	}

	fz_layout_document(ctx, doc, layout_w, layout_h, layout_em);

	fz_try(ctx)
		outline = fz_load_outline(ctx, doc);
	fz_catch(ctx)
		outline = NULL;

	pdf = pdf_specifics(ctx, doc);
	if (pdf)
	{
		pdf_enable_js(ctx, pdf);
		if (anchor)
			currentpage = pdf_lookup_anchor(ctx, pdf, anchor, NULL, NULL);
	}
	else
	{
		if (anchor)
			currentpage = fz_atoi(anchor) - 1;
	}
	anchor = NULL;

	currentpage = fz_clampi(currentpage, 0, fz_count_pages(ctx, doc) - 1);
}

static void reload(void)
{
	load_document();
	load_page();
	render_page();
	update_title();
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
		case KEY_ESCAPE: clear_search(); break;
		case KEY_F1: showhelp = !showhelp; break;
		case 'o': toggle_outline(); break;
		case 'L': showlinks = !showlinks; break;
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
		case '[': currentrotate += 90; break;
		case ']': currentrotate -= 90; break;
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

static int do_info_line(int x, int y, char *label, char *text)
{
	char buf[512];
	fz_snprintf(buf, sizeof buf, "%s: %s", label, text);
	ui_draw_string(x, y, buf);
	return y + ui.lineheight;
}

static void do_info(void)
{
	char buf[256];

	int x = canvas_x + 4 * ui.lineheight;
	int y = canvas_y + 4 * ui.lineheight;
	int w = canvas_w - 8 * ui.lineheight;
	int h = 9 * ui.lineheight;

	glBegin(GL_TRIANGLE_STRIP);
	{
		glColor4f(0.9f, 0.9f, 0.9f, 1.0f);
		glVertex2f(x, y);
		glVertex2f(x, y + h);
		glVertex2f(x + w, y);
		glVertex2f(x + w, y + h);
	}
	glEnd();

	x += ui.lineheight;
	y += ui.lineheight + ui.baseline;

	glColor4f(0, 0, 0, 1);
	if (fz_lookup_metadata(ctx, doc, FZ_META_INFO_TITLE, buf, sizeof buf) > 0)
		y = do_info_line(x, y, "Title", buf);
	if (fz_lookup_metadata(ctx, doc, FZ_META_INFO_AUTHOR, buf, sizeof buf) > 0)
		y = do_info_line(x, y, "Author", buf);
	if (fz_lookup_metadata(ctx, doc, FZ_META_FORMAT, buf, sizeof buf) > 0)
		y = do_info_line(x, y, "Format", buf);
	if (fz_lookup_metadata(ctx, doc, FZ_META_ENCRYPTION, buf, sizeof buf) > 0)
		y = do_info_line(x, y, "Encryption", buf);
	if (pdf_specifics(ctx, doc))
	{
		if (fz_lookup_metadata(ctx, doc, "info:Creator", buf, sizeof buf) > 0)
			y = do_info_line(x, y, "PDF Creator", buf);
		if (fz_lookup_metadata(ctx, doc, "info:Producer", buf, sizeof buf) > 0)
			y = do_info_line(x, y, "PDF Producer", buf);
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
		y = do_info_line(x, y, "Permissions", buf);
	}
}

static int do_help_line(int x, int y, char *label, char *text)
{
	ui_draw_string(x, y, label);
	ui_draw_string(x+100, y, text);
	return y + ui.lineheight;
}

static void do_help(void)
{
	int x = canvas_x + 4 * ui.lineheight;
	int y = canvas_y + 4 * ui.lineheight;
	int w = canvas_w - 8 * ui.lineheight;
	int h = 38 * ui.lineheight;

	glBegin(GL_TRIANGLE_STRIP);
	{
		glColor4f(0.9f, 0.9f, 0.9f, 1.0f);
		glVertex2f(x, y);
		glVertex2f(x, y + h);
		glVertex2f(x + w, y);
		glVertex2f(x + w, y + h);
	}
	glEnd();

	x += ui.lineheight;
	y += ui.lineheight + ui.baseline;

	glColor4f(0, 0, 0, 1);
	y = do_help_line(x, y, "MuPDF", FZ_VERSION);
	y += ui.lineheight;
	y = do_help_line(x, y, "F1", "show this message");
	y = do_help_line(x, y, "i", "show document information");
	y = do_help_line(x, y, "o", "show/hide outline");
	y = do_help_line(x, y, "L", "show/hide links");
	y = do_help_line(x, y, "r", "reload file");
	y = do_help_line(x, y, "q", "quit");
	y += ui.lineheight;
	y = do_help_line(x, y, "I", "toggle inverted color mode");
	y = do_help_line(x, y, "f", "fullscreen window");
	y = do_help_line(x, y, "w", "shrink wrap window");
	y = do_help_line(x, y, "W or H", "fit to width or height");
	y = do_help_line(x, y, "Z", "fit to page");
	y = do_help_line(x, y, "z", "reset zoom");
	y = do_help_line(x, y, "N z", "set zoom to N");
	y = do_help_line(x, y, "+ or -", "zoom in or out");
	y = do_help_line(x, y, "[ or ]", "rotate left or right");
	y = do_help_line(x, y, "arrow keys", "pan in small increments");
	y += ui.lineheight;
	y = do_help_line(x, y, "b", "smart move backward");
	y = do_help_line(x, y, "Space", "smart move forward");
	y = do_help_line(x, y, ", or PgUp", "go backward");
	y = do_help_line(x, y, ". or PgDn", "go forward");
	y = do_help_line(x, y, "<", "go backward 10 pages");
	y = do_help_line(x, y, ">", "go forward 10 pages");
	y = do_help_line(x, y, "N g", "go to page N");
	y = do_help_line(x, y, "G", "go to last page");
	y += ui.lineheight;
	y = do_help_line(x, y, "t", "go backward in history");
	y = do_help_line(x, y, "T", "go forward in history");
	y = do_help_line(x, y, "N m", "save location in bookmark N");
	y = do_help_line(x, y, "N t", "go to bookmark N");
	y += ui.lineheight;
	y = do_help_line(x, y, "/ or ?", "search for text");
	y = do_help_line(x, y, "n or N", "repeat search");
}

static void do_canvas(void)
{
	static int saved_scroll_x = 0;
	static int saved_scroll_y = 0;
	static int saved_ui_x = 0;
	static int saved_ui_y = 0;
	fz_irect area;
	int state;

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
		page_x_ofs = canvas_x + (canvas_w - page_tex.w) / 2;
	}
	else
	{
		scroll_x = fz_clamp(scroll_x, 0, page_tex.w - canvas_w);
		page_x_ofs = canvas_x - scroll_x;
	}

	if (page_tex.h <= canvas_h)
	{
		scroll_y = 0;
		page_y_ofs = canvas_y + (canvas_h - page_tex.h) / 2;
	}
	else
	{
		scroll_y = fz_clamp(scroll_y, 0, page_tex.h - canvas_h);
		page_y_ofs = canvas_y - scroll_y;
	}

	page_x_ofs -= page_tex.x;
	page_y_ofs -= page_tex.y;
	ui_draw_image(&page_tex, page_x_ofs, page_y_ofs);

	if (search_active)
	{
		ui_layout(T, X, NW, 2, 2);
		ui_label("Searching page %d of %d.", search_page + 1, fz_count_pages(ctx, doc));
	}
	else
	{
		do_forms();
		do_links(links);
		do_page_selection(page_x_ofs, page_y_ofs, page_x_ofs+page_tex.w, page_y_ofs+page_tex.h);

		if (search_hit_page == currentpage && search_hit_count > 0)
			do_search_hits();
	}

	if (showsearch)
	{
		ui_layout(T, X, NW, 0, 0);
		state = ui_input(&search_input, 0);
		if (state == UI_INPUT_CANCEL)
		{
			showsearch = 0;
		}
		else if (state == UI_INPUT_ACCEPT)
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
	}

	ui_pack_pop();
	glDisable(GL_SCISSOR_TEST);
}

void run_main_loop(void)
{
	ui_begin();

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
					search_hit_bbox, nelem(search_hit_bbox));
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

	do_canvas();

	if (showinfo)
		do_info();
	else if (showhelp)
		do_help();

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
	exit(1);
}

#ifdef _MSC_VER
int main_utf8(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	int c;

	glutInit(&argc, argv);
	while ((c = fz_getopt(argc, argv, "p:r:IW:H:S:U:X")) != -1)
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
		}
	}

	if (fz_optind < argc)
	{
		fz_strlcpy(filename, argv[fz_optind++], sizeof filename);
	}
	else
	{
#ifdef _WIN32
		win_install();
		if (!win_open_file(filename, sizeof filename))
			exit(0);
#else
		usage(argv[0]);
#endif
	}

	if (fz_optind < argc)
		anchor = argv[fz_optind++];

	title = strrchr(filename, '/');
	if (!title)
		title = strrchr(filename, '\\');
	if (title)
		++title;
	else
		title = filename;

	ctx = fz_new_context(NULL, NULL, 0);
	fz_register_document_handlers(ctx);
	if (layout_css)
	{
		fz_buffer *buf = fz_read_file(ctx, layout_css);
		fz_set_user_css(ctx, fz_string_from_buffer(ctx, buf));
		fz_drop_buffer(ctx, buf);
	}
	fz_set_use_document_css(ctx, layout_use_doc_css);

	load_document();
	load_page();

	ui_init(page_tex.w, page_tex.h, title);
	ui_input_init(&search_input, "");

	render_page();
	update_title();

	glutMainLoop();

	ui_finish();

#ifndef NDEBUG
	if (fz_atoi(getenv("FZ_DEBUG_STORE")))
		fz_debug_store(ctx);
#endif

	fz_drop_stext_page(ctx, text);
	fz_drop_link(ctx, links);
	fz_drop_page(ctx, fzpage);
	fz_drop_outline(ctx, outline);
	fz_drop_document(ctx, doc);
	fz_drop_context(ctx);

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
