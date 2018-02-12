#include "gl-app.h"

#include "mupdf/pdf.h" /* for pdf specifics and forms */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _WIN32
#include <unistd.h> /* for fork and exec */
#endif

#ifndef FREEGLUT
/* freeglut extension no-ops */
void glutExit(void) {}
void glutMouseWheelFunc(void *fn) {}
void glutInitErrorFunc(void *fn) {}
void glutInitWarningFunc(void *fn) {}
#endif

enum
{
	/* Screen furniture: aggregate size of unusable space from title bars, task bars, window borders, etc */
	SCREEN_FURNITURE_W = 20,
	SCREEN_FURNITURE_H = 40,

	/* Default EPUB/HTML layout dimensions */
	DEFAULT_LAYOUT_W = 450,
	DEFAULT_LAYOUT_H = 600,
	DEFAULT_LAYOUT_EM = 12,

	/* Default UI sizes */
	DEFAULT_UI_FONTSIZE = 15,
	DEFAULT_UI_BASELINE = 14,
	DEFAULT_UI_LINEHEIGHT = 18,
};

struct ui ui;
fz_context *ctx = NULL;

/* OpenGL capabilities */
static int has_ARB_texture_non_power_of_two = 1;
static GLint max_texture_size = 8192;

static void ui_begin(void)
{
	ui.hot = NULL;
}

static void ui_end(void)
{
	if (!ui.down && !ui.middle && !ui.right)
		ui.active = NULL;
}

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

const char *ogl_error_string(GLenum code)
{
#define CASE(E) case E: return #E; break
	switch (code)
	{
	/* glGetError */
	CASE(GL_NO_ERROR);
	CASE(GL_INVALID_ENUM);
	CASE(GL_INVALID_VALUE);
	CASE(GL_INVALID_OPERATION);
	CASE(GL_OUT_OF_MEMORY);
	CASE(GL_STACK_UNDERFLOW);
	CASE(GL_STACK_OVERFLOW);
	default: return "(unknown)";
	}
#undef CASE
}

void ogl_assert(fz_context *ctx, const char *msg)
{
	int code = glGetError();
	if (code != GL_NO_ERROR) {
		fz_warn(ctx, "glGetError(%s): %s", msg, ogl_error_string(code));
	}
}

void ui_draw_image(struct texture *tex, float x, float y)
{
	glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_BLEND);
	glBindTexture(GL_TEXTURE_2D, tex->id);
	glEnable(GL_TEXTURE_2D);
	glBegin(GL_TRIANGLE_STRIP);
	{
		glColor4f(1, 1, 1, 1);
		glTexCoord2f(0, tex->t);
		glVertex2f(x + tex->x, y + tex->y + tex->h);
		glTexCoord2f(0, 0);
		glVertex2f(x + tex->x, y + tex->y);
		glTexCoord2f(tex->s, tex->t);
		glVertex2f(x + tex->x + tex->w, y + tex->y + tex->h);
		glTexCoord2f(tex->s, 0);
		glVertex2f(x + tex->x + tex->w, y + tex->y);
	}
	glEnd();
	glDisable(GL_TEXTURE_2D);
	glDisable(GL_BLEND);
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
static fz_page *page = NULL;
static fz_stext_page *text = NULL;
static pdf_document *pdf = NULL;
static fz_outline *outline = NULL;
static fz_link *links = NULL;

static int number = 0;

static struct texture page_tex = { 0 };
static int scroll_x = 0, scroll_y = 0;
static int canvas_x = 0, canvas_w = 100;
static int canvas_y = 0, canvas_h = 100;

static struct texture annot_tex[256];
static int annot_count = 0;

static int window_w = 1, window_h = 1;

static int oldinvert = 0, currentinvert = 0;
static int oldpage = 0, currentpage = 0;
static float oldzoom = DEFRES, currentzoom = DEFRES;
static float oldrotate = 0, currentrotate = 0;
static fz_matrix page_ctm, page_inv_ctm;
static int loaded = 0;
static int window = 0;

static int isfullscreen = 0;
static int showoutline = 0;
static int showlinks = 0;
static int showsearch = 0;
static int showinfo = 0;
static int showhelp = 0;
static int doquit = 0;

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

static unsigned int next_power_of_two(unsigned int n)
{
	--n;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	return ++n;
}

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

void texture_from_pixmap(struct texture *tex, fz_pixmap *pix)
{
	if (!tex->id)
		glGenTextures(1, &tex->id);
	glBindTexture(GL_TEXTURE_2D, tex->id);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);

	tex->x = pix->x;
	tex->y = pix->y;
	tex->w = pix->w;
	tex->h = pix->h;

	if (has_ARB_texture_non_power_of_two)
	{
		if (tex->w > max_texture_size || tex->h > max_texture_size)
			fz_warn(ctx, "texture size (%d x %d) exceeds implementation limit (%d)", tex->w, tex->h, max_texture_size);
		glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
		glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, tex->w, tex->h, 0, pix->n == 4 ? GL_RGBA : GL_RGB, GL_UNSIGNED_BYTE, pix->samples);
		tex->s = 1;
		tex->t = 1;
	}
	else
	{
		int w2 = next_power_of_two(tex->w);
		int h2 = next_power_of_two(tex->h);
		if (w2 > max_texture_size || h2 > max_texture_size)
			fz_warn(ctx, "texture size (%d x %d) exceeds implementation limit (%d)", w2, h2, max_texture_size);
		glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
		glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w2, h2, 0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
		glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, tex->w, tex->h, pix->n == 4 ? GL_RGBA : GL_RGB, GL_UNSIGNED_BYTE, pix->samples);
		tex->s = (float) tex->w / w2;
		tex->t = (float) tex->h / h2;
	}
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
	fz_drop_page(ctx, page);
	page = NULL;

	page = fz_load_page(ctx, doc, currentpage);
	links = fz_load_links(ctx, page);
	text = fz_new_stext_page_from_page(ctx, page, NULL);

	/* compute bounds here for initial window size */
	fz_bound_page(ctx, page, &rect);
	fz_transform_rect(&rect, &page_ctm);
	fz_round_rect(&irect, &rect);
	page_tex.w = irect.x1 - irect.x0;
	page_tex.h = irect.y1 - irect.y0;

	loaded = 1;
}

void render_page(void)
{
	fz_annot *annot;
	fz_pixmap *pix;

	if (!loaded)
		load_page();

	pix = fz_new_pixmap_from_page_contents(ctx, page, &page_ctm, fz_device_rgb(ctx), 0);
	if (currentinvert)
	{
		fz_invert_pixmap(ctx, pix);
		fz_gamma_pixmap(ctx, pix, 1 / 1.4f);
	}

	texture_from_pixmap(&page_tex, pix);
	fz_drop_pixmap(ctx, pix);

	annot_count = 0;
	for (annot = fz_first_annot(ctx, page); annot; annot = fz_next_annot(ctx, annot))
	{
		pix = fz_new_pixmap_from_annot(ctx, annot, &page_ctm, fz_device_rgb(ctx), 1);
		texture_from_pixmap(&annot_tex[annot_count++], pix);
		fz_drop_pixmap(ctx, pix);
		if (annot_count >= nelem(annot_tex))
		{
			fz_warn(ctx, "too many annotations to display!");
			break;
		}
	}

	loaded = 0;
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

static void ui_label_draw(int x0, int y0, int x1, int y1, const char *text)
{
	glColor4f(1, 1, 1, 1);
	glRectf(x0, y0, x1, y1);
	glColor4f(0, 0, 0, 1);
	ui_draw_string(ctx, x0 + 2, y0 + 2 + ui.baseline, text);
}

static void ui_scrollbar(int x0, int y0, int x1, int y1, int *value, int page_size, int max)
{
	static float saved_top = 0;
	static int saved_ui_y = 0;
	float top;

	int total_h = y1 - y0;
	int thumb_h = fz_maxi(x1 - x0, total_h * page_size / max);
	int avail_h = total_h - thumb_h;

	max -= page_size;

	if (max <= 0)
	{
		*value = 0;
		glColor4f(0.6f, 0.6f, 0.6f, 1.0f);
		glRectf(x0, y0, x1, y1);
		return;
	}

	top = (float) *value * avail_h / max;

	if (ui.down && !ui.active)
	{
		if (ui.x >= x0 && ui.x < x1 && ui.y >= y0 && ui.y < y1)
		{
			if (ui.y < top)
			{
				ui.active = "pgdn";
				*value -= page_size;
			}
			else if (ui.y >= top + thumb_h)
			{
				ui.active = "pgup";
				*value += page_size;
			}
			else
			{
				ui.hot = value;
				ui.active = value;
				saved_top = top;
				saved_ui_y = ui.y;
			}
		}
	}

	if (ui.active == value)
	{
		*value = (saved_top + ui.y - saved_ui_y) * max / avail_h;
	}

	if (*value < 0)
		*value = 0;
	else if (*value > max)
		*value = max;

	top = (float) *value * avail_h / max;

	glColor4f(0.6f, 0.6f, 0.6f, 1.0f);
	glRectf(x0, y0, x1, y1);
	glColor4f(0.8f, 0.8f, 0.8f, 1.0f);
	glRectf(x0, top, x1, top + thumb_h);
}

static int measure_outline_height(fz_outline *node)
{
	int h = 0;
	while (node)
	{
		h += ui.lineheight;
		if (node->down)
			h += measure_outline_height(node->down);
		node = node->next;
	}
	return h;
}

static int do_outline_imp(fz_outline *node, int end, int x0, int x1, int x, int y)
{
	int h = 0;
	int p = currentpage;
	int n = end;

	while (node)
	{
		p = node->page;
		if (p >= 0)
		{
			if (ui.x >= x0 && ui.x < x1 && ui.y >= y + h && ui.y < y + h + ui.lineheight)
			{
				ui.hot = node;
				if (!ui.active && ui.down)
				{
					ui.active = node;
					jump_to_page_xy(p, node->x, node->y);
					glutPostRedisplay(); /* we changed the current page, so force a redraw */
				}
			}

			n = end;
			if (node->next && node->next->page >= 0)
			{
				n = node->next->page;
			}
			if (currentpage == p || (currentpage > p && currentpage < n))
			{
				glColor4f(0.9f, 0.9f, 0.9f, 1.0f);
				glRectf(x0, y + h, x1, y + h + ui.lineheight);
			}
		}

		glColor4f(0, 0, 0, 1);
		ui_draw_string(ctx, x, y + h + ui.baseline, node->title);
		h += ui.lineheight;
		if (node->down)
			h += do_outline_imp(node->down, n, x0, x1, x + ui.lineheight, y + h);

		node = node->next;
	}
	return h;
}

static void do_outline(fz_outline *node, int outline_w)
{
	static char *id = "outline";
	static int outline_scroll_y = 0;
	static int saved_outline_scroll_y = 0;
	static int saved_ui_y = 0;

	int outline_h;
	int total_h;

	outline_w -= ui.lineheight;
	outline_h = window_h;
	total_h = measure_outline_height(outline);

	if (ui.x >= 0 && ui.x < outline_w && ui.y >= 0 && ui.y < outline_h)
	{
		ui.hot = id;
		if (!ui.active && ui.middle)
		{
			ui.active = id;
			saved_ui_y = ui.y;
			saved_outline_scroll_y = outline_scroll_y;
		}
	}

	if (ui.active == id)
		outline_scroll_y = saved_outline_scroll_y + (saved_ui_y - ui.y) * 5;

	if (ui.hot == id)
		outline_scroll_y -= ui.scroll_y * ui.lineheight * 3;

	ui_scrollbar(outline_w, 0, outline_w+ui.lineheight, outline_h, &outline_scroll_y, outline_h, total_h);

	glScissor(0, 0, outline_w, outline_h);
	glEnable(GL_SCISSOR_TEST);

	glColor4f(1, 1, 1, 1);
	glRectf(0, 0, outline_w, outline_h);

	do_outline_imp(outline, fz_count_pages(ctx, doc), 0, outline_w, 10, -outline_scroll_y);

	glDisable(GL_SCISSOR_TEST);
}

static void do_links(fz_link *link, int xofs, int yofs)
{
	fz_rect r;
	float x, y;
	float link_x, link_y;

	x = ui.x;
	y = ui.y;

	xofs -= page_tex.x;
	yofs -= page_tex.y;

	glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_BLEND);

	while (link)
	{
		r = link->rect;
		fz_transform_rect(&r, &page_ctm);

		if (x >= xofs + r.x0 && x < xofs + r.x1 && y >= yofs + r.y0 && y < yofs + r.y1)
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
			glRectf(xofs + r.x0, yofs + r.y0, xofs + r.x1, yofs + r.y1);
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
					glutPostRedisplay(); /* we changed the current page, so force a redraw */
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
			glutPostRedisplay();
		}
	}
}

static void do_search_hits(int xofs, int yofs)
{
	fz_rect r;
	int i;

	xofs -= page_tex.x;
	yofs -= page_tex.y;

	glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_BLEND);

	for (i = 0; i < search_hit_count; ++i)
	{
		r = search_hit_bbox[i];

		fz_transform_rect(&r, &page_ctm);

		glColor4f(1, 0, 0, 0.4f);
		glRectf(xofs + r.x0, yofs + r.y0, xofs + r.x1, yofs + r.y1);
	}

	glDisable(GL_BLEND);
}

static void do_forms(float xofs, float yofs)
{
	static int do_forms_tag = 0;
	pdf_ui_event event;
	fz_point p;
	int i;

	for (i = 0; i < annot_count; ++i)
		ui_draw_image(&annot_tex[i], xofs - page_tex.x, yofs - page_tex.y);

	if (!pdf || search_active)
		return;

	p.x = xofs - page_tex.x + ui.x;
	p.y = xofs - page_tex.x + ui.y;
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
			glutPostRedisplay();
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
			glutPostRedisplay();
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
	int w = page_tex.w + canvas_x;
	int h = page_tex.h + canvas_y;
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
	render_page();
	update_title();
}

static void toggle_outline(void)
{
	if (outline)
	{
		showoutline = !showoutline;
		if (showoutline)
			canvas_x = ui.lineheight * 16;
		else
			canvas_x = 0;
		if (canvas_w == page_tex.w && canvas_h == page_tex.h)
			shrinkwrap();
	}
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

static void quit(void)
{
	doquit = 1;
}

static void clear_search(void)
{
	search_hit_page = -1;
	search_hit_count = 0;
}

static void do_app(void)
{
	if (ui.key == KEY_F4 && ui.mod == GLUT_ACTIVE_ALT)
		quit();

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
		case 'q': quit(); break;

		case 'I': currentinvert = !currentinvert; break;
		case 'f': toggle_fullscreen(); break;
		case 'w': shrinkwrap(); break;
		case 'W': auto_zoom_w(); break;
		case 'H': auto_zoom_h(); break;
		case 'Z': auto_zoom(); break;
		case 'z': currentzoom = number > 0 ? number : DEFRES; break;
		case '+': currentzoom = zoom_in(currentzoom); break;
		case '-': currentzoom = zoom_out(currentzoom); break;
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
			search_input.p = search_input.text;
			search_input.q = search_input.end;
			break;
		case '?':
			clear_search();
			search_dir = -1;
			showsearch = 1;
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
			glutPostRedisplay();
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
			glutPostRedisplay();
			break;
		}

		if (ui.key >= '0' && ui.key <= '9')
			number = number * 10 + ui.key - '0';
		else
			number = 0;

		currentpage = fz_clampi(currentpage, 0, fz_count_pages(ctx, doc) - 1);
		currentzoom = fz_clamp(currentzoom, MINRES, MAXRES);
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
	ui_draw_string(ctx, x, y, buf);
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
	ui_draw_string(ctx, x, y, label);
	ui_draw_string(ctx, x+100, y, text);
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

	float x, y;

	if (oldpage != currentpage || oldzoom != currentzoom || oldrotate != currentrotate || oldinvert != currentinvert)
	{
		render_page();
		update_title();
		oldpage = currentpage;
		oldzoom = currentzoom;
		oldrotate = currentrotate;
		oldinvert = currentinvert;
	}

	if (ui.x >= canvas_x && ui.x < canvas_x + canvas_w && ui.y >= canvas_y && ui.y < canvas_y + canvas_h)
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
		x = canvas_x + (canvas_w - page_tex.w) / 2;
	}
	else
	{
		scroll_x = fz_clamp(scroll_x, 0, page_tex.w - canvas_w);
		x = canvas_x - scroll_x;
	}

	if (page_tex.h <= canvas_h)
	{
		scroll_y = 0;
		y = canvas_y + (canvas_h - page_tex.h) / 2;
	}
	else
	{
		scroll_y = fz_clamp(scroll_y, 0, page_tex.h - canvas_h);
		y = canvas_y - scroll_y;
	}

	ui_draw_image(&page_tex, x - page_tex.x, y - page_tex.y);

	do_forms(x, y);

	if (!search_active)
	{
		do_links(links, x, y);
		do_page_selection(x, y, x+page_tex.w, y+page_tex.h);
		if (search_hit_page == currentpage && search_hit_count > 0)
			do_search_hits(x, y);
	}
}

static void run_main_loop(void)
{
	glViewport(0, 0, window_w, window_h);
	glClearColor(0.3f, 0.3f, 0.3f, 1.0f);
	glClear(GL_COLOR_BUFFER_BIT);

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrtho(0, window_w, window_h, 0, -1, 1);

	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();

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

	if (doquit)
	{
		glutDestroyWindow(window);
#ifdef __APPLE__
		exit(1); /* GLUT on MacOS keeps running even with no windows */
#endif
		return;
	}

	canvas_w = window_w - canvas_x;
	canvas_h = window_h - canvas_y;

	do_canvas();

	if (showinfo)
		do_info();
	else if (showhelp)
		do_help();

	if (showoutline)
		do_outline(outline, canvas_x);

	if (showsearch)
	{
		int state = ui_input(canvas_x, 0, canvas_x + canvas_w, ui.lineheight+4, &search_input);
		if (state == -1)
		{
			ui.focus = NULL;
			showsearch = 0;
			glutPostRedisplay();
		}
		else if (state == 1)
		{
			ui.focus = NULL;
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
			glutPostRedisplay();
		}
	}

	if (search_active)
	{
		char buf[256];
		sprintf(buf, "Searching page %d of %d.", search_page + 1, fz_count_pages(ctx, doc));
		ui_label_draw(canvas_x, 0, canvas_x + canvas_w, ui.lineheight+4, buf);
	}

	ui_end();

	glutSwapBuffers();

	ogl_assert(ctx, "swap buffers");
}

#if defined(FREEGLUT) && (GLUT_API_VERSION >= 6)
static void on_keyboard(int key, int x, int y)
#else
static void on_keyboard(unsigned char key, int x, int y)
#endif
{
#ifdef __APPLE__
	/* Apple's GLUT has swapped DELETE and BACKSPACE */
	if (key == 8)
		key = 127;
	else if (key == 127)
		key = 8;
#endif
	ui.key = key;
	ui.mod = glutGetModifiers();
	ui.plain = !(ui.mod & ~GLUT_ACTIVE_SHIFT);
	run_main_loop();
	ui.key = ui.mod = ui.plain = 0;
}

static void on_special(int key, int x, int y)
{
	ui.key = 0;

	switch (key)
	{
	case GLUT_KEY_INSERT: ui.key = KEY_INSERT; break;
#ifdef GLUT_KEY_DELETE
	case GLUT_KEY_DELETE: ui.key = KEY_DELETE; break;
#endif
	case GLUT_KEY_RIGHT: ui.key = KEY_RIGHT; break;
	case GLUT_KEY_LEFT: ui.key = KEY_LEFT; break;
	case GLUT_KEY_DOWN: ui.key = KEY_DOWN; break;
	case GLUT_KEY_UP: ui.key = KEY_UP; break;
	case GLUT_KEY_PAGE_UP: ui.key = KEY_PAGE_UP; break;
	case GLUT_KEY_PAGE_DOWN: ui.key = KEY_PAGE_DOWN; break;
	case GLUT_KEY_HOME: ui.key = KEY_HOME; break;
	case GLUT_KEY_END: ui.key = KEY_END; break;
	case GLUT_KEY_F1: ui.key = KEY_F1; break;
	case GLUT_KEY_F2: ui.key = KEY_F2; break;
	case GLUT_KEY_F3: ui.key = KEY_F3; break;
	case GLUT_KEY_F4: ui.key = KEY_F4; break;
	case GLUT_KEY_F5: ui.key = KEY_F5; break;
	case GLUT_KEY_F6: ui.key = KEY_F6; break;
	case GLUT_KEY_F7: ui.key = KEY_F7; break;
	case GLUT_KEY_F8: ui.key = KEY_F8; break;
	case GLUT_KEY_F9: ui.key = KEY_F9; break;
	case GLUT_KEY_F10: ui.key = KEY_F10; break;
	case GLUT_KEY_F11: ui.key = KEY_F11; break;
	case GLUT_KEY_F12: ui.key = KEY_F12; break;
	}

	if (ui.key)
	{
		ui.mod = glutGetModifiers();
		ui.plain = !(ui.mod & ~GLUT_ACTIVE_SHIFT);
		run_main_loop();
		ui.key = ui.mod = ui.plain = 0;
	}
}

static void on_wheel(int wheel, int direction, int x, int y)
{
	ui.scroll_x = wheel == 1 ? direction : 0;
	ui.scroll_y = wheel == 0 ? direction : 0;
	run_main_loop();
	ui.scroll_x = ui.scroll_y = 0;
}

static void on_mouse(int button, int action, int x, int y)
{
	ui.x = x;
	ui.y = y;
	switch (button)
	{
	case GLUT_LEFT_BUTTON: ui.down = (action == GLUT_DOWN); break;
	case GLUT_MIDDLE_BUTTON: ui.middle = (action == GLUT_DOWN); break;
	case GLUT_RIGHT_BUTTON: ui.right = (action == GLUT_DOWN); break;
	case 3: if (action == GLUT_DOWN) on_wheel(0, 1, x, y); break;
	case 4: if (action == GLUT_DOWN) on_wheel(0, -1, x, y); break;
	case 5: if (action == GLUT_DOWN) on_wheel(1, 1, x, y); break;
	case 6: if (action == GLUT_DOWN) on_wheel(1, -1, x, y); break;
	}
	run_main_loop();
}

static void on_motion(int x, int y)
{
	ui.x = x;
	ui.y = y;
	glutPostRedisplay();
}

static void on_reshape(int w, int h)
{
	showinfo = 0;
	showhelp = 0;
	window_w = w;
	window_h = h;
}

static void on_display(void)
{
	run_main_loop();
}

static void on_error(const char *fmt, va_list ap)
{
#ifdef _WIN32
	char buf[1000];
	fz_vsnprintf(buf, sizeof buf, fmt, ap);
	MessageBoxA(NULL, buf, "MuPDF GLUT Error", MB_ICONERROR);
#else
	fprintf(stderr, "GLUT error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
#endif
}

static void on_warning(const char *fmt, va_list ap)
{
	fprintf(stderr, "GLUT warning: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
}

#if defined(FREEGLUT) && (GLUT_API_VERSION >= 6)

void ui_set_clipboard(const char *buf)
{
	glutSetClipboard(GLUT_CLIPBOARD, buf);
}

const char *ui_get_clipboard(void)
{
	return glutGetClipboard(GLUT_CLIPBOARD);
}

#else

static char *clipboard_buffer = NULL;

void ui_set_clipboard(const char *buf)
{
	fz_free(ctx, clipboard_buffer);
	clipboard_buffer = fz_strdup(ctx, buf);
}

const char *ui_get_clipboard(void)
{
	return clipboard_buffer;
}

#endif

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

	/* Init MuPDF */

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

	/* Init IMGUI */

	memset(&ui, 0, sizeof ui);

	search_input.p = search_input.text;
	search_input.q = search_input.p;
	search_input.end = search_input.p;

	/* Init GLUT */

	glutSetOption(GLUT_ACTION_ON_WINDOW_CLOSE, GLUT_ACTION_GLUTMAINLOOP_RETURNS);

	glutInitErrorFunc(on_error);
	glutInitWarningFunc(on_warning);
	glutInitDisplayMode(GLUT_RGBA | GLUT_DOUBLE);
	glutInitWindowSize(page_tex.w, page_tex.h);
	window = glutCreateWindow(title);

	glutReshapeFunc(on_reshape);
	glutDisplayFunc(on_display);
#if defined(FREEGLUT) && (GLUT_API_VERSION >= 6)
	glutKeyboardExtFunc(on_keyboard);
#else
	glutKeyboardFunc(on_keyboard);
#endif
	glutSpecialFunc(on_special);
	glutMouseFunc(on_mouse);
	glutMotionFunc(on_motion);
	glutPassiveMotionFunc(on_motion);
	glutMouseWheelFunc(on_wheel);

	has_ARB_texture_non_power_of_two = glutExtensionSupported("GL_ARB_texture_non_power_of_two");
	if (!has_ARB_texture_non_power_of_two)
		fz_warn(ctx, "OpenGL implementation does not support non-power of two texture sizes");

	glGetIntegerv(GL_MAX_TEXTURE_SIZE, &max_texture_size);

	ui.fontsize = DEFAULT_UI_FONTSIZE;
	ui.baseline = DEFAULT_UI_BASELINE;
	ui.lineheight = DEFAULT_UI_LINEHEIGHT;

	ui_init_fonts(ctx, ui.fontsize);

	render_page();
	update_title();

	glutMainLoop();

	ui_finish_fonts(ctx);

	glutExit();

#ifndef NDEBUG
	if (fz_atoi(getenv("FZ_DEBUG_STORE")))
		fz_debug_store(ctx);
#endif

	fz_drop_stext_page(ctx, text);
	fz_drop_link(ctx, links);
	fz_drop_page(ctx, page);
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
