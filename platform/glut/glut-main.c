#include "mupdf/fitz.h"

// TODO: event queue and handle key/mouse based on 'active' inside display()

#ifdef __APPLE__
#include <OpenGL/OpenGL.h>
#include <GLUT/glut.h>
#else
#include <GL/gl.h>
#include <GL/freeglut.h>
#endif

struct input
{
	int text[256];
	int *end, *p, *q;
};

struct ui
{
	int x, y, down, middle, right;
	void *hot, *active;
} ui;

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
	ShellExecuteA(hwndframe, "open", uri, 0, 0, SW_SHOWNORMAL);
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
	CASE(GL_INVALID_FRAMEBUFFER_OPERATION);
	CASE(GL_OUT_OF_MEMORY);
	CASE(GL_STACK_UNDERFLOW);
	CASE(GL_STACK_OVERFLOW);

	/* glCheckFramebufferStatus */
	CASE(GL_FRAMEBUFFER_COMPLETE);
	CASE(GL_FRAMEBUFFER_UNDEFINED);
	CASE(GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT);
	CASE(GL_FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT);
	CASE(GL_FRAMEBUFFER_INCOMPLETE_DRAW_BUFFER);
	CASE(GL_FRAMEBUFFER_INCOMPLETE_READ_BUFFER);
	CASE(GL_FRAMEBUFFER_UNSUPPORTED);
	CASE(GL_FRAMEBUFFER_INCOMPLETE_MULTISAMPLE);
	CASE(GL_FRAMEBUFFER_INCOMPLETE_LAYER_TARGETS);

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

void draw_image(int tex, fz_rect *r)
{
	glBindTexture(GL_TEXTURE_2D, tex);

	glEnable(GL_TEXTURE_2D);
	glBegin(GL_TRIANGLE_STRIP);
	{
		glColor4f(1, 1, 1, 1);
		glTexCoord2f(0, 1);
		glVertex2f(r->x0, r->y1);

		glColor4f(1, 1, 1, 1);
		glTexCoord2f(0, 0);
		glVertex2f(r->x0, r->y0);

		glColor4f(1, 1, 1, 1);
		glTexCoord2f(1, 1);
		glVertex2f(r->x1, r->y1);

		glColor4f(1, 1, 1, 1);
		glTexCoord2f(1, 0);
		glVertex2f(r->x1, r->y0);
	}
	glEnd();
	glDisable(GL_TEXTURE_2D);
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

static const char *filename = "";
static const char *title = "MuPDF/GL";
static fz_context *ctx = NULL;
static fz_document *doc = NULL;
static fz_outline *outline = NULL;
static fz_link *links = NULL;

static int number = 0;

static unsigned int page_tex = 0;
static int page_x, page_y, page_w, page_h;
static int scroll_x = 0, scroll_y = 0;
static int canvas_x = 0, canvas_w = 100;
static int canvas_y = 0, canvas_h = 100;

static int screen_w = 1, screen_h = 1;

static int oldpage = 0, currentpage = 0;
static float oldzoom = DEFRES, currentzoom = DEFRES;
static float oldrotate = 0, currentrotate = 0;

static int isfullscreen = 0;
static int showoutline = 0;
static int showlinks = 0;
static int showsearch = 0;

static int history_count = 0;
static int history[256];
static int future_count = 0;
static int future[256];
static int marks[10];

static int search_active = 0;
static struct input search_input = { { 0 }, 0 };
static char *search_needle = 0;
static int search_dir = 1;
static int search_page = -1;
static int search_hit_page = -1;
static int search_hit_count = 0;
static fz_rect search_hit_bbox[500];

static void update_title(void)
{
	static char buf[256];
	int n = strlen(title);
	if (n > 50)
		sprintf(buf, "...%s - %d / %d", title + n - 50, currentpage + 1, fz_count_pages(ctx, doc));
	else
		sprintf(buf, "%s - %d / %d", title, currentpage + 1, fz_count_pages(ctx, doc));
	glutSetWindowTitle(buf);
	glutSetIconTitle(buf);
}

void render_page(int pagenumber, float zoom, float rotate)
{
	fz_page *page;
	fz_matrix ctm;
	fz_rect bounds;
	fz_irect ibounds;
	fz_pixmap *pix;
	fz_device *dev;

	fz_scale(&ctm, zoom / 72, zoom / 72);
	fz_pre_rotate(&ctm, -rotate);

	page = fz_load_page(ctx, doc, pagenumber);
	fz_bound_page(ctx, page, &bounds);
	fz_transform_rect(&bounds, &ctm);
	fz_round_rect(&ibounds, &bounds);

	fz_drop_link(ctx, links);
	links = NULL;
	links = fz_load_links(ctx, page);

	pix = fz_new_pixmap_with_bbox(ctx, fz_device_rgb(ctx), &ibounds);
	fz_clear_pixmap_with_value(ctx, pix, 0xff);
	dev = fz_new_draw_device(ctx, pix);
	fz_run_page(ctx, page, dev, &ctm, NULL);
	fz_drop_device(ctx, dev);

	page_x = pix->x;
	page_y = pix->y;
	page_w = pix->w;
	page_h = pix->h;

	if (!page_tex)
		glGenTextures(1, &page_tex);
	glBindTexture(GL_TEXTURE_2D, page_tex);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, page_w, page_h, 0, GL_RGBA, GL_UNSIGNED_BYTE, pix->samples);

	fz_drop_pixmap(ctx, pix);
	fz_drop_page(ctx, page);
}

static void push_history(void)
{
	if (history_count + 1 >= nelem(history))
	{
		memmove(history, history + 1, sizeof *history * (nelem(history) - 1));
		history[history_count] = currentpage;
	}
	else
	{
		history[history_count++] = currentpage;
	}
}

static void push_future(void)
{
	if (future_count + 1 >= nelem(future))
	{
		memmove(future, future + 1, sizeof *future * (nelem(future) - 1));
		future[future_count] = currentpage;
	}
	else
	{
		future[future_count++] = currentpage;
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

static void pop_history(void)
{
	int here = currentpage;
	push_future();
	while (history_count > 0 && currentpage == here)
		currentpage = history[--history_count];
}

static void pop_future(void)
{
	int here = currentpage;
	push_history();
	while (future_count > 0 && currentpage == here)
		currentpage = future[--future_count];
	push_history();
}

void do_search_page(int number, char *needle, fz_cookie *cookie)
{
	fz_page *page = fz_load_page(ctx, doc, number);

	fz_text_sheet *sheet = fz_new_text_sheet(ctx);
	fz_text_page *text = fz_new_text_page(ctx);
	fz_device *dev = fz_new_text_device(ctx, sheet, text);
	fz_run_page(ctx, page, dev, &fz_identity, cookie);
	fz_drop_device(ctx, dev);

	search_hit_count = fz_search_text_page(ctx, text, needle, search_hit_bbox, nelem(search_hit_bbox));

	fz_drop_text_page(ctx, text);
	fz_drop_text_sheet(ctx, sheet);
	fz_drop_page(ctx, page);
}

static void draw_string(float x, float y, const char *s)
{
	int c;
	glRasterPos2f(x + 0.375f, y + 0.375f + 11);
	while (*s)
	{
		s += fz_chartorune(&c, s);
		glutBitmapCharacter(GLUT_BITMAP_HELVETICA_12, c);
	}
}

#if 0
static float measure_string(const char *s)
{
	int w = 0, c;
	while (*s)
	{
		s += fz_chartorune(&c, s);
		w += glutBitmapWidth(GLUT_BITMAP_HELVETICA_12, c);
	}
	return w;
}
#endif

static void ui_label_draw(int x0, int y0, int x1, int y1, const char *text)
{
	glColor4f(1, 1, 1, 1);
	glRectf(x0, y0, x1, y1);
	glColor4f(0, 0, 0, 1);
	draw_string(x0 + 2, y0 + 2, text);
}

static void draw_string_part(float x, float y, const int *s, const int *e)
{
	glRasterPos2f(x + 0.375f, y + 0.375f + 11);
	while (s < e)
		glutBitmapCharacter(GLUT_BITMAP_HELVETICA_12, *s++);
}

static float measure_string_part(const int *s, const int *e)
{
	int w = 0;
	while (s < e)
		w += glutBitmapWidth(GLUT_BITMAP_HELVETICA_12, *s++);
	return w;
}

static int *find_string_location(int *s, int *e, float w, float x)
{
	while (s < e)
	{
		int cw = glutBitmapWidth(GLUT_BITMAP_HELVETICA_12, *s);
		if (w + (cw / 2) >= x)
			return s;
		w += cw;
		++s;
	}
	return e;
}

static inline int isalnum(int c)
{
	int cat = ucdn_get_general_category(c);
	if (cat >= UCDN_GENERAL_CATEGORY_LL && cat <= UCDN_GENERAL_CATEGORY_LU)
		return 1;
	if (cat >= UCDN_GENERAL_CATEGORY_ND && cat <= UCDN_GENERAL_CATEGORY_NO)
		return 1;
	return 0;
}

static int *skip_word_left(int *p, int *start)
{
	while (p > start && !isalnum(p[-1])) --p;
	while (p > start && isalnum(p[-1])) --p;
	return p;
}

static int *skip_word_right(int *p, int *end)
{
	while (p < end && !isalnum(p[0])) ++p;
	while (p < end && isalnum(p[0])) ++p;
	return p;
}

static void ui_input_draw(int x0, int y0, int x1, int y1, struct input *input)
{
	float px, qx, ex;
	int *p, *q;

	if (ui.x >= x0 && ui.x < x1 && ui.y >= y0 && ui.y < y1)
	{
		ui.hot = input;
		if (!ui.active && ui.down)
		{
			ui.active = input;
			input->p = find_string_location(input->text, input->end, x0 + 2, ui.x);
		}
	}

	if (ui.active == input)
		input->q = find_string_location(input->text, input->end, x0 + 2, ui.x);

	glColor4f(1, 1, 1, 1);
	glRectf(x0, y0, x1, y1);

	p = input->p < input->q ? input->p : input->q;
	q = input->p > input->q ? input->p : input->q;

	px = x0 + 2 + measure_string_part(input->text, p);
	qx = px + measure_string_part(p, q);
	ex = qx + measure_string_part(q, input->end);

	glColor4f(0.6, 0.6, 1.0, 1);
	glRectf(px, y0 + 2, qx+1, y1 - 2);

	glColor4f(0, 0, 0, 1);
	draw_string_part(x0 + 2, y0 + 2, input->text, input->end);
}

static void ui_input_delete_selection(struct input *input)
{
	int *p = input->p < input->q ? input->p : input->q;
	int *q = input->p > input->q ? input->p : input->q;
	memmove(p, q, (input->end - q) * sizeof (*p));
	input->end -= q - p;
	input->p = input->q = p;
}

static int ui_input_keyboard(int key, struct input *input)
{
	int cat;

	switch (key)
	{
	default:
		cat = ucdn_get_general_category(key);
		if (key == ' ' || (cat >= UCDN_GENERAL_CATEGORY_LL && cat < UCDN_GENERAL_CATEGORY_ZL))
		{
			if (input->p != input->q)
				ui_input_delete_selection(input);
			if (input->end < input->text + nelem(input->text))
			{
				memmove(input->p + 1, input->p, (input->end - input->p) * sizeof (*input->p));
				++(input->end);
				*(input->p++) = key;
			}
			input->q = input->p;
		}
		break;
	case 27:
		return -1;
	case '\r':
		return 1;
	case '\b':
		if (input->p != input->q)
			ui_input_delete_selection(input);
		else if (input->p > input->text && input->end > input->text)
		{
			memmove(input->p - 1, input->p, (input->end - input->p) * sizeof (*input->p));
			input->q = --(input->p);
			--(input->end);
		}
		break;
	case 127:
		if (input->p != input->q)
			ui_input_delete_selection(input);
		else if (input->p < input->end)
		{
			memmove(input->p, input->p + 1, (input->end - input->p - 1) * sizeof (*input->p));
			input->q = input->p;
			--(input->end);
		}
		break;
	case 'A' - 64:
		input->p = input->q = input->text;
		break;
	case 'E' - 64:
		input->p = input->q = input->end;
		break;
	case 'W' - 64:
		if (input->p != input->q)
			ui_input_delete_selection(input);
		else
		{
			input->p = skip_word_left(input->p, input->text);
			ui_input_delete_selection(input);
		}
		break;
	case 'U' - 64:
		input->p = input->q = input->end = input->text;
		break;
	}

	return 0;
}

static void ui_input_special(int key, int mod, struct input *input)
{
	if (mod == GLUT_ACTIVE_CTRL + GLUT_ACTIVE_SHIFT)
	{
		switch (key)
		{
		case GLUT_KEY_LEFT: input->q = skip_word_left(input->q, input->text); break;
		case GLUT_KEY_RIGHT: input->q = skip_word_right(input->q, input->end); break;
		case GLUT_KEY_UP: case GLUT_KEY_HOME: input->q = input->text; break;
		case GLUT_KEY_DOWN: case GLUT_KEY_END: input->q = input->end; break;
		}
	}
	else if (mod == GLUT_ACTIVE_CTRL)
	{
		switch (key)
		{
		case GLUT_KEY_LEFT:
			if (input->p != input->q)
				input->p = input->q = input->p < input->q ? input->p : input->q;
			else
				input->p = input->q = skip_word_left(input->q, input->text);
			break;
		case GLUT_KEY_RIGHT:
			if (input->p != input->q)
				input->p = input->q = input->p > input->q ? input->p : input->q;
			else
				input->p = input->q = skip_word_right(input->q, input->end);
			break;
		case GLUT_KEY_HOME:
		case GLUT_KEY_UP:
			input->p = input->q = input->text;
			break;
		case GLUT_KEY_END:
		case GLUT_KEY_DOWN:
			input->p = input->q = input->end;
			break;
		}
	}
	else if (mod == GLUT_ACTIVE_SHIFT)
	{
		switch (key)
		{
		case GLUT_KEY_LEFT: if (input->q > input->text) input->q = --(input->q); break;
		case GLUT_KEY_RIGHT: if (input->q < input->end) input->q = ++(input->q); break;
		case GLUT_KEY_HOME: input->q = input->text; break;
		case GLUT_KEY_END: input->q = input->end; break;
		}
	}
	else if (mod == 0)
	{
		switch (key)
		{
		case GLUT_KEY_LEFT:
			if (input->p != input->q)
				input->p = input->q = input->p < input->q ? input->p : input->q;
			else if (input->q > input->text)
				input->p = input->q = --(input->q);
			break;
		case GLUT_KEY_RIGHT:
			if (input->p != input->q)
				input->p = input->q = input->p > input->q ? input->p : input->q;
			else if (input->q < input->end)
				input->p = input->q = ++(input->q);
			break;
		case GLUT_KEY_HOME:
			input->p = input->q = input->text;
			break;
		case GLUT_KEY_END:
			input->p = input->q = input->end;
			break;
		}
	}
}

static void ui_scrollbar(int x0, int y0, int x1, int y1, int *value, int page, int max)
{
	static float save_top = 0;
	static int save_ui_y = 0;
	float top;

	int total_h = y1 - y0;
	int thumb_h = fz_maxi(x1 - x0, total_h * page / max);
	int avail_h = total_h - thumb_h;

	max -= page;

	if (max <= 0)
	{
		glColor4f(0.6, 0.6, 0.6, 1);
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
				*value -= page;
			}
			else if (ui.y >= top + thumb_h)
			{
				ui.active = "pgup";
				*value += page;
			}
			else
			{
				ui.hot = value;
				ui.active = value;
				save_top = top;
				save_ui_y = ui.y;
			}
		}
	}

	if (ui.active == value)
	{
		*value = (save_top + ui.y - save_ui_y) * max / avail_h;
	}

	if (*value < 0)
		*value = 0;
	else if (*value > max)
		*value = max;

	top = (float) *value * avail_h / max;

	glColor4f(0.6, 0.6, 0.6, 1);
	glRectf(x0, y0, x1, y1);
	glColor4f(0.8, 0.8, 0.8, 1);
	glRectf(x0, top, x1, top + thumb_h);
}

static int measure_outline_height(fz_outline *node)
{
	int h = 0;
	while (node)
	{
		h += 15;
		if (node->down)
			h += measure_outline_height(node->down);
		node = node->next;
	}
	return h;
}

static int draw_outline_imp(fz_outline *node, int end, int x0, int x1, int x, int y)
{
	int h = 0;
	int p = currentpage;
	int n = end;

	while (node)
	{
		if (node->dest.kind == FZ_LINK_GOTO)
		{
			p = node->dest.ld.gotor.page;

			if (ui.x >= x0 && ui.x < x1 && ui.y >= y + h && ui.y < y + h + 15)
			{
				ui.hot = node;
				if (!ui.active && ui.down)
				{
					ui.active = node;
					jump_to_page(p);
					glutPostRedisplay(); /* we changed the current page, so force a redraw */
				}
			}

			n = end;
			if (node->next && node->next->dest.kind == FZ_LINK_GOTO)
			{
				n = node->next->dest.ld.gotor.page;
			}
			if (currentpage == p || (currentpage > p && currentpage < n))
			{
				glColor4f(0.9, 0.9, 0.9, 1);
				glRectf(x0, y + h, x1, y + h + 15);
			}
		}

		glColor4f(0, 0, 0, 1);
		draw_string(x, y + h, node->title);
		h += 15;
		if (node->down)
			h += draw_outline_imp(node->down, n, x0, x1, x + 15, y + h);

		node = node->next;
	}
	return h;
}

static void draw_outline(fz_outline *node, int outline_w)
{
	static char *id = "outline";
	static int scroll_y = 0;
	static int save_scroll_y = 0;
	static int save_ui_y = 0;

	int outline_h;
	int total_h;

	outline_w -= 15;
	outline_h = screen_h;
	total_h = measure_outline_height(outline);

	if (ui.x >= 0 && ui.x < outline_w && ui.y >= 0 && ui.y < outline_h)
	{
		if (!ui.active && ui.middle)
		{
			ui.active = id;
			save_ui_y = ui.y;
			save_scroll_y = scroll_y;
		}
	}

	if (ui.active == id)
		scroll_y = save_scroll_y + (save_ui_y - ui.y) * 5;

	ui_scrollbar(outline_w, 0, outline_w+15, outline_h, &scroll_y, outline_h, total_h);

	glScissor(0, 0, outline_w, outline_h);
	glEnable(GL_SCISSOR_TEST);

	glColor4f(1, 1, 1, 1);
	glRectf(0, 0, outline_w, outline_h);

	draw_outline_imp(outline, fz_count_pages(ctx, doc), 0, outline_w, 10, -scroll_y);

	glDisable(GL_SCISSOR_TEST);
}

static void draw_links(fz_link *link, int xofs, int yofs, float zoom, float rotate)
{
	fz_matrix ctm;
	fz_rect r;
	float x, y;

	x = ui.x;
	y = ui.y;

	xofs -= page_x;
	yofs -= page_y;

	fz_scale(&ctm, zoom / 72, zoom / 72);
	fz_pre_rotate(&ctm, -rotate);

	glEnable(GL_BLEND);
	glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);

	while (link)
	{
		r = link->rect;
		fz_transform_rect(&r, &ctm);

		if (x >= xofs + r.x0 && x < xofs + r.x1 && y >= yofs + r.y0 && y < yofs + r.y1)
		{
			ui.hot = link;
			if (!ui.active && ui.down)
				ui.active = link;
		}

		if (ui.hot == link || showlinks)
		{
			if (ui.active == link && ui.hot == link)
				glColor4f(0, 0, 1, 0.4);
			else if (ui.hot == link)
				glColor4f(0, 0, 1, 0.2);
			else
				glColor4f(0, 0, 1, 0.1);
			glRectf(xofs + r.x0, yofs + r.y0, xofs + r.x1, yofs + r.y1);
		}

		if (ui.active == link && !ui.down)
		{
			if (ui.hot == link)
			{
				if (link->dest.kind == FZ_LINK_GOTO)
					jump_to_page(link->dest.ld.gotor.page);
				else if (link->dest.kind == FZ_LINK_URI)
					open_browser(link->dest.ld.uri.uri);
			}
			glutPostRedisplay();
		}

		link = link->next;
	}

	glDisable(GL_BLEND);
}

static void draw_search_hits(int xofs, int yofs, float zoom, float rotate)
{
	fz_matrix ctm;
	fz_rect r;
	int i;

	xofs -= page_x;
	yofs -= page_y;

	fz_scale(&ctm, zoom / 72, zoom / 72);
	fz_pre_rotate(&ctm, -rotate);

	glEnable(GL_BLEND);
	glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);

	for (i = 0; i < search_hit_count; ++i)
	{
		r = search_hit_bbox[i];

		fz_transform_rect(&r, &ctm);

		glColor4f(1, 0, 0, 0.4);
		glRectf(xofs + r.x0, yofs + r.y0, xofs + r.x1, yofs + r.y1);
	}

	glDisable(GL_BLEND);
}

static void toggle_fullscreen(void)
{
	static int oldw = 100, oldh = 100, oldx = 0, oldy = 0;

	if (!isfullscreen)
	{
		oldw = glutGet(GLUT_WINDOW_WIDTH);
		oldh = glutGet(GLUT_WINDOW_HEIGHT);
		oldx = glutGet(GLUT_WINDOW_X);
		oldy = glutGet(GLUT_WINDOW_Y);
		glutFullScreen();
		isfullscreen = 1;
	}
	else
	{
		glutPositionWindow(oldx, oldy);
		glutReshapeWindow(oldw, oldh);
		isfullscreen = 0;
	}
}

static void shrinkwrap(void)
{
	int w = page_w + canvas_x;
	int h = page_h + canvas_y;
	if (isfullscreen)
		toggle_fullscreen();
	glutReshapeWindow(w, h);
}

static void auto_zoom_w(void)
{
	currentzoom = fz_clamp(currentzoom * canvas_w / (float)page_w, MINRES, MAXRES);
}

static void auto_zoom_h(void)
{
	currentzoom = fz_clamp(currentzoom * canvas_h / (float)page_h, MINRES, MAXRES);
}

static void auto_zoom(void)
{
	float page_a = (float) page_w / page_h;
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
				scroll_x = page_w;
				scroll_y = page_h;
				currentpage -= 1;
			}
		}
		else
		{
			scroll_y = page_h;
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
	if (scroll_y + canvas_h >= page_h)
	{
		if (scroll_x + canvas_w >= page_w)
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


static void reshape(int w, int h)
{
	screen_w = w;
	screen_h = h;
}

static void display(void)
{
	fz_rect r;
	float x, y;

	static int save_scroll_x = 0;
	static int save_scroll_y = 0;
	static int save_ui_x = 0;
	static int save_ui_y = 0;

	glViewport(0, 0, screen_w, screen_h);
	glClearColor(0.3, 0.3, 0.3, 1.0);
	glClear(GL_COLOR_BUFFER_BIT);

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrtho(0, screen_w, screen_h, 0, -1, 1);

	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();

	ui_begin();

	if (search_active)
	{
		int start_time = glutGet(GLUT_ELAPSED_TIME);
		while (glutGet(GLUT_ELAPSED_TIME) < start_time + 200)
		{
			do_search_page(search_page, search_needle, NULL);
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

	if (showoutline)
	{
		if (!outline)
			outline = fz_load_outline(ctx, doc);
		if (!outline)
			showoutline = 0;
	}

	if (oldpage != currentpage || oldzoom != currentzoom || oldrotate != currentrotate)
	{
		render_page(currentpage, currentzoom, currentrotate);
		update_title();
		oldpage = currentpage;
		oldzoom = currentzoom;
		oldrotate = currentrotate;
	}

	if (showoutline)
	{
		canvas_x = 300;
		canvas_w = screen_w - canvas_x;
	}
	else
	{
		canvas_x = 0;
		canvas_w = screen_w;
	}

	canvas_y = 0;
	canvas_h = screen_h;

	if (ui.x >= canvas_x && ui.x < canvas_x + canvas_w && ui.y >= canvas_y && ui.y < canvas_y + canvas_h)
	{
		ui.hot = doc;
		if (!ui.active && ui.middle)
		{
			ui.active = doc;
			save_scroll_x = scroll_x;
			save_scroll_y = scroll_y;
			save_ui_x = ui.x;
			save_ui_y = ui.y;
		}
	}

	if (ui.active == doc)
	{
		scroll_x = save_scroll_x + save_ui_x - ui.x;
		scroll_y = save_scroll_y + save_ui_y - ui.y;
	}

	if (page_w <= canvas_w)
	{
		scroll_x = 0;
		x = canvas_x + (canvas_w - page_w) / 2;
	}
	else
	{
		if (scroll_x < 0)
			scroll_x = 0;
		if (scroll_x + canvas_w > page_w)
			scroll_x = page_w - canvas_w;
		x = canvas_x - scroll_x;
	}

	if (page_h <= canvas_h)
	{
		scroll_y = 0;
		y = canvas_y + (canvas_h - page_h) / 2;
	}
	else
	{
		if (scroll_y < 0)
			scroll_y = 0;
		if (scroll_y + canvas_h > page_h)
			scroll_y = page_h - canvas_h;
		y = canvas_y - scroll_y;
	}

	r.x0 = x;
	r.y0 = y;
	r.x1 = x + page_w;
	r.y1 = y + page_h;

	draw_image(page_tex, &r);
	draw_links(links, x, y, currentzoom, currentrotate);

	if (search_hit_page == currentpage && search_hit_count > 0)
		draw_search_hits(x, y, currentzoom, currentrotate);

	if (showoutline)
	{
		draw_outline(outline, canvas_x);
	}

	if (showsearch)
	{
		ui_input_draw(canvas_x, 0, canvas_x + canvas_w, 15+4, &search_input);
	}

	if (search_active)
	{
		char buf[256];
		sprintf(buf, "searching page %d / %d", search_page + 1, fz_count_pages(ctx, doc));
		ui_label_draw(canvas_x, 0, canvas_x + canvas_w, 15+4, buf);
	}

	ui_end();

	glutSwapBuffers();

	ogl_assert(ctx, "swap buffers");
}

static char *
utf8_from_rune_string(fz_context *ctx, const int *s, const int *e)
{
	const int *src = s;
	char *d;
	char *dst;
	int len = 1;

	while (src < e)
		len += fz_runelen(*src++);

	d = fz_malloc(ctx, len);
	if (d != NULL)
	{
		dst = d;
		src = s;
		while (src < e)
			dst += fz_runetochar(dst, *src++);
		*dst = 0;
	}
	return d;
}

static void keyboard(unsigned char key, int x, int y)
{
	if (search_active)
	{
		if (key == 27)
			search_active = 0;
		glutPostRedisplay();
		return;
	}

	if (showsearch)
	{
		int state = ui_input_keyboard(key, &search_input);
		if (state == -1)
			showsearch = 0;
		else if (state == 1)
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
				search_needle = utf8_from_rune_string(ctx, search_input.text, search_input.end);
				search_active = 1;
				search_page = currentpage;
				printf("search '%s'\n", search_needle);
			}
		}
		glutPostRedisplay();
		return;
	}

	switch (key)
	{
	case 'q':
		exit(0);
		break;
	case 'm':
		if (number == 0)
			push_history();
		else if (number > 0 && number < nelem(marks))
			marks[number] = currentpage;
		break;
	case 't':
		if (number == 0)
		{
			if (history_count > 0)
				pop_history();
		}
		else if (number > 0 && number < nelem(marks))
		{
			jump_to_page(marks[number]);
		}
		break;
	case 'T':
		if (number == 0)
		{
			if (future_count > 0)
				pop_future();
		}
		break;
	case 'N':
		search_dir = -1;
		if (search_hit_page == currentpage)
			search_page = currentpage + search_dir;
		else
			search_page = currentpage;
		search_hit_page = -1;
		if (search_needle)
			search_active = 1;
		break;
	case 'n':
		search_dir = 1;
		if (search_hit_page == currentpage)
			search_page = currentpage + search_dir;
		else
			search_page = currentpage;
		search_hit_page = -1;
		if (search_needle)
			search_active = 1;
		break;
	case 'f': toggle_fullscreen(); break;
	case 'w': shrinkwrap(); break;
	case 'W': auto_zoom_w(); break;
	case 'H': auto_zoom_h(); break;
	case 'Z': auto_zoom(); break;
	case 'z': currentzoom = number > 0 ? number : DEFRES; break;
	case '<': currentpage -= 10 * fz_maxi(number, 1); break;
	case '>': currentpage += 10 * fz_maxi(number, 1); break;
	case ',': currentpage -= fz_maxi(number, 1); break;
	case '.': currentpage += fz_maxi(number, 1); break;
	case 'b': number = fz_maxi(number, 1); while (number--) smart_move_backward(); break;
	case ' ': number = fz_maxi(number, 1); while (number--) smart_move_forward(); break;
	case 'g': jump_to_page(number - 1); break;
	case 'G': jump_to_page(fz_count_pages(ctx, doc) - 1); break;
	case '+': currentzoom = zoom_in(currentzoom); break;
	case '-': currentzoom = zoom_out(currentzoom); break;
	case '[': currentrotate += 90; break;
	case ']': currentrotate -= 90; break;
	case 'o': showoutline = !showoutline; break;
	case 'l': showlinks = !showlinks; break;
	case '/': search_dir = 1; showsearch = 1; search_input.p = search_input.text; search_input.q = search_input.end; break;
	case '?': search_dir = -1; showsearch = 1; search_input.p = search_input.text; search_input.q = search_input.end; break;
	}

	if (key >= '0' && key <= '9')
		number = number * 10 + key - '0';
	else
		number = 0;

	currentpage = fz_clampi(currentpage, 0, fz_count_pages(ctx, doc) - 1);
	currentzoom = fz_clamp(currentzoom, MINRES, MAXRES);
	while (currentrotate < 0) currentrotate += 360;
	while (currentrotate >= 360) currentrotate -= 360;

	if (search_hit_page != currentpage)
		search_hit_page = -1; /* clear highlights when navigating */

	glutPostRedisplay();
}

static void special(int key, int x, int y)
{
	int mod = glutGetModifiers();

	if (key == GLUT_KEY_F4 && mod == GLUT_ACTIVE_ALT)
		exit(0);

	if (showsearch)
	{
		ui_input_special(key, mod, &search_input);
		glutPostRedisplay();
		return;
	}

	switch (key)
	{
	case GLUT_KEY_UP: scroll_y -= 10; break;
	case GLUT_KEY_DOWN: scroll_y += 10; break;
	case GLUT_KEY_LEFT: scroll_x -= 10; break;
	case GLUT_KEY_RIGHT: scroll_x += 10; break;
	case GLUT_KEY_PAGE_UP: currentpage -= fz_maxi(number, 1); break;
	case GLUT_KEY_PAGE_DOWN: currentpage += fz_maxi(number, 1); break;
	}

	number = 0;

	currentpage = fz_clampi(currentpage, 0, fz_count_pages(ctx, doc) - 1);

	if (search_hit_page != currentpage)
		search_hit_page = -1; /* clear highlights when navigating */

	glutPostRedisplay();
}

static void mouse(int button, int state, int x, int y)
{
	switch (button)
	{
	case GLUT_LEFT_BUTTON: ui.down = (state == GLUT_DOWN); break;
	case GLUT_MIDDLE_BUTTON: ui.middle = (state == GLUT_DOWN); break;
	case GLUT_RIGHT_BUTTON: ui.right = (state == GLUT_DOWN); break;
	}
	ui.x = x;
	ui.y = y;
	glutPostRedisplay();
}

static void motion(int x, int y)
{
	ui.x = x;
	ui.y = y;
	glutPostRedisplay();
}

int main(int argc, char **argv)
{
	glutInit(&argc, argv);
	glutInitDisplayMode(GLUT_RGBA | GLUT_DOUBLE);
	glutInitWindowSize(800, 1000);

	if (argc < 2) {
		fprintf(stderr, "usage: mupdf-glut input.pdf\n");
		exit(1);
	}

	filename = argv[1];
	title = strrchr(filename, '/');
	if (!title)
		title = strrchr(filename, '\\');
	if (title)
		++title;
	else
		title = filename;

	memset(&ui, 0, sizeof ui);

	search_input.p = search_input.text;
	search_input.q = search_input.p;
	search_input.end = search_input.p;

	glutCreateWindow(filename);

	ctx = fz_new_context(NULL, NULL, 0);
	fz_register_document_handlers(ctx);

	doc = fz_open_document(ctx, argv[1]);

	render_page(currentpage, currentzoom, currentrotate);
	update_title();
	shrinkwrap();

	glutReshapeFunc(reshape);
	glutDisplayFunc(display);
	glutKeyboardFunc(keyboard);
	glutSpecialFunc(special);
	glutMouseFunc(mouse);
	glutMotionFunc(motion);
	glutPassiveMotionFunc(motion);
	glutMainLoop();

	fz_drop_link(ctx, links);
	fz_drop_document(ctx, doc);
	fz_drop_context(ctx);

	return 0;
}
