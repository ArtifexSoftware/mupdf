#include "mupdf/fitz.h"

#ifdef __APPLE__
#include <OpenGL/OpenGL.h>
#include <GLUT/glut.h>
#else
#include <GL/gl.h>
#include <GL/freeglut.h>
#endif

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

static int screen_w = 1, screen_h = 1;

static int oldpage = 0, currentpage = 0;
static float oldzoom = DEFRES, currentzoom = DEFRES;
static float oldrotate = 0, currentrotate = 0;

static int showoutline = 0;
static int showlinks = 0;

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

static float measure_string(const char *s)
{
	int w, c;
	while (*s)
	{
		s += fz_chartorune(&c, s);
		w += glutBitmapWidth(GLUT_BITMAP_HELVETICA_12, c);
	}
	return w;
}

static void ui_scrollbar(int x0, int y0, int x1, int y1, int *value, int page, int max)
{
	int h = y1 - y0;
	int t, b;

	if (ui.x >= x0 && ui.x < x1 && ui.y >= y0 && ui.y < y1)
	{
		ui.hot = value;
		if (!ui.active && ui.down)
			ui.active = value;
	}

	if (ui.active == value)
	{
		*value = fz_clampi((ui.y - y0) * max / h, 0, max);
	}

	t = *value * h / max;
	b = t + page * h / max;
	if (b - t < 2)
	{
		t = t - 1;
		b = t + 2;
	}

	glColor4f(0.6, 0.6, 0.6, 1);
	glRectf(x0, y0, x1, y1);
	glColor4f(0.8, 0.8, 0.8, 1);
	glRectf(x0, t, x1, b);
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
					currentpage = p;
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

static void draw_outline(fz_outline *node, int w)
{
	static int y = 0;
	int h;

	w -= 15;
	h = measure_outline_height(outline);

	ui_scrollbar(w, 0, w+15, screen_h, &y, screen_h, h);

	glColor4f(1, 1, 1, 1);
	glRectf(0, 0, w, screen_h);

	glScissor(0, 0, w, screen_h);
	glEnable(GL_SCISSOR_TEST);

	draw_outline_imp(outline, fz_count_pages(ctx, doc), 0, w, 10, -y);

	glScissor(0, 0, screen_w, screen_h);
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
					currentpage = link->dest.ld.gotor.page;
				else if (link->dest.kind == FZ_LINK_URI)
					open_browser(link->dest.ld.uri.uri);
			}
			glutPostRedisplay();
		}

		link = link->next;
	}

	glDisable(GL_BLEND);
}

static void toggle_fullscreen(void)
{
	static int oldw = 100, oldh = 100, oldx = 0, oldy = 0;
	static int isfullscreen = 0;

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

static void auto_zoom_w(void)
{
	currentzoom = fz_clamp(currentzoom * screen_w / (float)page_w, MINRES, MAXRES);
}

static void auto_zoom_h(void)
{
	currentzoom = fz_clamp(currentzoom * screen_h / (float)page_h, MINRES, MAXRES);
}

static void auto_zoom(void)
{
	float page_a = (float) page_w / page_h;
	float screen_a = (float) screen_w / screen_h;
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
	glClearColor(0.3, 0.3, 0.4, 1.0);
	glClear(GL_COLOR_BUFFER_BIT);

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrtho(0, screen_w, screen_h, 0, -1, 1);

	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();

	ui_begin();

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

	if (ui.active == doc)
	{
		scroll_x = save_scroll_x + save_ui_x - ui.x;
		scroll_y = save_scroll_y + save_ui_y - ui.y;
	}

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

	if (showoutline)
	{
		draw_outline(outline, canvas_x);
	}

	ui_end();

	glutSwapBuffers();

	ogl_assert(ctx, "swap buffers");
}

static void keyboard(unsigned char key, int x, int y)
{
	if (key == 27 || key == 'q')
		exit(0);

	switch (key)
	{
	case 'f': toggle_fullscreen(); break;
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
	case 'g': currentpage = number - 1; break;
	case 'G': currentpage = fz_count_pages(ctx, doc) - 1; break;
	case '+': currentzoom = zoom_in(currentzoom); break;
	case '-': currentzoom = zoom_out(currentzoom); break;
	case '[': currentrotate += 90; break;
	case ']': currentrotate -= 90; break;
	case 'o': showoutline = !showoutline; break;
	case 'l': showlinks = !showlinks; break;
	}

	if (key >= '0' && key <= '9')
		number = number * 10 + key - '0';
	else
		number = 0;

	currentpage = fz_clampi(currentpage, 0, fz_count_pages(ctx, doc) - 1);
	currentzoom = fz_clamp(currentzoom, MINRES, MAXRES);
	while (currentrotate < 0) currentrotate += 360;
	while (currentrotate >= 360) currentrotate -= 360;

	glutPostRedisplay();
}

static void special(int key, int x, int y)
{
	int mod = glutGetModifiers();

	if (key == GLUT_KEY_F4 && mod == GLUT_ACTIVE_ALT)
		exit(0);

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

	memset(&ui, 0, sizeof ui);

	glutCreateWindow("MuPDF/GL");

	ctx = fz_new_context(NULL, NULL, 0);
	fz_register_document_handlers(ctx);

	doc = fz_open_document(ctx, argv[1]);

	render_page(currentpage, currentzoom, currentrotate);

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
