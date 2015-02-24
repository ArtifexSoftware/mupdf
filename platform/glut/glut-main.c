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
	int x, y, down;
	void *hot, *active;
} ui;

static void ui_begin(void)
{
	ui.hot = NULL;
}

static void ui_end(void)
{
	if (!ui.down)
	{
		ui.active = NULL;
	}
	else
	{
		if (!ui.active)
			ui.active = ui.hot;
	}
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

static unsigned int page_tex = 0;
static int page_w, page_h;

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

	pix = fz_new_pixmap_with_bbox(ctx, fz_device_rgb(ctx), &ibounds);
	fz_clear_pixmap_with_value(ctx, pix, 0xff);
	dev = fz_new_draw_device(ctx, pix);
	fz_run_page(ctx, page, dev, &ctm, NULL);
	fz_drop_device(ctx, dev);

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

static void reshape(int w, int h)
{
	screen_w = w;
	screen_h = h;
}

static void display(void)
{
	fz_rect r;
	float x, y;
	int canvas_x, canvas_w;

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

	x = canvas_x + (canvas_w - page_w) / 2;
	y = (screen_h - page_h) / 2;

	r.x0 = x;
	r.y0 = y;
	r.x1 = x + page_w;
	r.y1 = y + page_h;

	draw_image(page_tex, &r);

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
	static int number = 0;

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
	case ',': case 'b': currentpage -= fz_maxi(number, 1); break;
	case '.': case ' ': currentpage += fz_maxi(number, 1); break;
	case 'g': currentpage = number - 1; break;
	case 'G': currentpage = fz_count_pages(ctx, doc) - 1; break;
	case '+': currentzoom = zoom_in(currentzoom); break;
	case '-': currentzoom = zoom_out(currentzoom); break;
	case '[': currentrotate += 90; break;
	case ']': currentrotate -= 90; break;
	case 'l': showoutline = !showoutline; break;
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
}

static void mouse(int button, int state, int x, int y)
{
	if (button == GLUT_LEFT_BUTTON)
		ui.down = state == GLUT_DOWN;
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
	//glutPassiveMotionFunc(motion);
	glutMainLoop();

	fz_drop_document(ctx, doc);
	fz_drop_context(ctx);

	return 0;
}
