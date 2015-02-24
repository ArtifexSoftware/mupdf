#include "mupdf/fitz.h"

#ifdef __APPLE__
#include <OpenGL/OpenGL.h>
#include <GLUT/glut.h>
#else
#include <GL/gl.h>
#include <GL/freeglut.h>
#endif

#define ZOOMSTEP 1.25

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

static fz_context *ctx = NULL;
static fz_document *doc = NULL;

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

	fz_scale(&ctm, zoom, zoom);
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
static float oldzoom = 1, currentzoom = 1;
static float oldrotate = 0, currentrotate = 0;

static void reshape(int w, int h)
{
	screen_w = w;
	screen_h = h;
}

static void display(void)
{
	fz_rect r;
	float x, y;

	glViewport(0, 0, screen_w, screen_h);
	glClearColor(0.3, 0.3, 0.4, 1.0);
	glClear(GL_COLOR_BUFFER_BIT);

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrtho(0, screen_w, screen_h, 0, -1, 1);

	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();

	x = (screen_w - page_w) / 2;
	y = (screen_h - page_h) / 2;

	r.x0 = x;
	r.y0 = y;
	r.x1 = x + page_w;
	r.y1 = y + page_h;

	draw_image(page_tex, &r);

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
	case '<': currentpage -= 10 * fz_maxi(number, 1); break;
	case '>': currentpage += 10 * fz_maxi(number, 1); break;
	case ',': case 'b': currentpage -= fz_maxi(number, 1); break;
	case '.': case ' ': currentpage += fz_maxi(number, 1); break;
	case 'g': currentpage = number - 1; break;
	case 'G': currentpage = fz_count_pages(ctx, doc) - 1; break;
	case '+': currentzoom *= ZOOMSTEP; break;
	case '-': currentzoom *= 1 / ZOOMSTEP; break;
	case '[': currentrotate += 90; break;
	case ']': currentrotate -= 90; break;
	}

	if (key >= '0' && key <= '9')
		number = number * 10 + key - '0';
	else
		number = 0;

	currentpage = fz_clampi(currentpage, 0, fz_count_pages(ctx, doc) - 1);
	currentzoom = fz_clamp(currentzoom, powf(ZOOMSTEP, -10), powf(ZOOMSTEP, 10));
	while (currentrotate < 0) currentrotate += 360;
	while (currentrotate >= 360) currentrotate -= 360;

	if (oldpage != currentpage || oldzoom != currentzoom || oldrotate != currentrotate)
	{
		render_page(currentpage, currentzoom, currentrotate);
		oldpage = currentpage;
		oldzoom = currentzoom;
		oldrotate = currentrotate;
		glutPostRedisplay();
	}
}

static void special(int key, int x, int y)
{
	int mod = glutGetModifiers();
	if (key == GLUT_KEY_F4 && mod == GLUT_ACTIVE_ALT)
		exit(0);
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
	//glutMouseFunc(mouse);
	//glutMotionFunc(motion);
	glutMainLoop();

	fz_drop_document(ctx, doc);
	fz_drop_context(ctx);

	return 0;
}
