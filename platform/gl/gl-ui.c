#include "gl-app.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef FREEGLUT
/* freeglut extension no-ops */
void glutExit(void) {}
void glutMouseWheelFunc(void *fn) {}
void glutInitErrorFunc(void *fn) {}
void glutInitWarningFunc(void *fn) {}
#define glutSetOption(X,Y)
#endif

enum
{
	/* Default UI sizes */
	DEFAULT_UI_FONTSIZE = 15,
	DEFAULT_UI_BASELINE = 14,
	DEFAULT_UI_LINEHEIGHT = 18,
};

struct ui ui = {};

#if defined(FREEGLUT) && (GLUT_API_VERSION >= 6)

void ui_set_clipboard(const char *buf)
{
	glutSetClipboard(GLUT_PRIMARY, buf);
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

static const char *ogl_error_string(GLenum code)
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

static int has_ARB_texture_non_power_of_two = 1;
static GLint max_texture_size = 8192;

void ui_init_draw(void)
{
}

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

void ui_texture_from_pixmap(struct texture *tex, fz_pixmap *pix)
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
	ui.x = x;
	ui.y = y;
	ui.key = key;
	ui.mod = glutGetModifiers();
	ui.plain = !(ui.mod & ~GLUT_ACTIVE_SHIFT);
	run_main_loop();
	ui_invalidate(); // TODO: leave this to caller
	ui.key = ui.mod = ui.plain = 0;
}

static void on_special(int key, int x, int y)
{
	ui.x = x;
	ui.y = y;
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
		ui_invalidate(); // TODO: leave this to caller
		ui.key = ui.mod = ui.plain = 0;
	}
}

static void on_wheel(int wheel, int direction, int x, int y)
{
	ui.scroll_x = wheel == 1 ? direction : 0;
	ui.scroll_y = wheel == 0 ? direction : 0;
	run_main_loop();
	ui_invalidate(); // TODO: leave this to caller
	ui.scroll_x = ui.scroll_y = 0;
}

static void on_mouse(int button, int action, int x, int y)
{
	ui.x = x;
	ui.y = y;
	if (action == GLUT_DOWN)
	{
		switch (button)
		{
		case GLUT_LEFT_BUTTON:
			ui.down_x = x;
			ui.down_y = y;
			ui.down = 1;
			break;
		case GLUT_MIDDLE_BUTTON:
			ui.middle_x = x;
			ui.middle_y = y;
			ui.middle = 1;
			break;
		case GLUT_RIGHT_BUTTON:
			ui.right_x = x;
			ui.right_y = y;
			ui.right = 1;
			break;
		case 3: on_wheel(0, 1, x, y); break;
		case 4: on_wheel(0, -1, x, y); break;
		case 5: on_wheel(1, 1, x, y); break;
		case 6: on_wheel(1, -1, x, y); break;
		}
	}
	else if (action == GLUT_UP)
	{
		switch (button)
		{
		case GLUT_LEFT_BUTTON: ui.down = 0; break;
		case GLUT_MIDDLE_BUTTON: ui.middle = 0; break;
		case GLUT_RIGHT_BUTTON: ui.right = 0; break;
		}
	}
	run_main_loop();
	ui_invalidate(); // TODO: leave this to caller
}

static void on_motion(int x, int y)
{
	ui.x = x;
	ui.y = y;
	ui_invalidate();
}

static void on_reshape(int w, int h)
{
	ui.window_w = w;
	ui.window_h = h;
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

void ui_init(int w, int h, const char *title)
{
	glutSetOption(GLUT_ACTION_ON_WINDOW_CLOSE, GLUT_ACTION_GLUTMAINLOOP_RETURNS);

	glutInitErrorFunc(on_error);
	glutInitWarningFunc(on_warning);
	glutInitDisplayMode(GLUT_RGBA | GLUT_DOUBLE);
	glutInitWindowSize(w, h);
	glutCreateWindow(title);

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

	memset(&ui, 0, sizeof ui);

	ui.fontsize = DEFAULT_UI_FONTSIZE;
	ui.baseline = DEFAULT_UI_BASELINE;
	ui.lineheight = DEFAULT_UI_LINEHEIGHT;

	ui_init_fonts(ui.fontsize);
}

void ui_finish(void)
{
	ui_finish_fonts();
	glutExit();
}

void ui_invalidate(void)
{
	glutPostRedisplay();
}

void ui_begin(void)
{
	ui.hot = NULL;

	ui.cavity = ui.cavity_stack;
	ui.cavity->x0 = 0;
	ui.cavity->y0 = 0;
	ui.cavity->x1 = ui.window_w;
	ui.cavity->y1 = ui.window_h;

	ui.layout = ui.layout_stack;
	ui.layout->side = ALL;
	ui.layout->fill = BOTH;
	ui.layout->anchor = NW;
	ui.layout->padx = 0;
	ui.layout->pady = 0;

	glViewport(0, 0, ui.window_w, ui.window_h);
	glClearColor(0.3f, 0.3f, 0.3f, 1.0f);
	glClear(GL_COLOR_BUFFER_BIT);

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrtho(0, ui.window_w, ui.window_h, 0, -1, 1);

	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();
}

void ui_end(void)
{
	int code = glGetError();
	if (code != GL_NO_ERROR)
		fz_warn(ctx, "glGetError: %s", ogl_error_string(code));

	if (!ui.active && (ui.down || ui.middle || ui.right))
		ui.active = "dummy";

	if (ui.active)
	{
		if (ui.active != ui.focus)
			ui.focus = NULL;
		if (!ui.grab_down && !ui.grab_middle && !ui.grab_right)
		{
			ui.grab_down = ui.down;
			ui.grab_middle = ui.middle;
			ui.grab_right = ui.right;
		}
	}

	if ((ui.grab_down && !ui.down) || (ui.grab_middle && !ui.middle) || (ui.grab_right && !ui.right))
	{
		ui.grab_down = ui.grab_middle = ui.grab_right = 0;
		ui.active = NULL;
	}

	glutSwapBuffers();
}

/* Widgets */

int ui_mouse_inside(fz_irect *area)
{
	if (ui.x >= area->x0 && ui.x < area->x1 && ui.y >= area->y0 && ui.y < area->y1)
		return 1;
	return 0;
}

fz_irect ui_pack_layout(int slave_w, int slave_h, enum side side, enum fill fill, enum anchor anchor, int padx, int pady)
{
	fz_irect parcel, slave;
	int parcel_w, parcel_h;
	int anchor_x, anchor_y;

	switch (side)
	{
	default:
	case ALL:
		parcel.x0 = ui.cavity->x0 + padx;
		parcel.x1 = ui.cavity->x1 - padx;
		parcel.y0 = ui.cavity->y0 + pady;
		parcel.y1 = ui.cavity->y1 - pady;
		ui.cavity->x0 = ui.cavity->x1;
		ui.cavity->y0 = ui.cavity->y1;
		break;
	case T:
		parcel.x0 = ui.cavity->x0 + padx;
		parcel.x1 = ui.cavity->x1 - padx;
		parcel.y0 = ui.cavity->y0 + pady;
		parcel.y1 = ui.cavity->y0 + pady + slave_h;
		ui.cavity->y0 = parcel.y1 + pady;
		break;
	case B:
		parcel.x0 = ui.cavity->x0 + padx;
		parcel.x1 = ui.cavity->x1 - padx;
		parcel.y0 = ui.cavity->y1 - pady - slave_h;
		parcel.y1 = ui.cavity->y1 - pady;
		ui.cavity->y1 = parcel.y0 - pady;
		break;
	case L:
		parcel.x0 = ui.cavity->x0 + padx;
		parcel.x1 = ui.cavity->x0 + padx + slave_w;
		parcel.y0 = ui.cavity->y0 + pady;
		parcel.y1 = ui.cavity->y1 - pady;
		ui.cavity->x0 = parcel.x1 + padx;
		break;
	case R:
		parcel.x0 = ui.cavity->x1 - padx - slave_w;
		parcel.x1 = ui.cavity->x1 - padx;
		parcel.y0 = ui.cavity->y0 + pady;
		parcel.y1 = ui.cavity->y1 - pady;
		ui.cavity->x1 = parcel.x0 - padx;
		break;
	}

	parcel_w = parcel.x1 - parcel.x0;
	parcel_h = parcel.y1 - parcel.y0;

	if (fill & X)
		slave_w = parcel_w;
	if (fill & Y)
		slave_h = parcel_h;

	anchor_x = parcel_w - slave_w;
	anchor_y = parcel_h - slave_h;

	switch (anchor)
	{
	default:
	case CENTER:
		slave.x0 = parcel.x0 + anchor_x / 2;
		slave.y0 = parcel.y0 + anchor_y / 2;
		break;
	case N:
		slave.x0 = parcel.x0 + anchor_x / 2;
		slave.y0 = parcel.y0;
		break;
	case NE:
		slave.x0 = parcel.x0 + anchor_x;
		slave.y0 = parcel.y0;
		break;
	case E:
		slave.x0 = parcel.x0 + anchor_x;
		slave.y0 = parcel.y0 + anchor_y / 2;
		break;
	case SE:
		slave.x0 = parcel.x0 + anchor_x;
		slave.y0 = parcel.y0 + anchor_y;
		break;
	case S:
		slave.x0 = parcel.x0 + anchor_x / 2;
		slave.y0 = parcel.y0 + anchor_y;
		break;
	case SW:
		slave.x0 = parcel.x0;
		slave.y0 = parcel.y0 + anchor_y;
		break;
	case W:
		slave.x0 = parcel.x0;
		slave.y0 = parcel.y0 + anchor_y / 2;
		break;
	case NW:
		slave.x0 = parcel.x0;
		slave.y0 = parcel.y0;
		break;
	}

	slave.x1 = slave.x0 + slave_w;
	slave.y1 = slave.y0 + slave_h;

	return slave;
}

fz_irect ui_pack(int slave_w, int slave_h)
{
	return ui_pack_layout(slave_w, slave_h, ui.layout->side, ui.layout->fill, ui.layout->anchor, ui.layout->padx, ui.layout->pady);
}

void ui_pack_push(fz_irect cavity)
{
	*(++ui.cavity) = cavity;
	++ui.layout;
	ui.layout->side = ALL;
	ui.layout->fill = BOTH;
	ui.layout->anchor = NW;
	ui.layout->padx = 0;
	ui.layout->pady = 0;
}

void ui_pack_pop(void)
{
	--ui.cavity;
	--ui.layout;
}

void ui_layout(enum side side, enum fill fill, enum anchor anchor, int padx, int pady)
{
	ui.layout->side = side;
	ui.layout->fill = fill;
	ui.layout->anchor = anchor;
	ui.layout->padx = padx;
	ui.layout->pady = pady;
}

void ui_panel_begin(int w, int h, int opaque)
{
	fz_irect area = ui_pack(w, h);
	if (opaque)
	{
		fz_irect total = {
			area.x0 - ui.layout->padx,
			area.y0 - ui.layout->pady,
			area.x1 + ui.layout->padx,
			area.y1 + ui.layout->pady
		};
		glColor4f(0.8f, 0.8f, 0.8f, 1);
		glRectf(total.x0, total.y0, total.x1, total.y1);
	}
	ui_pack_push(area);
}

void ui_panel_end(void)
{
	ui_pack_pop();
}

void ui_spacer(void)
{
	ui_pack(ui.lineheight / 2, ui.lineheight / 2);
}

void ui_label(const char *fmt, ...)
{
	char buf[512];
	int width;
	fz_irect area;
	va_list ap;

	va_start(ap, fmt);
	fz_vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	width = ui_measure_string(buf);
	area = ui_pack(width, ui.lineheight);
	glColor4f(0, 0, 0, 1);
	ui_draw_string(area.x0, area.y0 + ui.baseline, buf);
}

int ui_button(const char *label)
{
	int width = ui_measure_string(label);
	fz_irect area = ui_pack(width + 12, ui.lineheight + 6);
	int text_x = area.x0 + ((area.x1 - area.x0) - width) / 2;

	if (ui_mouse_inside(&area))
	{
		ui.hot = label;
		if (!ui.active && ui.down)
			ui.active = label;
	}

	glColor4f(0, 0, 0, 1);
	glRectf(area.x0, area.y0, area.x1, area.y1);

	if (ui.hot == label && ui.active == label && ui.down)
		glColor4f(0, 0, 0, 1);
	else
		glColor4f(1, 1, 1, 1);
	glRectf(area.x0+2, area.y0+2, area.x1-2, area.y1-2);

	if (ui.hot == label && ui.active == label && ui.down)
		glColor4f(1, 1, 1, 1);
	else
		glColor4f(0, 0, 0, 1);
	ui_draw_string(text_x, area.y0 + 3 + ui.baseline, label);

	return ui.hot == label && ui.active == label && !ui.down;
}

void ui_checkbox(const char *label, int *value)
{
	int width = ui_measure_string(label);
	fz_irect area = ui_pack(width + ui.baseline - 3 + 4, ui.lineheight);
	fz_irect mark = { area.x0, area.y0 + 3, area.x0 + ui.baseline - 3, area.y0 + ui.baseline };

	glColor4f(0, 0, 0, 1);
	ui_draw_string(mark.x1 + 4, area.y0 + ui.baseline, label);

	glColor4f(0, 0, 0, 1);
	glRectf(mark.x0, mark.y0, mark.x1, mark.y1);

	if (ui_mouse_inside(&area))
	{
		ui.hot = label;
		if (!ui.active && ui.down)
			ui.active = label;
	}

	if (ui.hot == label && ui.active == label && !ui.down)
		*value = !*value;

	glColor4f(1, 1, 1, 1);
	if (ui.hot == label && ui.active == label && ui.down)
		glRectf(mark.x0+2, mark.y0+2, mark.x1-2, mark.y1-2);
	else
		glRectf(mark.x0+1, mark.y0+1, mark.x1-1, mark.y1-1);

	if (*value)
	{
		glColor4f(0, 0, 0, 1);
		glRectf(mark.x0+3, mark.y0+3, mark.x1-3, mark.y1-3);
	}
}

void ui_slider(float *value, float min, float max, int width)
{
	fz_irect area = ui_pack(width, ui.lineheight);
	static float start_value = 0;
	float w = area.x1 - area.x0 - 4;
	char buf[50];

	if (ui_mouse_inside(&area))
	{
		ui.hot = value;
		if (!ui.active && ui.down)
		{
			ui.active = value;
			start_value = *value;
		}
	}

	if (ui.active == value)
	{
		if (ui.y < area.y0 || ui.y > area.y1)
			*value = start_value;
		else
		{
			float v = (float)(ui.x - (area.x0+2)) / (area.x1-area.x0-4);
			*value = fz_clamp(min + v * (max - min), min, max);
		}
	}

	glColor4f(0.4, 0.4, 0.4, 1);
	glRectf(area.x0, area.y0, area.x1, area.y1);
	glColor4f(0.7, 0.7, 0.7, 1);
	glRectf(area.x0+2, area.y0+2, area.x0+2 + (*value - min) / (max - min) * w, area.y1 - 2);

	glColor4f(1, 1, 1, 1);
	fz_snprintf(buf, sizeof buf, "%0.2f", *value);
	w = ui_measure_string(buf);
	ui_draw_string(area.x0 + ((area.x1-area.x0) - w) / 2, area.y0 + ui.baseline, buf);
}

void ui_scrollbar(int x0, int y0, int x1, int y1, int *value, int page_size, int max)
{
	static float start_top = 0; /* we can only drag in one scrollbar at a time, so static is safe */
	float top;

	int total_h = y1 - y0 - 4;
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
			if (ui.y < y0 + top)
			{
				ui.active = "pgdn";
				*value -= page_size;
			}
			else if (ui.y >= y0 + top + thumb_h)
			{
				ui.active = "pgup";
				*value += page_size;
			}
			else
			{
				ui.hot = value;
				ui.active = value;
				start_top = top;
			}
		}
	}

	if (ui.active == value)
	{
		*value = (start_top + ui.y - ui.down_y) * max / avail_h;
	}

	if (*value < 0)
		*value = 0;
	else if (*value > max)
		*value = max;

	top = (float) *value * avail_h / max;

	glColor4f(0.6f, 0.6f, 0.6f, 1.0f);
	glRectf(x0, y0, x1, y1);
	glColor4f(0.8f, 0.8f, 0.8f, 1.0f);
	glRectf(x0+2, y0+2 + top, x1-2, y0+2 + top + thumb_h);
}

void ui_list_begin(struct list *list, int count, int req_w, int req_h)
{
	static int start_scroll_y = 0; /* we can only drag in one list at a time, so static is safe */

	fz_irect area = ui_pack(req_w, req_h);

	int max_scroll_y = count * ui.lineheight - (area.y1-area.y0);

	if (max_scroll_y > 0)
		area.x1 -= ui.lineheight;

	if (ui_mouse_inside(&area))
	{
		ui.hot = list;
		if (!ui.active && ui.middle)
		{
			ui.active = list;
			start_scroll_y = list->scroll_y;
		}
	}

	/* middle button dragging */
	if (ui.active == list)
		list->scroll_y = start_scroll_y + (ui.middle_y - ui.y) * 5;

	/* scroll wheel events */
	if (ui.hot == list)
		list->scroll_y -= ui.scroll_y * ui.lineheight * 3;

	/* clamp scrolling to client area */
	if (list->scroll_y >= max_scroll_y)
		list->scroll_y = max_scroll_y;
	if (list->scroll_y < 0)
		list->scroll_y = 0;

	if (max_scroll_y > 0)
	{
		ui_scrollbar(area.x1, area.y0, area.x1+ui.lineheight, area.y1,
				&list->scroll_y, area.y1-area.y0, count * ui.lineheight);
	}

	list->area = area;
	list->item_y = area.y0 - list->scroll_y;

	glColor4f(1, 1, 1, 1);
	glRectf(area.x0, area.y0, area.x1, area.y1);

	glScissor(area.x0, ui.window_h-area.y1, area.x1-area.x0, area.y1-area.y0);
	glEnable(GL_SCISSOR_TEST);
}

int ui_list_item(struct list *list, void *id, int indent, const char *label, int selected)
{
	fz_irect area = { list->area.x0, list->item_y, list->area.x1, list->item_y + ui.lineheight };

	/* only process visible items */
	if (area.y1 >= list->area.y0 && area.y0 <= list->area.y1)
	{
		if (ui_mouse_inside(&list->area) && ui_mouse_inside(&area))
		{
			ui.hot = id;
			if (!ui.active && ui.down)
				ui.active = id;
		}

		if (selected)
		{
			glColor4f(0.9f, 0.9f, 0.9f, 1);
			glRectf(area.x0, area.y0, area.x1, area.y1);
		}

		glColor4f(0, 0, 0, 1);
		ui_draw_string(area.x0 + indent, area.y0 + ui.baseline, label);
	}

	list->item_y += ui.lineheight;

	/* trigger on first mouse down */
	return ui.active == id;
}

void ui_list_end(struct list *list)
{
	glDisable(GL_SCISSOR_TEST);
}
