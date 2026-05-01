// Copyright (C) 2004-2022 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 39 Mesa Street, Suite 108A, San Francisco,
// CA 94129, USA, for further information.

#include "gl-app.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

GLFWwindow *ui_window = NULL;

static GLFWcursor *cursor_text = NULL;
static GLFWcursor *cursor_hresize = NULL;
static GLFWcursor *cursor_vresize = NULL;
static GLFWcursor *cursor_crosshair = NULL;

double ui_get_time_ms(void)
{
	return glfwGetTime() * 1000.0;
}

void ui_request_close(void)
{
	glfwSetWindowShouldClose(ui_window, GLFW_TRUE);
}

enum
{
	/* Default UI sizes */
	DEFAULT_UI_FONTSIZE = 15,
	DEFAULT_UI_BASELINE = 14,
	DEFAULT_UI_LINEHEIGHT = 18,
	DEFAULT_UI_GRIDSIZE = DEFAULT_UI_LINEHEIGHT + 6,
};

struct ui ui;

void ui_set_clipboard(const char *buf)
{
	glfwSetClipboardString(ui_window, buf);
}

const char *ui_get_clipboard(void)
{
	return glfwGetClipboardString(ui_window);
}

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

static GLint max_texture_size = 8192;

void ui_init_draw(void)
{
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

	if (tex->w > max_texture_size || tex->h > max_texture_size)
		fz_warn(ctx, "texture size (%d x %d) exceeds implementation limit (%d)", tex->w, tex->h, max_texture_size);
	glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, tex->w, tex->h, 0, pix->n == 4 ? GL_RGBA : GL_RGB, GL_UNSIGNED_BYTE, pix->samples);
	tex->s = 1;
	tex->t = 1;
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

void glColorHex(unsigned int hex)
{
	float r = ((hex>>16)&0xff) / 255.0f;
	float g = ((hex>>8)&0xff) / 255.0f;
	float b = ((hex)&0xff) / 255.0f;
	glColor3f(r, g, b);
}

void ui_draw_bevel_imp(fz_irect area, unsigned ot, unsigned it, unsigned ib, unsigned ob)
{
	glColorHex(ot);
	glRectf(area.x0, area.y0, area.x1-1, area.y0+1);
	glRectf(area.x0, area.y0+1, area.x0+1, area.y1-1);
	glColorHex(ob);
	glRectf(area.x1-1, area.y0, area.x1, area.y1);
	glRectf(area.x0, area.y1-1, area.x1-1, area.y1);
	glColorHex(it);
	glRectf(area.x0+1, area.y0+1, area.x1-2, area.y0+2);
	glRectf(area.x0+1, area.y0+2, area.x0+2, area.y1-2);
	glColorHex(ib);
	glRectf(area.x1-2, area.y0+1, area.x1-1, area.y1-1);
	glRectf(area.x0+1, area.y1-2, area.x1-2, area.y1-1);
}

void ui_draw_bevel(fz_irect area, int depressed)
{
	if (depressed)
		ui_draw_bevel_imp(area, UI_COLOR_BEVEL_2, UI_COLOR_BEVEL_1, UI_COLOR_BEVEL_3, UI_COLOR_BEVEL_4);
	else
		ui_draw_bevel_imp(area, UI_COLOR_BEVEL_4, UI_COLOR_BEVEL_3, UI_COLOR_BEVEL_2, UI_COLOR_BEVEL_1);
}

void ui_draw_ibevel(fz_irect area, int depressed)
{
	if (depressed)
		ui_draw_bevel_imp(area, UI_COLOR_BEVEL_2, UI_COLOR_BEVEL_1, UI_COLOR_BEVEL_3, UI_COLOR_BEVEL_4);
	else
		ui_draw_bevel_imp(area, UI_COLOR_BEVEL_3, UI_COLOR_BEVEL_4, UI_COLOR_BEVEL_2, UI_COLOR_BEVEL_1);
}

void ui_draw_bevel_rect(fz_irect area, unsigned int fill, int depressed)
{
	ui_draw_bevel(area, depressed);
	glColorHex(fill);
	glRectf(area.x0+2, area.y0+2, area.x1-2, area.y1-2);
}

void ui_draw_ibevel_rect(fz_irect area, unsigned int fill, int depressed)
{
	ui_draw_ibevel(area, depressed);
	glColorHex(fill);
	glRectf(area.x0+2, area.y0+2, area.x1-2, area.y1-2);
}

static int glfw_mods_to_ui(int mods)
{
	int m = 0;
	if (mods & GLFW_MOD_SHIFT) m |= GLFW_MOD_ACTIVE_SHIFT;
	if (mods & GLFW_MOD_CONTROL) m |= GLFW_MOD_ACTIVE_CTRL;
	if (mods & GLFW_MOD_ALT) m |= GLFW_MOD_ACTIVE_ALT;
	return m;
}

static void on_char(GLFWwindow *window, unsigned int codepoint)
{
	double mx, my;
	glfwGetCursorPos(window, &mx, &my);
	ui.x = (int)mx;
	ui.y = (int)my;
	ui.key = codepoint;
	ui.mod = glfw_mods_to_ui(0);
	ui.plain = 1;
	run_main_loop();
	ui.key = ui.plain = 0;
	ui_invalidate(); // TODO: leave this to caller
}

static void on_key(GLFWwindow *window, int key, int scancode, int action, int mods)
{
	double mx, my;
	int uikey = 0;

	if (action == GLFW_RELEASE)
		return;

	glfwGetCursorPos(window, &mx, &my);
	ui.x = (int)mx;
	ui.y = (int)my;

	switch (key)
	{
	case GLFW_KEY_INSERT: uikey = KEY_INSERT; break;
	case GLFW_KEY_DELETE: uikey = KEY_DELETE; break;
	case GLFW_KEY_RIGHT: uikey = KEY_RIGHT; break;
	case GLFW_KEY_LEFT: uikey = KEY_LEFT; break;
	case GLFW_KEY_DOWN: uikey = KEY_DOWN; break;
	case GLFW_KEY_UP: uikey = KEY_UP; break;
	case GLFW_KEY_PAGE_UP: uikey = KEY_PAGE_UP; break;
	case GLFW_KEY_PAGE_DOWN: uikey = KEY_PAGE_DOWN; break;
	case GLFW_KEY_HOME: uikey = KEY_HOME; break;
	case GLFW_KEY_END: uikey = KEY_END; break;
	case GLFW_KEY_F1: uikey = KEY_F1; break;
	case GLFW_KEY_F2: uikey = KEY_F2; break;
	case GLFW_KEY_F3: uikey = KEY_F3; break;
	case GLFW_KEY_F4: uikey = KEY_F4; break;
	case GLFW_KEY_F5: uikey = KEY_F5; break;
	case GLFW_KEY_F6: uikey = KEY_F6; break;
	case GLFW_KEY_F7: uikey = KEY_F7; break;
	case GLFW_KEY_F8: uikey = KEY_F8; break;
	case GLFW_KEY_F9: uikey = KEY_F9; break;
	case GLFW_KEY_F10: uikey = KEY_F10; break;
	case GLFW_KEY_F11: uikey = KEY_F11; break;
	case GLFW_KEY_F12: uikey = KEY_F12; break;
	case GLFW_KEY_ESCAPE: uikey = KEY_ESCAPE; break;
	case GLFW_KEY_ENTER: uikey = KEY_ENTER; break;
	case GLFW_KEY_KP_ENTER: uikey = KEY_ENTER; break;
	case GLFW_KEY_TAB: uikey = KEY_TAB; break;
	case GLFW_KEY_BACKSPACE: uikey = KEY_BACKSPACE; break;
	default:
		/* Handle Ctrl+key combinations */
		if ((mods & GLFW_MOD_CONTROL) && key >= GLFW_KEY_A && key <= GLFW_KEY_Z)
		{
			uikey = key - GLFW_KEY_A + 1; /* CTL_A=1, CTL_B=2, ... */
		}
		break;
	}

	if (uikey)
	{
		ui.key = uikey;
		ui.mod = glfw_mods_to_ui(mods);
		ui.plain = !(ui.mod & ~GLFW_MOD_ACTIVE_SHIFT);
		run_main_loop();
		ui.key = ui.plain = 0;
		ui_invalidate(); // TODO: leave this to caller
	}
}

static void on_scroll(GLFWwindow *window, double xoffset, double yoffset)
{
	ui.scroll_x = (int)xoffset;
	ui.scroll_y = (int)yoffset;
	ui.mod = 0;
	if (glfwGetKey(window, GLFW_KEY_LEFT_SHIFT) == GLFW_PRESS ||
		glfwGetKey(window, GLFW_KEY_RIGHT_SHIFT) == GLFW_PRESS)
		ui.mod |= GLFW_MOD_ACTIVE_SHIFT;
	if (glfwGetKey(window, GLFW_KEY_LEFT_CONTROL) == GLFW_PRESS ||
		glfwGetKey(window, GLFW_KEY_RIGHT_CONTROL) == GLFW_PRESS)
		ui.mod |= GLFW_MOD_ACTIVE_CTRL;
	if (glfwGetKey(window, GLFW_KEY_LEFT_ALT) == GLFW_PRESS ||
		glfwGetKey(window, GLFW_KEY_RIGHT_ALT) == GLFW_PRESS)
		ui.mod |= GLFW_MOD_ACTIVE_ALT;
	run_main_loop();
	ui_invalidate(); // TODO: leave this to caller
	ui.scroll_x = ui.scroll_y = 0;
}

static void on_mouse_button(GLFWwindow *window, int button, int action, int mods)
{
	double mx, my;
	glfwGetCursorPos(window, &mx, &my);
	ui.x = (int)mx;
	ui.y = (int)my;

	if (action == GLFW_PRESS)
	{
		switch (button)
		{
		case GLFW_MOUSE_BUTTON_LEFT:
			ui.down_x = ui.x;
			ui.down_y = ui.y;
			ui.down = 1;
			break;
		case GLFW_MOUSE_BUTTON_MIDDLE:
			ui.middle_x = ui.x;
			ui.middle_y = ui.y;
			ui.middle = 1;
			break;
		case GLFW_MOUSE_BUTTON_RIGHT:
			ui.right_x = ui.x;
			ui.right_y = ui.y;
			ui.right = 1;
			break;
		}
	}
	else if (action == GLFW_RELEASE)
	{
		switch (button)
		{
		case GLFW_MOUSE_BUTTON_LEFT: ui.down = 0; break;
		case GLFW_MOUSE_BUTTON_MIDDLE: ui.middle = 0; break;
		case GLFW_MOUSE_BUTTON_RIGHT: ui.right = 0; break;
		}
	}
	ui.mod = glfw_mods_to_ui(mods);
	run_main_loop();
	ui_invalidate(); // TODO: leave this to caller
}

static void on_cursor_pos(GLFWwindow *window, double x, double y)
{
	ui.x = (int)x;
	ui.y = (int)y;
	ui_invalidate();
}

static void on_framebuffer_size(GLFWwindow *window, int w, int h)
{
	// WAYLAND FIX: Ignore 0x0 compositor hints so the window doesn't collapse
	if (w == 0 || h == 0) return;
	ui.window_w = w;
	ui.window_h = h;
	ui_invalidate();
}

static void on_window_refresh(GLFWwindow *window)
{
	ui_invalidate();
}

static void on_error(int error, const char *description)
{
#ifdef _WIN32
	MessageBoxA(NULL, description, "MuPDF GLFW Error", MB_ICONERROR);
#else
	fprintf(stderr, "GLFW error %d: %s\n", error, description);
#endif
}

static double last_timer_check = 0;

void check_timer(void)
{
	double now = glfwGetTime();
	if (now - last_timer_check >= 0.5)
	{
		last_timer_check = now;
		if (reloadrequested)
		{
			reload();
			ui_invalidate();
			reloadrequested = 0;
		}
	}
}

void ui_init_dpi(float override_scale)
{
	ui.scale = 1;

	if (override_scale)
	{
		ui.scale = override_scale;
	}
	else
	{
		/*
		 * GLFW 3.4 supports content scale queries.
		 * We use the primary monitor's content scale as a DPI hint.
		 */
		GLFWmonitor *mon = glfwGetPrimaryMonitor();
		if (mon)
		{
			float xscale, yscale;
			glfwGetMonitorContentScale(mon, &xscale, &yscale);
			float scale = (xscale + yscale) / 2.0f;
			if (scale >= 3.0f) ui.scale = 3;
			else if (scale >= 2.0f) ui.scale = 2;
			else if (scale >= 1.5f) ui.scale = 1.5f;
		}
	}

	ui.fontsize = DEFAULT_UI_FONTSIZE * ui.scale;
	ui.baseline = DEFAULT_UI_BASELINE * ui.scale;
	ui.lineheight = DEFAULT_UI_LINEHEIGHT * ui.scale;
	ui.gridsize = DEFAULT_UI_GRIDSIZE * ui.scale;
	ui.padsize = 2 * ui.scale;
}

void ui_init(int w, int h, const char *title)
{
	glfwSetErrorCallback(on_error);

	glfwWindowHint(GLFW_DOUBLEBUFFER, GLFW_TRUE);
	ui_window = glfwCreateWindow(w, h, title, NULL, NULL);
	if (!ui_window)
	{
		fprintf(stderr, "Failed to create GLFW window\n");
		exit(1);
	}

	glfwMakeContextCurrent(ui_window);
	glfwSwapInterval(1);

	glfwSetFramebufferSizeCallback(ui_window, on_framebuffer_size);
	glfwSetWindowRefreshCallback(ui_window, on_window_refresh);
	glfwSetKeyCallback(ui_window, on_key);
	glfwSetCharCallback(ui_window, on_char);
	glfwSetMouseButtonCallback(ui_window, on_mouse_button);
	glfwSetCursorPosCallback(ui_window, on_cursor_pos);
	glfwSetScrollCallback(ui_window, on_scroll);

	/* Create standard cursors */
	cursor_text = glfwCreateStandardCursor(GLFW_IBEAM_CURSOR);
	cursor_hresize = glfwCreateStandardCursor(GLFW_RESIZE_EW_CURSOR);
	cursor_vresize = glfwCreateStandardCursor(GLFW_RESIZE_NS_CURSOR);
	cursor_crosshair = glfwCreateStandardCursor(GLFW_CROSSHAIR_CURSOR);

	glGetIntegerv(GL_MAX_TEXTURE_SIZE, &max_texture_size);

	ui_init_fonts();

	ui.overlay_list = glGenLists(1);

	/* Initialize framebuffer size */
	glfwGetFramebufferSize(ui_window, &ui.window_w, &ui.window_h);
	if (ui.window_w == 0 || ui.window_h == 0) {
		ui.window_w = w;
		ui.window_h = h;
	}

	last_timer_check = glfwGetTime();
}

void ui_finish(void)
{
	pdf_drop_annot(ctx, ui.selected_annot);
	glDeleteLists(ui.overlay_list, 1);
	ui_finish_fonts();

	glfwDestroyCursor(cursor_text);
	glfwDestroyCursor(cursor_hresize);
	glfwDestroyCursor(cursor_vresize);
	glfwDestroyCursor(cursor_crosshair);

	if (ui_window)
		glfwDestroyWindow(ui_window);
	glfwTerminate();
}

static int needs_redisplay = 0;

void ui_invalidate(void)
{
	needs_redisplay = 1;
}

int ui_needs_redisplay(void)
{
	int r = needs_redisplay;
	needs_redisplay = 0;
	return r;
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

	ui.cursor = UI_CURSOR_INHERIT;

	ui.overlay = 0;

	glViewport(0, 0, ui.window_w, ui.window_h);
	glClear(GL_COLOR_BUFFER_BIT);

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrtho(0, ui.window_w, ui.window_h, 0, -1, 1);

	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();
}

void ui_end(void)
{
	int code;

	if (ui.overlay)
		glCallList(ui.overlay_list);

	if (ui.cursor != ui.last_cursor)
	{
		switch (ui.cursor)
		{
		case UI_CURSOR_TEXT: glfwSetCursor(ui_window, cursor_text); break;
		case UI_CURSOR_LEFT_RIGHT: glfwSetCursor(ui_window, cursor_hresize); break;
		case UI_CURSOR_UP_DOWN: glfwSetCursor(ui_window, cursor_vresize); break;
		case UI_CURSOR_CROSSHAIR: glfwSetCursor(ui_window, cursor_crosshair); break;
		default: glfwSetCursor(ui_window, NULL); break;
		}
		ui.last_cursor = ui.cursor;
	}

	code = glGetError();
	if (code != GL_NO_ERROR)
		fz_warn(ctx, "glGetError: %s", ogl_error_string(code));

	if (!ui.active && (ui.down || ui.middle || ui.right))
		ui.active = "dummy";

	if ((ui.grab_down && !ui.down) || (ui.grab_middle && !ui.middle) || (ui.grab_right && !ui.right))
	{
		ui.grab_down = ui.grab_middle = ui.grab_right = 0;
		ui.active = NULL;
	}

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

	glfwSwapBuffers(ui_window);
}

/* Widgets */

int ui_mouse_inside(fz_irect area)
{
	if (ui.x >= area.x0 && ui.x < area.x1 && ui.y >= area.y0 && ui.y < area.y1)
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
		ui.cavity->y0 = fz_clampi(parcel.y1 + pady, ui.cavity->y0, ui.cavity->y1);
		break;
	case B:
		parcel.x0 = ui.cavity->x0 + padx;
		parcel.x1 = ui.cavity->x1 - padx;
		parcel.y0 = ui.cavity->y1 - pady - slave_h;
		parcel.y1 = ui.cavity->y1 - pady;
		ui.cavity->y1 = fz_clampi(parcel.y0 - pady, ui.cavity->y0, ui.cavity->y1);
		break;
	case L:
		parcel.x0 = ui.cavity->x0 + padx;
		parcel.x1 = ui.cavity->x0 + padx + slave_w;
		parcel.y0 = ui.cavity->y0 + pady;
		parcel.y1 = ui.cavity->y1 - pady;
		ui.cavity->x0 = fz_clampi(parcel.x1 + padx, ui.cavity->x0, ui.cavity->x1);
		break;
	case R:
		parcel.x0 = ui.cavity->x1 - padx - slave_w;
		parcel.x1 = ui.cavity->x1 - padx;
		parcel.y0 = ui.cavity->y0 + pady;
		parcel.y1 = ui.cavity->y1 - pady;
		ui.cavity->x1 = fz_clampi(parcel.x0 - padx, ui.cavity->x0, ui.cavity->x1);
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

int ui_available_width(void)
{
	return ui.cavity->x1 - ui.cavity->x0 - ui.layout->padx * 2;
}

int ui_available_height(void)
{
	return ui.cavity->y1 - ui.cavity->y0 - ui.layout->pady * 2;
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

void ui_panel_begin(int w, int h, int padx, int pady, int opaque)
{
	fz_irect area = ui_pack(w, h);
	if (opaque)
	{
		glColorHex(UI_COLOR_PANEL);
		glRectf(area.x0, area.y0, area.x1, area.y1);
	}
	area.x0 += padx; area.y0 += pady;
	area.x1 -= padx; area.y1 -= pady;
	ui_pack_push(area);
}

void ui_panel_end(void)
{
	ui_pack_pop();
}

void ui_dialog_begin(int w, int h)
{
	fz_irect area;
	int x, y;
	w += 24 + 4;
	h += 24 + 4;
	if (w > ui.window_w) w = ui.window_w - 20;
	if (h > ui.window_h) h = ui.window_h - 20;
	x = (ui.window_w-w)/2;
	y = (ui.window_h-h)/3;
	area = fz_make_irect(x, y, x+w, y+h);
	ui_draw_bevel_rect(area, UI_COLOR_PANEL, 0);
	area = fz_expand_irect(area, -14);
	ui_pack_push(area);
}

void ui_dialog_end(void)
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
	struct line lines[20];
	int avail, used, n;
	fz_irect area;
	va_list ap;

	va_start(ap, fmt);
	fz_vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	avail = ui_available_width();
	n = ui_break_lines(buf, lines, nelem(lines), avail, &used);
	area = ui_pack(used, n * ui.lineheight);
	glColorHex(UI_COLOR_TEXT_FG);
	ui_draw_lines(area.x0, area.y0, lines, n);
}

int ui_button(const char *label)
{
	return ui_button_aux(label, 0);
}

int ui_button_aux(const char *label, int flags)
{
	int width = ui_measure_string(label);
	fz_irect area = ui_pack(width + 20, ui.gridsize);
	int text_x = area.x0 + ((area.x1 - area.x0) - width) / 2;
	int pressed = 0;
	int disabled = (flags & 1);

	if (!disabled)
	{
		if (ui_mouse_inside(area))
		{
			ui.hot = label;
			if (!ui.active && ui.down)
				ui.active = label;
		}

		pressed = (ui.hot == label && ui.active == label && ui.down);
	}
	ui_draw_bevel_rect(area, UI_COLOR_BUTTON, pressed);
	glColorHex(disabled ? UI_COLOR_TEXT_GRAY : UI_COLOR_TEXT_FG);
	ui_draw_string(text_x + pressed, area.y0+3 + pressed, label);

	return !disabled && ui.hot == label && ui.active == label && !ui.down;
}

int ui_checkbox(const char *label, int *value)
{
	return ui_checkbox_aux(label, value, 0);
}

int ui_checkbox_aux(const char *label, int *value, int flags)
{
	int width = ui_measure_string(label);
	fz_irect area = ui_pack(13 + 4 + width, ui.lineheight);
	fz_irect mark = { area.x0, area.y0 + ui.baseline-12, area.x0 + 13, area.y0 + ui.baseline+1 };
	int pressed = 0;
	int disabled = (flags & 1);

	glColorHex(disabled ? UI_COLOR_TEXT_GRAY : UI_COLOR_TEXT_FG);
	ui_draw_string(mark.x1 + 4, area.y0, label);

	if (!disabled)
	{
		if (ui_mouse_inside(area))
		{
			ui.hot = label;
			if (!ui.active && ui.down)
				ui.active = label;
		}

		if (ui.hot == label && ui.active == label && !ui.down)
			*value = !*value;

		pressed = (ui.hot == label && ui.active == label && ui.down);
	}
	ui_draw_bevel_rect(mark, (disabled || pressed) ? UI_COLOR_PANEL : UI_COLOR_TEXT_BG, 1);
	if (*value)
	{
		float ax = mark.x0+2 + 1, ay = mark.y0+2 + 3;
		float bx = mark.x0+2 + 4, by = mark.y0+2 + 5;
		float cx = mark.x0+2 + 8, cy = mark.y0+2 + 1;
		glColorHex(disabled ? UI_COLOR_TEXT_GRAY : UI_COLOR_TEXT_FG);
		glBegin(GL_TRIANGLE_STRIP);
		glVertex2f(ax, ay); glVertex2f(ax, ay+3);
		glVertex2f(bx, by); glVertex2f(bx, by+3);
		glVertex2f(cx, cy); glVertex2f(cx, cy+3);
		glEnd();
	}

	return !disabled && ui.hot == label && ui.active == label && !ui.down;
}

int ui_slider(int *value, int min, int max, int width)
{
	static int start_value = 0;
	fz_irect area = ui_pack(width, ui.lineheight);
	int m = 6;
	int w = area.x1 - area.x0 - m * 2;
	int h = area.y1 - area.y0;
	fz_irect gutter = { area.x0, area.y0+h/2-2, area.x1, area.y0+h/2+2 };
	fz_irect thumb;
	int x;

	if (ui_mouse_inside(area))
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
			float v = (float)(ui.x - (area.x0+m)) / w;
			*value = fz_clamp(min + v * (max - min), min, max);
		}
	}

	x = ((*value - min) * w) / (max - min);
	thumb = fz_make_irect(area.x0+m + x-m, area.y0, area.x0+m + x+m, area.y1);

	ui_draw_bevel(gutter, 1);
	ui_draw_bevel_rect(thumb, UI_COLOR_BUTTON, 0);

	return *value != start_value && ui.active == value && !ui.down;
}

void ui_splitter(int *start, int *v, int min, int max, enum side side)
{
	fz_irect area = { 0 };

	if (side == L || side == R)
		area = ui_pack(4, 0);
	else if (side == T || side == B)
		area = ui_pack(0, 4);

	if (ui_mouse_inside(area))
	{
		ui.hot = v;
		if (!ui.active && ui.down)
		{
			ui.active = v;
			*start = *v;
		}
	}

	if (ui.active == v)
	{
		// how we slide the splitter coords depends on the packing direction
		switch (ui.layout->side)
		{
		default:
		case L: *v = fz_clampi(*start + (ui.x - ui.down_x), min, max); break;
		case R: *v = fz_clampi(*start + (ui.down_x - ui.x), min, max); break;
		case B: *v = fz_clampi(*start + (ui.down_y - ui.y), min, max); break;
		case T: *v = fz_clampi(*start + (ui.y - ui.down_y), min, max); break;
		}
	}

	if (ui.hot == v || ui.active == v)
	{
		if (side == L || side == R)
			ui.cursor = UI_CURSOR_LEFT_RIGHT;
		else if (side == T || side == B)
			ui.cursor = UI_CURSOR_UP_DOWN;
	}

	if (side == R)
	{
		glColorHex(UI_COLOR_PANEL);
		glRectf(area.x0+0, area.y0, area.x0+2, area.y1);
		glColorHex(UI_COLOR_BEVEL_2);
		glRectf(area.x0+2, area.y0, area.x0+3, area.y1);
		glColorHex(UI_COLOR_BEVEL_1);
		glRectf(area.x0+3, area.y0, area.x0+4, area.y1);
	}
	else if (side == L)
	{
		glColorHex(UI_COLOR_BEVEL_4);
		glRectf(area.x0+0, area.y0, area.x0+1, area.y1);
		glColorHex(UI_COLOR_BEVEL_3);
		glRectf(area.x0+1, area.y0, area.x0+3, area.y1);
		glColorHex(UI_COLOR_PANEL);
		glRectf(area.x0+2, area.y0, area.x0+4, area.y1);
	}
	else if (side == T)
	{
		glColorHex(UI_COLOR_BEVEL_4);
		glRectf(area.x0, area.y0+0, area.x1, area.y0+1);
		glColorHex(UI_COLOR_BEVEL_3);
		glRectf(area.x0, area.y0+1, area.x1, area.y0+2);
		glColorHex(UI_COLOR_PANEL);
		glRectf(area.x0, area.y0+2, area.x1, area.y0+4);
	}
	else if (side == B)
	{
		glColorHex(UI_COLOR_PANEL);
		glRectf(area.x0, area.y0+0, area.x1, area.y0+2);
		glColorHex(UI_COLOR_BEVEL_2);
		glRectf(area.x0, area.y0+2, area.x1, area.y0+3);
		glColorHex(UI_COLOR_BEVEL_1);
		glRectf(area.x0, area.y0+3, area.x1, area.y0+4);
	}
}

void ui_scrollbar(int x0, int y0, int x1, int y1, int *value, int page_size, int max, int *sticky)
{
	static float start_top = 0; /* we can only drag in one scrollbar at a time, so static is safe */
	float top;

	int total_h = y1 - y0;
	int thumb_h = fz_maxi(x1 - x0, total_h * page_size / max);
	int avail_h = total_h - thumb_h;

	max -= page_size;

	if (max <= 0)
	{
		*value = 0;
		glColorHex(UI_COLOR_SCROLLBAR);
		glRectf(x0, y0, x1, y1);
		return;
	}

	if (sticky)
	{
		if (*sticky <= -1)
			*value = 0;
		else if (*sticky >= 1)
			*value = max;
	}

	top = (float) *value * avail_h / max;

	if (ui.down && !ui.active)
	{
		if (ui.x >= x0 && ui.x < x1 && ui.y >= y0 && ui.y < y1)
		{
			if (ui.y < y0 + top)
			{
				ui.active = "pgup";
				*value -= page_size;
			}
			else if (ui.y >= y0 + top + thumb_h)
			{
				ui.active = "pgdn";
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

	if (sticky)
	{
		if (*sticky == 0 && *value == 0)
			*sticky = -1;
		else if (*sticky == 0 && *value == max)
			*sticky = 1;
		else if (*sticky <= -1 && *value != 0)
			*sticky = 0;
		else if (*sticky >= 1 && *value != max)
			*sticky = 0;
	}

	top = (float) *value * avail_h / max;

	glColorHex(UI_COLOR_SCROLLBAR);
	glRectf(x0, y0, x1, y1);
	ui_draw_ibevel_rect(fz_make_irect(x0, y0+top, x1, y0+top+thumb_h), UI_COLOR_BUTTON, 0);
}

void ui_tree_begin(struct list *list, int count, int req_w, int req_h, int is_tree)
{
	static int start_scroll_y = 0; /* we can only drag in one list at a time, so static is safe */

	fz_irect outer_area = ui_pack(req_w, req_h);
	fz_irect area = { outer_area.x0+2, outer_area.y0+2, outer_area.x1-2, outer_area.y1-2 };

	int max_scroll_y = count * ui.lineheight - (area.y1-area.y0);

	if (max_scroll_y > 0)
		area.x1 -= 16;

	if (ui_mouse_inside(area))
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

	/* keyboard keys */
	if (ui.hot == list && ui.key == KEY_HOME)
		list->scroll_y = 0;
	if (ui.hot == list && ui.key == KEY_END)
		list->scroll_y = max_scroll_y;
	if (ui.hot == list && ui.key == KEY_PAGE_UP)
		list->scroll_y -= ((area.y1 - area.y0) / ui.lineheight) * ui.lineheight;
	if (ui.hot == list && ui.key == KEY_PAGE_DOWN)
		list->scroll_y += ((area.y1 - area.y0) / ui.lineheight) * ui.lineheight;

	/* clamp scrolling to client area */
	if (list->scroll_y >= max_scroll_y)
		list->scroll_y = max_scroll_y;
	if (list->scroll_y < 0)
		list->scroll_y = 0;

	ui_draw_bevel_rect(outer_area, UI_COLOR_TEXT_BG, 1);
	if (max_scroll_y > 0)
	{
		ui_scrollbar(area.x1, area.y0, area.x1+16, area.y1,
				&list->scroll_y, area.y1-area.y0, count * ui.lineheight, NULL);
	}

	list->is_tree = is_tree;
	list->area = area;
	list->item_y = area.y0 - list->scroll_y;

	glScissor(list->area.x0, ui.window_h-list->area.y1, list->area.x1-list->area.x0, list->area.y1-list->area.y0);
	glEnable(GL_SCISSOR_TEST);
}

int ui_tree_item(struct list *list, const void *id, const char *label, int selected, int depth, int is_branch, int *is_open)
{
	fz_irect area = { list->area.x0, list->item_y, list->area.x1, list->item_y + ui.lineheight };
	int x_handle, x_item;

	x_item = ui.lineheight / 4;
	x_item += depth * ui.lineheight;
	x_handle = x_item;
	if (list->is_tree)
		x_item += ui_measure_character(0x25BC) + ui.lineheight / 4;

	/* only process visible items */
	if (area.y1 >= list->area.y0 && area.y0 <= list->area.y1)
	{
		if (ui_mouse_inside(list->area) && ui_mouse_inside(area))
		{
			if (list->is_tree && ui.x < area.x0 + x_item)
			{
				ui.hot = is_open;
			}
			else
				ui.hot = id;
			if (!ui.active && ui.down)
			{
				if (list->is_tree && ui.hot == is_open)
					*is_open = !*is_open;
				ui.active = ui.hot;
			}
		}

		if (ui.active == id || selected)
		{
			glColorHex(UI_COLOR_TEXT_SEL_BG);
			glRectf(area.x0, area.y0, area.x1, area.y1);
			glColorHex(UI_COLOR_TEXT_SEL_FG);
		}
		else
		{
			glColorHex(UI_COLOR_TEXT_FG);
		}

		ui_draw_string(area.x0 + x_item, area.y0, label);
		if (list->is_tree && is_branch)
			ui_draw_character(area.x0 + x_handle, area.y0,
				*is_open ? 0x25BC : 0x25B6);
	}

	list->item_y += ui.lineheight;

	/* trigger on mouse up */
	return ui.active == id && !ui.down;
}

void ui_list_begin(struct list *list, int count, int req_w, int req_h)
{
	ui_tree_begin(list, count, req_w, req_h, 0);
}

int ui_list_item(struct list *list, const void *id, const char *label, int selected)
{
	return ui_tree_item(list, id, label, selected, 0, 0, NULL);
}

void ui_tree_end(struct list *list)
{
	glDisable(GL_SCISSOR_TEST);
}

void ui_list_end(struct list *list)
{
	ui_tree_end(list);
}

void ui_label_with_scrollbar(char *text, int width, int height, int *scroll, int *sticky)
{
	struct line lines[500];
	fz_irect area;
	int n;

	area = ui_pack(width, height);
	n = ui_break_lines(text, lines, nelem(lines), area.x1-area.x0 - 16, NULL);
	if (n > (area.y1-area.y0) / ui.lineheight)
	{
		if (ui_mouse_inside(area))
		{
			*scroll -= ui.scroll_y * ui.lineheight * 3;
			if (ui.scroll_y != 0 && sticky)
				*sticky = 0;
		}
		ui_scrollbar(area.x1-16, area.y0, area.x1, area.y1,
				scroll, area.y1-area.y0, n * ui.lineheight, sticky);
	}
	else
		*scroll = 0;

	glScissor(area.x0, ui.window_h-area.y1, area.x1-area.x0-16, area.y1-area.y0);
	glEnable(GL_SCISSOR_TEST);
	glColorHex(UI_COLOR_TEXT_FG);
	ui_draw_lines(area.x0, area.y0 - *scroll, lines, n);
	glDisable(GL_SCISSOR_TEST);
}

int ui_popup(const void *id, const char *label, int is_button, int count)
{
	return ui_popup_aux(id, label, is_button, count, 0);
}

int ui_popup_aux(const void *id, const char *label, int is_button, int count, int flags)
{
	int width = ui_measure_string(label);
	fz_irect area = ui_pack(width + 22 + 6, ui.gridsize);
	fz_irect menu_area;
	int pressed = 0;
	int disabled = (flags & 1);

	if (!disabled)
	{
		if (ui_mouse_inside(area))
		{
			ui.hot = id;
			if (!ui.active && ui.down)
				ui.active = id;
		}

		pressed = (ui.active == id);
	}

	if (is_button)
	{
		ui_draw_bevel_rect(area, UI_COLOR_BUTTON, pressed);
		glColorHex(disabled? UI_COLOR_TEXT_GRAY : UI_COLOR_TEXT_FG);
		ui_draw_string(area.x0 + 6+pressed, area.y0+3+pressed, label);
		glBegin(GL_TRIANGLES);
		glVertex2f(area.x1+pressed-8-10, area.y0+pressed+9);
		glVertex2f(area.x1+pressed-8, area.y0+pressed+9);
		glVertex2f(area.x1+pressed-8-4, area.y0+pressed+14);
		glEnd();
	}
	else
	{
		fz_irect arrow = { area.x1-22, area.y0+2, area.x1-2, area.y1-2 };
		ui_draw_bevel_rect(area, UI_COLOR_TEXT_BG, 1);
		glColorHex(disabled ? UI_COLOR_TEXT_GRAY : UI_COLOR_TEXT_FG);
		ui_draw_string(area.x0 + 6, area.y0+3, label);
		ui_draw_ibevel_rect(arrow, UI_COLOR_BUTTON, pressed);

		glColorHex(disabled ? UI_COLOR_TEXT_GRAY : UI_COLOR_TEXT_FG);
		glBegin(GL_TRIANGLES);
		glVertex2f(area.x1+pressed-8-10, area.y0+pressed+9);
		glVertex2f(area.x1+pressed-8, area.y0+pressed+9);
		glVertex2f(area.x1+pressed-8-4, area.y0+pressed+14);
		glEnd();
	}

	if (pressed)
	{
		ui.overlay = 1;

		glNewList(ui.overlay_list, GL_COMPILE);

		/* Area inside the border line */
		menu_area.x0 = area.x0+1;
		menu_area.x1 = area.x1-1; // TODO: width of submenu
		if (area.y1+2 + count * ui.lineheight < ui.window_h)
		{
			menu_area.y0 = area.y1+2;
			menu_area.y1 = menu_area.y0 + count * ui.lineheight;
		}
		else
		{
			menu_area.y1 = area.y0-2;
			menu_area.y0 = menu_area.y1 - count * ui.lineheight;
		}

		glColorHex(UI_COLOR_TEXT_FG);
		glRectf(menu_area.x0-1, menu_area.y0-1, menu_area.x1+1, menu_area.y1+1);
		glColorHex(UI_COLOR_TEXT_BG);
		glRectf(menu_area.x0, menu_area.y0, menu_area.x1, menu_area.y1);

		ui_pack_push(menu_area);
		ui_layout(T, X, NW, 0, 0);
	}

	return pressed;
}

int ui_popup_item(const char *title)
{
	return ui_popup_item_aux(title, 0);
}

int ui_popup_item_aux(const char *title, int flags)
{
	fz_irect area = ui_pack(0, ui.lineheight);
	int disabled = (flags & 1);

	if (!disabled && ui_mouse_inside(area))
	{
		ui.hot = title;
		glColorHex(UI_COLOR_TEXT_SEL_BG);
		glRectf(area.x0, area.y0, area.x1, area.y1);
		glColorHex(UI_COLOR_TEXT_SEL_FG);
		ui_draw_string(area.x0 + 4, area.y0, title);
	}
	else
	{
		glColorHex(disabled ? UI_COLOR_TEXT_GRAY : UI_COLOR_TEXT_FG);
		ui_draw_string(area.x0 + 4, area.y0, title);
	}

	return !disabled && ui.hot == title && !ui.down;
}

void ui_popup_end(void)
{
	glEndList();
	ui_pack_pop();
}

int ui_select(const void *id, const char *current, const char *options[], int n)
{
	return ui_select_aux(id, current, options, n, 0);
}

int ui_select_aux(const void *id, const char *current, const char *options[], int n, int flags)
{
	int i, choice = -1;
	if (ui_popup_aux(id, current, 0, n, flags))
	{
		for (i = 0; i < n; ++i)
			if (ui_popup_item_aux(options[i], flags))
				choice = i;
		ui_popup_end();
	}
	return choice;
}

void ui_select_annot(pdf_annot *annot)
{
	pdf_drop_annot(ctx, ui.selected_annot);
	ui.selected_annot = annot;
}
