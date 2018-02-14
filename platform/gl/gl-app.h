#ifdef _WIN32
#include <windows.h>
void win_install(void);
int win_open_file(char *buf, int len);
#endif

#include "mupdf/fitz.h"
#include "mupdf/ucdn.h"
#include "mupdf/pdf.h" /* for pdf specifics and forms */

#ifndef __APPLE__
#include <GL/freeglut.h>
#else
#include <GLUT/glut.h>
#endif

/* UI */

enum
{
	/* regular control characters */
	KEY_ESCAPE = 27,
	KEY_ENTER = '\r',
	KEY_TAB = '\t',
	KEY_BACKSPACE = '\b',
	KEY_DELETE = 127,

	KEY_CTL_A = 'A' - 64,
	KEY_CTL_B, KEY_CTL_C, KEY_CTL_D, KEY_CTL_E, KEY_CTL_F,
	KEY_CTL_G, KEY_CTL_H, KEY_CTL_I, KEY_CTL_J, KEY_CTL_K, KEY_CTL_L,
	KEY_CTL_M, KEY_CTL_N, KEY_CTL_O, KEY_CTL_P, KEY_CTL_Q, KEY_CTL_R,
	KEY_CTL_S, KEY_CTL_T, KEY_CTL_U, KEY_CTL_V, KEY_CTL_W, KEY_CTL_X,
	KEY_CTL_Y, KEY_CTL_Z,

	/* reuse control characters > 127 for special keys */
	KEY_INSERT = 128,
	KEY_PAGE_UP,
	KEY_PAGE_DOWN,
	KEY_HOME,
	KEY_END,
	KEY_LEFT,
	KEY_UP,
	KEY_RIGHT,
	KEY_DOWN,
	KEY_F1,
	KEY_F2,
	KEY_F3,
	KEY_F4,
	KEY_F5,
	KEY_F6,
	KEY_F7,
	KEY_F8,
	KEY_F9,
	KEY_F10,
	KEY_F11,
	KEY_F12,
};

enum side { ALL, T, R, B, L };
enum fill { NONE = 0, X = 1, Y = 2, BOTH = 3 };
enum anchor { CENTER, N, NE, E, SE, S, SW, W, NW };

struct layout
{
	enum side side;
	enum fill fill;
	enum anchor anchor;
	int padx, pady;
};

struct ui
{
	int window_w, window_h;

	int x, y;
	int down, down_x, down_y;
	int middle, middle_x, middle_y;
	int right, right_x, right_y;

	int scroll_x, scroll_y;
	int key, mod, plain;

	int grab_down, grab_middle, grab_right;
	const void *hot, *active, *focus;

	int fontsize;
	int baseline;
	int lineheight;

	struct layout *layout;
	fz_irect *cavity;
	struct layout layout_stack[32];
	fz_irect cavity_stack[32];
};

extern struct ui ui;

void ui_init(int w, int h, const char *title);
void ui_quit(void);
void ui_invalidate(void);
void ui_finish(void);

void ui_set_clipboard(const char *buf);
const char *ui_get_clipboard(void);

void ui_init_fonts(float pixelsize);
void ui_finish_fonts(void);
float ui_measure_character(int ucs);
void ui_begin_text(void);
float ui_draw_character(int ucs, float x, float y);
void ui_end_text(void);

float ui_draw_string(float x, float y, const char *str);
float ui_measure_string(const char *str);

struct texture
{
	GLuint id;
	int x, y, w, h;
	float s, t;
};

void ui_texture_from_pixmap(struct texture *tex, fz_pixmap *pix);
void ui_draw_image(struct texture *tex, float x, float y);

enum
{
	UI_INPUT_CANCEL = -1,
	UI_INPUT_ACCEPT = 1,
	UI_INPUT_CONTINUE = 0,
};

struct input
{
	char text[256];
	char *end, *p, *q;
};

struct list
{
	fz_irect area;
	int scroll_y;
	int item_y;
};

void ui_begin(void);
void ui_end(void);

int ui_mouse_inside(fz_irect *area);

void ui_layout(enum side side, enum fill fill, enum anchor anchor, int padx, int pady);
fz_irect ui_pack_layout(int slave_w, int slave_h, enum side side, enum fill fill, enum anchor anchor, int padx, int pady);
fz_irect ui_pack(int slave_w, int slave_h);
void ui_pack_push(fz_irect cavity);
void ui_pack_pop(void);

void ui_panel_begin(int w, int h, int opaque);
void ui_panel_end(void);

void ui_spacer(void);
void ui_label(const char *fmt, ...);
int ui_button(const char *label);
void ui_checkbox(const char *label, int *value);
void ui_slider(float *value, float min, float max, int width);

void ui_input_init(struct input *input, const char *text);
int ui_input(struct input *input, int width);
void ui_scrollbar(int x0, int y0, int x1, int y1, int *value, int page_size, int max);

void ui_list_begin(struct list *list, int count, int req_w, int req_h);
int ui_list_item(struct list *list, void *id, int indent, const char *label, int selected);
void ui_list_end(struct list *list);

/* App */

extern fz_context *ctx;
extern pdf_document *pdf;
extern pdf_page *page;
extern fz_matrix page_ctm, page_inv_ctm;
extern int page_x_ofs, page_y_ofs;

void run_main_loop(void);
