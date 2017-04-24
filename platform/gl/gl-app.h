#ifdef _WIN32
#include <windows.h>
void win_install(void);
int win_open_file(char *buf, int len);
#endif

#include "mupdf/fitz.h"
#include "mupdf/ucdn.h"

#include <GLFW/glfw3.h>

extern fz_context *ctx;
extern GLFWwindow *window;

enum
{
	/* regular control characters */
	KEY_ESCAPE = 27,
	KEY_ENTER = '\r',
	KEY_TAB = '\t',
	KEY_BACKSPACE = '\b',

	KEY_CTL_A = 'A' - 64,
	KEY_CTL_B, KEY_CTL_C, KEY_CTL_D, KEY_CTL_E, KEY_CTL_F,
	KEY_CTL_G, KEY_CTL_H, KEY_CTL_I, KEY_CTL_J, KEY_CTL_K, KEY_CTL_L,
	KEY_CTL_M, KEY_CTL_N, KEY_CTL_O, KEY_CTL_P, KEY_CTL_Q, KEY_CTL_R,
	KEY_CTL_S, KEY_CTL_T, KEY_CTL_U, KEY_CTL_V, KEY_CTL_W, KEY_CTL_X,
	KEY_CTL_Y, KEY_CTL_Z,

	/* reuse control characters > 127 for special keys */
	KEY_INSERT = 127,
	KEY_DELETE,
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

struct ui
{
	int x, y;
	int down, middle, right;
	int scroll_x, scroll_y;
	int key, mod;

	void *hot, *active, *focus;

	int fontsize;
	int baseline;
	int lineheight;
};

extern struct ui ui;

void ui_init_fonts(fz_context *ctx, float pixelsize);
void ui_finish_fonts(fz_context *ctx);
float ui_measure_character(fz_context *ctx, int ucs);
void ui_begin_text(fz_context *ctx);
float ui_draw_character(fz_context *ctx, int ucs, float x, float y);
void ui_end_text(fz_context *ctx);
float ui_draw_string(fz_context *ctx, float x, float y, const char *str);
float ui_measure_string(fz_context *ctx, char *str);

struct texture
{
	GLuint id;
	int x, y, w, h;
	float s, t;
};

void ui_draw_image(struct texture *tex, float x, float y);

struct input
{
	char text[256];
	char *end, *p, *q;
};

int ui_input(int x0, int y0, int x1, int y1, struct input *input);
