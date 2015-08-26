#include "mupdf/fitz.h"
#include <GLFW/glfw3.h>

struct ui
{
	int x, y, down, middle, right;
	void *hot, *active;

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
