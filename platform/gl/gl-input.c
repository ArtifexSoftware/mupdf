#include "gl-app.h"

#include <string.h>

static void draw_string_part(float x, float y, const char *s, const char *e)
{
	int c;
	ui_begin_text();
	while (s < e)
	{
		s += fz_chartorune(&c, s);
		x += ui_draw_character(c, x, y + ui.baseline);
	}
	ui_end_text();
}

static float measure_string_part(const char *s, const char *e)
{
	int c;
	float w = 0;
	while (s < e)
	{
		s += fz_chartorune(&c, s);
		w += ui_measure_character(c);
	}
	return w;
}

static char *find_string_location(char *s, char *e, float w, float x)
{
	int c;
	while (s < e)
	{
		int n = fz_chartorune(&c, s);
		float cw = ui_measure_character(c);
		if (w + (cw / 2) >= x)
			return s;
		w += cw;
		s += n;
	}
	return e;
}

static inline int myisalnum(char *s)
{
	int cat, c;
	fz_chartorune(&c, s);
	cat = ucdn_get_general_category(c);
	if (cat >= UCDN_GENERAL_CATEGORY_LL && cat <= UCDN_GENERAL_CATEGORY_LU)
		return 1;
	if (cat >= UCDN_GENERAL_CATEGORY_ND && cat <= UCDN_GENERAL_CATEGORY_NO)
		return 1;
	return 0;
}

static char *prev_char(char *p, char *start)
{
	--p;
	while ((*p & 0xC0) == 0x80 && p > start) /* skip middle and final multibytes */
		--p;
	return p;
}

static char *next_char(char *p)
{
	++p;
	while ((*p & 0xC0) == 0x80) /* skip middle and final multibytes */
		++p;
	return p;
}

static char *prev_word(char *p, char *start)
{
	while (p > start && !myisalnum(prev_char(p, start))) p = prev_char(p, start);
	while (p > start && myisalnum(prev_char(p, start))) p = prev_char(p, start);
	return p;
}

static char *next_word(char *p, char *end)
{
	while (p < end && !myisalnum(p)) p = next_char(p);
	while (p < end && myisalnum(p)) p = next_char(p);
	return p;
}

static void ui_input_delete_selection(struct input *input)
{
	char *p = input->p < input->q ? input->p : input->q;
	char *q = input->p > input->q ? input->p : input->q;
	memmove(p, q, input->end - q);
	input->end -= q - p;
	*input->end = 0;
	input->p = input->q = p;
}

static void ui_input_paste(struct input *input, const char *buf, int n)
{
	if (input->p != input->q)
		ui_input_delete_selection(input);
	if (input->end + n + 1 < input->text + sizeof(input->text))
	{
		memmove(input->p + n, input->p, input->end - input->p);
		memmove(input->p, buf, n);
		input->p += n;
		input->end += n;
		*input->end = 0;
	}
	input->q = input->p;
}

static int ui_input_key(struct input *input)
{
	switch (ui.key)
	{
	case 0:
		return UI_INPUT_NONE;
	case KEY_LEFT:
		if (ui.mod == GLUT_ACTIVE_CTRL + GLUT_ACTIVE_SHIFT)
		{
			input->q = prev_word(input->q, input->text);
		}
		else if (ui.mod == GLUT_ACTIVE_CTRL)
		{
			if (input->p != input->q)
				input->p = input->q = input->p < input->q ? input->p : input->q;
			else
				input->p = input->q = prev_word(input->q, input->text);
		}
		else if (ui.mod == GLUT_ACTIVE_SHIFT)
		{
			if (input->q > input->text)
				input->q = prev_char(input->q, input->text);
		}
		else if (ui.mod == 0)
		{
			if (input->p != input->q)
				input->p = input->q = input->p < input->q ? input->p : input->q;
			else if (input->q > input->text)
				input->p = input->q = prev_char(input->q, input->text);
		}
		break;
	case KEY_RIGHT:
		if (ui.mod == GLUT_ACTIVE_CTRL + GLUT_ACTIVE_SHIFT)
		{
			input->q = next_word(input->q, input->end);
		}
		else if (ui.mod == GLUT_ACTIVE_CTRL)
		{
			if (input->p != input->q)
				input->p = input->q = input->p > input->q ? input->p : input->q;
			else
				input->p = input->q = next_word(input->q, input->end);
		}
		else if (ui.mod == GLUT_ACTIVE_SHIFT)
		{
			if (input->q < input->end)
				input->q = next_char(input->q);
		}
		else if (ui.mod == 0)
		{
			if (input->p != input->q)
				input->p = input->q = input->p > input->q ? input->p : input->q;
			else if (input->q < input->end)
				input->p = input->q = next_char(input->q);
		}
		break;
	case KEY_UP:
	case KEY_HOME:
		if (ui.mod == GLUT_ACTIVE_CTRL + GLUT_ACTIVE_SHIFT)
		{
			input->q = input->text;
		}
		else if (ui.mod == GLUT_ACTIVE_CTRL)
		{
			input->p = input->q = input->text;
		}
		else if (ui.mod == GLUT_ACTIVE_SHIFT)
		{
			input->q = input->text;
		}
		else if (ui.mod == 0)
		{
			input->p = input->q = input->text;
		}
		break;
	case KEY_DOWN:
	case KEY_END:
		if (ui.mod == GLUT_ACTIVE_CTRL + GLUT_ACTIVE_SHIFT)
		{
			input->q = input->end;
		}
		else if (ui.mod == GLUT_ACTIVE_CTRL)
		{
			input->p = input->q = input->end;
		}
		else if (ui.mod == GLUT_ACTIVE_SHIFT)
		{
			input->q = input->end;
		}
		else if (ui.mod == 0)
		{
			input->p = input->q = input->end;
		}
		break;
	case KEY_DELETE:
		if (input->p != input->q)
			ui_input_delete_selection(input);
		else if (input->p < input->end)
		{
			char *np = next_char(input->p);
			memmove(input->p, np, input->end - np);
			input->end -= np - input->p;
			*input->end = 0;
			input->q = input->p;
		}
		break;
	case KEY_ESCAPE:
		ui.focus = NULL;
		return UI_INPUT_NONE;
	case KEY_ENTER:
		ui.focus = NULL;
		return UI_INPUT_ACCEPT;
	case KEY_BACKSPACE:
		if (input->p != input->q)
			ui_input_delete_selection(input);
		else if (input->p > input->text)
		{
			char *pp = prev_char(input->p, input->text);
			memmove(pp, input->p, input->end - input->p);
			input->end -= input->p - pp;
			*input->end = 0;
			input->q = input->p = pp;
		}
		break;
	case KEY_CTL_A:
		input->p = input->q = input->text;
		break;
	case KEY_CTL_E:
		input->p = input->q = input->end;
		break;
	case KEY_CTL_W:
		if (input->p != input->q)
			ui_input_delete_selection(input);
		else
		{
			input->p = prev_word(input->p, input->text);
			ui_input_delete_selection(input);
		}
		break;
	case KEY_CTL_U:
		input->p = input->q = input->end = input->text;
		break;
	case KEY_CTL_C:
	case KEY_CTL_X:
		if (input->p != input->q)
		{
			char buf[sizeof input->text];
			char *p = input->p < input->q ? input->p : input->q;
			char *q = input->p > input->q ? input->p : input->q;
			memmove(buf, p, q - p);
			buf[q-p] = 0;
			ui_set_clipboard(buf);
			if (ui.key == KEY_CTL_X)
				ui_input_delete_selection(input);
		}
		break;
	case KEY_CTL_V:
		{
			const char *buf = ui_get_clipboard();
			if (buf)
				ui_input_paste(input, buf, (int)strlen(buf));
		}
		break;
	default:
		if (ui.key >= 32 && ui.plain)
		{
			int cat = ucdn_get_general_category(ui.key);
			if (ui.key == ' ' || (cat >= UCDN_GENERAL_CATEGORY_LL && cat < UCDN_GENERAL_CATEGORY_ZL))
			{
				char buf[8];
				int n = fz_runetochar(buf, ui.key);
				ui_input_paste(input, buf, n);
			}
		}
		break;
	}
	return UI_INPUT_EDIT;
}

void ui_input_init(struct input *input, const char *text)
{
	fz_strlcpy(input->text, text, sizeof input->text);
	input->end = input->text + strlen(input->text);
	input->p = input->text;
	input->q = input->end;
}

int ui_input(struct input *input, int width)
{
	fz_irect area;
	float ax, px, qx;
	char *p, *q;
	int state;

	area = ui_pack(width, ui.lineheight + 6);

	if (ui_mouse_inside(&area))
	{
		ui.hot = input;
		if (!ui.active || ui.active == input)
			ui.cursor = GLUT_CURSOR_TEXT;
		if (!ui.active && ui.down)
		{
			input->p = find_string_location(input->text, input->end, area.x0 + 3, ui.x);
			ui.active = input;
		}
	}

	if (ui.active == input)
	{
		input->q = find_string_location(input->text, input->end, area.x0 + 3, ui.x);
		ui.focus = input;
	}

	if (ui.focus == input)
		state = ui_input_key(input);
	else
		state = UI_INPUT_NONE;

	ui_draw_bevel_rect(area, UI_COLOR_TEXT_BG, 1);

	p = input->p < input->q ? input->p : input->q;
	q = input->p > input->q ? input->p : input->q;

	ax = area.x0 + 4;
	px = ax + measure_string_part(input->text, p);
	qx = px + measure_string_part(p, q);

	if (ui.focus == input)
	{
		glColorHex(UI_COLOR_TEXT_SEL_BG);
		glRectf(px, area.y0 + 3, qx+1, area.y1 - 3);
		glColorHex(UI_COLOR_TEXT_FG);
		draw_string_part(ax, area.y0 + 3, input->text, p);
		glColorHex(UI_COLOR_TEXT_SEL_FG);
		draw_string_part(px, area.y0 + 3, p, q);
		glColorHex(UI_COLOR_TEXT_FG);
		draw_string_part(qx, area.y0 + 3, q, input->end);
	}
	else
	{
		glColorHex(UI_COLOR_TEXT_FG);
		draw_string_part(ax, area.y0 + 3, input->text, input->end);
	}

	return state;
}
