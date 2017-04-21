#include "gl-app.h"

#include <string.h>

static void draw_string_part(float x, float y, const char *s, const char *e)
{
	int c;
	ui_begin_text(ctx);
	while (s < e)
	{
		s += fz_chartorune(&c, s);
		x += ui_draw_character(ctx, c, x, y + ui.baseline);
	}
	ui_end_text(ctx);
}

static float measure_string_part(const char *s, const char *e)
{
	int c;
	float w = 0;
	while (s < e)
	{
		s += fz_chartorune(&c, s);
		w += ui_measure_character(ctx, c);
	}
	return w;
}

static char *find_string_location(char *s, char *e, float w, float x)
{
	int c;
	while (s < e)
	{
		int n = fz_chartorune(&c, s);
		float cw = ui_measure_character(ctx, c);
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
	case KEY_LEFT:
		if (ui.mod == GLFW_MOD_CONTROL + GLFW_MOD_SHIFT)
		{
			input->q = prev_word(input->q, input->text);
		}
		else if (ui.mod == GLFW_MOD_CONTROL)
		{
			if (input->p != input->q)
				input->p = input->q = input->p < input->q ? input->p : input->q;
			else
				input->p = input->q = prev_word(input->q, input->text);
		}
		else if (ui.mod == GLFW_MOD_SHIFT)
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
		if (ui.mod == GLFW_MOD_CONTROL + GLFW_MOD_SHIFT)
		{
			input->q = next_word(input->q, input->end);
		}
		else if (ui.mod == GLFW_MOD_CONTROL)
		{
			if (input->p != input->q)
				input->p = input->q = input->p > input->q ? input->p : input->q;
			else
				input->p = input->q = next_word(input->q, input->end);
		}
		else if (ui.mod == GLFW_MOD_SHIFT)
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
		if (ui.mod == GLFW_MOD_CONTROL + GLFW_MOD_SHIFT)
		{
			input->q = input->text;
		}
		else if (ui.mod == GLFW_MOD_CONTROL)
		{
			input->p = input->q = input->text;
		}
		else if (ui.mod == GLFW_MOD_SHIFT)
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
		if (ui.mod == GLFW_MOD_CONTROL + GLFW_MOD_SHIFT)
		{
			input->q = input->end;
		}
		else if (ui.mod == GLFW_MOD_CONTROL)
		{
			input->p = input->q = input->end;
		}
		else if (ui.mod == GLFW_MOD_SHIFT)
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
		return -1;
	case KEY_ENTER:
		return 1;
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
			glfwSetClipboardString(window, buf);
			if (ui.key == KEY_CTL_X)
				ui_input_delete_selection(input);
		}
		break;
	case KEY_CTL_V:
		{
			const char *buf = glfwGetClipboardString(window);
			if (buf)
				ui_input_paste(input, buf, (int)strlen(buf));
		}
		break;
	default:
		if (ui.key >= 32)
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
	return 0;
}

int ui_input(int x0, int y0, int x1, int y1, struct input *input)
{
	float px, qx;
	char *p, *q;
	int state;

	if (ui.x >= x0 && ui.x < x1 && ui.y >= y0 && ui.y < y1)
	{
		ui.hot = input;
		if (!ui.active && ui.down)
		{
			input->p = find_string_location(input->text, input->end, x0 + 2, ui.x);
			ui.active = input;
		}
	}

	if (ui.active == input)
	{
		input->q = find_string_location(input->text, input->end, x0 + 2, ui.x);
		ui.focus = input;
	}

	if (!ui.focus)
		ui.focus = input;

	if (ui.focus == input)
		state = ui_input_key(input);
	else
		state = 0;

	glColor4f(0, 0, 0, 1);
	glRectf(x0, y0, x1, y1);

	glColor4f(1, 1, 1, 1);
	glRectf(x0+1, y0+1, x1-1, y1-1);

	p = input->p < input->q ? input->p : input->q;
	q = input->p > input->q ? input->p : input->q;

	px = x0 + 2 + measure_string_part(input->text, p);
	qx = px + measure_string_part(p, q);

	if (ui.focus)
	{
		glColor4f(0.6f, 0.6f, 1.0f, 1.0f);
		glRectf(px, y0 + 2, qx+1, y1 - 2);
	}

	glColor4f(0, 0, 0, 1);
	draw_string_part(x0 + 2, y0 + 2, input->text, input->end);

	return state;
}
