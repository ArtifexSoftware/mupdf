#include "gl-app.h"

static void draw_string_part(float x, float y, const int *s, const int *e)
{
	ui_begin_text(ctx);
	while (s < e)
		x += ui_draw_character(ctx, *s++, x, y + ui.baseline);
	ui_end_text(ctx);
}

static float measure_string_part(const int *s, const int *e)
{
	float w = 0;
	while (s < e)
		w += ui_measure_character(ctx, *s++);
	return w;
}

static int *find_string_location(int *s, int *e, float w, float x)
{
	while (s < e)
	{
		float cw = ui_measure_character(ctx, *s);
		if (w + (cw / 2) >= x)
			return s;
		w += cw;
		++s;
	}
	return e;
}

static inline int myisalnum(int c)
{
	int cat = ucdn_get_general_category(c);
	if (cat >= UCDN_GENERAL_CATEGORY_LL && cat <= UCDN_GENERAL_CATEGORY_LU)
		return 1;
	if (cat >= UCDN_GENERAL_CATEGORY_ND && cat <= UCDN_GENERAL_CATEGORY_NO)
		return 1;
	return 0;
}

static int *skip_word_left(int *p, int *start)
{
	while (p > start && !myisalnum(p[-1])) --p;
	while (p > start && myisalnum(p[-1])) --p;
	return p;
}

static int *skip_word_right(int *p, int *end)
{
	while (p < end && !myisalnum(p[0])) ++p;
	while (p < end && myisalnum(p[0])) ++p;
	return p;
}

static void ui_input_delete_selection(struct input *input)
{
	int *p = input->p < input->q ? input->p : input->q;
	int *q = input->p > input->q ? input->p : input->q;
	memmove(p, q, (input->end - q) * sizeof (*p));
	input->end -= q - p;
	input->p = input->q = p;
}

static int ui_input_key(struct input *input)
{
	switch (ui.key)
	{
	case KEY_LEFT:
		if (ui.mod == GLFW_MOD_CONTROL + GLFW_MOD_SHIFT)
		{
			input->q = skip_word_left(input->q, input->text);
		}
		else if (ui.mod == GLFW_MOD_CONTROL)
		{
			if (input->p != input->q)
				input->p = input->q = input->p < input->q ? input->p : input->q;
			else
				input->p = input->q = skip_word_left(input->q, input->text);
		}
		else if (ui.mod == GLFW_MOD_SHIFT)
		{
			if (input->q > input->text)
				input->q = --(input->q);
		}
		else if (ui.mod == 0)
		{
			if (input->p != input->q)
				input->p = input->q = input->p < input->q ? input->p : input->q;
			else if (input->q > input->text)
				input->p = input->q = --(input->q);
		}
		break;
	case KEY_RIGHT:
		if (ui.mod == GLFW_MOD_CONTROL + GLFW_MOD_SHIFT)
		{
			input->q = skip_word_right(input->q, input->end);
		}
		else if (ui.mod == GLFW_MOD_CONTROL)
		{
			if (input->p != input->q)
				input->p = input->q = input->p > input->q ? input->p : input->q;
			else
				input->p = input->q = skip_word_right(input->q, input->end);
		}
		else if (ui.mod == GLFW_MOD_SHIFT)
		{
			if (input->q < input->end)
				input->q = ++(input->q);
		}
		else if (ui.mod == 0)
		{
			if (input->p != input->q)
				input->p = input->q = input->p > input->q ? input->p : input->q;
			else if (input->q < input->end)
				input->p = input->q = ++(input->q);
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
			memmove(input->p, input->p + 1, (input->end - input->p - 1) * sizeof (*input->p));
			input->q = input->p;
			--(input->end);
		}
		break;
	case KEY_ESCAPE:
		return -1;
	case KEY_ENTER:
		return 1;
	case KEY_BACKSPACE:
		if (input->p != input->q)
			ui_input_delete_selection(input);
		else if (input->p > input->text && input->end > input->text)
		{
			memmove(input->p - 1, input->p, (input->end - input->p) * sizeof (*input->p));
			input->q = --(input->p);
			--(input->end);
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
			input->p = skip_word_left(input->p, input->text);
			ui_input_delete_selection(input);
		}
		break;
	case KEY_CTL_U:
		input->p = input->q = input->end = input->text;
		break;
	default:
		if (ui.key >= 32)
		{
			int cat = ucdn_get_general_category(ui.key);
			if (ui.key == ' ' || (cat >= UCDN_GENERAL_CATEGORY_LL && cat < UCDN_GENERAL_CATEGORY_ZL))
			{
				if (input->p != input->q)
					ui_input_delete_selection(input);
				if (input->end < input->text + nelem(input->text))
				{
					memmove(input->p + 1, input->p, (input->end - input->p) * sizeof (*input->p));
					++(input->end);
					*(input->p++) = ui.key;
				}
				input->q = input->p;
			}
		}
		break;
	}
	return 0;
}

int ui_input(int x0, int y0, int x1, int y1, struct input *input)
{
	float px, qx, ex;
	int *p, *q;
	int state;

	if (ui.x >= x0 && ui.x < x1 && ui.y >= y0 && ui.y < y1)
	{
		ui.hot = input;
		if (!ui.active && ui.down)
			ui.active = input;
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

	glColor4f(1, 1, 1, 1);
	glRectf(x0, y0, x1, y1);

	p = input->p < input->q ? input->p : input->q;
	q = input->p > input->q ? input->p : input->q;

	px = x0 + 2 + measure_string_part(input->text, p);
	qx = px + measure_string_part(p, q);
	ex = qx + measure_string_part(q, input->end);

	if (ui.focus)
	{
		glColor4f(0.6f, 0.6f, 1.0f, 1.0f);
		glRectf(px, y0 + 2, qx+1, y1 - 2);
	}

	glColor4f(0, 0, 0, 1);
	draw_string_part(x0 + 2, y0 + 2, input->text, input->end);

	return state;
}
