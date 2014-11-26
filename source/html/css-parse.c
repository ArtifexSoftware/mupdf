#include "mupdf/html.h"

struct lexbuf
{
	fz_context *ctx;
	const char *s;
	int lookahead;
	int c;
	int color;
	int string_len;
	char string[1024];
};

static void css_lex_next(struct lexbuf *buf)
{
	// buf->s += fz_chartorune(&buf->c, buf->s);
	buf->c = *(buf->s++);
}

static void css_lex_init(fz_context *ctx, struct lexbuf *buf, const char *s)
{
	buf->ctx = ctx;
	buf->s = s;
	buf->c = 0;
	css_lex_next(buf);

	buf->color = 0;
	buf->string_len = 0;
}

static int iswhite(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f';
}

static int isnmstart(int c)
{
	return c == '\\' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= 128 && c <= 255);
}

static int isnmchar(int c)
{
	return c == '\\' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-' || (c >= 128 && c <= 255);
}

static void css_push_char(struct lexbuf *buf, int c)
{
	if (buf->string_len + 1 >= nelem(buf->string))
		fz_throw(buf->ctx, FZ_ERROR_GENERIC, "token too long");
	buf->string[buf->string_len++] = c;
}

static int css_lex_accept(struct lexbuf *buf, int t)
{
	if (buf->c == t)
	{
		css_lex_next(buf);
		return 1;
	}
	return 0;
}

static void css_lex_expect(struct lexbuf *buf, int t)
{
	if (!css_lex_accept(buf, t))
		fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected '%c'", t);
}

static int ishex(int c, int *v)
{
	if (c >= '0' && c <= '9')
	{
		*v = c - '0';
		return 1;
	}
	if (c >= 'A' && c <= 'F')
	{
		*v = c - 'A' + 0xA;
		return 1;
	}
	if (c >= 'a' && c <= 'f')
	{
		*v = c - 'a' + 0xA;
		return 1;
	}
	return 0;
}

static int css_lex_accept_hex(struct lexbuf *buf, int *v)
{
	if (ishex(buf->c, v))
	{
		css_lex_next(buf);
		return 1;
	}
	return 0;
}

static int css_lex_number(struct lexbuf *buf)
{
	while (buf->c >= '0' && buf->c <= '9')
	{
		css_push_char(buf, buf->c);
		css_lex_next(buf);
	}

	if (css_lex_accept(buf, '.'))
	{
		css_push_char(buf, '.');
		while (buf->c >= '0' && buf->c <= '9')
		{
			css_push_char(buf, buf->c);
			css_lex_next(buf);
		}
	}

	if (css_lex_accept(buf, '%'))
	{
		css_push_char(buf, '%');
		css_push_char(buf, 0);
		return CSS_PERCENT;
	}

	if (isnmstart(buf->c))
	{
		css_push_char(buf, buf->c);
		css_lex_next(buf);
		while (isnmchar(buf->c))
		{
			css_push_char(buf, buf->c);
			css_lex_next(buf);
		}
		css_push_char(buf, 0);
		return CSS_LENGTH;
	}

	css_push_char(buf, 0);
	return CSS_NUMBER;
}

static int css_lex_keyword(struct lexbuf *buf)
{
	while (isnmchar(buf->c))
	{
		css_push_char(buf, buf->c);
		css_lex_next(buf);
	}
	css_push_char(buf, 0);
	return CSS_KEYWORD;
}

static int css_lex_string(struct lexbuf *buf, int q)
{
	while (buf->c && buf->c != q)
	{
		if (css_lex_accept(buf, '\\'))
		{
			if (css_lex_accept(buf, 'n'))
				css_push_char(buf, '\n');
			else if (css_lex_accept(buf, 'r'))
				css_push_char(buf, '\r');
			else if (css_lex_accept(buf, 'f'))
				css_push_char(buf, '\f');
			else if (css_lex_accept(buf, '\f'))
				/* line continuation */ ;
			else if (css_lex_accept(buf, '\n'))
				/* line continuation */ ;
			else if (css_lex_accept(buf, '\r'))
				css_lex_accept(buf, '\n');
			else
			{
				css_push_char(buf, buf->c);
				css_lex_next(buf);
			}
		}
		else
		{
			css_push_char(buf, buf->c);
			css_lex_next(buf);
		}
	}
	css_lex_expect(buf, q);
	css_push_char(buf, 0);
	return CSS_STRING;
}

static int css_lex(struct lexbuf *buf)
{
	int t;

	// TODO: keyword escape sequences

	buf->string_len = 0;

	while (buf->c)
	{
restart:
		while (iswhite(buf->c))
			css_lex_next(buf);

		if (buf->c == 0)
			break;

		if (css_lex_accept(buf, '/'))
		{
			if (css_lex_accept(buf, '*'))
			{
				while (buf->c)
				{
					if (css_lex_accept(buf, '*'))
					{
						while (buf->c == '*')
							css_lex_next(buf);
						if (css_lex_accept(buf, '/'))
							goto restart;
					}
					css_lex_next(buf);
				}
				fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: unterminated comment");
			}
			return '/';
		}

		if (css_lex_accept(buf, '<'))
		{
			if (css_lex_accept(buf, '!'))
			{
				css_lex_expect(buf, '-');
				css_lex_expect(buf, '-');
				continue; /* ignore CDO */
			}
			return '<';
		}

		if (css_lex_accept(buf, '-'))
		{
			if (css_lex_accept(buf, '-'))
			{
				css_lex_expect(buf, '>');
				continue; /* ignore CDC */
			}
			if (buf->c >= '0' && buf->c <= '9')
			{
				css_push_char(buf, '-');
				return css_lex_number(buf);
			}
			if (isnmstart(buf->c))
			{
				css_push_char(buf, '-');
				css_push_char(buf, buf->c);
				css_lex_next(buf);
				return css_lex_keyword(buf);
			}
			return '-';
		}

		if (css_lex_accept(buf, '.'))
		{
			if (buf->c >= '0' && buf->c <= '9')
			{
				css_push_char(buf, '.');
				return css_lex_number(buf);
			}
			return '.';
		}

		if (css_lex_accept(buf, '#'))
		{
			int a, b, c, d, e, f;
			if (!css_lex_accept_hex(buf, &a)) goto colorerror;
			if (!css_lex_accept_hex(buf, &b)) goto colorerror;
			if (!css_lex_accept_hex(buf, &c)) goto colorerror;
			if (css_lex_accept_hex(buf, &d))
			{
				if (!css_lex_accept_hex(buf, &e)) goto colorerror;
				if (!css_lex_accept_hex(buf, &f)) goto colorerror;
				buf->color = (a << 20) | (b << 16) | (c << 12) | (d << 8) | (e << 4) | f;
			}
			else
			{
				buf->color = (a << 20) | (b << 12) | (c << 4);
			}
			sprintf(buf->string, "%06x", buf->color); // XXX
			return CSS_COLOR;
colorerror:
			fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error in color");
		}

		if (css_lex_accept(buf, '"'))
			return css_lex_string(buf, '"');
		if (css_lex_accept(buf, '\''))
			return css_lex_string(buf, '\'');

		if (buf->c >= '0' && buf->c <= '9')
			return css_lex_number(buf);

		if (css_lex_accept(buf, 'u'))
		{
			if (css_lex_accept(buf, 'r'))
			{
				if (css_lex_accept(buf, 'l'))
				{
					if (css_lex_accept(buf, '('))
					{
						// string or url
						css_lex_expect(buf, ')');
						return CSS_URI;
					}
					css_push_char(buf, 'u');
					css_push_char(buf, 'r');
					css_push_char(buf, 'l');
					return css_lex_keyword(buf);
				}
				css_push_char(buf, 'u');
				css_push_char(buf, 'r');
				return css_lex_keyword(buf);
			}
			css_push_char(buf, 'u');
			return css_lex_keyword(buf);
		}

		if (isnmstart(buf->c))
		{
			css_push_char(buf, buf->c);
			css_lex_next(buf);
			return css_lex_keyword(buf);
		}

		t = buf->c;
		css_lex_next(buf);
		return t;
	}
	return EOF;
}

static void next(struct lexbuf *buf)
{
	buf->lookahead = css_lex(buf);
}

static int accept(struct lexbuf *buf, int t)
{
	if (buf->lookahead == t)
	{
		next(buf);
		return 1;
	}
	return 0;
}

static void expect(struct lexbuf *buf, int t)
{
	if (accept(buf, t))
		return;
	if (t < 256)
		fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected '%c'", t);
	else
		fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: unexpected token");
}

static int iscond(int t)
{
	return t == ':' || t == '.' || t == '#' || t == '[';
}

static struct value *parse_value_list(struct lexbuf *buf);

static struct value *parse_value(struct lexbuf *buf)
{
	struct value *v;

	if (buf->lookahead == CSS_KEYWORD)
	{
		v = fz_new_css_value(buf->ctx, CSS_KEYWORD, buf->string);
		next(buf);

		if (accept(buf, '('))
		{
			v->type = '(';
			v->args = parse_value_list(buf);
			expect(buf, ')');
		}

		return v;
	}

	switch (buf->lookahead)
	{
	case CSS_NUMBER:
	case CSS_LENGTH:
	case CSS_PERCENT:
	case CSS_STRING:
	case CSS_COLOR:
	case CSS_URI:
		v = fz_new_css_value(buf->ctx, buf->lookahead, buf->string);
		next(buf);
		return v;
	}

	if (accept(buf, ','))
		return fz_new_css_value(buf->ctx, ',', ",");
	if (accept(buf, '/'))
		return fz_new_css_value(buf->ctx, '/', "/");

	fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected value");
}

static struct value *parse_value_list(struct lexbuf *buf)
{
	struct value *head, *tail;

	head = tail = NULL;

	while (buf->lookahead != '}' && buf->lookahead != ';' && buf->lookahead != '!' &&
			buf->lookahead != ')' && buf->lookahead != EOF)
	{
		if (!head)
			head = tail = parse_value(buf);
		else
			tail = tail->next = parse_value(buf);
	}

	return head;
}

static struct property *parse_declaration(struct lexbuf *buf)
{
	struct property *p;

	if (buf->lookahead != CSS_KEYWORD)
		fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected keyword in property");
	p = fz_new_css_property(buf->ctx, buf->string, NULL, 0);
	next(buf);

	expect(buf, ':');

	p->value = parse_value_list(buf);

	/* !important */
	if (accept(buf, '!'))
		expect(buf, CSS_KEYWORD);

	return p;
}

static struct property *parse_declaration_list(struct lexbuf *buf)
{
	struct property *head, *tail;

	if (buf->lookahead == '}' || buf->lookahead == EOF)
		return NULL;

	head = tail = parse_declaration(buf);

	while (accept(buf, ';'))
	{
		if (buf->lookahead != '}' && buf->lookahead != ';' && buf->lookahead != EOF)
		{
			tail = tail->next = parse_declaration(buf);
		}
	}

	return head;
}

static const char *parse_attrib_value(struct lexbuf *buf)
{
	const char *s;

	if (buf->lookahead == CSS_KEYWORD || buf->lookahead == CSS_STRING)
	{
		s = strdup(buf->string);
		next(buf);
		return s;
	}

	fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected attribute value");
}

static struct condition *parse_condition(struct lexbuf *buf)
{
	struct condition *c;

	if (accept(buf, ':'))
	{
		if (buf->lookahead != CSS_KEYWORD)
			fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected keyword after ':'");
		c = fz_new_css_condition(buf->ctx, ':', "pseudo", buf->string);
		next(buf);
		return c;
	}

	if (accept(buf, '.'))
	{
		if (buf->lookahead != CSS_KEYWORD)
			fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected keyword after '.'");
		c = fz_new_css_condition(buf->ctx, '.', "class", buf->string);
		next(buf);
		return c;
	}

	if (accept(buf, '#'))
	{
		if (buf->lookahead != CSS_KEYWORD)
			fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected keyword after '#'");
		c = fz_new_css_condition(buf->ctx, '#', "id", buf->string);
		next(buf);
		return c;
	}

	if (accept(buf, '['))
	{
		if (buf->lookahead != CSS_KEYWORD)
			fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected keyword after '['");

		c = fz_new_css_condition(buf->ctx, '[', buf->string, NULL);
		next(buf);

		if (accept(buf, '='))
		{
			c->type = '=';
			c->val = parse_attrib_value(buf);
		}
		else if (accept(buf, '|'))
		{
			expect(buf, '=');
			c->type = '|';
			c->val = parse_attrib_value(buf);
		}
		else if (accept(buf, '~'))
		{
			expect(buf, '=');
			c->type = '~';
			c->val = parse_attrib_value(buf);
		}

		expect(buf, ']');

		return c;
	}

	fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected condition");
}

static struct condition *parse_condition_list(struct lexbuf *buf)
{
	struct condition *head, *tail;

	head = tail = parse_condition(buf);
	while (iscond(buf->lookahead))
	{
		tail = tail->next = parse_condition(buf);
	}
	return head;
}

static struct selector *parse_simple_selector(struct lexbuf *buf)
{
	struct selector *s;

	if (accept(buf, '*'))
	{
		s = fz_new_css_selector(buf->ctx, NULL);
		if (iscond(buf->lookahead))
			s->cond = parse_condition_list(buf);
		return s;
	}
	else if (buf->lookahead == CSS_KEYWORD)
	{
		s = fz_new_css_selector(buf->ctx, buf->string);
		next(buf);
		if (iscond(buf->lookahead))
			s->cond = parse_condition_list(buf);
		return s;
	}
	else if (iscond(buf->lookahead))
	{
		s = fz_new_css_selector(buf->ctx, NULL);
		s->cond = parse_condition_list(buf);
		return s;
	}

	fz_throw(buf->ctx, FZ_ERROR_GENERIC, "syntax error: expected selector");
}

static struct selector *parse_adjacent_selector(struct lexbuf *buf)
{
	struct selector *s, *a, *b;

	a = parse_simple_selector(buf);
	if (accept(buf, '+'))
	{
		b = parse_adjacent_selector(buf);
		s = fz_new_css_selector(buf->ctx, NULL);
		s->combine = '+';
		s->left = a;
		s->right = b;
		return s;
	}
	return a;
}

static struct selector *parse_child_selector(struct lexbuf *buf)
{
	struct selector *s, *a, *b;

	a = parse_adjacent_selector(buf);
	if (accept(buf, '>'))
	{
		b = parse_child_selector(buf);
		s = fz_new_css_selector(buf->ctx, NULL);
		s->combine = '>';
		s->left = a;
		s->right = b;
		return s;
	}
	return a;
}

static struct selector *parse_descendant_selector(struct lexbuf *buf)
{
	struct selector *s, *a, *b;

	a = parse_child_selector(buf);
	if (buf->lookahead != ',' && buf->lookahead != '{' && buf->lookahead != EOF)
	{
		b = parse_descendant_selector(buf);
		s = fz_new_css_selector(buf->ctx, NULL);
		s->combine = ' ';
		s->left = a;
		s->right = b;
		return s;
	}
	return a;
}

static struct selector *parse_selector_list(struct lexbuf *buf)
{
	struct selector *head, *tail;

	head = tail = parse_descendant_selector(buf);
	while (accept(buf, ','))
	{
		tail = tail->next = parse_descendant_selector(buf);
	}
	return head;
}

static struct rule *parse_rule(struct lexbuf *buf)
{
	struct selector *s;
	struct property *p;

	s = parse_selector_list(buf);
	expect(buf, '{');
	p = parse_declaration_list(buf);
	expect(buf, '}');
	return fz_new_css_rule(buf->ctx, s, p);
}

static void parse_media_list(struct lexbuf *buf)
{
	struct rule *r;

	while (buf->lookahead != '}' && buf->lookahead != EOF)
	{
		r = parse_rule(buf);
		// TODO: free_rule(r);
	}
}

static void parse_at_rule(struct lexbuf *buf)
{
	struct property *p;
	struct value *v;

	expect(buf, CSS_KEYWORD);
	if (accept(buf, '{')) /* @page */
	{
		p = parse_declaration_list(buf);
		// TODO: free_properties(p);
		expect(buf, '}');
	}
	else
	{
		v = parse_value_list(buf);
		// TODO: free_value_list(v);
		if (accept(buf, '{')) /* @media */
		{
			parse_media_list(buf);
			expect(buf, '}');
		}
		else /* @import */
		{
			expect(buf, ';');
		}
	}
}

static struct rule *parse_stylesheet(struct lexbuf *buf, struct rule *chain)
{
	struct rule *rule, **nextp, *tail;

	tail = chain;
	if (tail)
	{
		while (tail->next)
			tail = tail->next;
		nextp = &tail->next;
	}
	else
	{
		nextp = &tail;
	}

	while (buf->lookahead != EOF)
	{
		if (accept(buf, '@'))
		{
			parse_at_rule(buf);
		}
		else
		{
			rule = *nextp = parse_rule(buf);
			nextp = &rule->next;
		}
	}

	return chain ? chain : tail;
}

struct property *fz_parse_css_properties(fz_context *ctx, const char *source)
{
	struct lexbuf buf;
	css_lex_init(ctx, &buf, source);
	next(&buf);
	return parse_declaration_list(&buf);
}

struct rule *fz_parse_css(fz_context *ctx, struct rule *chain, const char *source)
{
	struct lexbuf buf;
	css_lex_init(ctx, &buf, source);
	next(&buf);
	return parse_stylesheet(&buf, chain);
}
