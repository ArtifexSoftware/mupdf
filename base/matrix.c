#include <fitz.h>

fz_matrix
fz_concat(fz_matrix one, fz_matrix two)
{
	fz_matrix dst;
	dst.a = one.a * two.a + one.b * two.c;
	dst.b = one.a * two.b + one.b * two.d;
	dst.c = one.c * two.a + one.d * two.c;
	dst.d = one.c * two.b + one.d * two.d;
	dst.e = one.e * two.a + one.f * two.c + two.e;
	dst.f = one.e * two.b + one.f * two.d + two.f;
	return dst;
}

fz_matrix
fz_identity(void)
{
	fz_matrix m;
	m.a =  1;  m.b =  0;
	m.c =  0;  m.d =  1;
	m.e =  0;  m.f =  0;
	return m;
}

fz_matrix
fz_scale(float sx, float sy)
{
	fz_matrix m;
	m.a = sx;  m.b =  0;
	m.c =  0;  m.d = sy;
	m.e =  0;  m.f =  0;
	return m;
}

fz_matrix
fz_rotate(float theta)
{
	fz_matrix m;
	float s = sin(theta * M_PI / 180.0);
	float c = cos(theta * M_PI / 180.0);
	m.a =  c;  m.b = s;
	m.c = -s;  m.d = c;
	m.e =  0;  m.f = 0;
	return m;
}

fz_matrix
fz_translate(float tx, float ty)
{
	fz_matrix m;
	m.a =  1;  m.b =  0;
	m.c =  0;  m.d =  1;
	m.e = tx;  m.f = ty;
	return m;
}

fz_matrix
fz_invertmatrix(fz_matrix src)
{
	fz_matrix dst;
	float rdet = 1.0 / (src.a * src.d - src.b * src.c);
	dst.a = src.d * rdet;
	dst.b = -src.b * rdet;
	dst.c = -src.c * rdet;
	dst.d = src.a * rdet;
	dst.e = -src.e * dst.a - src.f * dst.c;
	dst.f = -src.e * dst.b - src.f * dst.d;
	return dst;
}

int
fz_isrectilinear(fz_matrix m)
{
	return	(fabs(m.b) < FLT_EPSILON && fabs(m.c) < FLT_EPSILON) ||
			(fabs(m.a) < FLT_EPSILON && fabs(m.d) < FLT_EPSILON);
}

float
fz_matrixexpansion(fz_matrix m)
{
	return sqrt(fabs(m.a * m.d - m.b * m.c));
}

fz_point
fz_transformpoint(fz_matrix m, fz_point p)
{
	fz_point t;
	t.x = p.x * m.a + p.y * m.c + m.e;
	t.y = p.x * m.b + p.y * m.d + m.f;
	return t;
}

fz_rect
fz_transformaabb(fz_matrix m, fz_rect r)
{
	fz_point s, t, u, v;
	s.x = r.min.x; s.y = r.min.y;
	t.x = r.min.x; t.y = r.max.y;
	u.x = r.max.x; u.y = r.max.y;
	v.x = r.max.x; v.y = r.min.y;
	s = fz_transformpoint(m, s);
	t = fz_transformpoint(m, t);
	u = fz_transformpoint(m, u);
	v = fz_transformpoint(m, v);
	r.min.x = MIN4(s.x, t.x, u.x, v.x);
	r.min.y = MIN4(s.y, t.y, u.y, v.y);
	r.max.x = MAX4(s.x, t.x, u.x, v.x);
	r.max.y = MAX4(s.y, t.y, u.y, v.y);
	return r;
}

