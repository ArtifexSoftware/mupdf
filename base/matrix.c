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
	return (fz_matrix) { 1, 0, 0, 1, 0, 0 };
}

fz_matrix
fz_scale(float sx, float sy)
{
	return (fz_matrix) { sx, 0, 0, sy, 0, 0 };
}

fz_matrix
fz_rotate(float theta)
{
	float s = sin(theta * M_PI / 180.0);
	float c = cos(theta * M_PI / 180.0);
	return (fz_matrix) { c, s, -s, c, 0 ,0 };
}

fz_matrix
fz_translate(float tx, float ty)
{
	return (fz_matrix) { 1, 0, 0, 1, tx, ty };
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

fz_point
fz_transformpoint(fz_matrix m, fz_point p)
{
	float x = p.x * m.a + p.y * m.c + m.e;
	float y = p.x * m.b + p.y * m.d + m.f;
	return (fz_point) { x, y };
}

