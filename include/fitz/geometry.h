typedef struct fz_matrix_s fz_matrix;
typedef struct fz_point_s fz_point;
typedef struct fz_rect_s fz_rect;
typedef struct fz_ipoint_s fz_ipoint;
typedef struct fz_irect_s fz_irect;

/*
	/ a b 0 \
	| c d 0 |
	\ e f 1 /
*/
struct fz_matrix_s
{
	float a, b, c, d, e, f;
};

struct fz_point_s
{
	float x, y;
};

struct fz_rect_s
{
	fz_point min;
	fz_point max;
};

struct fz_ipoint_s
{
	int x, y;
};

struct fz_irect_s
{
	fz_ipoint min;
	fz_ipoint max;
};

fz_rect fz_infiniterect(void);

fz_matrix fz_concat(fz_matrix one, fz_matrix two);
fz_matrix fz_identity(void);
fz_matrix fz_scale(float sx, float sy);
fz_matrix fz_rotate(float theta);
fz_matrix fz_translate(float tx, float ty);
fz_matrix fz_invertmatrix(fz_matrix m);
int fz_isrectilinear(fz_matrix m);

fz_rect fz_intersectrects(fz_rect a, fz_rect b);
fz_rect fz_mergerects(fz_rect a, fz_rect b);

fz_irect fz_intersectirects(fz_irect a, fz_irect b);
fz_irect fz_mergeirects(fz_irect a, fz_irect b);

fz_point fz_transformpoint(fz_matrix m, fz_point p);

