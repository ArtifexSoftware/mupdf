typedef enum fz_pathkind_e fz_pathkind;
typedef enum fz_pathelkind_e fz_pathelkind;
typedef struct fz_stroke_s fz_stroke;
typedef struct fz_dash_s fz_dash;
typedef union fz_pathel_s fz_pathel;

enum fz_pathkind_e { FZ_STROKE, FZ_FILL, FZ_EOFILL };
enum fz_pathelkind_e { FZ_MOVETO, FZ_LINETO, FZ_CURVETO, FZ_CLOSEPATH };

struct fz_stroke_s
{
	int linecap;
	int linejoin;
	float linewidth;
	float miterlimit;
};

struct fz_dash_s
{
	int len;
	float phase;
	float array[];
};

union fz_pathel_s
{
	fz_pathelkind k;
	float v;
};

struct fz_path_s
{
	fz_node super;
	fz_pathkind paint;
	fz_stroke *stroke;
	fz_dash *dash;
	int len, cap;
	fz_pathel *els;
};

fz_error *fz_newpath(fz_path **pathp);
fz_error *fz_clonepath(fz_path **pathp, fz_path *oldpath);
fz_error *fz_moveto(fz_path*, float x, float y);
fz_error *fz_lineto(fz_path*, float x, float y);
fz_error *fz_curveto(fz_path*, float, float, float, float, float, float);
fz_error *fz_curvetov(fz_path*, float, float, float, float);
fz_error *fz_curvetoy(fz_path*, float, float, float, float);
fz_error *fz_closepath(fz_path*);
fz_error *fz_endpath(fz_path*, fz_pathkind paint, fz_stroke *stroke, fz_dash *dash);
void fz_freepath(fz_path *path);

fz_rect fz_boundpath(fz_path *node, fz_matrix ctm);
void fz_debugpath(fz_path *node);

fz_error *fz_newdash(fz_dash **dashp, float phase, int len, float *array);
void fz_freedash(fz_dash *dash);

