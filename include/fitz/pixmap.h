typedef struct fz_pixmap_s fz_pixmap;
typedef struct fz_colorspace_s fz_colorspace;

struct fz_pixmap_s
{
	int refcount;
	int x, y, w, h;
	int n, a;
	int stride;
	fz_colorspace *cs;
	short *samples;
};

fz_error *fz_newpixmap(fz_pixmap **mapp, int x, int y, int w, int h, int n, int a);
fz_pixmap *fz_keeppixmap(fz_pixmap *map);
void fz_droppixmap(fz_pixmap *map);
void fz_clearpixmap(fz_pixmap *map);

void fz_blendover(fz_pixmap *dst, fz_pixmap *fg, fz_pixmap *bg);
void fz_blendmask(fz_pixmap *dst, fz_pixmap *color, fz_pixmap *shape);

