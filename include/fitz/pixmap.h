typedef struct fz_pixmap_s fz_pixmap;
typedef struct fz_colorspace_s fz_colorspace;

struct fz_pixmap_s
{
	int x, y, w, h;
	int n, a;
	int stride;
	fz_colorspace *cs;
	short *samples;
};

fz_error *fz_newpixmap(fz_pixmap **mapp, int x, int y, int w, int h, int n, int a);
void fz_debugpixmap(fz_pixmap *map);
void fz_freepixmap(fz_pixmap *map);
void fz_clearpixmap(fz_pixmap *map);

void fz_blendover(fz_pixmap *src, fz_pixmap *dst);
void fz_blendmask(fz_pixmap *dst, fz_pixmap *color, fz_pixmap *shape);

