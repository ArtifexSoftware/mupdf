typedef struct fz_pixmap_s fz_pixmap;

struct fz_pixmap_s
{
	fz_colorspace *cs;
	int x, y, w, h;
	int n, a;
	int stride;
	short *samples;
};

fz_error *fz_newpixmap(fz_pixmap **mapp, fz_colorspace *cs, int x, int y, int w, int h, int n, int a);
fz_error *fz_convertpixmap(fz_pixmap **dstp, fz_pixmap *src, fz_colorspace *dstcs);
void fz_debugpixmap(fz_pixmap *map);
void fz_freepixmap(fz_pixmap *map);
void fz_clearpixmap(fz_pixmap *map);

void fz_blendover(fz_pixmap *src, fz_pixmap *dst);
void fz_blendmask(fz_pixmap *dst, fz_pixmap *color, fz_pixmap *shape);

