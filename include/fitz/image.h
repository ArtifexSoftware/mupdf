typedef struct fz_image_s fz_image;

struct fz_image_s
{
	fz_error* (*loadtile)(fz_image*,fz_pixmap*);
	void (*free)(fz_image*);
	fz_colorspace *cs;
	int w, h, n, a;
};

