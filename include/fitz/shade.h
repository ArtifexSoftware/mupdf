typedef struct fz_shade_s fz_shade;

struct fz_shade_s
{
	int refs;
	fz_colorspace *cs;
	/* ... */
};

fz_shade *fz_keepshade(fz_shade *shade);
void fz_dropshade(fz_shade *shade);

fz_rect fz_boundshade(fz_shade *shade, fz_matrix ctm);
fz_error *fz_rendershade(fz_shade *shade, fz_matrix ctm, fz_colorspace *dsts, fz_pixmap *dstp, int over);

