typedef struct fz_renderer_s fz_renderer;
typedef struct fz_rastfuncs_s fz_rastfuncs;

#define FZ_BYTE unsigned char
#define FZ_PID \
	FZ_BYTE *src, int w, int h, int nx, int ny, \
	FZ_BYTE *dst0, int dstw, \
	int u0, int v0, int fa, int fb, int fc, int fd
#define FZ_PIM \
	FZ_BYTE *src, int w, int h, int nx, int ny, \
	FZ_BYTE *dst0, int dstw, \
	FZ_BYTE *msk0, int mskw, \
	int u0, int v0, int fa, int fb, int fc, int fd

struct fz_rastfuncs_s
{
	void (*mask_g)(int, FZ_BYTE*, FZ_BYTE*);
	void (*mask_i1)(int, FZ_BYTE*, FZ_BYTE*);
	void (*mask_o1)(int, FZ_BYTE*, FZ_BYTE*);
	void (*mask_i1o1)(int, FZ_BYTE*, FZ_BYTE*, FZ_BYTE*);
	void (*mask_o4w3)(int, FZ_BYTE*, FZ_BYTE*, FZ_BYTE*);
	void (*mask_i1o4w3)(int, FZ_BYTE*, FZ_BYTE*, FZ_BYTE*, FZ_BYTE*);

	void (*img1_g)(FZ_PID);
	void (*img1_i1)(FZ_PID);
	void (*img1_o1)(FZ_PID);
	void (*img1_i1o1)(FZ_PIM);
	void (*img1_o4w3)(FZ_PID, FZ_BYTE*);
	void (*img1_i1o4w3)(FZ_PIM, FZ_BYTE*);

	void (*img4_g)(FZ_PID);
	void (*img4_o4)(FZ_PID);
	void (*img4_i1o4)(FZ_PIM);
};

#undef FZ_PIM
#undef FZ_PID
#undef FZ_BYTE

struct fz_renderer_s
{
	int maskonly;
	fz_colorspace *model;
	fz_glyphcache *cache;
	fz_gel *gel;
	fz_ael *ael;

	fz_rastfuncs rast;

	fz_irect clip;
	fz_pixmap *dest;
	fz_pixmap *over;
	fz_pixmap *mask;
	unsigned char rgb[3];
	int flag;
};

void fz_defaultrastfuncs(fz_rastfuncs *);

fz_error *fz_newrenderer(fz_renderer **gcp, fz_colorspace *pcm, int maskonly, int gcmem);
void fz_droprenderer(fz_renderer *gc);

fz_error *fz_rendertree(fz_pixmap **out, fz_renderer *gc, fz_tree *tree, fz_matrix ctm, fz_irect bbox, int white);

