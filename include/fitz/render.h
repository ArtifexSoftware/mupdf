typedef struct fz_renderer_s fz_renderer;
typedef struct fz_rastfuncs_s fz_rastfuncs;

#define FZ_BYTE unsigned char

/* TODO: use 'restrict' on pointers - they never alias, do they? */
#define FZ_PSRC \
	unsigned char *src, int srcw, int srch
#define FZ_PDST \
	unsigned char *dst0, int dstw
#define FZ_PCTM \
	int u0, int v0, int fa, int fb, int fc, int fd, int w0, int h

struct fz_rastfuncs_s
{
	void (*duff_NoN)(FZ_BYTE*,int,int,FZ_BYTE*,int,int,int);
	void (*duff_NiMcN)(FZ_BYTE*,int,int,FZ_BYTE*,int,int,FZ_BYTE*,int,int,int);
	void (*duff_NiMoN)(FZ_BYTE*,int,int,FZ_BYTE*,int,int,FZ_BYTE*,int,int,int);
	void (*duff_1o1)(FZ_BYTE*,int,FZ_BYTE*,int,int,int);
	void (*duff_4o4)(FZ_BYTE*,int,FZ_BYTE*,int,int,int);
	void (*duff_1i1c1)(FZ_BYTE*,int,FZ_BYTE*,int,FZ_BYTE*,int,int,int);
	void (*duff_4i1c4)(FZ_BYTE*,int,FZ_BYTE*,int,FZ_BYTE*,int,int,int);
	void (*duff_1i1o1)(FZ_BYTE*,int,FZ_BYTE*,int,FZ_BYTE*,int,int,int);
	void (*duff_4i1o4)(FZ_BYTE*,int,FZ_BYTE*,int,FZ_BYTE*,int,int,int);

	void (*msk_1c1)(FZ_BYTE*,FZ_BYTE*,int);
	void (*msk_1o1)(FZ_BYTE*,FZ_BYTE*,int);
	void (*msk_w3i1o4)(FZ_BYTE*,FZ_BYTE*,FZ_BYTE*,int);

	void (*glf_1c1)(FZ_BYTE*,int,FZ_BYTE*,int,int,int);
	void (*glf_1o1)(FZ_BYTE*,int,FZ_BYTE*,int,int,int);
	void (*glf_w3i1o4)(FZ_BYTE*,FZ_BYTE*,int,FZ_BYTE*,int,int,int);

	void (*img_NcN)(FZ_PSRC, int sn, FZ_PDST, FZ_PCTM);
	void (*img_1c1)(FZ_PSRC, FZ_PDST, FZ_PCTM);
	void (*img_4c4)(FZ_PSRC, FZ_PDST, FZ_PCTM);
	void (*img_1o1)(FZ_PSRC, FZ_PDST, FZ_PCTM);
	void (*img_4o4)(FZ_PSRC, FZ_PDST, FZ_PCTM);
	void (*img_w3i1o4)(FZ_BYTE*,FZ_PSRC,FZ_PDST,FZ_PCTM);
};

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
	unsigned char rgb[3];
	int flag;
};

extern void fz_loadrastfuncs(fz_rastfuncs *);
extern void fz_accelrastfuncs(fz_rastfuncs *);

fz_error *fz_newrenderer(fz_renderer **gcp, fz_colorspace *pcm, int maskonly, int gcmem);
void fz_droprenderer(fz_renderer *gc);

fz_error *fz_rendertree(fz_pixmap **out, fz_renderer *gc, fz_tree *tree, fz_matrix ctm, fz_irect bbox, int white);

