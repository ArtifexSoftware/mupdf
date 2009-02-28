/*
 * Resource store
 */

typedef struct pdf_store_s pdf_store;

typedef enum pdf_itemkind_e
{
	PDF_KCOLORSPACE,
	PDF_KFUNCTION,
	PDF_KXOBJECT,
	PDF_KIMAGE,
	PDF_KPATTERN,
	PDF_KSHADE,
	PDF_KCMAP,
	PDF_KFONT
} pdf_itemkind;

fz_error *pdf_newstore(pdf_store **storep);
void pdf_emptystore(pdf_store *store);
void pdf_dropstore(pdf_store *store);

fz_error *pdf_storeitem(pdf_store *store, pdf_itemkind tag, fz_obj *key, void *val);
void *pdf_finditem(pdf_store *store, pdf_itemkind tag, fz_obj *key);
fz_error *pdf_removeitem(pdf_store *store, pdf_itemkind tag, fz_obj *key);

fz_error *pdf_loadresources(fz_obj **rdb, pdf_xref *xref, fz_obj *orig);

/*
 * Functions
 */

typedef struct pdf_function_s pdf_function;

fz_error *pdf_loadfunction(pdf_function **func, pdf_xref *xref, fz_obj *ref);
fz_error *pdf_evalfunction(pdf_function *func, float *in, int inlen, float *out, int outlen);
pdf_function *pdf_keepfunction(pdf_function *func);
void pdf_dropfunction(pdf_function *func);

/*
 * ColorSpace
 */

typedef struct pdf_indexed_s pdf_indexed;

struct pdf_indexed_s
{
	fz_colorspace super;	/* hmmm... */
	fz_colorspace *base;
	int high;
	unsigned char *lookup;
};

extern fz_colorspace *pdf_devicegray;
extern fz_colorspace *pdf_devicergb;
extern fz_colorspace *pdf_devicecmyk;
extern fz_colorspace *pdf_devicelab;
extern fz_colorspace *pdf_devicepattern;

void pdf_convcolor(fz_colorspace *ss, float *sv, fz_colorspace *ds, float *dv);
void pdf_convpixmap(fz_colorspace *ss, fz_pixmap *sp, fz_colorspace *ds, fz_pixmap *dp);

fz_error *pdf_loadcolorspace(fz_colorspace **csp, pdf_xref *xref, fz_obj *obj);

/*
 * Pattern
 */

typedef struct pdf_pattern_s pdf_pattern;

struct pdf_pattern_s
{
	int refs;
	int ismask;
	float xstep;
	float ystep;
	fz_matrix matrix;
	fz_rect bbox;
	fz_tree *tree;
};

fz_error *pdf_loadpattern(pdf_pattern **patp, pdf_xref *xref, fz_obj *obj, fz_obj *ref);
pdf_pattern *pdf_keeppattern(pdf_pattern *pat);
void pdf_droppattern(pdf_pattern *pat);

/*
 * Shading
 */

void pdf_setmeshvalue(float *mesh, int i, float x, float y, float t);
fz_error *pdf_loadshadefunction(fz_shade *shade, pdf_xref *xref, fz_obj *dict, float t0, float t1);
fz_error *pdf_loadtype1shade(fz_shade *, pdf_xref *, fz_obj *dict, fz_obj *ref);
fz_error *pdf_loadtype2shade(fz_shade *, pdf_xref *, fz_obj *dict, fz_obj *ref);
fz_error *pdf_loadtype3shade(fz_shade *, pdf_xref *, fz_obj *dict, fz_obj *ref);
fz_error *pdf_loadtype4shade(fz_shade *, pdf_xref *, fz_obj *dict, fz_obj *ref);
fz_error *pdf_loadtype5shade(fz_shade *, pdf_xref *, fz_obj *dict, fz_obj *ref);
fz_error *pdf_loadtype6shade(fz_shade *, pdf_xref *, fz_obj *dict, fz_obj *ref);
fz_error *pdf_loadtype7shade(fz_shade *, pdf_xref *, fz_obj *dict, fz_obj *ref);
fz_error *pdf_loadshade(fz_shade **shadep, pdf_xref *xref, fz_obj *obj, fz_obj *ref);

/*
 * XObject
 */

typedef struct pdf_xobject_s pdf_xobject;

struct pdf_xobject_s
{
	int refs;
	fz_matrix matrix;
	fz_rect bbox;
	int isolated;
	int knockout;
	fz_obj *resources;
	fz_buffer *contents;
};

fz_error *pdf_loadxobject(pdf_xobject **xobjp, pdf_xref *xref, fz_obj *obj, fz_obj *ref);
pdf_xobject *pdf_keepxobject(pdf_xobject *xobj);
void pdf_dropxobject(pdf_xobject *xobj);

/*
 * Image
 */

typedef struct pdf_image_s pdf_image;

struct pdf_image_s
{
	fz_image super;
	fz_image *mask;			/* explicit mask with subimage */
	int usecolorkey;		/* explicit color-keyed masking */
	int colorkey[FZ_MAXCOLORS * 2];
	pdf_indexed *indexed;
	float decode[32];
	int bpc;
	int stride;
	fz_buffer *samples;
};

fz_error *pdf_loadinlineimage(pdf_image **imgp, pdf_xref *xref, fz_obj *rdb, fz_obj *dict, fz_stream *file);
fz_error *pdf_loadimage(pdf_image **imgp, pdf_xref *xref, fz_obj *obj, fz_obj *ref);
fz_error *pdf_loadtile(fz_image *image, fz_pixmap *tile);

/*
 * CMap
 */

typedef struct pdf_cmap_s pdf_cmap;
typedef struct pdf_range_s pdf_range;

enum { PDF_CMAP_SINGLE, PDF_CMAP_RANGE, PDF_CMAP_TABLE, PDF_CMAP_MULTI };

struct pdf_range_s
{
	int low;
	int high;
	int flag;	/* what kind of lookup is this (single, range, table, multi) */
	int offset;	/* either range-delta or table-index */
};

struct pdf_cmap_s
{
	int refs;
	char cmapname[32];

	char usecmapname[32];
	pdf_cmap *usecmap;

	int wmode;

	int ncspace;
	struct {
		int n;
		unsigned lo;
		unsigned hi;
	} cspace[40];

	int rlen, rcap;
	pdf_range *ranges;

	int tlen, tcap;
	int *table;
};

extern pdf_cmap *pdf_cmaptable[]; /* list of builtin system cmaps */

fz_error *pdf_newcmap(pdf_cmap **cmapp);
pdf_cmap *pdf_keepcmap(pdf_cmap *cmap);
void pdf_dropcmap(pdf_cmap *cmap);

void pdf_debugcmap(pdf_cmap *cmap);
int pdf_getwmode(pdf_cmap *cmap);
pdf_cmap *pdf_getusecmap(pdf_cmap *cmap);
void pdf_setwmode(pdf_cmap *cmap, int wmode);
void pdf_setusecmap(pdf_cmap *cmap, pdf_cmap *usecmap);

fz_error *pdf_addcodespace(pdf_cmap *cmap, unsigned lo, unsigned hi, int n);
fz_error *pdf_maprangetotable(pdf_cmap *cmap, int low, int *map, int len);
fz_error *pdf_maprangetorange(pdf_cmap *cmap, int srclo, int srchi, int dstlo);
fz_error *pdf_maponetomany(pdf_cmap *cmap, int one, int *many, int len);
fz_error *pdf_sortcmap(pdf_cmap *cmap);

int pdf_lookupcmap(pdf_cmap *cmap, int cpt);
unsigned char *pdf_decodecmap(pdf_cmap *cmap, unsigned char *s, int *cpt);

fz_error *pdf_parsecmap(pdf_cmap **cmapp, fz_stream *file);
fz_error *pdf_loadembeddedcmap(pdf_cmap **cmapp, pdf_xref *xref, fz_obj *ref);
fz_error *pdf_loadsystemcmap(pdf_cmap **cmapp, char *name);
fz_error *pdf_newidentitycmap(pdf_cmap **cmapp, int wmode, int bytes);

/*
 * Font
 */

void pdf_loadencoding(char **estrings, char *encoding);
int pdf_lookupagl(char *name, int *ucsbuf, int ucscap);

extern const unsigned short pdf_docencoding[256];
extern const char * const pdf_macroman[256];
extern const char * const pdf_macexpert[256];
extern const char * const pdf_winansi[256];
extern const char * const pdf_standard[256];
extern const char * const pdf_expert[256];
extern const char * const pdf_symbol[256];
extern const char * const pdf_zapfdingbats[256];

typedef struct pdf_hmtx_s pdf_hmtx;
typedef struct pdf_vmtx_s pdf_vmtx;
typedef struct pdf_fontdesc_s pdf_fontdesc;

struct pdf_hmtx_s
{
	unsigned short lo;
	unsigned short hi;
	int w;	/* type3 fonts can be big! */
};

struct pdf_vmtx_s
{
	unsigned short lo;
	unsigned short hi;
	short x;
	short y;
	short w;
};

struct pdf_fontdesc_s
{
	int refs;

	fz_font *font;

	/* FontDescriptor */
	int flags;
	float italicangle;
	float ascent;
	float descent;
	float capheight;
	float xheight;
	float missingwidth;

	/* Encoding (CMap) */
	pdf_cmap *encoding;
	pdf_cmap *tottfcmap;
	int ncidtogid;
	unsigned short *cidtogid;

	/* ToUnicode */
	pdf_cmap *tounicode;
	int ncidtoucs;
	unsigned short *cidtoucs;

	/* Metrics (given in the PDF file) */
	int wmode;

	int nhmtx, hmtxcap;
	pdf_hmtx dhmtx;
	pdf_hmtx *hmtx;

	int nvmtx, vmtxcap;
	pdf_vmtx dvmtx;
	pdf_vmtx *vmtx;
};

/* fontmtx.c */
void pdf_setfontwmode(pdf_fontdesc *font, int wmode);
void pdf_setdefaulthmtx(pdf_fontdesc *font, int w);
void pdf_setdefaultvmtx(pdf_fontdesc *font, int y, int w);
fz_error *pdf_addhmtx(pdf_fontdesc *font, int lo, int hi, int w);
fz_error *pdf_addvmtx(pdf_fontdesc *font, int lo, int hi, int x, int y, int w);
fz_error *pdf_endhmtx(pdf_fontdesc *font);
fz_error *pdf_endvmtx(pdf_fontdesc *font);
pdf_hmtx pdf_gethmtx(pdf_fontdesc *font, int cid);
pdf_vmtx pdf_getvmtx(pdf_fontdesc *font, int cid);

/* unicode.c */
fz_error *pdf_loadtounicode(pdf_fontdesc *font, pdf_xref *xref, char **strings, char *collection, fz_obj *cmapstm);

/* fontfile.c */
fz_error *pdf_loadbuiltinfont(pdf_fontdesc *font, char *basefont);
fz_error *pdf_loadembeddedfont(pdf_fontdesc *font, pdf_xref *xref, fz_obj *stmref);
fz_error *pdf_loadsystemfont(pdf_fontdesc *font, char *basefont, char *collection);
fz_error *pdf_loadsubstitutefont(pdf_fontdesc *font, int fdflags, char *collection);

/* type3.c */
fz_error *pdf_loadtype3font(pdf_fontdesc **fontp, pdf_xref *xref, fz_obj *obj, fz_obj *ref);

/* font.c */
int pdf_fontcidtogid(pdf_fontdesc *fontdesc, int cid);
fz_error *pdf_loadfontdescriptor(pdf_fontdesc *font, pdf_xref *xref, fz_obj *desc, char *collection);
fz_error *pdf_loadfont(pdf_fontdesc **fontp, pdf_xref *xref, fz_obj *obj, fz_obj *ref);
pdf_fontdesc * pdf_newfontdesc(void);
pdf_fontdesc * pdf_keepfont(pdf_fontdesc *fontdesc);
void pdf_dropfont(pdf_fontdesc *font);
void pdf_debugfont(pdf_fontdesc *fontdesc);

