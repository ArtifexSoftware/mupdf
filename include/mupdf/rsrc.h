/*
 * Resource registry and dictionaries
 */

struct pdf_rsrc_s
{
	int oid;
	int gen;
	void *val;
	pdf_rsrc *next;
};

fz_error *pdf_loadresources(fz_obj **rdb, pdf_xref *xref, fz_obj *orig);
void *pdf_findresource(pdf_rsrc *list, fz_obj *ref);

/*
 * Functions
 */

typedef struct pdf_function_s pdf_function;

fz_error *pdf_loadfunction(pdf_function **func, pdf_xref *xref, fz_obj *obj);
fz_error *pdf_evalfunction(pdf_function *func, float *in, int inlen, float *out, int outlen);
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

fz_error *pdf_loadcolorspace(fz_colorspace **csp, pdf_xref *xref, fz_obj *obj);

/*
 * Pattern
 */

typedef struct pdf_pattern_s pdf_pattern;

struct pdf_pattern_s
{
	int ismask;
	float xstep;
	float ystep;
	fz_matrix matrix;
	fz_rect bbox;
	fz_tree *tree;
};

fz_error *pdf_loadpattern(pdf_pattern **patp, pdf_xref *xref, fz_obj *obj, fz_obj *ref);
void pdf_droppattern(pdf_pattern *pat);

/*
 * XObject
 */

typedef struct pdf_xobject_s pdf_xobject;

struct pdf_xobject_s
{
	fz_matrix matrix;
	fz_rect bbox;
	fz_obj *resources;
	fz_buffer *contents;
};

fz_error *pdf_loadxobject(pdf_xobject **xobjp, pdf_xref *xref, fz_obj *obj, fz_obj *ref);
void pdf_dropxobject(pdf_xobject *xobj);

/*
 * Image
 */

typedef struct pdf_image_s pdf_image;

struct pdf_image_s
{
	fz_image super;
	fz_image *mask;			/* explicit mask with subimage */
	pdf_indexed *indexed;
	float decode[32];
	int bpc;
	int stride;
	fz_buffer *samples;
};

fz_error *pdf_loadinlineimage(pdf_image **imgp, pdf_xref *xref, fz_obj *dict, fz_file *file);
fz_error *pdf_loadimage(pdf_image **imgp, pdf_xref *xref, fz_obj *obj, fz_obj *stm);

/*
 * CMap and Font
 */

struct pdf_aglpair { char *name; unsigned short code; };
extern struct pdf_aglpair pdf_adobeglyphlist[];
extern int pdf_adobeglyphlen;

void pdf_loadencoding(char **estrings, char *encoding);
int pdf_lookupagl(char *name);

extern char *pdf_macroman[256];
extern char *pdf_macexpert[256];
extern char *pdf_winansi[256];
extern char *pdf_standard[256];
extern char *pdf_expert[256];
extern char *pdf_symbol[256];
extern char *pdf_zapfdingbats[256];

typedef struct pdf_font_s pdf_font;

struct pdf_font_s
{
	fz_font super;

	/* FontDescriptor */
	int flags;
	float italicangle;
	float ascent;
	float descent;
	float capheight;
	float xheight;
	float missingwidth;

	/* Encoding (CMap) */
	fz_cmap *encoding;
	int ncidtogid;
	unsigned short *cidtogid;

	/* ToUnicode */
	fz_cmap *tounicode;
	int ncidtoucs;
	unsigned short *cidtoucs;

	/* Freetype */
	int substitute;
	void *ftface;
	char *filename;
	fz_buffer *fontdata;

	/* Type3 data */
	fz_rect bbox;
	fz_matrix matrix;
	fz_tree *charprocs[256];
};

/* cmap.c */
fz_error *pdf_parsecmap(fz_cmap **cmapp, fz_file *file);
fz_error *pdf_loadembeddedcmap(fz_cmap **cmapp, pdf_xref *xref, fz_obj *stmref);
fz_error *pdf_loadsystemcmap(fz_cmap **cmapp, char *name);
fz_error *pdf_makeidentitycmap(fz_cmap **cmapp, int wmode, int bytes);

/* fontfile.c */
fz_error *pdf_loadbuiltinfont(pdf_font *font, char *basefont);
fz_error *pdf_loadembeddedfont(pdf_font *font, pdf_xref *xref, fz_obj *stmref);
fz_error *pdf_loadsystemfont(pdf_font *font, char *basefont, char *collection);
fz_error *pdf_loadsubstitutefont(pdf_font *font, int fdflags, char *collection);

/* type3.c */
fz_error *pdf_loadtype3font(pdf_font **fontp, pdf_xref *xref, fz_obj *font);

/* font.c */
fz_error *pdf_loadfontdescriptor(pdf_font *font, pdf_xref *xref, fz_obj *desc, char *collection);
fz_error *pdf_loadfont(pdf_font **fontp, pdf_xref *xref, fz_obj *font);
void pdf_dropfont(pdf_font *font);

