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
void pdf_freefunction(pdf_function *func);

/*
 * ColorSpace
 */

extern fz_colorspace *pdf_devicegray;
extern fz_colorspace *pdf_devicergb;
extern fz_colorspace *pdf_devicecmyk;

fz_error *pdf_loadcolorspace(fz_colorspace **csp, pdf_xref *xref, fz_obj *obj);

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

fz_error *pdf_loadxobject(pdf_xobject **xobjp, pdf_xref *xref, fz_obj *obj);
void pdf_freexobject(pdf_xobject *xobj);

/*
 * Image
 */

typedef struct pdf_image_s pdf_image;

struct pdf_image_s
{
	fz_image super;
	fz_image *mask;			/* explicit mask with subimage */
	float decode[32];
	int bpc;
	int stride;
	fz_buffer *samples;
};

fz_error *pdf_loadimage(pdf_image **imgp, pdf_xref *xref, fz_obj *obj, fz_obj *stm);

/*
 * CMap and Font
 */

typedef struct pdf_font_s pdf_font;

struct pdf_font_s
{
	fz_font super;

	void *ftface;
	int substitute;

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

	/* Raw data for freetype */
	char *filename;
	fz_buffer *fontdata;
};

struct pdf_type3_s
{
	fz_rect bbox;
	fz_matrix matrix;
	int widths[256];
	fz_tree *charprocs[256];
	int tounicode[256];
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

/* font.c */
fz_error *pdf_loadfontdescriptor(pdf_font *font, pdf_xref *xref, fz_obj *desc, char *collection);
fz_error *pdf_loadfont(pdf_font **fontp, pdf_xref *xref, fz_obj *font);
void pdf_freefont(pdf_font *font);

