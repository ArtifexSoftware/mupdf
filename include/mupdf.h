#ifdef _MUPDF_H_
#error "mupdf.h must only be included once"
#endif
#define _MUPDF_H_

#ifndef _FITZ_H_
#error "fitz.h must be included before mupdf.h"
#endif

/*
 * tokenizer and low-level object parser
 */

enum
{
	PDF_TERROR, PDF_TEOF,
	PDF_TOARRAY, PDF_TCARRAY,
	PDF_TODICT, PDF_TCDICT,
	PDF_TNAME, PDF_TINT, PDF_TREAL, PDF_TSTRING, PDF_TKEYWORD,
	PDF_TR, PDF_TTRUE, PDF_TFALSE, PDF_TNULL,
	PDF_TOBJ, PDF_TENDOBJ,
	PDF_TSTREAM, PDF_TENDSTREAM,
	PDF_TXREF, PDF_TTRAILER, PDF_TSTARTXREF,
	PDF_NTOKENS
};

/* lex.c */
int pdf_lex(fz_file *f, unsigned char *buf, int n, int *len);

/* parse.c */
fz_error *pdf_parsearray(fz_obj **op, fz_file *f, unsigned char *buf, int cap);
fz_error *pdf_parsedict(fz_obj **op, fz_file *f, unsigned char *buf, int cap);
fz_error *pdf_parsestmobj(fz_obj **op, fz_file *f, unsigned char *buf, int cap);
fz_error *pdf_parseindobj(fz_obj **op, fz_file *f, unsigned char *buf, int cap, int *oid, int *gid, int *stmofs);

/*
 * xref and syntax object api
 */

typedef struct pdf_xref_s pdf_xref;
typedef struct pdf_xrefentry_s pdf_xrefentry;
typedef struct pdf_crypt_s pdf_crypt;

struct pdf_xref_s
{
	fz_file *file;
	fz_file *stream;
	float version;
	int startxref;
	fz_obj *trailer;		/* TODO split this into root/info/encrypt/id */
	pdf_crypt *crypt;

	int len;
	int cap;
	pdf_xrefentry *table;
};

struct pdf_xrefentry_s
{
	unsigned int ofs;		/* file offset / objstm object number */
	unsigned short gen;		/* generation / objstm index */
	char type;				/* 0=unset (f)ree i(n)use (o)bjstm (d)elete (a)dd */
	char mark;				/* for garbage collection etc */
	fz_buffer *stmbuf;		/* in-memory stream */
	unsigned int stmofs;	/* on-disk stream */
	fz_obj *obj;			/* stored/cached object */
};

struct pdf_crypt_s
{
	unsigned char o[32];
	unsigned char u[32];
	unsigned int p;
	int r;
	int n;

	fz_obj *encrypt;
	fz_obj *id;

	unsigned char key[16];
	int keylen;
};

/* crypt.c */
fz_error *pdf_newdecrypt(pdf_crypt **cp, fz_obj *enc, fz_obj *id);
fz_error *pdf_newencrypt(pdf_crypt **cp, char *userpw, char *ownerpw, int p, int n, fz_obj *id);
fz_error *pdf_setpassword(pdf_crypt *crypt, char *pw);
fz_error *pdf_cryptstm(fz_filter **fp, pdf_crypt *crypt, int oid, int gid);
void pdf_cryptobj(pdf_crypt *crypt, fz_obj *obj, int oid, int gid);
void pdf_freecrypt(pdf_crypt *crypt);

/* --- */

fz_error *pdf_repairpdf(pdf_xref **, char *filename);
fz_error *pdf_openpdf(pdf_xref **, char *filename);
fz_error *pdf_newpdf(pdf_xref **);

fz_error *pdf_updatepdf(pdf_xref *, char *filename);
fz_error *pdf_savepdf(pdf_xref *, char *filename, pdf_crypt *encrypt);

void pdf_debugpdf(pdf_xref *);
void pdf_closepdf(pdf_xref *);

fz_error *pdf_allocobject(pdf_xref *, int *oidp, int *genp);
fz_error *pdf_deleteobject(pdf_xref *, int oid, int gen);
fz_error *pdf_updateobject(pdf_xref *, int oid, int gen, fz_obj *obj);
fz_error *pdf_updatestream(pdf_xref *, int oid, int gen, fz_buffer *stm);

fz_error *pdf_cacheobject(pdf_xref *, int oid, int gen);
fz_error *pdf_loadobject(fz_obj **objp, pdf_xref *, int oid, int gen);
fz_error *pdf_loadindirect(fz_obj **objp, pdf_xref *, fz_obj *ref);
fz_error *pdf_resolve(fz_obj **reforobj, pdf_xref *);

int pdf_isstream(pdf_xref *xref, int oid, int gen);
fz_error *pdf_loadrawstream(fz_buffer **bufp, pdf_xref *xref, int oid, int gen);
fz_error *pdf_loadstream(fz_buffer **bufp, pdf_xref *xref, int oid, int gen);
fz_error *pdf_openrawstream(pdf_xref *, int oid, int gen);
fz_error *pdf_openstream(pdf_xref *, int oid, int gen);
void pdf_closestream(pdf_xref *);

fz_error *pdf_garbagecollect(pdf_xref *xref);
fz_error *pdf_transplant(pdf_xref *dst, pdf_xref *src, fz_obj **newp, fz_obj *old);

/* private */
fz_error *pdf_loadobjstm(pdf_xref *xref, int oid, int gen, unsigned char *buf, int cap);
fz_error *pdf_decryptpdf(pdf_xref *xref);

/* --- */

/*
 * high-level semantic objects for resources and pages
 */

extern fz_colorspace *pdf_devicegray;
extern fz_colorspace *pdf_devicergb;
extern fz_colorspace *pdf_devicecmyk;

typedef struct pdf_nametree_s pdf_nametree;
typedef struct pdf_pagetree_s pdf_pagetree;
typedef struct pdf_font_s pdf_font;
typedef struct pdf_resources_s pdf_resources;
typedef struct pdf_page_s pdf_page;
typedef struct pdf_gstate_s pdf_gstate;
typedef struct pdf_csi_s pdf_csi;

struct pdf_nametree_s
{
	int len;
	int cap;
	struct fz_keyval_s *items;
};

struct pdf_pagetree_s
{
	int count;
	int cursor;
	fz_obj **pref;
	fz_obj **pobj;
};

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

struct pdf_resources_s
{
	fz_obj *extgstate;
	fz_obj *colorspace;
	fz_obj *font;
	fz_obj *ximage;
	fz_obj *xform;
};

struct pdf_page_s
{
	fz_rect mediabox;
	int rotate;
	pdf_resources *rdb;
	fz_tree *tree;
};

struct pdf_gstate_s
{
	/* path stroking */
	float linewidth;
	int linecap;
	int linejoin;
	float miterlimit;
	float dashphase;
	int dashlen;
	float dashlist[32];

	/* materials */
	fz_colorspace *strokecs;
	float stroke[32];
	fz_colorspace *fillcs;
	float fill[32];

	/* text state */
	float charspace;
	float wordspace;
	float scale;
	float leading;
	pdf_font *font;
	float size;
	int render;
	float rise;

	/* tree construction state */
	fz_node *head;
};

struct pdf_csi_s
{
	pdf_gstate gstate[32];
	int gtop;
	fz_obj *stack[32];
	int top;
	int xbalance;

	/* path object state */
	fz_pathnode *path;
	fz_pathnode *clip;

	/* text object state */
	fz_textnode *text;
	fz_matrix tlm;
	fz_matrix tm;

	fz_tree *tree;
};

/* nametree.c */
fz_error *pdf_loadnametree(pdf_nametree **ntp, pdf_xref *xref, char *key);
void pdf_freenametree(pdf_nametree *nt);
void pdf_debugnametree(pdf_nametree *nt);
fz_obj *pdf_lookupname(pdf_nametree *nt, fz_obj *name);
fz_obj *pdf_lookupnames(pdf_nametree *nt, char *name);

/* pagetree.c */
fz_error *pdf_loadpagetree(pdf_pagetree **pp, pdf_xref *xref);
int pdf_getpagecount(pdf_pagetree *pages);
fz_obj *pdf_getpageobject(pdf_pagetree *pages, int p);
void pdf_debugpagetree(pdf_pagetree *pages);
void pdf_freepagetree(pdf_pagetree *pages);

/* page.c */
fz_error *pdf_loadpage(pdf_page **pagep, pdf_xref *xref, fz_obj *ref);
void pdf_freepage(pdf_page *page);

/* cmap.c */
fz_error *pdf_parsecmap(fz_cmap **cmapp, fz_file *file);
fz_error *pdf_loadembeddedcmap(fz_cmap **cmapp, pdf_xref *xref, fz_obj *stmref);
fz_error *pdf_loadsystemcmap(fz_cmap **cmapp, char *name);
fz_error *pdf_makeidentitycmap(fz_cmap **cmapp, int wmode, int bytes);

/* fontfile.c */
fz_error *pdf_loadbuiltinfont(pdf_font *font, char *basefont);
fz_error *pdf_loadsystemfont(pdf_font *font, char *basefont, char *collection);
fz_error *pdf_loadsubstitutefont(pdf_font *font, int fdflags, char *collection);
fz_error *pdf_loadfontdescriptor(pdf_font *font, pdf_xref *xref, fz_obj *desc, char *collection);

/* font.c */
fz_error *pdf_loadfont(pdf_font **fontp, pdf_xref *xref, fz_obj *font);
void pdf_freefont(pdf_font *font);

/* colorspace.c */
fz_error *pdf_loadcolorspace(fz_colorspace **csp, pdf_xref *xref, fz_obj *obj);

/* resources.c */
fz_error *pdf_loadresources(pdf_resources **rdbp, pdf_xref *xref, fz_obj *resdict);
void pdf_freeresources(pdf_resources *rdb);

/* interpret.c */
fz_error *pdf_newcsi(pdf_csi **csip);
fz_error *pdf_runcsi(pdf_csi *, pdf_resources *, fz_file *);
void pdf_freecsi(pdf_csi *csi);

