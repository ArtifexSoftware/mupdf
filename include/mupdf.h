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
fz_error *pdf_parseindobj(fz_obj **op, fz_file *f, unsigned char *buf, int cap, int *oid, int *gid, int *stmofsj);

/*
 * xref and syntax object api
 */

typedef struct pdf_xref_s pdf_xref;
typedef struct pdf_xrefentry_s pdf_xrefentry;
typedef struct pdf_crypt_s pdf_crypt;

struct pdf_xref_s
{
	float version;
	pdf_crypt *crypt;
	fz_file *file;
	int size;
	int capacity;
	pdf_xrefentry *table;
	fz_obj *trailer;
	int startxref;
	fz_hashtable *store;
};

struct pdf_xrefentry_s
{
	unsigned int ofs;	/* file offset / objstm object number */
	unsigned short gen;	/* generation / objstm index */
	char type;			/* 0=unset (f)ree i(n)use (o)bjstm (d)elete (a)dd */
	char mark;			/* for garbage collection etc */
};

struct pdf_crypt_s
{
	unsigned char o[32];
	unsigned char u[32];
	unsigned int p;
	int r;
	int n;

	fz_obj *id;

	unsigned char key[16];
	int keylen;
};

/* stream.c */
fz_error *pdf_buildfilter(fz_filter**, pdf_xref*, fz_obj *stm, int oid, int gid);
fz_error *pdf_openstream0(pdf_xref*, fz_obj *stmobj, int oid, int gid, int ofs);
fz_error *pdf_openstream(pdf_xref*, fz_obj *stmref);
void pdf_closestream(pdf_xref*);
fz_error *pdf_readstream(unsigned char **bufp, int *lenp, pdf_xref*, fz_obj *stmref);

/* crypt.c */
fz_error *pdf_newdecrypt(pdf_crypt **cp, fz_obj *enc, fz_obj *id);
fz_error *pdf_newencrypt(pdf_crypt **cp, fz_obj **edict, char *userpw, char *ownerpw, int p, int n, fz_obj *id);
fz_error *pdf_setpassword(pdf_crypt *crypt, char *pw);
fz_error *pdf_cryptstm(fz_filter **fp, pdf_crypt *crypt, int oid, int gid);
void pdf_cryptobj(pdf_crypt *crypt, fz_obj *obj, int oid, int gid);
void pdf_freecrypt(pdf_crypt *crypt);

/* repair.c */
fz_error *pdf_repairxref(pdf_xref*, char *filename);

/* open.c */
fz_error *pdf_openxref(pdf_xref*, char *filename);
fz_error *pdf_readobjstm(pdf_xref *xref, int oid, int gid, unsigned char *buf, int cap);

/* xref.c */
fz_error *pdf_newxref(pdf_xref **xrefp);
fz_error *pdf_decryptxref(pdf_xref *xref);
void pdf_closexref(pdf_xref*);
void pdf_debugxref(pdf_xref*);

fz_obj *pdf_findstoredobject(fz_hashtable *store, int oid, int gid);
fz_buffer *pdf_findstoredstream(fz_hashtable *store, int oid, int gid);
fz_error *pdf_deletestoredobject(fz_hashtable *store, int oid, int gid);
fz_error *pdf_deletestoredstream(fz_hashtable *store, int oid, int gid);
fz_error *pdf_storeobject(fz_hashtable *store, int oid, int gid, fz_obj *obj);
fz_error *pdf_storestream(fz_hashtable *store, int oid, int gid, fz_buffer *buf);

fz_error *pdf_createobject(pdf_xref *xref, int *oidp, int *gidp);
fz_error *pdf_deleteobject(pdf_xref *xref, int oid, int gid);
fz_error *pdf_saveobject(pdf_xref *xref, int oid, int gid, fz_obj *obj);
fz_error *pdf_loadobject0(fz_obj **, pdf_xref*, int oid, int gid, int *stmofs);
fz_error *pdf_loadobject(fz_obj **, pdf_xref*, fz_obj *ref, int *stmofs);
fz_error *pdf_resolve(fz_obj **, pdf_xref*);

/* save.c */
fz_error *pdf_saveincrementalpdf(pdf_xref *xref, char *path);
fz_error *pdf_savepdf(pdf_xref *xref, char *path);

/*
 * high-level semantic objects for resources and pages
 */

typedef struct pdf_pagetree_s pdf_pagetree;
typedef struct pdf_font_s pdf_font;
typedef struct pdf_resources_s pdf_resources;
typedef struct pdf_gstate_s pdf_gstate;
typedef struct pdf_csi_s pdf_csi;

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

	fz_cmap *encoding;
	int cidtogidlen;
	int *cidtogidmap;

	char *filename;
	char *fontdata;
	int fontlen;
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

	/* colors and colorspaces */
	struct { float r, g, b; } stroke, fill;

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

/* pagetree.c */
fz_error *pdf_loadpagetree(pdf_pagetree **pp, pdf_xref *xref);
void pdf_debugpagetree(pdf_pagetree *pages);
void pdf_freepagetree(pdf_pagetree *pages);

/* cmap.c */
fz_error *pdf_parsecmap(fz_cmap **cmapp, fz_file *file);
fz_error *pdf_loadembeddedcmap(fz_cmap **cmapp, pdf_xref *xref, fz_obj *stmref);
fz_error *pdf_loadsystemcmap(fz_cmap **cmapp, char *name);
fz_error *pdf_makeidentitycmap(fz_cmap **cmapp, int wmode);

/* fontfile.c */
fz_error *pdf_loadbuiltinfont(void **fontp, char *pattern);
fz_error *pdf_loadsystemfont(void **fontp, char *basefont, char *collection);
fz_error *pdf_loadembeddedfont(void **fontp, pdf_xref *xref, fz_obj *stmref);
fz_error *pdf_loadfontdescriptor(void **fontp, pdf_xref *xref, fz_obj *desc, char *collection);

/* font.c */
fz_error *pdf_loadfont(pdf_font **fontp, pdf_xref *xref, fz_obj *font);
void pdf_freefont(pdf_font *font);

/* resources.c */
fz_error *pdf_loadresources(pdf_resources **rdbp, pdf_xref *xref, fz_obj *resdict);
void pdf_freeresources(pdf_resources *rdb);

/* interpret.c */
fz_error *pdf_newcsi(pdf_csi **csip);
fz_error *pdf_runcsi(pdf_csi *, pdf_resources *, fz_file *);
void pdf_freecsi(pdf_csi *csi);

