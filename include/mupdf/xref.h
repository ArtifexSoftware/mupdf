/*
 * xref and object / stream api
 */

typedef struct pdf_rsrc_s pdf_rsrc;		/* parsed resource registry */

typedef struct pdf_xrefentry_s pdf_xrefentry;
typedef struct pdf_xref_s pdf_xref;

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

	pdf_rsrc *rfont;
	pdf_rsrc *rimage;
	pdf_rsrc *rxobject;
	pdf_rsrc *rcolorspace;
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

