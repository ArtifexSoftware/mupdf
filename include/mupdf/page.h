/*
 * Page tree, pages and related objects
 */

typedef struct pdf_outlinetree_s pdf_outlinetree;
typedef struct pdf_outline_s pdf_outline;
typedef struct pdf_nametree_s pdf_nametree;
typedef struct pdf_pagetree_s pdf_pagetree;
typedef struct pdf_page_s pdf_page;

struct pdf_outlinetree_s
{
	pdf_outline *first;
	int count;
};

struct pdf_outline_s
{
	char *title;
	pdf_outline *next;
	pdf_outline *first;
	int count;
	fz_obj *dest;
	fz_obj *a;
	fz_obj *se;
	float c[3];
	int f;
};

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

struct pdf_page_s
{
	fz_rect mediabox;
	int rotate;
	fz_obj *resources;
	fz_tree *tree;
};

/* outline.c */
fz_error *pdf_loadoutlinetree(pdf_outlinetree **oo, pdf_xref *xref);
void pdf_debugoutlinetree(pdf_outlinetree *outlinetree);
void pdf_freeoutlinetree(pdf_outlinetree *outlinetree);

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

