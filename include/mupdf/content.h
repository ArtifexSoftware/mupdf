/*
 * content stream parsing
 */

typedef struct pdf_gstate_s pdf_gstate;
typedef struct pdf_csi_s pdf_csi;

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

/* build.c */
void pdf_initgstate(pdf_gstate *gs);
fz_error *pdf_buildstrokepath(pdf_gstate *gs, fz_pathnode *path);
fz_error *pdf_buildfillpath(pdf_gstate *gs, fz_pathnode *path, int evenodd);
fz_error *pdf_addfillshape(pdf_gstate *gs, fz_node *shape);
fz_error *pdf_addstrokeshape(pdf_gstate *gs, fz_node *shape);
fz_error *pdf_addclipmask(pdf_gstate *gs, fz_node *shape);
fz_error *pdf_addtransform(pdf_gstate *gs, fz_node *transform);
fz_error *pdf_showpath(pdf_csi*, int close, int fill, int stroke, int evenodd);
fz_error *pdf_showtext(pdf_csi*, fz_obj *text);
fz_error *pdf_flushtext(pdf_csi*);

/* interpret.c */
fz_error *pdf_newcsi(pdf_csi **csip);
fz_error *pdf_runcsi(pdf_csi *, pdf_xref *xref, fz_obj *rdb, fz_file *);
void pdf_freecsi(pdf_csi *csi);

