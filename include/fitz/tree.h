typedef struct fz_tree_s fz_tree;
typedef struct fz_node_s fz_node;

typedef enum fz_nodekind_e fz_nodekind;
typedef enum fz_blendkind_e fz_blendkind;

typedef struct fz_transform_s fz_transform;
typedef struct fz_over_s fz_over;
typedef struct fz_mask_s fz_mask;
typedef struct fz_blend_s fz_blend;
typedef struct fz_path_s fz_path;
typedef struct fz_text_s fz_text;
typedef struct fz_solid_s fz_solid;
typedef struct fz_image_s fz_image;
typedef struct fz_shade_s fz_shade;
typedef struct fz_form_s fz_form;
typedef struct fz_meta_s fz_meta;
typedef struct fz_halftone_s fz_halftone;

enum fz_nodekind_e
{
	FZ_NTRANSFORM,
	FZ_NOVER,
	FZ_NMASK,
	FZ_NBLEND,
	FZ_NPATH,
	FZ_NTEXT,
	FZ_NSOLID,
	FZ_NIMAGE,
	FZ_NSHADE,
	FZ_NFORM,
	FZ_NMETA,
	FZ_NHALFTONE
};

enum fz_blendkind_e
{
	/* PDF 1.4 -- standard separable */
	FZ_BNORMAL,
	FZ_BMULTIPLY,
	FZ_BSCREEN,
	FZ_BOVERLAY,
	FZ_BDARKEN,
	FZ_BLIGHTEN,
	FZ_BCOLORDODGE,
	FZ_BCOLORBURN,
	FZ_BHARDLIGHT,
	FZ_BSOFTLIGHT,
	FZ_BDIFFERENCE,
	FZ_BEXCLUSION,

	/* PDF 1.4 -- standard non-separable */
	FZ_BHUE,
	FZ_BSATURATION,
	FZ_BCOLOR,
	FZ_BLUMINOSITY,

	FZ_BOVERPRINT,
};

struct fz_tree_s
{
	fz_node *root;
	fz_node *head;
};

struct fz_node_s
{
	fz_nodekind kind;
	fz_node *parent;
	fz_node *next;
};

struct fz_meta_s
{
	fz_node super;
	fz_node *child;
	fz_obj *info;
};

struct fz_over_s
{
	fz_node super;
	fz_node *child;
};

struct fz_mask_s
{
	fz_node super;
	fz_node *child;
};

struct fz_blend_s
{
	fz_node super;
	fz_node *child;
	fz_blendkind mode;
	int isolated;
	int knockout;
};

struct fz_transform_s
{
	fz_node super;
	fz_node *child;
	fz_matrix m;
};

struct fz_form_s
{
	fz_node super;
	fz_tree *tree;
};

struct fz_solid_s
{
	fz_node super;
	float r, g, b;
};

/* tree operations */
fz_error *fz_newtree(fz_tree **treep);
void fz_freetree(fz_tree *tree);
fz_rect fz_boundtree(fz_tree *tree, fz_matrix ctm);

void fz_debugtree(fz_tree *tree);
void fz_insertnode(fz_node *node, fz_node *child);

/* common to all nodes */
void fz_initnode(fz_node *node, fz_nodekind kind);
fz_rect fz_boundnode(fz_node *node, fz_matrix ctm);
void fz_freenode(fz_node *node);

/* branch nodes */
fz_error *fz_newmeta(fz_node **nodep, fz_obj *info);
fz_error *fz_newover(fz_node **nodep);
fz_error *fz_newmask(fz_node **nodep);
fz_error *fz_newblend(fz_node **nodep, fz_blendkind b, int k, int i);
fz_error *fz_newtransform(fz_node **nodep, fz_matrix m);

int fz_ismeta(fz_node *node);
int fz_isover(fz_node *node);
int fz_ismask(fz_node *node);
int fz_isblend(fz_node *node);
int fz_istransform(fz_node *node);

/* leaf nodes */
fz_error *fz_newform(fz_node **nodep, fz_tree *subtree);
fz_error *fz_newsolid(fz_node **nodep, float r, float g, float b);

int fz_isform(fz_node *node);
int fz_issolid(fz_node *node);
int fz_ispath(fz_node *node);
int fz_istext(fz_node *node);
int fz_isimage(fz_node *node);

