typedef struct fz_textel_s fz_textel;

struct fz_textel_s
{
	float x, y;
	int g;
};

struct fz_textnode_s
{
	fz_node super;
	fz_font *font;
	fz_matrix trm;
	int len, cap;
	fz_textel *els;
};

fz_error *fz_newtextnode(fz_textnode **textp, fz_font *face);
fz_error *fz_addtext(fz_textnode *text, int g, float x, float y);
fz_error *fz_endtext(fz_textnode *text);

