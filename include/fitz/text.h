typedef struct fz_textbuilder_s fz_textbuilder;
typedef struct fz_textel_s fz_textel;

struct fz_textel_s
{
	float x, y;
	int g;
};

struct fz_text_s
{
	fz_node super;
	fz_font *font;
	fz_matrix trm;
	int len, cap;
	fz_textel *els;
};

fz_error *fz_newtext(fz_text **textp, fz_font *face);
fz_error *fz_addtext(fz_text *text, int g, float x, float y);
fz_error *fz_endtext(fz_text *text);
void fz_freetext(fz_text *text);

