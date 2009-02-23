typedef struct fz_font_s fz_font;
typedef struct fz_glyph_s fz_glyph;
typedef struct fz_glyphcache_s fz_glyphcache;

char *ft_errorstring(int err);

struct fz_font_s
{
	int refs;
	char name[32];

	void *ftface; /* has an FT_Face if used */
	int ftsubstitute; /* ... substitute metrics */

	struct fz_tree_s **t3procs; /* has 256 entries if used */
	fz_matrix t3matrix;

	fz_irect bbox;

};

struct fz_glyph_s
{
	int x, y, w, h;
	unsigned char *samples;
};

fz_error * fz_newfreetypefont(fz_font **fontp, char *name, int substitute);
fz_error * fz_loadfreetypefontfile(fz_font *font, char *path, int index);
fz_error * fz_loadfreetypefontbuffer(fz_font *font, unsigned char *data, int len, int index);
fz_error * fz_newtype3font(fz_font **fontp, char *name, fz_matrix matrix, void **procs);

fz_error * fz_newfontfrombuffer(fz_font **fontp, unsigned char *data, int len, int index);
fz_error * fz_newfontfromfile(fz_font **fontp, char *path, int index);

fz_font * fz_keepfont(fz_font *font);
void fz_dropfont(fz_font *font);

void fz_debugfont(fz_font *font);
void fz_setfontbbox(fz_font *font, int xmin, int ymin, int xmax, int ymax);

fz_error * fz_renderftglyph(fz_glyph *glyph, fz_font *font, int cid, fz_matrix trm);
fz_error * fz_rendert3glyph(fz_glyph *glyph, fz_font *font, int cid, fz_matrix trm);
fz_error * fz_newglyphcache(fz_glyphcache **arenap, int slots, int size);
fz_error * fz_renderglyph(fz_glyphcache*, fz_glyph*, fz_font*, int, fz_matrix);
void fz_debugglyphcache(fz_glyphcache *);
void fz_dropglyphcache(fz_glyphcache *);

