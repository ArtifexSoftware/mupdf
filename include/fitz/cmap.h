typedef struct fz_cmap_s fz_cmap;

fz_error *fz_newcmap(fz_cmap **cmapp);
void fz_debugcmap(fz_cmap *cmap);
void fz_freecmap(fz_cmap *cmap);

char *fz_getcmapname(fz_cmap *cmap);
void fz_setcmapname(fz_cmap *cmap, char *name);
char *fz_getusecmapname(fz_cmap *cmap);
void fz_setusecmapname(fz_cmap *cmap, char *usecmap);
void fz_setusecmap(fz_cmap *cmap, fz_cmap *usecmap);
fz_cmap *fz_getusecmap(fz_cmap *cmap);
void fz_setwmode(fz_cmap *cmap, int wmode);
int fz_getwmode(fz_cmap *cmap);

fz_error *fz_addcodespacerange(fz_cmap *cmap, unsigned lo, unsigned hi, int n);

fz_error *fz_setcidlookup(fz_cmap *cmap, int map[256]);

fz_error *fz_addcidrange(fz_cmap *cmap, int srclo, int srchi, int dstlo);
fz_error *fz_endcidrange(fz_cmap *cmap);

int fz_lookupcid(fz_cmap *cmap, int cpt);
char *fz_decodecpt(fz_cmap *cmap, unsigned char *s, int *cpt);

