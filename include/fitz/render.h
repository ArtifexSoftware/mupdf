typedef struct fz_renderer_s fz_renderer;

fz_error *fz_newrenderer(fz_renderer **gcp);
void fz_freerenderer(fz_renderer *gc);

fz_error *fz_renderover(fz_renderer *gc, fz_over *over, fz_matrix ctm, fz_pixmap *out);
fz_error *fz_rendermask(fz_renderer *gc, fz_mask *mask, fz_matrix ctm, fz_pixmap *out);
fz_error *fz_rendertransform(fz_renderer *gc, fz_transform *xform, fz_matrix ctm, fz_pixmap *out);
fz_error *fz_rendertext(fz_renderer *gc, fz_text *text, fz_matrix ctm, fz_pixmap *out);
fz_error *fz_rendernode(fz_renderer *gc, fz_node *node, fz_matrix ctm, fz_pixmap *out);

