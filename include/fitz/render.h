typedef struct fz_renderer_s fz_renderer;

fz_error *fz_newrenderer(fz_renderer **gcp, fz_colorspace *pcm);
void fz_freerenderer(fz_renderer *gc);

fz_error *fz_renderover(fz_renderer *gc, fz_overnode *over, fz_matrix ctm);
fz_error *fz_rendermask(fz_renderer *gc, fz_masknode *mask, fz_matrix ctm);
fz_error *fz_rendertransform(fz_renderer *gc, fz_transformnode *xform, fz_matrix ctm);
fz_error *fz_rendertext(fz_renderer *gc, fz_textnode *text, fz_matrix ctm);
fz_error *fz_rendernode(fz_renderer *gc, fz_node *node, fz_matrix ctm);
fz_error *fz_rendertree(fz_pixmap **out, fz_renderer *gc, fz_tree *tree, fz_matrix ctm, fz_rect bbox);

