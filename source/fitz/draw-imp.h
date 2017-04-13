#ifndef MUPDF_DRAW_IMP_H
#define MUPDF_DRAW_IMP_H

/*
 * Scan converter
 */

typedef struct fz_gel_s fz_gel;

fz_gel *fz_new_gel(fz_context *ctx);
void fz_insert_gel(fz_context *ctx, fz_gel *gel, float x0, float y0, float x1, float y1);
void fz_insert_gel_rect(fz_context *ctx, fz_gel *gel, float x0, float y0, float x1, float y1);
void fz_reset_gel(fz_context *ctx, fz_gel *gel, const fz_irect *clip);
fz_irect *fz_bound_gel(fz_context *ctx, const fz_gel *gel, fz_irect *bbox);
void fz_drop_gel(fz_context *ctx, fz_gel *gel);
int fz_is_rect_gel(fz_context *ctx, fz_gel *gel);
fz_rect *fz_gel_scissor(fz_context *ctx, const fz_gel *gel, fz_rect *rect);

void fz_scan_convert(fz_context *ctx, fz_gel *gel, int eofill, const fz_irect *clip, fz_pixmap *pix, unsigned char *colorbv);

void fz_flatten_fill_path(fz_context *ctx, fz_gel *gel, const fz_path *path, const fz_matrix *ctm, float flatness, const fz_irect *irect);
void fz_flatten_stroke_path(fz_context *ctx, fz_gel *gel, const fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, float flatness, float linewidth, const fz_irect *irect);
void fz_flatten_dash_path(fz_context *ctx, fz_gel *gel, const fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, float flatness, float linewidth, const fz_irect *irect);

fz_irect *fz_bound_path_accurate(fz_context *ctx, fz_irect *bbox, const fz_irect *scissor, const fz_path *path, const fz_stroke_state *stroke, const fz_matrix *ctm, float flatness, float linewidth);

/*
 * Plotting functions.
 */

typedef void (fz_solid_color_painter_t)(unsigned char * restrict dp, int n, int w, const unsigned char * restrict color, int da);

typedef void (fz_span_painter_t)(unsigned char * restrict dp, int da, const unsigned char * restrict sp, int sa, int n, int w, int alpha);
typedef void (fz_span_color_painter_t)(unsigned char * restrict dp, const unsigned char * restrict mp, int n, int w, const unsigned char * restrict color, int da);

fz_solid_color_painter_t *fz_get_solid_color_painter(int n, const unsigned char * restrict color, int da);
fz_span_painter_t *fz_get_span_painter(int da, int sa, int n, int alpha);
fz_span_color_painter_t *fz_get_span_color_painter(int n, int da, const unsigned char * restrict color);

void fz_paint_image(fz_pixmap * restrict dst, const fz_irect * restrict scissor, fz_pixmap * restrict shape, const fz_pixmap * restrict img, const fz_matrix * restrict ctm, int alpha, int lerp_allowed, int gridfit_as_tiled);
void fz_paint_image_with_color(fz_pixmap * restrict dst, const fz_irect * restrict scissor, fz_pixmap *restrict shape, const fz_pixmap * restrict img, const fz_matrix * restrict ctm, const unsigned char * restrict colorbv, int lerp_allowed, int gridfit_as_tiled);

void fz_paint_pixmap(fz_pixmap * restrict dst, const fz_pixmap * restrict src, int alpha);
void fz_paint_pixmap_with_mask(fz_pixmap * restrict dst, const fz_pixmap * restrict src, const fz_pixmap * restrict msk);
void fz_paint_pixmap_with_bbox(fz_pixmap * restrict dst, const fz_pixmap * restrict src, int alpha, fz_irect bbox);

void fz_blend_pixmap(fz_pixmap * restrict dst, fz_pixmap * restrict src, int alpha, int blendmode, int isolated, const fz_pixmap * restrict shape);
void fz_blend_pixel(unsigned char dp[3], unsigned char bp[3], unsigned char sp[3], int blendmode);

void fz_paint_glyph(const unsigned char * restrict colorbv, fz_pixmap * restrict dst, unsigned char * restrict dp, const fz_glyph * restrict glyph, int w, int h, int skip_x, int skip_y);

#endif
