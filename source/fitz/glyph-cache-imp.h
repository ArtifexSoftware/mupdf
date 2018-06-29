#ifndef MUPDF_FITZ_GLYPH_CACHE_IMP_H
#define MUPDF_FITZ_GLYPH_CACHE_IMP_H

fz_path *fz_outline_glyph(fz_context *ctx, fz_font *font, int gid, fz_matrix ctm);
fz_path *fz_outline_ft_glyph(fz_context *ctx, fz_font *font, int gid, fz_matrix trm);
fz_glyph *fz_render_ft_glyph(fz_context *ctx, fz_font *font, int cid, fz_matrix trm, int aa);
fz_pixmap *fz_render_ft_glyph_pixmap(fz_context *ctx, fz_font *font, int cid, fz_matrix trm, int aa);
fz_glyph *fz_render_t3_glyph(fz_context *ctx, fz_font *font, int cid, fz_matrix trm, fz_colorspace *model, const fz_irect *scissor, int aa);
fz_pixmap *fz_render_t3_glyph_pixmap(fz_context *ctx, fz_font *font, int cid, fz_matrix trm, fz_colorspace *model, const fz_irect *scissor, int aa);
fz_glyph *fz_render_ft_stroked_glyph(fz_context *ctx, fz_font *font, int gid, fz_matrix trm, fz_matrix ctm, const fz_stroke_state *state, int aa);
fz_pixmap *fz_render_ft_stroked_glyph_pixmap(fz_context *ctx, fz_font *font, int gid, fz_matrix trm, fz_matrix ctm, const fz_stroke_state *state, int aa);
fz_glyph *fz_render_glyph(fz_context *ctx, fz_font*, int gid, fz_matrix *, fz_colorspace *model, const fz_irect *scissor, int alpha, int aa);
fz_glyph *fz_render_stroked_glyph(fz_context *ctx, fz_font*, int, fz_matrix *, fz_matrix , const fz_stroke_state *stroke, const fz_irect *scissor, int aa);
fz_pixmap *fz_render_stroked_glyph_pixmap(fz_context *ctx, fz_font*, int, fz_matrix *, fz_matrix , const fz_stroke_state *stroke, const fz_irect *scissor, int aa);

#endif
