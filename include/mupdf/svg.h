#ifndef MUPDF_SVG_H
#define MUPDF_SVG_H

fz_display_list *fz_new_display_list_from_svg(fz_context *ctx, fz_buffer *buf, float *w, float *h);
fz_image *fz_new_image_from_svg(fz_context *ctx, fz_buffer *buf);

#endif
