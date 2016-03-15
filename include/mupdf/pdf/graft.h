#ifndef MUPDF_PDF_GRAFT_H
#define MUPDF_PDF_GRAFT_H

typedef struct pdf_graft_map_s pdf_graft_map;

struct pdf_graft_map_s
{
	int refs;
	int len;
	int *dst_from_src;
};

pdf_graft_map *pdf_new_graft_map(fz_context *ctx, pdf_document *src);
void pdf_drop_graft_map(fz_context *ctx, pdf_graft_map *map);
pdf_obj *pdf_graft_object(fz_context *ctx, pdf_document *dst, pdf_document *src, pdf_obj *obj, pdf_graft_map *map);

#endif
