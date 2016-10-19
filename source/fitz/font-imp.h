#ifndef MUPDF_FITZ_FONT_IMP_H
#define MUPDF_FITZ_FONT_IMP_H

struct fz_font_s
{
	int refs;
	char name[32];
	fz_buffer *buffer;

	fz_font_flags_t flags;

	void *ft_face; /* has an FT_Face if used */
	fz_shaper_data_t shaper_data;

	fz_matrix t3matrix;
	void *t3resources;
	fz_buffer **t3procs; /* has 256 entries if used */
	struct fz_display_list_s **t3lists; /* has 256 entries if used */
	float *t3widths; /* has 256 entries if used */
	unsigned short *t3flags; /* has 256 entries if used */
	void *t3doc; /* a pdf_document for the callback */
	void (*t3run)(fz_context *ctx, void *doc, void *resources, fz_buffer *contents, struct fz_device_s *dev, const fz_matrix *ctm, void *gstate, int nestedDepth);
	void (*t3freeres)(fz_context *ctx, void *doc, void *resources);

	fz_rect bbox;	/* font bbox is used only for t3 fonts */

	int glyph_count;

	/* per glyph bounding box cache */
	fz_rect *bbox_table;

	/* substitute metrics */
	int width_count;
	short width_default; /* in 1000 units */
	short *width_table; /* in 1000 units */

	/* cached glyph metrics */
	float *advance_cache;

	/* cached encoding lookup */
	uint16_t *encoding_cache[256];
};

#endif
