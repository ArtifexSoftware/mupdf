#ifndef MUPDF_PDF_RESOURCE_H
#define MUPDF_PDF_RESOURCE_H

/*
 * PDF interface to store
 */
void pdf_store_item(fz_context *ctx, pdf_obj *key, void *val, size_t itemsize);
void *pdf_find_item(fz_context *ctx, fz_store_drop_fn *drop, pdf_obj *key);
void pdf_remove_item(fz_context *ctx, fz_store_drop_fn *drop, pdf_obj *key);
void pdf_empty_store(fz_context *ctx, pdf_document *doc);

/*
 * Structures used for managing resource locations and avoiding multiple
 * occurrences when resources are added to the document. The search for existing
 * resources will be performed when we are first trying to add an item. Object
 * refs are stored in a fz_hash_table structure using a hash of the md5 sum of
 * the data, enabling rapid lookup.
 */

pdf_obj *pdf_find_font_resource(fz_context *ctx, pdf_document *doc, fz_buffer *item, unsigned char md5[16]);
pdf_obj *pdf_insert_font_resource(fz_context *ctx, pdf_document *doc, unsigned char md5[16], pdf_obj *obj);
pdf_obj *pdf_find_image_resource(fz_context *ctx, pdf_document *doc, fz_image *item, unsigned char md5[16]);
pdf_obj *pdf_insert_image_resource(fz_context *ctx, pdf_document *doc, unsigned char md5[16], pdf_obj *obj);
void pdf_drop_resource_tables(fz_context *ctx, pdf_document *doc);

/*
 * Functions, Colorspaces, Shadings and Images
 */

typedef struct pdf_function_s pdf_function;

void pdf_eval_function(fz_context *ctx, pdf_function *func, const float *in, int inlen, float *out, int outlen);
pdf_function *pdf_keep_function(fz_context *ctx, pdf_function *func);
void pdf_drop_function(fz_context *ctx, pdf_function *func);
size_t pdf_function_size(fz_context *ctx, pdf_function *func);
pdf_function *pdf_load_function(fz_context *ctx, pdf_obj *ref, int in, int out);

fz_colorspace *pdf_document_output_intent(fz_context *ctx, pdf_document *doc);
fz_colorspace *pdf_load_colorspace(fz_context *ctx, pdf_obj *obj);
int pdf_is_tint_colorspace(fz_context *ctx, fz_colorspace *cs);

fz_shade *pdf_load_shading(fz_context *ctx, pdf_document *doc, pdf_obj *obj);

fz_image *pdf_load_inline_image(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, pdf_obj *dict, fz_stream *file);
int pdf_is_jpx_image(fz_context *ctx, pdf_obj *dict);

fz_image *pdf_load_image(fz_context *ctx, pdf_document *doc, pdf_obj *obj);

pdf_obj *pdf_add_image(fz_context *ctx, pdf_document *doc, fz_image *image, int mask);

/*
 * Pattern
 */

typedef struct pdf_pattern_s pdf_pattern;

struct pdf_pattern_s
{
	fz_storable storable;
	int ismask;
	float xstep;
	float ystep;
	fz_matrix matrix;
	fz_rect bbox;
	pdf_document *document;
	pdf_obj *resources;
	pdf_obj *contents;
	int id; /* unique ID for caching rendered tiles */
};

pdf_pattern *pdf_load_pattern(fz_context *ctx, pdf_document *doc, pdf_obj *obj);
pdf_pattern *pdf_keep_pattern(fz_context *ctx, pdf_pattern *pat);
void pdf_drop_pattern(fz_context *ctx, pdf_pattern *pat);

/*
 * XObject
 */

typedef struct pdf_xobject_s pdf_xobject;

struct pdf_xobject_s
{
	fz_storable storable;
	pdf_obj *obj;
	int iteration;
};

pdf_xobject *pdf_load_xobject(fz_context *ctx, pdf_document *doc, pdf_obj *obj);
pdf_obj *pdf_new_xobject(fz_context *ctx, pdf_document *doc, const fz_rect *bbox, const fz_matrix *mat);
pdf_xobject *pdf_keep_xobject(fz_context *ctx, pdf_xobject *xobj);
void pdf_drop_xobject(fz_context *ctx, pdf_xobject *xobj);
void pdf_update_xobject_contents(fz_context *ctx, pdf_document *doc, pdf_xobject *form, fz_buffer *buffer);

void pdf_update_appearance(fz_context *ctx, pdf_document *doc, pdf_annot *annot);

pdf_obj *pdf_xobject_resources(fz_context *ctx, pdf_xobject *xobj);
fz_rect *pdf_xobject_bbox(fz_context *ctx, pdf_xobject *xobj, fz_rect *bbox);
fz_matrix *pdf_xobject_matrix(fz_context *ctx, pdf_xobject *xobj, fz_matrix *matrix);
int pdf_xobject_isolated(fz_context *ctx, pdf_xobject *xobj);
int pdf_xobject_knockout(fz_context *ctx, pdf_xobject *xobj);
int pdf_xobject_transparency(fz_context *ctx, pdf_xobject *xobj);
fz_colorspace *pdf_xobject_colorspace(fz_context *ctx, pdf_xobject *xobj);

#endif
