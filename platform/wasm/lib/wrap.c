// Copyright (C) 2004-2022 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 1305 Grant Avenue - Suite 200, Novato,
// CA 94945, U.S.A., +1(415)492-9861, for further information.

#include "emscripten.h"
#include "mupdf/fitz.h"
#include "mupdf/pdf.h"
#include <string.h>

static fz_context *ctx;

static fz_rect out_rect;
static fz_irect out_irect;
static fz_matrix out_matrix;

// TODO - instrument fz_throw to include call stack
void wasm_rethrow(fz_context *ctx)
{
	if (fz_caught(ctx) == FZ_ERROR_TRYLATER)
		EM_ASM({ throw new libmupdf.MupdfTryLaterError("operation in progress"); });
	else
		EM_ASM({ throw new libmupdf.MupdfError(UTF8ToString($0)); }, fz_caught_message(ctx));
}

EMSCRIPTEN_KEEPALIVE
void wasm_init_context(void)
{
	ctx = fz_new_context(NULL, NULL, 100<<20);
	if (!ctx)
		EM_ASM({ throw new Error("Cannot create MuPDF context!"); });
	fz_register_document_handlers(ctx);
}

EMSCRIPTEN_KEEPALIVE
fz_matrix *wasm_scale(float scale_x, float scale_y) {
	out_matrix = fz_scale(scale_x, scale_y);
	return &out_matrix;
}

EMSCRIPTEN_KEEPALIVE
fz_rect *wasm_transform_rect(
	float r_0, float r_1, float r_2, float r_3,
	float tr_0, float tr_1, float tr_2, float tr_3, float tr_4, float tr_5
) {
	fz_rect rect = fz_make_rect(r_0, r_1, r_2, r_3);
	fz_matrix transform = fz_make_matrix(tr_0, tr_1, tr_2, tr_3, tr_4, tr_5);
	out_rect = fz_transform_rect(rect, transform);
	return &out_rect;
}

EMSCRIPTEN_KEEPALIVE
fz_document *wasm_open_document_with_buffer(unsigned char *data, int size, char *magic)
{
	fz_document *document = NULL;
	fz_buffer *buf = NULL;
	fz_stream *stm = NULL;

	fz_var(buf);
	fz_var(stm);

	/* NOTE: We take ownership of input data! */

	fz_try(ctx)
	{
		buf = fz_new_buffer_from_data(ctx, data, size);
		stm = fz_open_buffer(ctx, buf);
		document = fz_open_document_with_stream(ctx, magic, stm);
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, stm);
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, data);
		wasm_rethrow(ctx);
	}
	return document;
}

EMSCRIPTEN_KEEPALIVE
void wasm_drop_document(fz_document *doc)
{
	fz_drop_document(ctx, doc);
}

EMSCRIPTEN_KEEPALIVE
char *wasm_document_title(fz_document *doc)
{
	static char buf[100], *result = NULL;
	fz_try(ctx)
	{
		if (fz_lookup_metadata(ctx, doc, FZ_META_INFO_TITLE, buf, sizeof buf) > 0)
			result = buf;
	}
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return result;
}

EMSCRIPTEN_KEEPALIVE
int wasm_count_pages(fz_document *doc)
{
	int n = 1;
	fz_try(ctx)
		n = fz_count_pages(ctx, doc);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return n;
}

EMSCRIPTEN_KEEPALIVE
fz_page *wasm_load_page(fz_document *doc, int number)
{
	fz_page *page;
	fz_try(ctx)
		page = fz_load_page(ctx, doc, number);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return page;
}

EMSCRIPTEN_KEEPALIVE
fz_outline *wasm_load_outline(fz_document *doc)
{
	fz_outline *outline = NULL;
	fz_try(ctx)
		outline = fz_load_outline(ctx, doc);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return outline;
}

EMSCRIPTEN_KEEPALIVE
void wasm_drop_page(fz_page *page)
{
	fz_drop_page(ctx, page);
}

EMSCRIPTEN_KEEPALIVE
fz_rect *wasm_bound_page(fz_page *page)
{
	fz_try(ctx)
		out_rect = fz_bound_page(ctx, page);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return &out_rect;
}

EMSCRIPTEN_KEEPALIVE
fz_stext_page *wasm_new_stext_page_from_page(fz_page *page) {
	fz_stext_page *stext_page;
	// FIXME
	const fz_stext_options options = { FZ_STEXT_PRESERVE_SPANS };

	fz_try(ctx)
		stext_page = fz_new_stext_page_from_page(ctx, page, &options);
	fz_catch(ctx)
		wasm_rethrow(ctx);

	return stext_page;
}

EMSCRIPTEN_KEEPALIVE
void wasm_drop_stext_page(fz_stext_page *page) {
	fz_try(ctx)
		fz_drop_stext_page(ctx, page);
	fz_catch(ctx)
		wasm_rethrow(ctx);
}

EMSCRIPTEN_KEEPALIVE void wasm_print_stext_page_as_json(fz_output *out, fz_stext_page *page, float scale) {
	fz_try(ctx)
		fz_print_stext_page_as_json(ctx, out, page, scale);
	fz_catch(ctx)
		wasm_rethrow(ctx);
}

EMSCRIPTEN_KEEPALIVE
fz_link *wasm_load_links(fz_page *page)
{
	fz_link *links = NULL;
	fz_try(ctx)
		links = fz_load_links(ctx, page);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return links;
}

EMSCRIPTEN_KEEPALIVE
pdf_page *wasm_pdf_page_from_fz_page(fz_page *page) {
	return pdf_page_from_fz_page(ctx, page);
}

EMSCRIPTEN_KEEPALIVE
fz_link* wasm_next_link(fz_link *link) {
	return link->next;
}

EMSCRIPTEN_KEEPALIVE
fz_rect *wasm_link_rect(fz_link *link) {
	return &link->rect;
}

EMSCRIPTEN_KEEPALIVE
int wasm_is_external_link(fz_link *link) {
	return fz_is_external_link(ctx, link->uri);
}

EMSCRIPTEN_KEEPALIVE
char* wasm_link_uri(fz_link *link) {
	return link->uri;
}

EMSCRIPTEN_KEEPALIVE
int wasm_resolve_link_chapter(fz_document *doc, const char *uri) {
	int chapter;
	fz_try(ctx)
		chapter = fz_resolve_link(ctx, doc, uri, NULL, NULL).chapter;
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return chapter;
}

EMSCRIPTEN_KEEPALIVE
int wasm_resolve_link_page(fz_document *doc, const char *uri) {
	int page;
	fz_try(ctx)
		page = fz_resolve_link(ctx, doc, uri, NULL, NULL).page;
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return page;
}

EMSCRIPTEN_KEEPALIVE
int wasm_page_number_from_location(fz_document *doc, int chapter, int page) {
	fz_location link_loc = { chapter, page };
	int page_number;
	fz_try(ctx)
		page_number = fz_page_number_from_location(ctx, doc, link_loc);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return page_number;
}

EMSCRIPTEN_KEEPALIVE
char *wasm_outline_title(fz_outline *node)
{
	return node->title;
}

EMSCRIPTEN_KEEPALIVE
int wasm_outline_page(fz_document *doc, fz_outline *node)
{
	int pageNumber;
	fz_try(ctx)
		pageNumber = fz_page_number_from_location(ctx, doc, node->page);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return pageNumber;
}

EMSCRIPTEN_KEEPALIVE
fz_outline *wasm_outline_down(fz_outline *node)
{
	return node->down;
}

EMSCRIPTEN_KEEPALIVE
fz_outline *wasm_outline_next(fz_outline *node)
{
	return node->next;
}

EMSCRIPTEN_KEEPALIVE
pdf_annot *wasm_pdf_first_annot(pdf_page *page)
{
	return pdf_first_annot(ctx, page);
}

EMSCRIPTEN_KEEPALIVE
pdf_annot *wasm_pdf_next_annot(pdf_annot *annot)
{
	return pdf_next_annot(ctx, annot);
}

EMSCRIPTEN_KEEPALIVE
fz_rect *wasm_pdf_bound_annot(pdf_annot *annot)
{
	fz_try(ctx)
		out_rect = pdf_bound_annot(ctx, annot);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return &out_rect;
}

EMSCRIPTEN_KEEPALIVE
const char *wasm_pdf_annot_type_string(pdf_annot *annot)
{
	const char *type_string = NULL;
	fz_try(ctx)
		type_string = pdf_string_from_annot_type(ctx, pdf_annot_type(ctx, annot));
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return type_string;
}

EMSCRIPTEN_KEEPALIVE
int wasm_search_page(fz_page *page, const char *needle, fz_quad *hit_bbox, int hit_max)
{
	int hitCount;
	fz_try(ctx)
		hitCount = fz_search_page(ctx, page, needle, NULL, hit_bbox, hit_max);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return hitCount;
}

EMSCRIPTEN_KEEPALIVE
size_t wasm_size_of_quad() {
	return sizeof(fz_quad);
}

EMSCRIPTEN_KEEPALIVE
fz_rect *wasm_rect_from_quad(fz_quad *quad)
{
	out_rect = fz_rect_from_quad(*quad);
	return &out_rect;
}

EMSCRIPTEN_KEEPALIVE
fz_colorspace *wasm_device_gray(void)
{
	return fz_device_rgb(ctx);
}

EMSCRIPTEN_KEEPALIVE
fz_colorspace *wasm_device_rgb(void)
{
	return fz_device_rgb(ctx);
}

EMSCRIPTEN_KEEPALIVE
fz_colorspace *wasm_device_bgr(void)
{
	return fz_device_bgr(ctx);
}

EMSCRIPTEN_KEEPALIVE
fz_colorspace *wasm_device_cmyk(void)
{
	return fz_device_cmyk(ctx);
}

EMSCRIPTEN_KEEPALIVE
void wasm_drop_colorspace(fz_colorspace *cs)
{
	fz_drop_colorspace(ctx, cs);
}

EMSCRIPTEN_KEEPALIVE
fz_pixmap *wasm_new_pixmap_from_page(fz_page *page,
	float a, float b, float c, float d, float e, float f,
	fz_colorspace *colorspace,
	int alpha)
{
	fz_pixmap *pix;
	fz_try(ctx)
		pix = fz_new_pixmap_from_page(ctx, page, fz_make_matrix(a,b,c,d,e,f), colorspace, alpha);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return pix;
}

EMSCRIPTEN_KEEPALIVE
void wasm_drop_pixmap(fz_pixmap *pix)
{
	fz_drop_pixmap(ctx, pix);
}

EMSCRIPTEN_KEEPALIVE
fz_irect *wasm_pixmap_bbox(fz_pixmap *pix)
{
	fz_try(ctx)
		out_irect = fz_pixmap_bbox(ctx, pix);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return &out_irect;
}

EMSCRIPTEN_KEEPALIVE
int wasm_pixmap_stride(fz_pixmap *pix)
{
	int stride;
	fz_try(ctx)
		stride = fz_pixmap_stride(ctx, pix);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return stride;
}

EMSCRIPTEN_KEEPALIVE
unsigned char *wasm_pixmap_samples(fz_pixmap *pix)
{
	unsigned char *samples;
	fz_try(ctx)
		samples = fz_pixmap_samples(ctx, pix);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return samples;
}

EMSCRIPTEN_KEEPALIVE
fz_buffer *wasm_new_buffer(size_t capacity)
{
	fz_buffer *buf;
	fz_try(ctx)
		buf = fz_new_buffer(ctx, capacity);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return buf;
}

EMSCRIPTEN_KEEPALIVE
fz_buffer *wasm_new_buffer_from_data(unsigned char *data, size_t size)
{
	fz_buffer *buf;
	fz_try(ctx)
		buf = fz_new_buffer_from_data(ctx, data, size);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return buf;
}

EMSCRIPTEN_KEEPALIVE
fz_buffer *wasm_new_buffer_from_pixmap_as_png(fz_pixmap *pix)
{
	fz_buffer *buf;
	fz_try(ctx)
		buf = fz_new_buffer_from_pixmap_as_png(ctx, pix, fz_default_color_params);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return buf;
}

EMSCRIPTEN_KEEPALIVE
void wasm_drop_buffer(fz_buffer *buf)
{
	fz_drop_buffer(ctx, buf);
}

EMSCRIPTEN_KEEPALIVE
unsigned char *wasm_buffer_data(fz_buffer *buf)
{
	return buf->data;
}

EMSCRIPTEN_KEEPALIVE
size_t wasm_buffer_size(fz_buffer *buf)
{
	return buf->len;
}

EMSCRIPTEN_KEEPALIVE
size_t wasm_buffer_capacity(fz_buffer *buf)
{
	return buf->cap;
}

EMSCRIPTEN_KEEPALIVE
void wasm_resize_buffer(fz_buffer *buf, size_t capacity) {
	fz_try(ctx)
		fz_resize_buffer(ctx, buf, capacity);
	fz_catch(ctx)
		wasm_rethrow(ctx);
}

EMSCRIPTEN_KEEPALIVE
void wasm_grow_buffer(fz_buffer *buf) {
	fz_try(ctx)
		fz_grow_buffer(ctx, buf);
	fz_catch(ctx)
		wasm_rethrow(ctx);
}

EMSCRIPTEN_KEEPALIVE
void wasm_trim_buffer(fz_buffer *buf) {
	fz_try(ctx)
		fz_trim_buffer(ctx, buf);
	fz_catch(ctx)
		wasm_rethrow(ctx);
}

EMSCRIPTEN_KEEPALIVE
void wasm_clear_buffer(fz_buffer *buf) {
	fz_try(ctx)
		fz_clear_buffer(ctx, buf);
	fz_catch(ctx)
		wasm_rethrow(ctx);
}

EMSCRIPTEN_KEEPALIVE
int wasm_buffers_eq(fz_buffer *buf1, fz_buffer *buf2) {
	if (buf1->len != buf2->len)
		return 0;
	else
		return memcmp(buf1->data, buf2->data, buf1->len) == 0;
}

EMSCRIPTEN_KEEPALIVE
fz_output *wasm_new_output_with_buffer(fz_buffer *buf) {
	fz_output *output;
	fz_try(ctx)
		output = fz_new_output_with_buffer(ctx, buf);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return output;
}

EMSCRIPTEN_KEEPALIVE
void wasm_close_output(fz_output *output) {
	fz_try(ctx)
		fz_close_output(ctx, output);
	fz_catch(ctx)
		wasm_rethrow(ctx);
}

EMSCRIPTEN_KEEPALIVE
fz_stream *wasm_new_stream_from_buffer(fz_buffer *buf)
{
	fz_stream *stream;
	fz_try(ctx)
		stream = fz_open_buffer(ctx, buf);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return stream;
}

EMSCRIPTEN_KEEPALIVE
fz_stream *wasm_new_stream_from_data(unsigned char *data, size_t size)
{
	fz_stream *stream;
	fz_try(ctx)
		stream = fz_open_memory(ctx, data, size);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return stream;
}

EMSCRIPTEN_KEEPALIVE
void wasm_drop_stream(fz_stream *stream)
{
	fz_drop_stream(ctx, stream);
}

EMSCRIPTEN_KEEPALIVE
fz_buffer *wasm_read_all(fz_stream *stream, size_t initial) {
	fz_buffer *buffer;
	fz_try(ctx)
		buffer = fz_read_all(ctx, stream, initial);
	fz_catch(ctx)
		wasm_rethrow(ctx);
	return buffer;
}
