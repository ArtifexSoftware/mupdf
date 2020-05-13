#ifndef MUPDF_FITZ_GLYPH_CACHE_H
#define MUPDF_FITZ_GLYPH_CACHE_H

#include "mupdf/fitz/context.h"
#include "mupdf/fitz/geometry.h"
#include "mupdf/fitz/font.h"
#include "mupdf/fitz/pixmap.h"

/**
	Purge all the glyphs from the cache.
*/
void fz_purge_glyph_cache(fz_context *ctx);

/**
	Create a pixmap containing a rendered glyph.

	Lookup gid from font, clip it with scissor, and rendering it
	with aa bits of antialiasing into a new pixmap.

	The caller takes ownership of the pixmap and so must free it.

	Note: This function is no longer used for normal rendering
	operations, and is kept around just because we use it in the
	app. It should be considered "at risk" of removal from the API.
*/
fz_pixmap *fz_render_glyph_pixmap(fz_context *ctx, fz_font *font, int gid, fz_matrix *ctm, const fz_irect *scissor, int aa);

/**
	Nasty PDF interpreter specific hernia, required to allow the
	interpreter to replay glyphs from a type3 font directly into
	the target device.

	This is only used in exceptional circumstances (such as type3
	glyphs that inherit current graphics state, or nested type3
	glyphs).
*/
void fz_render_t3_glyph_direct(fz_context *ctx, fz_device *dev, fz_font *font, int gid, fz_matrix trm, void *gstate, fz_default_colorspaces *def_cs);

/**
	Force a type3 font to cache the displaylist for a given glyph
	id.

	This caching can involve reading the underlying file, so must
	happen ahead of time, so we aren't suddenly forced to read the
	file while playing a displaylist back.
*/
void fz_prepare_t3_glyph(fz_context *ctx, fz_font *font, int gid);

/**
	Dump debug statistics for the glyph cache.
*/
void fz_dump_glyph_cache_stats(fz_context *ctx, fz_output *out);

/**
	Perform subpixel quantisation and adjustment on a glyph matrix.

	ctm: On entry, the desired 'ideal' transformation for a glyph.
	On exit, adjusted to a (very similar) transformation quantised
	for subpixel caching.

	subpix_ctm: Initialised by the routine to the transform that
	should be used to render the glyph.

	qe, qf: which subpixel position we quantised to.

	Returns: the size of the glyph.

	Note: This is currently only exposed for use in our app. It
	should be considered "at risk" of removal from the API.
*/
float fz_subpixel_adjust(fz_context *ctx, fz_matrix *ctm, fz_matrix *subpix_ctm, unsigned char *qe, unsigned char *qf);

#endif
