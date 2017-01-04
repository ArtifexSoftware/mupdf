#ifndef MUPDF_FITZ_BITMAP_H
#define MUPDF_FITZ_BITMAP_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/pixmap.h"

/*
	Bitmaps have 1 bit per component. Only used for creating halftoned
	versions of contone buffers, and saving out. Samples are stored msb
	first, akin to pbms.
*/
typedef struct fz_bitmap_s fz_bitmap;

/*
	fz_keep_bitmap: Take a reference to a bitmap.

	bit: The bitmap to increment the reference for.

	Returns bit. Does not throw exceptions.
*/
fz_bitmap *fz_keep_bitmap(fz_context *ctx, fz_bitmap *bit);

/*
	fz_drop_bitmap: Drop a reference and free a bitmap.

	Decrement the reference count for the bitmap. When no
	references remain the pixmap will be freed.

	Does not throw exceptions.
*/
void fz_drop_bitmap(fz_context *ctx, fz_bitmap *bit);

/*
	A halftone is a set of threshold tiles, one per component. Each
	threshold tile is a pixmap, possibly of varying sizes and phases.
	Currently, we only provide one 'default' halftone tile for operating
	on 1 component plus alpha pixmaps (where the alpha is ignored). This
	is signified by a fz_halftone pointer to NULL.
*/
typedef struct fz_halftone_s fz_halftone;

/*
	fz_new_bitmap_from_pixmap: Make a bitmap from a pixmap and a halftone.

	pix: The pixmap to generate from. Currently must be a single color
	component with no alpha.

	ht: The halftone to use. NULL implies the default halftone.

	Returns the resultant bitmap. Throws exceptions in the case of
	failure to allocate.
*/
fz_bitmap *fz_new_bitmap_from_pixmap(fz_context *ctx, fz_pixmap *pix, fz_halftone *ht);

/*
	fz_new_bitmap_from_pixmap_band: Make a bitmap from a pixmap and a
	halftone, allowing for the position of the pixmap within an
	overall banded rendering.

	pix: The pixmap to generate from. Currently must be a single color
	component with no alpha.

	ht: The halftone to use. NULL implies the default halftone.

	band_start: Vertical offset within the overall banded rendering
	(in pixels)

	Returns the resultant bitmap. Throws exceptions in the case of
	failure to allocate.
*/
fz_bitmap *fz_new_bitmap_from_pixmap_band(fz_context *ctx, fz_pixmap *pix, fz_halftone *ht, int band_start);

struct fz_bitmap_s
{
	int refs;
	int w, h, stride, n;
	int xres, yres;
	unsigned char *samples;
};

/*
	fz_new_bitmap: Create a new bitmap.

	w, h: Width and Height for the bitmap

	n: Number of color components (assumed to be a divisor of 8)

	xres, yres: X and Y resolutions (in pixels per inch).

	Returns pointer to created bitmap structure. The bitmap
	data is uninitialised.
*/
fz_bitmap *fz_new_bitmap(fz_context *ctx, int w, int h, int n, int xres, int yres);

/*
	fz_bitmap_details: Retrieve details of a given bitmap.

	bitmap: The bitmap to query.

	w: Pointer to storage to retrieve width (or NULL).

	h: Pointer to storage to retrieve height (or NULL).

	n: Pointer to storage to retrieve number of color components (or NULL).

	stride: Pointer to storage to retrieve bitmap stride (or NULL).
*/
void fz_bitmap_details(fz_bitmap *bitmap, int *w, int *h, int *n, int *stride);

/*
	fz_clear_bitmap: Clear a previously created bitmap.

	bit: The bitmap to clear.
*/
void fz_clear_bitmap(fz_context *ctx, fz_bitmap *bit);

/*
	fz_default_halftone: Create a 'default' halftone structure
	for the given number of components.

	num_comps: The number of components to use.

	Returns a simple default halftone. The default halftone uses
	the same halftone tile for each plane, which may not be ideal
	for all purposes.
*/
fz_halftone *fz_default_halftone(fz_context *ctx, int num_comps);

/*
	fz_keep_halftone: Take an additional reference to a
	halftone.
*/
fz_halftone *fz_keep_halftone(fz_context *ctx, fz_halftone *half);

/*
	fz_drop_halftone: Drop a reference to a halftone. If the
	reference count reaches zero, ht will be destroyed.
*/
void fz_drop_halftone(fz_context *ctx, fz_halftone *ht);

#endif
