#ifndef MUPDF_FITZ_SEPARATION_H
#define MUPDF_FITZ_SEPARATION_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"

/*
	A fz_separation structure holds details of a set of separations
	(such as might be used on within a page of the document).

	The app might control the separations by enabling/disabling them,
	and subsequent renders would take this into account.
*/

enum
{
	FZ_MAX_SEPARATIONS = 64
};

typedef struct fz_separations_s fz_separations;

typedef enum
{
	/* "Composite" separations are rendered using process
	 * colors using the equivalent colors */
	FZ_SEPARATION_COMPOSITE = 0,
	/* Spot colors are rendered into their own spot plane. */
	FZ_SEPARATION_SPOT = 1,
	/* Disabled colors are not rendered at all in the final
	 * output. */
	FZ_SEPARATION_DISABLED = 2
} fz_separation_behavior;

/* Create a new separations structure (initially empty) */
fz_separations *fz_new_separations(fz_context *ctx, int controllable);

/* Keep a reference */
fz_separations *fz_keep_separations(fz_context *ctx, fz_separations *sep);

/* Drop a reference */
void fz_drop_separations(fz_context *ctx, fz_separations *sep);

/* Add a separation (RGBA and CYMK equivalents, null terminated name) */
void fz_add_separation(fz_context *ctx, fz_separations *sep, uint32_t rgba, uint32_t cmyk, const char *name);

/* Control the rendering of a given separation */
void fz_set_separation_behavior(fz_context *ctx, fz_separations *sep, int separation, fz_separation_behavior behavior);

/* Test for the current behavior of a separation */
fz_separation_behavior fz_separation_current_behavior(fz_context *ctx, const fz_separations *sep, int separation);

/* Quick test for all separations composite (the common case) */
int fz_separations_all_composite(fz_context *ctx, const fz_separations *sep);

/* Read separation details */
const char *fz_get_separation(fz_context *ctx, const fz_separations *sep, int separation, uint32_t *rgb, uint32_t *cmyk);

/* Count the number of separations */
int fz_count_separations(fz_context *ctx, const fz_separations *sep);

/* Find out if separations are controllable. */
int fz_separations_controllable(fz_context *ctx, const fz_separations *seps);

/* Return the number of active separations. */
int fz_count_active_separations(fz_context *ctx, const fz_separations *seps);

#endif
